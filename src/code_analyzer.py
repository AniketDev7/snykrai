import json
import logging
import os
from dataclasses import dataclass, field, asdict
from typing import Optional

from src.snyk_client import SnykClient
from src.llm_client import LLMClient

logger = logging.getLogger(__name__)

# Process findings in batches to stay within LLM context limits
BATCH_SIZE = 5
# Lines of context to read around each finding
CONTEXT_LINES = 40
# Default minimum confidence to auto-ignore a false positive.
# Override via IGNORE_CONFIDENCE env var or --ignore-confidence CLI flag.
AUTO_IGNORE_CONFIDENCE = float(os.environ.get("IGNORE_CONFIDENCE", "0.75"))


@dataclass
class AnalysisResult:
    project_id: str
    repo: str
    total_findings: int = 0
    unique_issue_count: int = 0  # Deduped by rule key — matches Snyk UI count
    false_positives: list[dict] = field(default_factory=list)
    true_positives: list[dict] = field(default_factory=list)
    needs_review: list[dict] = field(default_factory=list)
    ignored_count: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class CodeAnalyzer:
    def __init__(
        self,
        snyk_client: SnykClient,
        llm_client: LLMClient,
    ):
        self.snyk_client = snyk_client
        self.llm_client = llm_client

    def run(
        self,
        project_id: str,
        repo_path: str,
        repo_name: str = "",
        auto_ignore: bool = False,
    ) -> AnalysisResult:
        """Analyze SAST findings for a project, classify with LLM, optionally auto-ignore."""
        result = AnalysisResult(project_id=project_id, repo=repo_name)

        # Fetch code analysis issues from Snyk
        logger.info(f"Fetching code analysis issues for project {project_id}...")
        try:
            findings = self.snyk_client.get_code_issues(project_id)
        except Exception as e:
            logger.error(f"Failed to fetch code issues: {e}")
            result.errors.append(f"API error: {e}")
            return result

        # Filter out already-ignored findings
        open_findings = [f for f in findings if not f.get("ignored")]
        result.total_findings = len(open_findings)
        result.unique_issue_count = len(open_findings)
        logger.info(f"Found {len(open_findings)} open code analysis findings")

        if not open_findings:
            return result

        # Process in batches
        for i in range(0, len(open_findings), BATCH_SIZE):
            batch = open_findings[i:i + BATCH_SIZE]
            self._analyze_batch(batch, repo_path, result)

        # Auto-ignore false positives if requested
        if auto_ignore:
            self._auto_ignore_false_positives(project_id, result)
            # Verify ignores took effect and log updated counts
            if result.ignored_count > 0:
                counts = self.snyk_client.verify_ignores_applied(project_id)
                logger.info(
                    f"Snyk state after auto-ignore: {counts['open']} open, "
                    f"{counts['ignored']} ignored (UI may lag — use 'Retest now' in browser)"
                )

        logger.info(
            f"Analysis complete: {len(result.false_positives)} false positives, "
            f"{len(result.true_positives)} true positives, "
            f"{len(result.needs_review)} needs review"
        )
        return result

    def _analyze_batch(
        self,
        findings: list[dict],
        repo_path: str,
        result: AnalysisResult,
    ) -> None:
        """Send a batch of findings to the LLM for classification."""
        # Build findings context with source code
        findings_text = []
        source_sections = []

        for finding in findings:
            finding_desc = {
                "id": finding["id"],
                "title": finding["title"],
                "severity": finding["severity"],
                "cwe": finding.get("cwe", []),
                "priority_score": finding.get("priority_score", 0),
                "file_paths": finding.get("file_paths", []),
            }
            findings_text.append(finding_desc)

            # Read source code for each file path
            for fp in finding.get("file_paths", []):
                source = self._read_source_context(
                    repo_path, fp["path"], fp.get("start_line", 0)
                )
                if source:
                    source_sections.append(
                        f"--- {fp['path']}:{fp.get('start_line', '?')} "
                        f"(finding: {finding['id']}) ---\n{source}"
                    )

        if not findings_text:
            return

        # Build and send prompt
        prompt = self._build_prompt(
            json.dumps(findings_text, indent=2),
            "\n\n".join(source_sections) if source_sections else "No source code available.",
            repo_name=result.repo,
        )

        try:
            providers = self.llm_client._get_provider_order()
            raw_response = ""
            for prov in providers:
                try:
                    raw_response = self.llm_client._call_provider(prov, prompt)
                    break
                except Exception:
                    continue

            if not raw_response:
                result.errors.append("All LLM providers failed for batch")
                # Mark all as needs_review
                for f in findings:
                    result.needs_review.append({
                        "id": f["id"], "title": f["title"],
                        "severity": f["severity"],
                        "verdict": "needs_review",
                        "reasoning": "LLM analysis failed",
                    })
                return

            classifications = self._parse_response(raw_response)
            self._apply_classifications(findings, classifications, result)

        except Exception as e:
            logger.error(f"Error analyzing batch: {e}")
            result.errors.append(str(e))
            for f in findings:
                result.needs_review.append({
                    "id": f["id"], "title": f["title"],
                    "severity": f["severity"],
                    "verdict": "needs_review",
                    "reasoning": f"Analysis error: {e}",
                })

    def _read_source_context(
        self, repo_path: str, file_path: str, start_line: int
    ) -> Optional[str]:
        """Read source code around the flagged location."""
        full_path = os.path.join(repo_path, file_path.lstrip("/"))
        if not os.path.exists(full_path):
            return None
        try:
            with open(full_path) as f:
                lines = f.readlines()
            # Read context around the flagged line
            start = max(0, start_line - CONTEXT_LINES // 2)
            end = min(len(lines), start_line + CONTEXT_LINES // 2)
            numbered = []
            for i, line in enumerate(lines[start:end], start=start + 1):
                marker = " >> " if i == start_line else "    "
                numbered.append(f"{marker}{i:4d} | {line.rstrip()}")
            return "\n".join(numbered)
        except Exception:
            return None

    def _build_prompt(self, findings_json: str, source_code: str, repo_name: str = "") -> str:
        """Build the analysis prompt from template, optionally injecting repo-specific context."""
        prompt_dir = os.path.join(
            os.path.dirname(__file__), "..", "resources", "prompts"
        )
        prompt_file = os.path.join(prompt_dir, "analyze_code.txt")
        with open(prompt_file) as f:
            template = f.read()

        # Load repo-specific context if available
        repo_context = ""
        if repo_name:
            context_file = os.path.join(prompt_dir, "repo_contexts", f"{repo_name}.md")
            if os.path.exists(context_file):
                with open(context_file) as f:
                    repo_context = f.read()
                logger.info(f"Loaded repo context for {repo_name}")

        return (
            template
            .replace("{findings}", findings_json)
            .replace("{source_code}", source_code)
            .replace("{repo_context}", repo_context)
        )

    def _parse_response(self, raw_text: str) -> list[dict]:
        """Parse LLM response into classification list."""
        cleaned = self.llm_client._extract_json(raw_text)
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            return []
        return data.get("findings", [])

    def _apply_classifications(
        self,
        findings: list[dict],
        classifications: list[dict],
        result: AnalysisResult,
    ) -> None:
        """Map LLM classifications back to findings and sort into buckets."""
        classification_map = {c["id"]: c for c in classifications if "id" in c}

        for finding in findings:
            fid = finding["id"]
            classification = classification_map.get(fid, {})
            verdict = classification.get("verdict", "needs_review")
            entry = {
                "id": fid,
                "key": finding.get("key", ""),
                "key_asset": finding.get("key_asset", ""),
                "title": finding["title"],
                "severity": finding["severity"],
                "cwe": finding.get("cwe", []),
                "file_paths": finding.get("file_paths", []),
                "verdict": verdict,
                "confidence": classification.get("confidence", 0),
                "reasoning": classification.get("reasoning", "No classification returned"),
                "evidence": classification.get("evidence", ""),
                "suggested_ignore_reason": classification.get("suggested_ignore_reason", ""),
            }

            if verdict == "false_positive":
                result.false_positives.append(entry)
            elif verdict == "true_positive":
                result.true_positives.append(entry)
            else:
                result.needs_review.append(entry)

    def _auto_ignore_false_positives(
        self, project_id: str, result: AnalysisResult
    ) -> None:
        """Ignore high-confidence false positives via Snyk Policies API.

        Code/SAST ignores use the Policies API (asset-scoped). The v1 ignore
        endpoint only works for dependency vulnerabilities. Duplicate detection
        is handled inside _ignore_via_policy by checking existing policies.
        """
        for fp in result.false_positives:
            confidence = fp.get("confidence", 0)
            if confidence < AUTO_IGNORE_CONFIDENCE:
                logger.info(
                    f"Skipping ignore for {fp['id']} — confidence {confidence:.0%} "
                    f"below threshold {AUTO_IGNORE_CONFIDENCE:.0%}"
                )
                continue

            key_asset = fp.get("key_asset", "")
            if not key_asset:
                logger.warning(
                    f"Cannot ignore {fp['id']} ({fp['title']}): "
                    f"key_asset missing from REST API response"
                )
                result.errors.append(f"Missing key_asset for {fp['id']}")
                continue

            reason_text = (
                f"SnykrAI auto-triage ({confidence:.0%} confidence): "
                f"{fp.get('suggested_ignore_reason') or fp.get('reasoning', 'false positive')}"
            )
            try:
                success = self.snyk_client.ignore_code_issue(
                    project_id=project_id,
                    issue_id=fp["id"],
                    reason_type="not-vulnerable",
                    reason_text=reason_text[:256],
                    key_asset=key_asset,
                )
                if success:
                    result.ignored_count += 1
                    logger.info(f"Ignored {fp['id']}: {fp['title']}")
                else:
                    logger.warning(f"Failed to ignore {fp['id']}: {fp['title']}")
                    result.errors.append(f"Ignore API failed for {fp['id']}")
            except Exception as e:
                logger.error(f"Error ignoring {fp['id']}: {e}")
                result.errors.append(f"Ignore error for {fp['id']}: {e}")
