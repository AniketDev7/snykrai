import json
import logging
import os
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

import requests

from src.snyk_client import SnykClient
from src.llm_client import LLMClient, LLMResponse
from src.git_ops import GitOps, SecurityError
from src.secret_scanner import SecretScanner
from src.ecosystems import get_handler

logger = logging.getLogger(__name__)

# Batch limits — keep PRs reviewable
MAX_VULNS_PER_PR = 20
MAX_FILES_PER_PR = 15
MAX_FIX_ATTEMPTS = 3


def parse_semver(version: str) -> tuple[int, int, int]:
    """Extract major.minor.patch from a version string. Returns (0,0,0) on failure."""
    cleaned = re.sub(r"^[^0-9]*", "", version)
    parts = cleaned.split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2].split("-")[0]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except (ValueError, IndexError):
        return (0, 0, 0)


def classify_upgrade_risk(from_version: str, to_version: str) -> str:
    """Classify upgrade risk based on semver difference.

    Returns: "patch", "minor", "major", or "unknown"
    """
    from_v = parse_semver(from_version)
    to_v = parse_semver(to_version)
    if from_v == (0, 0, 0) or to_v == (0, 0, 0):
        return "unknown"
    if to_v[0] > from_v[0]:
        return "major"
    if to_v[1] > from_v[1]:
        return "minor"
    return "patch"


@dataclass
class FixResult:
    repo: str
    name: str
    success: bool
    fixes_applied: list[dict] = field(default_factory=list)
    unfixable: list[dict] = field(default_factory=list)
    pr_url: Optional[str] = None
    issues_before: int = 0
    issues_after: int = 0
    error: Optional[str] = None
    strategy: str = ""
    branch: str = ""
    llm_provider: str = ""
    attempts: int = 0
    breaking_changes: list[dict] = field(default_factory=list)
    risk_level: str = ""  # "patch", "minor", "major"
    draft_pr: bool = False
    build_passed: bool = False
    tests_passed: bool = False
    tests_skipped: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class SnykFixer:
    def __init__(
        self,
        repo_config: dict,
        snyk_client: SnykClient,
        llm_client: LLMClient,
        git_ops: GitOps,
    ):
        self.repo_config = repo_config
        self.repo = repo_config["repo"]
        self.name = repo_config["name"]
        self.ecosystem = repo_config["ecosystem"]
        self.default_branch = repo_config.get("default_branch", "main")
        self.pr_base_branch = repo_config.get("pr_base_branch", self.default_branch)
        self.strategy = repo_config.get("strategy", "conservative")
        self.visibility = repo_config.get("visibility", "public")
        self.snyk_project_id = repo_config.get("snyk_project_id", "")
        self.transitive_overrides = repo_config.get("transitive_overrides", False)
        self.skip_tests = repo_config.get("skip_tests", False)
        self.off_limits_packages = {
            entry["package"]
            for entry in repo_config.get("off_limits_packages", [])
            if "package" in entry
        }
        self.snyk_client = snyk_client
        self.llm_client = llm_client
        self.git_ops = git_ops
        self.handler = get_handler(self.ecosystem)

    def run(self, work_dir: str, cascade_context: Optional[dict] = None) -> FixResult:
        branch_name = self.git_ops.get_branch_name()
        repo_dir = os.path.join(work_dir, "repo")
        internal_dir = os.path.join(work_dir, "_internal")
        os.makedirs(internal_dir, exist_ok=True)

        try:
            # Phase 1: Fetch and classify issues
            issues = self.snyk_client.get_issues(self.snyk_project_id)
            issues_before = len(issues)
            self._save_internal(internal_dir, "snyk_output.json", issues)

            if not issues:
                return FixResult(
                    repo=self.repo, name=self.name, success=True,
                    issues_before=0, issues_after=0, strategy=self.strategy,
                    branch=branch_name,
                )

            fixable, unfixable = self._classify_issues(issues)

            if not fixable:
                return FixResult(
                    repo=self.repo, name=self.name, success=True,
                    unfixable=[{"package": i["package_name"], "reason": "No fix version available"} for i in unfixable],
                    issues_before=issues_before, issues_after=issues_before,
                    strategy=self.strategy, branch=branch_name,
                )

            # Batch limit: cap fixable issues to keep PRs reviewable
            if len(fixable) > MAX_VULNS_PER_PR:
                logger.info(f"Capping fixable issues from {len(fixable)} to {MAX_VULNS_PER_PR}")
                severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                fixable.sort(key=lambda i: severity_order.get(i.get("severity", "low"), 3))
                overflow = fixable[MAX_VULNS_PER_PR:]
                fixable = fixable[:MAX_VULNS_PER_PR]
                unfixable.extend(overflow)

            # Phase 2: Clone and create fix branch
            self.git_ops.clone_repo(self.repo, repo_dir, self.pr_base_branch)
            self.git_ops.create_branch(repo_dir, branch_name)

            # Phase 3: Fix with retry loop
            if not self.handler.detect(repo_dir):
                return FixResult(
                    repo=self.repo, name=self.name, success=False,
                    error=f"No manifest found in repo for ecosystem '{self.ecosystem}'. Clone may have failed or ecosystem misdetected.",
                    issues_before=issues_before, issues_after=issues_before,
                    strategy=self.strategy, branch=branch_name,
                )
            manifest = self.handler.read_manifest(repo_dir)
            best_result = None

            for attempt in range(1, MAX_FIX_ATTEMPTS + 1):
                logger.info(f"Fix attempt {attempt}/{MAX_FIX_ATTEMPTS} for {self.name}")

                if attempt > 1:
                    self._rollback(repo_dir)
                    manifest = self.handler.read_manifest(repo_dir)

                llm_response = self.llm_client.get_fix_suggestions(
                    ecosystem=self.ecosystem,
                    manifest=manifest,
                    issues=fixable,
                    strategy=self.strategy,
                )
                self._save_internal(internal_dir, f"llm_response_attempt{attempt}.json", {
                    "fixes": llm_response.fixes,
                    "unfixable": llm_response.unfixable,
                    "provider": llm_response.provider_used,
                    "error": llm_response.raw_error,
                    "attempt": attempt,
                })

                if llm_response.raw_error:
                    logger.warning(f"LLM error on attempt {attempt}: {llm_response.raw_error}")
                    continue

                if not llm_response.fixes:
                    logger.warning(f"LLM returned no fixes on attempt {attempt}")
                    continue

                # Phase 3a: Check for breaking changes before applying
                breaking = self._check_breaking_changes(repo_dir, llm_response.fixes)
                if breaking:
                    logger.info(f"Potential breaking changes detected: {breaking}")

                # Apply fixes
                for fix in llm_response.fixes:
                    self.handler.apply_fix(repo_dir, fix)

                # Install dependencies
                install_cmd = shlex.split(self.handler.install_command)
                install_result = subprocess.run(
                    install_cmd,
                    cwd=repo_dir, capture_output=True, text=True,
                )
                if install_result.returncode != 0:
                    stderr = install_result.stderr
                    if any(sig in stderr for sig in ("ERESOLVE", "peer dep", "peer dependencies")):
                        logger.info("Retrying install with --legacy-peer-deps due to peer conflict")
                        install_result = subprocess.run(
                            install_cmd + ["--legacy-peer-deps"],
                            cwd=repo_dir, capture_output=True, text=True,
                        )
                if install_result.returncode != 0:
                    stderr = install_result.stderr
                    if "EBADENGINE" in stderr or "command sh -c" in stderr:
                        logger.info("Retrying install with --ignore-scripts due to postinstall failure")
                        install_result = subprocess.run(
                            install_cmd + ["--ignore-scripts"],
                            cwd=repo_dir, capture_output=True, text=True,
                        )
                if install_result.returncode != 0:
                    stderr = install_result.stderr
                    log_excerpt = (stderr[:300] + "\n...\n" + stderr[-500:]) if len(stderr) > 800 else stderr
                    logger.warning(f"Install failed on attempt {attempt}:\n{log_excerpt}")
                    continue

                # Phase 4: Validate — run snyk test
                issues_after = self._verify_fix(repo_dir, issues_before)

                if issues_after < issues_before:
                    best_result = {
                        "llm_response": llm_response,
                        "issues_after": issues_after,
                        "attempt": attempt,
                        "breaking": breaking,
                    }
                    break
                else:
                    logger.warning(
                        f"Attempt {attempt}: fix did not reduce issues "
                        f"({issues_before} -> {issues_after})"
                    )

            if best_result is None:
                self._rollback(repo_dir)
                return FixResult(
                    repo=self.repo, name=self.name, success=False,
                    error=f"Fix did not reduce issue count after {MAX_FIX_ATTEMPTS} attempts. Rolled back.",
                    issues_before=issues_before, issues_after=issues_before,
                    strategy=self.strategy, branch=branch_name,
                    attempts=MAX_FIX_ATTEMPTS,
                )

            llm_response = best_result["llm_response"]
            issues_after = best_result["issues_after"]

            # Phase 5: Assess upgrade risk
            risk_level = self._assess_risk(llm_response.fixes)
            logger.info(f"Upgrade risk level: {risk_level}")

            if best_result["breaking"]:
                logger.info("Running deep breaking change analysis with changelog + LLM...")
                analyzed_breaking = self._analyze_breaking_changes(
                    repo_dir, llm_response.fixes, best_result["breaking"],
                )
                best_result["breaking"] = analyzed_breaking
                self._save_internal(internal_dir, "breaking_change_analysis.json", analyzed_breaking)

            override_fixes = [
                f for f in llm_response.fixes
                if any(
                    i.get("_fix_mode") == "override" and i.get("package_name") == f.get("package")
                    for i in fixable
                )
            ]
            if override_fixes:
                logger.info(f"Running transitive override impact analysis for {len(override_fixes)} override(s)...")
                transitive_impact = self._analyze_transitive_override_impact(override_fixes, fixable)
                best_result["breaking"].extend(transitive_impact)
                self._save_internal(internal_dir, "transitive_override_impact.json", transitive_impact)

            # Phase 6: Build verification
            build_passed = self._run_build(repo_dir)
            if not build_passed:
                self._rollback(repo_dir)
                return FixResult(
                    repo=self.repo, name=self.name, success=False,
                    error="Build failed after applying fixes. Rolled back — no PR created.",
                    issues_before=issues_before, issues_after=issues_before,
                    strategy=self.strategy, branch=branch_name,
                    attempts=best_result["attempt"], risk_level=risk_level,
                    build_passed=False,
                )

            # Phase 7: Test verification
            tests_passed, tests_skipped = self._run_tests(repo_dir)
            if not tests_passed and not tests_skipped:
                self._rollback(repo_dir)
                return FixResult(
                    repo=self.repo, name=self.name, success=False,
                    error="Tests failed after applying fixes. Rolled back — no PR created.",
                    issues_before=issues_before, issues_after=issues_before,
                    strategy=self.strategy, branch=branch_name,
                    attempts=best_result["attempt"], risk_level=risk_level,
                    build_passed=True, tests_passed=False,
                )

            # Phase 8: File limit check
            changed = self.git_ops.get_changed_files(repo_dir)
            allowed = self.git_ops.filter_allowlisted(changed, self.handler.allowlisted_files)

            if not allowed:
                self._rollback(repo_dir)
                return FixResult(
                    repo=self.repo, name=self.name, success=False,
                    error="No allowlisted files changed. Rolled back.",
                    issues_before=issues_before, strategy=self.strategy,
                    branch=branch_name, attempts=best_result["attempt"],
                )

            if len(allowed) > MAX_FILES_PER_PR:
                logger.warning(
                    f"Changed {len(allowed)} files, exceeds limit of {MAX_FILES_PER_PR}. "
                    f"Proceeding with all files but flagging for review."
                )

            # Phase 9–10: Commit, push, PR
            use_draft = True
            packages = [
                (f["package"], f.get("from", ""), f["to"])
                for f in llm_response.fixes
            ]
            commit_msg = self.git_ops.build_commit_message(packages, self.visibility)
            self.git_ops.stage_and_commit(repo_dir, allowed, commit_msg)
            self.git_ops.push_branch(repo_dir, branch_name)

            risk_indicator = {"patch": "LOW", "minor": "MED", "major": "HIGH", "unknown": "???"}
            cascade_ctx = cascade_context
            if cascade_ctx and cascade_ctx.get("downstream_count", 0) > 0:
                downstream_n = cascade_ctx["downstream_count"]
                pr_title = (
                    f"fix(deps): upstream cascade fix — "
                    f"{len(llm_response.fixes)} package(s) "
                    f"[risk: {risk_indicator.get(risk_level, '???')}] "
                    f"[cascades to {downstream_n} repo(s)]"
                )
            else:
                pr_title = (
                    f"fix(deps): security update — "
                    f"{len(llm_response.fixes)} package(s) "
                    f"[risk: {risk_indicator.get(risk_level, '???')}]"
                )
            pr_body = self._build_pr_body_with_safety(
                fixes=llm_response.fixes,
                unfixable=llm_response.unfixable,
                fixable=fixable,
                risk_level=risk_level,
                build_passed=build_passed,
                tests_passed=tests_passed,
                tests_skipped=tests_skipped,
                breaking=best_result["breaking"],
                cascade_context=cascade_ctx,
            )

            pr_url = self.git_ops.create_or_update_pr(
                repo_dir, self.repo, branch_name, self.pr_base_branch,
                pr_title, pr_body, draft=use_draft,
            )

            all_unfixable = [
                {"package": u.get("package", ""), "reason": u.get("reason", "")}
                for u in llm_response.unfixable
            ] + [
                {"package": i["package_name"], "reason": "No fix version available"}
                for i in unfixable
            ]

            return FixResult(
                repo=self.repo, name=self.name, success=True,
                fixes_applied=[
                    {"package": f["package"], "from": f.get("from", ""), "to": f["to"],
                     "reasoning": f.get("reasoning", "")}
                    for f in llm_response.fixes
                ],
                unfixable=all_unfixable,
                pr_url=pr_url,
                issues_before=issues_before,
                issues_after=issues_after,
                strategy=self.strategy,
                branch=branch_name,
                llm_provider=llm_response.provider_used,
                attempts=best_result["attempt"],
                breaking_changes=best_result["breaking"],
                risk_level=risk_level,
                draft_pr=use_draft,
                build_passed=build_passed,
                tests_passed=tests_passed,
                tests_skipped=tests_skipped,
            )

        except SecurityError as e:
            self._rollback(repo_dir)
            return FixResult(
                repo=self.repo, name=self.name, success=False,
                error=f"Security abort: {e}. Rolled back.",
                strategy=self.strategy, branch=branch_name,
            )
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            logger.error(f"Unhandled error in fixer for {self.name}:\n{tb}")
            self._rollback(repo_dir)
            return FixResult(
                repo=self.repo, name=self.name, success=False,
                error=f"{e}. Rolled back.",
                strategy=self.strategy, branch=branch_name,
            )

    def _classify_issues(self, issues: list[dict]) -> tuple[list[dict], list[dict]]:
        """Classify issues as fixable or unfixable.

        Off-limits packages are always skipped.
        Direct deps with a fixed_in version are always fixable.
        Transitive deps are promoted to fixable when transitive_overrides: true.
        For transitive overrides, dep chains are fetched from Snyk so the PR body
        can show the full path and any org-owned upstream packages.
        """
        fixable = []
        unfixable = []
        for issue in issues:
            pkg = issue.get("package_name", "")
            if pkg in self.off_limits_packages:
                logger.info(f"Skipping {pkg} — in off_limits_packages for {self.name}")
                unfixable.append({**issue, "_skip_reason": "off_limits"})
                continue

            is_direct = issue.get("is_upgradeable") or issue.get("is_direct")
            if is_direct:
                fixable.append(issue)
            elif self.transitive_overrides and issue.get("fixed_in"):
                logger.info(f"Including transitive dep {pkg} for override (transitive_overrides=true)")
                enriched = {**issue, "_fix_mode": "override"}
                if self.snyk_project_id and issue.get("id"):
                    chains = self.snyk_client.get_issue_dep_chains(
                        self.snyk_project_id, issue["id"]
                    )
                    org_pkgs = self.snyk_client.find_org_packages_in_chains(chains, set())
                    enriched["_dep_chains"] = chains
                    enriched["_org_upstream_pkgs"] = org_pkgs
                    if org_pkgs:
                        logger.info(
                            f"  Upstream org package in chain for {pkg}: {org_pkgs[0]} "
                            f"— override is temporary; fix at source recommended"
                        )
                fixable.append(enriched)
            else:
                unfixable.append(issue)
        return fixable, unfixable

    def _verify_fix(self, repo_dir: str, issues_before: int) -> int:
        """Run snyk test and return the post-fix issue count."""
        manifests = self.handler.find_all_manifests(repo_dir)
        is_monorepo = len(manifests) > 1

        cmd = ["snyk", "test", "--json"]
        if is_monorepo:
            cmd.append("--all-projects")
            logger.info(f"Using snyk test --all-projects ({len(manifests)} manifests)")

        try:
            verify_result = subprocess.run(
                cmd, cwd=repo_dir, capture_output=True, text=True,
            )
        except FileNotFoundError:
            logger.warning("snyk CLI not found — skipping verify step")
            return issues_before - 1
        try:
            verify_data = json.loads(verify_result.stdout)
            if verify_data is None:
                return issues_before
            if isinstance(verify_data, list):
                return sum(r.get("uniqueCount", 0) for r in verify_data)
            return verify_data.get("uniqueCount", issues_before)
        except (json.JSONDecodeError, AttributeError):
            return issues_before

    def _rollback(self, repo_dir: str) -> None:
        """Reset the repo to the last commit state, discarding all local changes."""
        if not os.path.exists(os.path.join(repo_dir, ".git")):
            return
        subprocess.run(["git", "checkout", "--", "."], cwd=repo_dir, capture_output=True)
        subprocess.run(["git", "clean", "-fd"], cwd=repo_dir, capture_output=True)
        logger.info(f"Rolled back changes in {repo_dir}")

    def _check_breaking_changes(self, repo_dir: str, fixes: list[dict]) -> list[dict]:
        """Check if any upgraded packages are directly imported in the codebase."""
        breaking = []
        _js_globs = ("*.ts", "*.js", "*.tsx", "*.jsx", "*.mjs")
        _jvm_globs = ("*.java", "*.kt", "*.scala")
        search_globs = {
            "npm": _js_globs, "yarn": _js_globs,
            "maven": _jvm_globs, "gradle": _jvm_globs,
            "pip": ("*.py",), "python": ("*.py",),
            "gomodules": ("*.go",), "go": ("*.go",),
            "nuget": ("*.cs", "*.fs", "*.vb"), "dotnet": ("*.cs", "*.fs", "*.vb"),
        }
        globs = search_globs.get(self.ecosystem, ())

        exclude_dirs = [
            "--exclude-dir=node_modules", "--exclude-dir=.git",
            "--exclude-dir=vendor", "--exclude-dir=dist", "--exclude-dir=build",
            "--exclude-dir=target", "--exclude-dir=.tox", "--exclude-dir=__pycache__",
            "--exclude-dir=.next", "--exclude-dir=coverage",
        ]

        for fix in fixes:
            pkg = fix.get("package", "")
            if not pkg:
                continue
            search_term = pkg.split(":")[-1] if ":" in pkg else pkg

            for glob in globs:
                result = subprocess.run(
                    ["grep", "-rl", search_term, "--include", glob] + exclude_dirs + ["."],
                    cwd=repo_dir, capture_output=True, text=True,
                )
                if result.returncode == 0 and result.stdout.strip():
                    files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
                    breaking.append({
                        "package": pkg,
                        "from": fix.get("from", ""),
                        "to": fix.get("to", ""),
                        "imported_in": files[:5],
                    })
                    break

        return breaking

    def _assess_risk(self, fixes: list[dict]) -> str:
        """Determine the highest risk level across all fixes."""
        worst = "patch"
        order = {"patch": 0, "minor": 1, "major": 2, "unknown": 2}
        for fix in fixes:
            risk = classify_upgrade_risk(fix.get("from", ""), fix.get("to", ""))
            if order.get(risk, 0) > order.get(worst, 0):
                worst = risk
        return worst

    def _run_build(self, repo_dir: str) -> bool:
        """Run the ecosystem's build command. Returns True if build passes or no build command."""
        cmd = self.handler.build_command
        if not cmd:
            return True
        logger.info(f"Running build: {cmd}")
        result = subprocess.run(
            shlex.split(cmd), cwd=repo_dir, capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            logger.warning(f"Build failed: {result.stderr[:300]}")
        return result.returncode == 0

    def _run_tests(self, repo_dir: str) -> tuple[bool, bool]:
        """Run the ecosystem's test command.

        Returns: (passed: bool, skipped: bool)
        """
        if self.skip_tests:
            logger.warning(
                f"Skipping test gate for {self.name} — skip_tests: true in config.yaml. "
                f"Build gate still applies. Rationale: {self.repo_config.get('override_rationale', {}).get('reason', 'not provided')}"
            )
            return True, True

        cmd = self.handler.test_command
        if not cmd:
            return True, True

        logger.info(f"Running tests: {cmd}")
        try:
            result = subprocess.run(
                shlex.split(cmd), cwd=repo_dir, capture_output=True, text=True, timeout=600,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Tests timed out after 600s")
            return False, False

        output = result.stdout + result.stderr
        no_tests_indicators = [
            "no test specified",
            "no tests found",
            "0 tests",
            "nothing to compile",
            "is not a valid file",
            "no tests were executed",
            "no testng",
            "suite file",
            "command not found",
            "not recognized",
            "cannot find module",
            "err_module_not_found",
        ]
        if any(ind in output.lower() for ind in no_tests_indicators):
            logger.info("No tests found in repo, skipping test verification")
            return True, True

        if result.returncode != 0:
            logger.warning(f"Tests failed: {result.stderr[:300]}")
            return False, False

        return True, False

    def _build_pr_body_with_safety(
        self,
        fixes: list[dict],
        unfixable: list[dict],
        fixable: list[dict],
        risk_level: str,
        build_passed: bool,
        tests_passed: bool,
        tests_skipped: bool,
        breaking: list[dict],
        cascade_context: Optional[dict] = None,
    ) -> str:
        """Build PR body with full LLM reasoning, dep chains, and impact analysis."""
        issue_map = {i.get("package_name", ""): i for i in fixable}
        impact_map = {b.get("package", ""): b for b in breaking}

        lines = ["## Security Fix — SnykrAI", ""]

        # ── Cascade Impact ─────────────────────────────────────────────────────
        if cascade_context and cascade_context.get("downstream_count", 0) > 0:
            downstream_repos = cascade_context.get("downstream_repos", [])
            downstream_n = cascade_context["downstream_count"]
            org_pkg = cascade_context.get("org_package", cascade_context.get("cs_package", "this package"))
            vuln_pkg = cascade_context.get("vuln_package", "")
            fixed_in = cascade_context.get("fixed_in_version", "")
            lines.append("### Cascade Impact")
            lines.append("")
            lines.append(
                f"> 🔗 **Upstream fix.** Upgrading `{vuln_pkg}` in `{org_pkg}` and publishing "
                f"a new release will eliminate the need for npm `overrides` in "
                f"**{downstream_n}** downstream repo(s)."
            )
            if downstream_repos:
                repo_list = ", ".join(f"`{r}`" for r in downstream_repos[:10])
                if len(downstream_repos) > 10:
                    repo_list += f" _(+{len(downstream_repos) - 10} more)_"
                lines.append(f"> Downstream repos benefiting: {repo_list}")
            if fixed_in:
                lines.append(f"> Target version: `{vuln_pkg}@{fixed_in}` or later")
            lines.append("")
        elif cascade_context and cascade_context.get("upstream_repo_name"):
            upstream = cascade_context["upstream_repo_name"]
            org_pkg = cascade_context.get("org_package", cascade_context.get("cs_package", ""))
            lines.append("### Cascade Band-Aid")
            lines.append("")
            lines.append(
                f"> ⚠️ **Downstream override.** This is a temporary npm `overrides` fix. "
                f"A permanent fix is available upstream: upgrade `{org_pkg}` in "
                f"`{upstream}` and publish a new version."
            )
            lines.append("")

        # ── Verification ───────────────────────────────────────────────────────
        if build_passed and (tests_passed or tests_skipped):
            conf_label = "HIGH" if tests_passed else "MEDIUM (build passed; no test suite)"
        elif build_passed:
            conf_label = "MEDIUM (build passed; tests failed)"
        else:
            conf_label = "LOW (build did not pass)"

        lines.append("### Verification")
        lines.append(f"- [{'x' if build_passed else ' '}] Build passes")
        if tests_skipped:
            lines.append("- [ ] Tests _(no test suite — manual verification needed)_")
        else:
            lines.append(f"- [{'x' if tests_passed else ' '}] Tests pass")
        lines.append("- [x] Snyk re-scan confirms reduced vulnerabilities")
        lines.append(f"\n**Verification confidence: {conf_label}**")
        lines.append("")

        # ── Risk ───────────────────────────────────────────────────────────────
        risk_label = {"patch": "LOW", "minor": "MEDIUM", "major": "HIGH", "unknown": "UNKNOWN"}
        lines.append(f"### Risk: {risk_label.get(risk_level, 'UNKNOWN')}")
        if risk_level == "major":
            lines.append("> ⚠️ **Major version upgrade.** May include breaking API changes — review changelog before merging.")
        elif risk_level == "minor":
            lines.append("> Minor version upgrade. New features possible; breaking changes unlikely.")
        else:
            lines.append("> Patch-level upgrade. Security/bug fixes only.")
        lines.append("")

        # ── Fixes ──────────────────────────────────────────────────────────────
        direct_fixes = [f for f in fixes if issue_map.get(f.get("package", ""), {}).get("_fix_mode") != "override"]
        override_fixes = [f for f in fixes if issue_map.get(f.get("package", ""), {}).get("_fix_mode") == "override"]

        if direct_fixes:
            lines.append("### Direct Dependency Upgrades")
            lines.append("")
            lines.append("| Package | From | To | Risk | CVE / Snyk ID | LLM Reasoning |")
            lines.append("|---------|------|----|------|---------------|---------------|")
            for fix in direct_fixes:
                pkg = fix.get("package", "")
                from_v = fix.get("from", "?")
                to_v = fix.get("to", "?")
                risk = classify_upgrade_risk(from_v, to_v)
                issue = issue_map.get(pkg, {})
                identity = issue.get("cve") or issue.get("id", "")
                reasoning = fix.get("reasoning", "")
                lines.append(f"| {pkg} | {from_v} | {to_v} | {risk} | {identity} | {reasoning} |")
            lines.append("")

        if override_fixes:
            lines.append("### Transitive Dependency Overrides")
            lines.append("")
            lines.append("> These packages are not direct dependencies of this repo — they are pulled in")
            lines.append("> transitively. An `overrides` entry pins them to a safe version in this repo's")
            lines.append("> install tree. **This override only protects this repo's own runtime** (not downstream consumers).")
            lines.append("")
            for fix in override_fixes:
                pkg = fix.get("package", "")
                from_v = fix.get("from", "?")
                to_v = fix.get("to", "?")
                risk = classify_upgrade_risk(from_v, to_v)
                issue = issue_map.get(pkg, {})
                dep_chains = issue.get("_dep_chains", [])
                org_upstream = issue.get("_org_upstream_pkgs", [])
                identity = issue.get("cve") or issue.get("id", "")
                reasoning = fix.get("reasoning", "")
                changelog_url = self._get_changelog_url(pkg, to_v)

                lines.append(f"**{pkg}** `{from_v}` → `{to_v}` [{risk}]")
                if identity:
                    lines.append(f"- Vulnerability: `{identity}` (severity: {issue.get('severity', '?')})")
                if changelog_url:
                    lines.append(f"- Changelog: {changelog_url}")
                if dep_chains:
                    lines.append(f"- Dependency chain: `{'` → `'.join(dep_chains[0])}`")
                    if len(dep_chains) > 1:
                        lines.append(f"  _(+{len(dep_chains) - 1} more paths)_")
                if org_upstream:
                    lines.append(
                        f"- ⚠️ **Upstream fix available:** `{org_upstream[0]}` is an org-owned "
                        f"package in this dep chain. Upgrading `{pkg}` in `{org_upstream[0]}` and publishing "
                        f"a new version would eliminate this override across all repos that use `{org_upstream[0]}`."
                    )
                if reasoning:
                    lines.append(f"- LLM reasoning: {reasoning}")
                lines.append("")

        # ── LLM Impact Analysis ────────────────────────────────────────────────
        if breaking:
            direct_impacts = [b for b in breaking if b.get("fix_type") != "transitive_override" and b.get("analysis")]
            override_impacts = [b for b in breaking if b.get("fix_type") == "transitive_override" and b.get("analysis")]

            if direct_impacts:
                lines.append("### Breaking Change Analysis (Direct Upgrades)")
                lines.append("")
                for b in direct_impacts:
                    pkg = b.get("package", "")
                    files = ", ".join(f"`{f}`" for f in b.get("imported_in", []))
                    lines.append(f"**{pkg}** ({b.get('from', '?')} → {b.get('to', '?')})")
                    if files:
                        lines.append(f"- Imported in: {files}")
                    lines.append(f"- Changelog fetched: {'Yes' if b.get('changelog_available') else 'No'}")
                    lines.append(f"- **Analysis:** {b.get('analysis', '')}")
                    lines.append("")

            if override_impacts:
                lines.append("### Override Safety Analysis (LLM)")
                lines.append("")
                for b in override_impacts:
                    pkg = b.get("package", "")
                    lines.append(f"**{pkg}** override `{b.get('from', '?')}` → `{b.get('to', '?')}` [{b.get('version_jump', '?')}]")
                    lines.append(f"- Changelog fetched: {'Yes' if b.get('changelog_available') else 'No'}")
                    lines.append(f"- **Analysis:** {b.get('analysis', '')}")
                    lines.append("")

        # ── Upstream fix summary ───────────────────────────────────────────────
        all_org_upstream = []
        for fix in override_fixes:
            pkg = fix.get("package", "")
            issue = issue_map.get(pkg, {})
            org_pkgs = issue.get("_org_upstream_pkgs", [])
            for org_pkg in org_pkgs:
                all_org_upstream.append((org_pkg, pkg))

        if all_org_upstream:
            lines.append("### Upstream Fix Recommendations")
            lines.append("")
            lines.append("The following org-owned packages are root causes of the overrides above.")
            lines.append("Fixing them at source would eliminate these overrides across all downstream repos:")
            lines.append("")
            by_org_pkg: dict[str, list[str]] = {}
            for org_pkg, vuln_pkg in all_org_upstream:
                by_org_pkg.setdefault(org_pkg, []).append(vuln_pkg)
            for org_pkg, vuln_pkgs in by_org_pkg.items():
                lines.append(f"- **`{org_pkg}`** — fix transitive dep(s): `{'`, `'.join(set(vuln_pkgs))}`")
            lines.append("")

        # ── Not fixed ──────────────────────────────────────────────────────────
        if unfixable:
            lines.append("### Not Fixed")
            lines.append("")
            for u in unfixable:
                skip = u.get("_skip_reason", "")
                reason = "off-limits (config)" if skip == "off_limits" else u.get("reason", "no fix available")
                lines.append(f"- **{u.get('package', '?')}**: {reason}")
            lines.append("")

        lines.append("---")
        lines.append("_Automated by [SnykrAI](https://github.com/AniketDev7/snykrai)_")
        return "\n".join(lines)

    def _fetch_changelog(self, package: str, from_version: str, to_version: str) -> str:
        """Fetch changelog/release notes from the package registry."""
        try:
            if self.ecosystem in ("npm", "yarn"):
                return self._fetch_npm_changelog(package, from_version, to_version)
            elif self.ecosystem in ("maven", "gradle"):
                return self._fetch_maven_changelog(package, to_version)
            elif self.ecosystem in ("pip", "python"):
                return self._fetch_pypi_changelog(package, to_version)
        except Exception as e:
            logger.warning(f"Failed to fetch changelog for {package}: {e}")
        return ""

    def _fetch_npm_changelog(self, package: str, from_version: str, to_version: str) -> str:
        """Fetch npm package metadata and extract GitHub release notes if available."""
        resp = requests.get(
            f"https://registry.npmjs.org/{package}/{to_version}",
            timeout=10,
        )
        if resp.status_code != 200:
            return ""
        data = resp.json()
        repo_url = data.get("repository", {})
        if isinstance(repo_url, dict):
            repo_url = repo_url.get("url", "")
        if isinstance(repo_url, str) and "github.com" in repo_url:
            match = re.search(r"github\.com[/:]([^/]+)/([^/.]+)", repo_url)
            if match:
                owner, repo = match.group(1), match.group(2)
                return self._fetch_github_release(owner, repo, to_version)
        return ""

    def _fetch_maven_changelog(self, package: str, to_version: str) -> str:
        """For Maven, try to find GitHub release notes via search."""
        if ":" not in package:
            return ""
        group_id, artifact_id = package.split(":", 1)
        return self._fetch_github_release(group_id.split(".")[-1], artifact_id, to_version)

    def _fetch_pypi_changelog(self, package: str, to_version: str) -> str:
        """Fetch PyPI package info which sometimes contains release notes."""
        resp = requests.get(
            f"https://pypi.org/pypi/{package}/{to_version}/json",
            timeout=10,
        )
        if resp.status_code != 200:
            return ""
        data = resp.json()
        project_urls = data.get("info", {}).get("project_urls", {})
        for key in ("Repository", "Source", "GitHub", "Homepage"):
            url = project_urls.get(key, "")
            if "github.com" in url:
                match = re.search(r"github\.com/([^/]+)/([^/.]+)", url)
                if match:
                    return self._fetch_github_release(match.group(1), match.group(2), to_version)
        return ""

    def _fetch_github_release(self, owner: str, repo: str, version: str) -> str:
        """Fetch GitHub release notes for a specific version tag.

        Uses the git token if available to stay within rate limits.
        """
        headers = {"Accept": "application/vnd.github.v3+json"}
        git_token = self.git_ops.git_token
        if git_token:
            headers["Authorization"] = f"token {git_token}"

        for tag_fmt in [f"v{version}", version, f"{repo}-{version}"]:
            try:
                resp = requests.get(
                    f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag_fmt}",
                    timeout=10,
                    headers=headers,
                )
                if resp.status_code == 200:
                    body = resp.json().get("body", "")
                    if body:
                        return body[:2000]
            except Exception:
                continue
        return ""

    def _analyze_breaking_changes(
        self,
        repo_dir: str,
        fixes: list[dict],
        breaking: list[dict],
    ) -> list[dict]:
        """Use LLM to analyze whether upgrades will break existing code."""
        if not breaking:
            return []

        repo_context = self._read_repo_context(repo_dir)
        analyzed = []
        for b in breaking:
            pkg = b["package"]
            from_ver = b.get("from", "")
            to_ver = b.get("to", "")
            files = b.get("imported_in", [])

            changelog = self._fetch_changelog(pkg, from_ver, to_ver)

            code_snippets = []
            for filepath in files[:3]:
                full_path = os.path.join(repo_dir, filepath.lstrip("./"))
                if os.path.exists(full_path):
                    try:
                        with open(full_path) as f:
                            lines = f.readlines()[:200]
                            code_snippets.append(f"--- {filepath} ---\n{''.join(lines)}")
                    except Exception:
                        pass

            if changelog or code_snippets:
                analysis = self._llm_breaking_change_analysis(
                    pkg, from_ver, to_ver, changelog, code_snippets, repo_context,
                )
            else:
                analysis = "No changelog available. Manual review recommended."

            analyzed.append({
                **b,
                "changelog_available": bool(changelog),
                "analysis": analysis,
            })

        return analyzed

    def _read_repo_context(self, repo_dir: str) -> str:
        """Read project-level context files from the cloned repo."""
        exact_files = [
            "CLAUDE.md", ".claude/CLAUDE.md", ".claude/settings.json",
            ".cursorrules", ".cursorignore",
            "SKILLS.md", ".github/copilot-instructions.md",
            "codex.md", ".codex",
            "CONTRIBUTING.md", ".github/CONTRIBUTING.md",
            "tsconfig.json", ".eslintrc.json", ".eslintrc.js",
            "jest.config.js", "jest.config.ts",
            "pom.xml",
            ".babelrc", "webpack.config.js", "vite.config.ts",
            "Makefile", "Dockerfile",
        ]

        scan_dirs = [
            ".claude", ".cursor", ".cursor/rules",
            ".github", ".husky",
            "skills", "rules", ".rules",
            ".ai", ".copilot",
            "config",
        ]

        context = []
        seen = set()

        for name in exact_files:
            path = os.path.join(repo_dir, name)
            if os.path.exists(path) and os.path.isfile(path) and name not in seen:
                seen.add(name)
                try:
                    with open(path) as f:
                        content = f.read()[:1000]
                        context.append(f"--- {name} ---\n{content}")
                except Exception:
                    pass

        for dirname in scan_dirs:
            dir_path = os.path.join(repo_dir, dirname)
            if not os.path.isdir(dir_path):
                continue
            try:
                for root, _, files in os.walk(dir_path):
                    for fname in files:
                        if not fname.endswith((".md", ".mdc", ".txt", ".yaml", ".yml", ".json")):
                            continue
                        rel = os.path.relpath(os.path.join(root, fname), repo_dir)
                        if rel in seen:
                            continue
                        seen.add(rel)
                        try:
                            with open(os.path.join(root, fname)) as f:
                                content = f.read()[:1000]
                                context.append(f"--- {rel} ---\n{content}")
                        except Exception:
                            pass
                    if root.count(os.sep) - dir_path.count(os.sep) >= 2:
                        break
            except Exception:
                pass

        result = "\n".join(context)
        if len(result) > 5000:
            result = result[:5000] + "\n... (truncated)"
        return result

    def _llm_breaking_change_analysis(
        self,
        package: str,
        from_version: str,
        to_version: str,
        changelog: str,
        code_snippets: list[str],
        repo_context: str = "",
    ) -> str:
        """Ask LLM whether a package upgrade will break the existing code."""
        prompt = f"""You are analyzing whether upgrading {package} from {from_version} to {to_version} will break existing code.

CHANGELOG / RELEASE NOTES:
{changelog if changelog else "Not available."}

SOURCE CODE THAT USES THIS PACKAGE:
{chr(10).join(code_snippets) if code_snippets else "No source files available."}

{"PROJECT CONTEXT (coding standards, configs):" + chr(10) + repo_context if repo_context else ""}

Analyze and respond in this EXACT JSON format (no markdown, no explanation):
{{
  "will_break": false,
  "confidence": "high",
  "risk_summary": "One sentence summary of the risk",
  "affected_patterns": ["list of specific code patterns that may need changes"],
  "suggested_fixes": ["list of specific code changes needed, if any"]
}}

RULES:
- "will_break": true only if the changelog explicitly mentions removed/renamed APIs that the source code uses
- "confidence": "high" if changelog clearly shows no breaking changes, "medium" if unclear, "low" if changelog unavailable
- "affected_patterns": empty list if no breaking changes expected
- "suggested_fixes": empty list if no changes needed
- Be conservative — if unsure, say "medium" confidence, not "high"
"""
        try:
            raw, _ = self.llm_client.analyze(prompt)
            if raw:
                cleaned = self.llm_client._extract_json(raw)
                data = json.loads(cleaned)
                result = data.get("risk_summary", "Analysis unavailable.")
                if data.get("will_break"):
                    result = f"**LIKELY TO BREAK:** {result}"
                    patterns = data.get("affected_patterns", [])
                    if patterns:
                        result += "\n  - Affected: " + ", ".join(f"`{p}`" for p in patterns[:5])
                    suggestions = data.get("suggested_fixes", [])
                    if suggestions:
                        result += "\n  - Fix: " + "; ".join(suggestions[:3])
                else:
                    confidence = data.get("confidence", "medium")
                    result = f"Likely safe ({confidence} confidence). {result}"
                return result
        except Exception as e:
            logger.warning(f"Breaking change analysis failed for {package}: {e}")
        return "Analysis unavailable — manual review recommended."

    def _analyze_transitive_override_impact(
        self,
        override_fixes: list[dict],
        fixable_issues: list[dict],
    ) -> list[dict]:
        """LLM impact analysis specifically for transitive dependency overrides."""
        results = []
        issue_map = {i.get("package_name", ""): i for i in fixable_issues}

        for fix in override_fixes:
            pkg = fix.get("package", "")
            from_ver = fix.get("from", "")
            to_ver = fix.get("to", "")
            issue = issue_map.get(pkg, {})
            dep_chains = issue.get("_dep_chains", [])
            org_upstream = issue.get("_org_upstream_pkgs", [])
            cve = issue.get("cve", "")
            snyk_id = issue.get("id", "")
            severity = issue.get("severity", "")
            version_jump = classify_upgrade_risk(from_ver, to_ver)

            changelog = self._fetch_changelog(pkg, from_ver, to_ver) if from_ver else ""

            chains_text = ""
            if dep_chains:
                chain_lines = []
                for chain in dep_chains[:3]:
                    chain_lines.append(" → ".join(chain))
                chains_text = "\n".join(chain_lines)

            ecosystem_context = {
                "npm": "a Node.js/npm repository. The override uses the `overrides` field in package.json.",
                "yarn": "a Node.js/Yarn repository. The override uses the `resolutions` field in package.json.",
                "maven": "a Java/Maven project. The override uses `dependencyManagement` in pom.xml.",
                "gradle": "a Java/Gradle project. The override uses `resolutionStrategy.force` in build.gradle.",
                "pip": "a Python project. The override uses version constraints in requirements.txt or pyproject.toml.",
                "gomodules": "a Go module. The override uses a `replace` directive in go.mod.",
                "nuget": "a .NET/NuGet project. The override pins the version in the .csproj file.",
            }.get(self.ecosystem, f"a {self.ecosystem} repository")

            prompt = f"""You are a senior security engineer reviewing a transitive dependency override for {ecosystem_context}.

VULNERABILITY:
- Package: {pkg}
- Current version in tree: {from_ver}
- Pinning to: {to_ver}
- Severity: {severity}
- CVE: {cve or 'not assigned'}
- Snyk ID: {snyk_id}
- Version jump: {version_jump}

DEPENDENCY CHAINS (how {pkg} enters this repo's dependency tree):
{chains_text or 'Not available'}

ORG-OWNED PACKAGES IN CHAIN:
{chr(10).join(org_upstream) if org_upstream else 'None found — no cascade fix available'}

CHANGELOG / RELEASE NOTES FOR {pkg}@{to_ver}:
{changelog[:1500] if changelog else 'Not available from registry'}

Analyze this transitive override and respond in EXACT JSON format (no markdown):
{{
  "runtime_protection": true,
  "version_jump_risk": "patch",
  "risk_summary": "One sentence: is this override safe and does it protect the runtime?",
  "pinning_concerns": ["list any concerns about pinning to this specific version"],
  "upstream_fix_recommendation": "If an org-owned package is in the chain, recommend fixing it there. Otherwise empty string.",
  "exploit_context": "Is this CVE actually exploitable in a CLI/internal tool context?",
  "confidence": "high"
}}

RULES:
- runtime_protection: true only if this repo IS the root consumer (internal tool, CLI binary, example app)
- version_jump_risk: patch/minor/major based on semver
- pinning_concerns: empty list if pin is straightforward
- upstream_fix_recommendation: only populate if an org-owned package appears in the chain
- exploit_context: assess whether the vulnerability is reachable in this repo's usage
- confidence: high/medium/low based on available evidence
"""
            analysis_text = "No analysis available — manual review recommended."
            try:
                raw, _ = self.llm_client.analyze(prompt)
                if raw:
                    cleaned = self.llm_client._extract_json(raw)
                    data = json.loads(cleaned)
                    parts = [data.get("risk_summary", "")]
                    if data.get("pinning_concerns"):
                        parts.append("Concerns: " + "; ".join(data["pinning_concerns"][:3]))
                    if data.get("upstream_fix_recommendation"):
                        parts.append(f"⚠️ Upstream fix: {data['upstream_fix_recommendation']}")
                    if data.get("exploit_context"):
                        parts.append(f"Exploit context: {data['exploit_context']}")
                    conf = data.get("confidence", "medium")
                    parts.append(f"Confidence: {conf}")
                    analysis_text = " | ".join(p for p in parts if p)
            except Exception as e:
                logger.warning(f"Transitive override impact analysis failed for {pkg}: {e}")

            results.append({
                "package": pkg,
                "from": from_ver,
                "to": to_ver,
                "fix_type": "transitive_override",
                "imported_in": [],
                "dep_chains": dep_chains,
                "org_upstream_pkgs": org_upstream,
                "cve": cve,
                "snyk_id": snyk_id,
                "severity": severity,
                "version_jump": version_jump,
                "changelog_available": bool(changelog),
                "analysis": analysis_text,
            })

        return results

    def _get_changelog_url(self, package: str, version: str) -> str:
        """Generate a changelog/release URL based on ecosystem."""
        if self.ecosystem in ("npm", "yarn"):
            return f"https://www.npmjs.com/package/{package}?activeTab=versions"
        elif self.ecosystem in ("maven", "gradle"):
            if ":" in package:
                group, artifact = package.split(":", 1)
                return f"https://central.sonatype.com/artifact/{group}/{artifact}/{version}"
            return ""
        elif self.ecosystem in ("pip", "python"):
            return f"https://pypi.org/project/{package}/{version}/#changelog"
        elif self.ecosystem in ("gomodules", "go"):
            return f"https://pkg.go.dev/{package}@v{version}"
        return ""

    def _save_internal(self, internal_dir: str, filename: str, data) -> None:
        """Save internal artifact for debugging."""
        try:
            path = os.path.join(internal_dir, filename)
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"Failed to save internal artifact {filename}: {e}")
