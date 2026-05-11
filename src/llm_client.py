import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional

from google import genai
try:
    import anthropic as anthropic_sdk
except ImportError:
    anthropic_sdk = None


@dataclass
class LLMResponse:
    fixes: list[dict] = field(default_factory=list)
    unfixable: list[dict] = field(default_factory=list)
    raw_error: Optional[str] = None
    provider_used: str = ""


class LLMClient:
    DANGEROUS_PATTERNS = [
        r";\s*(rm|del|drop|truncate|exec|eval|system)\b",
        r"\|\s*(bash|sh|cmd|powershell)",
        r"&&\s*(rm|del|curl|wget)",
        r"`[^`]+`",
        r"\$\(",
    ]

    def __init__(
        self,
        provider: str = "auto",
        gemini_api_key: str = "",
        anthropic_api_key: str = "",
        gemini_model: str = "gemini-2.5-flash",
        anthropic_model: str = "claude-sonnet-4-6",
        max_retries: int = 2,
        timeout_seconds: int = 30,
    ):
        self.provider = provider
        self.gemini_api_key = gemini_api_key
        self.anthropic_api_key = anthropic_api_key
        self.gemini_model = gemini_model
        self.anthropic_model = anthropic_model
        self.max_retries = max_retries
        self.timeout_seconds = timeout_seconds

    def get_fix_suggestions(
        self,
        ecosystem: str,
        manifest: str,
        issues: list[dict],
        strategy: str,
    ) -> LLMResponse:
        prompt = self._build_prompt(ecosystem, manifest, issues, strategy)
        providers = self._get_provider_order()
        last_error = None
        for prov in providers:
            for attempt in range(self.max_retries + 1):
                try:
                    raw_text = self._call_provider(prov, prompt)
                    return self._parse_and_validate(raw_text, prov)
                except Exception as e:
                    last_error = str(e)
        return LLMResponse(raw_error=f"All providers failed: {last_error}")

    def analyze(self, prompt: str) -> tuple[str, str]:
        """Run a free-form analysis prompt. Returns (response_text, provider_used).

        Applies dangerous content filtering on the response — safe to use for
        PR body content and any text that may be displayed to users.
        """
        providers = self._get_provider_order()
        for prov in providers:
            try:
                raw = self._call_provider(prov, prompt)
                if self._contains_dangerous_content(raw):
                    return "[response redacted — contained suspicious content]", prov
                return raw, prov
            except Exception:
                continue
        return "", ""

    def _get_provider_order(self) -> list[str]:
        if self.provider == "auto":
            return ["anthropic", "gemini"]
        return [self.provider]

    def _call_provider(self, provider: str, prompt: str) -> str:
        if provider == "gemini":
            return self._call_gemini(prompt)
        elif provider == "anthropic":
            return self._call_anthropic(prompt)
        raise ValueError(f"Unknown provider: {provider}")

    def _call_gemini(self, prompt: str) -> str:
        client = genai.Client(api_key=self.gemini_api_key)
        response = client.models.generate_content(
            model=self.gemini_model,
            contents=prompt,
        )
        return response.text

    def _call_anthropic(self, prompt: str) -> str:
        if anthropic_sdk is None:
            raise ImportError("anthropic package not installed")
        client = anthropic_sdk.Anthropic(
            api_key=self.anthropic_api_key,
            timeout=float(self.timeout_seconds),
        )
        message = client.messages.create(
            model=self.anthropic_model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text

    def _build_prompt(
        self, ecosystem: str, manifest: str, issues: list[dict], strategy: str
    ) -> str:
        prompt_dir = os.path.join(os.path.dirname(__file__), "..", "resources", "prompts")
        skills_file = os.path.join(prompt_dir, "SKILLS.md")
        with open(skills_file) as f:
            skills = f.read()
        # Map Snyk ecosystem names to prompt template filenames
        prompt_ecosystem_map = {
            "pip": "python", "python": "python",
            "gomodules": "golang", "go": "golang",
            "yarn": "npm", "npm": "npm",
            "gradle": "maven", "maven": "maven",
            "nuget": "nuget", "dotnet": "nuget",
        }
        prompt_name = prompt_ecosystem_map.get(ecosystem, ecosystem)
        prompt_file = os.path.join(prompt_dir, f"fix_{prompt_name}.txt")
        with open(prompt_file) as f:
            template = f.read()
        template = skills + "\n\n---\n\n" + template
        enriched_issues = []
        for i in issues:
            entry = {
                "package": i.get("package_name", ""),
                "current_version": i.get("package_version", ""),
                "severity": i.get("severity", ""),
                "type": "transitive_override" if i.get("_fix_mode") == "override" else (
                    "direct_upgrade" if i.get("is_upgradeable") else "transitive"
                ),
                "fixed_in": i.get("fixed_in", ""),
                "vulnerable_range": i.get("vulnerable_range", ""),
            }
            # Enrich with Snyk/CVE identity for traceability
            if i.get("id"):
                entry["snyk_id"] = i["id"]
            if i.get("cve"):
                entry["cve"] = i["cve"]
            if i.get("cwe"):
                entry["cwe"] = i["cwe"]
            # Dep chain context for transitive overrides
            dep_chains = i.get("_dep_chains", [])
            if dep_chains:
                entry["dep_chain"] = " → ".join(dep_chains[0]) if dep_chains else ""
            org_pkgs = i.get("_org_upstream_pkgs", [])
            if org_pkgs:
                entry["upstream_fix_available"] = org_pkgs[0]
                entry["note"] = (
                    f"This override is TEMPORARY. {org_pkgs[0]} is an org-owned "
                    f"package in the dep chain — fixing {org_pkgs[0]} at source would "
                    f"cascade this fix to all repos that depend on it."
                )
            enriched_issues.append(entry)

        issues_text = json.dumps(enriched_issues, indent=2)
        return (
            template
            .replace("{strategy}", strategy)
            .replace("{manifest}", manifest)
            .replace("{issues}", issues_text)
            .replace("{manifest_type}", "requirements.txt")
        )

    def _parse_and_validate(self, raw_text: str, provider: str) -> LLMResponse:
        cleaned = self._extract_json(raw_text)
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as e:
            return LLMResponse(raw_error=f"Invalid JSON from {provider}: {e}", provider_used=provider)
        fixes = data.get("fixes", [])
        unfixable = data.get("unfixable", [])
        validated_fixes = []
        for fix in fixes:
            if not all(k in fix for k in ("package", "action", "to")):
                continue
            if self._contains_dangerous_content(fix.get("to", "")):
                continue
            if self._contains_dangerous_content(fix.get("reasoning", "")):
                fix["reasoning"] = "reasoning redacted (contained suspicious content)"
            validated_fixes.append(fix)
        return LLMResponse(
            fixes=validated_fixes,
            unfixable=unfixable,
            provider_used=provider,
        )

    def _extract_json(self, text: str) -> str:
        json_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
        if json_match:
            return json_match.group(1).strip()
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            return brace_match.group(0)
        return text.strip()

    def _contains_dangerous_content(self, value: str) -> bool:
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False
