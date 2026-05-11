import re
from dataclasses import dataclass, field


@dataclass
class ScanResult:
    is_clean: bool
    violations: list[str] = field(default_factory=list)


class SecretScanner:
    PATTERNS = [
        (r"SNYK_TOKEN", "SNYK_TOKEN detected"),
        (r"GEMINI_API_KEY", "GEMINI_API_KEY detected"),
        (r"ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY detected"),
        (r"GIT_TOKEN", "GIT_TOKEN detected"),
        (r"GIT_USER", "GIT_USER detected"),
        (r"xoxb-", "Slack bot token (xoxb-) detected"),
        (r"AIzaSy", "Google API key (AIzaSy) detected"),
        (r"sk-ant-", "Anthropic key (sk-ant-) detected"),
        (r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer token detected"),
        (r"-----BEGIN.*KEY-----", "Private key detected"),
        (r"AWS_SECRET_ACCESS_KEY", "AWS secret access key detected"),
        (r"password\s*[:=]", "Password assignment detected"),
    ]

    def scan(self, diff_text: str) -> ScanResult:
        violations = []
        for line in diff_text.splitlines():
            if not line.startswith("+"):
                continue
            if line.startswith("+++"):
                continue
            for pattern, message in self.PATTERNS:
                if re.search(pattern, line):
                    violations.append(f"{message}: {line[:80]}")
        return ScanResult(is_clean=len(violations) == 0, violations=violations)
