import os
import re
from src.ecosystems.base import EcosystemHandler


class PythonHandler(EcosystemHandler):
    @property
    def allowlisted_files(self) -> list[str]:
        return [
            "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
            "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock",
        ]

    @property
    def install_command(self) -> str:
        return "pip install -r requirements.txt"

    @property
    def test_command(self) -> str:
        return "pytest --tb=short -q"

    def detect(self, repo_path: str) -> bool:
        return (
            os.path.exists(os.path.join(repo_path, "requirements.txt"))
            or os.path.exists(os.path.join(repo_path, "pyproject.toml"))
            or os.path.exists(os.path.join(repo_path, "Pipfile"))
        )

    def read_manifest(self, repo_path: str) -> str:
        for name in ("requirements.txt", "pyproject.toml", "Pipfile"):
            path = os.path.join(repo_path, name)
            if os.path.exists(path):
                with open(path) as f:
                    return f.read()
        return ""

    def apply_fix(self, repo_path: str, fix: dict) -> None:
        target_file = fix.get("file", "requirements.txt")
        file_path = os.path.join(repo_path, target_file)
        if not os.path.exists(file_path):
            return
        with open(file_path) as f:
            content = f.read()
        package = fix.get("package", "")
        from_ver = fix.get("from", "")
        to_ver = fix.get("to", "")
        pattern = rf"({re.escape(package)}\s*[=><~!]+\s*){re.escape(from_ver)}"
        content = re.sub(pattern, rf"\g<1>{to_ver}", content)
        with open(file_path, "w") as f:
            f.write(content)
