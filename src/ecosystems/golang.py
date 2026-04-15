import os
import re
from src.ecosystems.base import EcosystemHandler


class GolangHandler(EcosystemHandler):
    @property
    def allowlisted_files(self) -> list[str]:
        return ["go.mod", "go.sum"]

    @property
    def install_command(self) -> str:
        return "go mod tidy"

    @property
    def build_command(self) -> str:
        return "go build ./..."

    @property
    def test_command(self) -> str:
        return "go test ./..."

    def detect(self, repo_path: str) -> bool:
        return os.path.exists(os.path.join(repo_path, "go.mod"))

    def read_manifest(self, repo_path: str) -> str:
        mod_path = os.path.join(repo_path, "go.mod")
        with open(mod_path) as f:
            return f.read()

    def apply_fix(self, repo_path: str, fix: dict) -> None:
        mod_path = os.path.join(repo_path, "go.mod")
        with open(mod_path) as f:
            content = f.read()
        package = fix.get("package", "")
        from_ver = fix.get("from", "")
        to_ver = fix.get("to", "")
        action = fix.get("action")
        if action == "upgrade":
            content = content.replace(f"{package} v{from_ver}", f"{package} v{to_ver}")
        elif action == "add_replace":
            replace_line = f"\nreplace {package} v{from_ver} => {package} v{to_ver}\n"
            if "replace" not in content or package not in content:
                content += replace_line
        with open(mod_path, "w") as f:
            f.write(content)
