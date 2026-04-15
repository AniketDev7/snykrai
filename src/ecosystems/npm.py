import json
import os
from src.ecosystems.base import EcosystemHandler


class NpmHandler(EcosystemHandler):
    @property
    def allowlisted_files(self) -> list[str]:
        return ["package.json", "package-lock.json", "npm-shrinkwrap.json", ".snyk"]

    @property
    def install_command(self) -> str:
        return "npm install"

    @property
    def build_command(self) -> str:
        return "npm run build --if-present"

    @property
    def test_command(self) -> str:
        return "npm test"

    def get_test_command(self, repo_path: str) -> str:
        """Read package.json and find the best unit test script.

        Prefers: test:unit > test:ci > test (skips test:e2e, test:integration)
        Returns empty string if no test script found.
        """
        pkg_path = os.path.join(repo_path, "package.json")
        if not os.path.exists(pkg_path):
            return ""
        try:
            with open(pkg_path) as f:
                data = json.load(f)
            scripts = data.get("scripts", {})
            if not scripts:
                return ""

            # Prefer unit test scripts, skip e2e/integration
            preferred = ["test:unit", "test:ci", "unit", "jest"]
            for name in preferred:
                if name in scripts:
                    return f"npm run {name}"

            # Default to "test" if it exists and doesn't look like e2e
            if "test" in scripts:
                test_val = scripts["test"].lower()
                # Skip if it's clearly e2e or integration
                if any(skip in test_val for skip in ["e2e", "cypress", "playwright", "selenium"]):
                    return ""
                return "npm test"

            return ""
        except (json.JSONDecodeError, OSError):
            return ""

    def detect(self, repo_path: str) -> bool:
        return os.path.exists(os.path.join(repo_path, "package.json"))

    def find_all_manifests(self, repo_path: str) -> list[str]:
        """Find package.json files. Only root-level (skip node_modules)."""
        manifests = []
        root_pkg = os.path.join(repo_path, "package.json")
        if os.path.exists(root_pkg):
            manifests.append("package.json")
        return manifests

    def read_manifest(self, repo_path: str) -> str:
        manifest_path = os.path.join(repo_path, "package.json")
        with open(manifest_path) as f:
            return f.read()

    def apply_fix(self, repo_path: str, fix: dict) -> None:
        manifest_path = os.path.join(repo_path, "package.json")
        with open(manifest_path) as f:
            data = json.load(f)

        action = fix.get("action")
        package = fix.get("package")
        to_version = fix.get("to")

        if action == "upgrade":
            for section in ("dependencies", "devDependencies"):
                if package in data.get(section, {}):
                    data[section][package] = to_version
                    break

        elif action == "add_override":
            # npm EOVERRIDE: can't override a package already listed as a direct dep.
            # If the package is a direct dep, upgrade it in-place instead.
            is_direct = any(package in data.get(sec, {}) for sec in ("dependencies", "devDependencies"))
            if is_direct:
                for section in ("dependencies", "devDependencies"):
                    if package in data.get(section, {}):
                        data[section][package] = to_version
                        break
            else:
                if "overrides" not in data:
                    data["overrides"] = {}
                data["overrides"][package] = to_version

        with open(manifest_path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
