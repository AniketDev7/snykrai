import os
import re
from src.ecosystems.base import EcosystemHandler


class DotnetHandler(EcosystemHandler):
    @property
    def allowlisted_files(self) -> list[str]:
        return [".csproj", ".fsproj", "Directory.Build.props", "packages.config"]

    @property
    def install_command(self) -> str:
        return "dotnet restore"

    @property
    def build_command(self) -> str:
        return "dotnet build --no-restore"

    @property
    def test_command(self) -> str:
        return "dotnet test --no-build"

    def detect(self, repo_path: str) -> bool:
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("bin", "obj", "node_modules")]
            if any(f.endswith(".csproj") or f.endswith(".fsproj") for f in files):
                return True
            if root.count(os.sep) - repo_path.count(os.sep) >= 3:
                break
        return False

    def read_manifest(self, repo_path: str) -> str:
        """Read the first .csproj found."""
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("bin", "obj", "node_modules")]
            for f in files:
                if f.endswith(".csproj") or f.endswith(".fsproj"):
                    with open(os.path.join(root, f)) as fh:
                        return fh.read()
        return ""

    def apply_fix(self, repo_path: str, fix: dict) -> None:
        """Apply version upgrade to all .csproj files in the given directory."""
        package = fix.get("package", "")
        from_version = fix.get("from", "")
        to_version = fix.get("to", "")

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("bin", "obj", "node_modules")]
            for f in files:
                if not (f.endswith(".csproj") or f.endswith(".fsproj")):
                    continue
                filepath = os.path.join(root, f)
                with open(filepath) as fh:
                    content = fh.read()

                if package not in content:
                    continue

                # Match: <PackageReference Include="Package" Version="1.0.0" />
                # or:    <PackageReference Include="Package"><Version>1.0.0</Version></PackageReference>
                pattern = (
                    rf'(<PackageReference\s+Include="{re.escape(package)}"\s+Version="){re.escape(from_version)}"'
                )
                new_content = re.sub(pattern, rf'\g<1>{to_version}"', content)

                # Also handle Version as child element
                pattern2 = (
                    rf'(<PackageReference\s+Include="{re.escape(package)}"[^>]*>\s*'
                    rf'<Version>){re.escape(from_version)}(</Version>)'
                )
                new_content = re.sub(pattern2, rf'\g<1>{to_version}\g<2>', new_content, flags=re.DOTALL)

                if new_content != content:
                    with open(filepath, "w") as fh:
                        fh.write(new_content)

    def find_all_manifests(self, repo_path: str) -> list[str]:
        """Find all .csproj and .fsproj files."""
        manifests = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("bin", "obj", "node_modules")]
            for f in files:
                if f.endswith(".csproj") or f.endswith(".fsproj"):
                    rel = os.path.relpath(os.path.join(root, f), repo_path)
                    manifests.append(rel)
        return manifests
