import os
from abc import ABC, abstractmethod


class EcosystemHandler(ABC):
    @property
    @abstractmethod
    def allowlisted_files(self) -> list[str]:
        pass

    @property
    @abstractmethod
    def install_command(self) -> str:
        pass

    @property
    def build_command(self) -> str:
        """Build/compile command. Override per ecosystem. Empty = skip."""
        return ""

    @property
    def test_command(self) -> str:
        """Test command. Override per ecosystem. Empty = skip."""
        return ""

    @abstractmethod
    def read_manifest(self, repo_path: str) -> str:
        pass

    @abstractmethod
    def apply_fix(self, repo_path: str, fix: dict) -> None:
        pass

    @abstractmethod
    def detect(self, repo_path: str) -> bool:
        pass

    def find_all_manifests(self, repo_path: str) -> list[str]:
        """Find all manifest files in the repo. Returns relative paths.

        Default: returns the root manifest only. Override for ecosystems
        that may have multiple manifests (Maven with bin/pom.xml, .NET with
        multiple .csproj files, etc.)
        """
        return []

    def apply_fix_all(self, repo_path: str, fix: dict) -> int:
        """Apply fix to ALL manifests in the repo. Returns count of files modified."""
        manifests = self.find_all_manifests(repo_path)
        if not manifests:
            # Fallback to single root manifest
            self.apply_fix(repo_path, fix)
            return 1
        count = 0
        for manifest_rel in manifests:
            manifest_dir = os.path.join(repo_path, os.path.dirname(manifest_rel))
            if os.path.isdir(manifest_dir):
                self.apply_fix(manifest_dir, fix)
                count += 1
        return count
