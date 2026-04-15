import os
import re
from src.ecosystems.base import EcosystemHandler


class MavenHandler(EcosystemHandler):
    @property
    def allowlisted_files(self) -> list[str]:
        return ["pom.xml"]

    @property
    def install_command(self) -> str:
        return "mvn dependency:resolve -q"

    @property
    def build_command(self) -> str:
        return "mvn compile -q"

    @property
    def test_command(self) -> str:
        return "mvn test -q"

    def detect(self, repo_path: str) -> bool:
        return os.path.exists(os.path.join(repo_path, "pom.xml"))

    def find_all_manifests(self, repo_path: str) -> list[str]:
        """Find all pom.xml files in the repo (root + subdirectories)."""
        manifests = []
        for root, dirs, files in os.walk(repo_path):
            # Skip hidden dirs, target/, node_modules/
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("target", "node_modules")]
            if "pom.xml" in files:
                rel = os.path.relpath(os.path.join(root, "pom.xml"), repo_path)
                manifests.append(rel)
        return manifests

    def read_manifest(self, repo_path: str) -> str:
        pom_path = os.path.join(repo_path, "pom.xml")
        with open(pom_path) as f:
            return f.read()

    def apply_fix(self, repo_path: str, fix: dict) -> None:
        pom_path = os.path.join(repo_path, "pom.xml")
        with open(pom_path) as f:
            content = f.read()

        action = fix.get("action")
        package = fix.get("package", "")
        from_version = fix.get("from", "")
        to_version = fix.get("to", "")

        if ":" in package:
            group_id, artifact_id = package.split(":", 1)
        else:
            group_id, artifact_id = "", package

        if action == "upgrade":
            pattern = (
                r"(<dependency>\s*"
                rf"<groupId>{re.escape(group_id)}</groupId>\s*"
                rf"<artifactId>{re.escape(artifact_id)}</artifactId>\s*"
                rf"<version>){re.escape(from_version)}(</version>)"
            )
            content = re.sub(pattern, rf"\g<1>{to_version}\g<2>", content, flags=re.DOTALL)

        elif action == "add_dependency_management":
            dm_entry = (
                f"\n    <dependencyManagement>\n"
                f"        <dependencies>\n"
                f"            <dependency>\n"
                f"                <groupId>{group_id}</groupId>\n"
                f"                <artifactId>{artifact_id}</artifactId>\n"
                f"                <version>{to_version}</version>\n"
                f"            </dependency>\n"
                f"        </dependencies>\n"
                f"    </dependencyManagement>\n"
            )
            if "<dependencyManagement>" not in content:
                content = content.replace("</project>", f"{dm_entry}</project>")
            else:
                content = content.replace(
                    "</dependencies>\n    </dependencyManagement>",
                    f"    <dependency>\n"
                    f"                <groupId>{group_id}</groupId>\n"
                    f"                <artifactId>{artifact_id}</artifactId>\n"
                    f"                <version>{to_version}</version>\n"
                    f"            </dependency>\n"
                    f"        </dependencies>\n    </dependencyManagement>",
                )

        with open(pom_path, "w") as f:
            f.write(content)
