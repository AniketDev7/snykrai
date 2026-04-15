from src.ecosystems.base import EcosystemHandler
from src.ecosystems.npm import NpmHandler
from src.ecosystems.maven import MavenHandler
from src.ecosystems.python_eco import PythonHandler
from src.ecosystems.golang import GolangHandler
from src.ecosystems.dotnet import DotnetHandler
from typing import Optional

HANDLERS = {
    "npm": NpmHandler,
    "yarn": NpmHandler,
    "maven": MavenHandler,
    "gradle": MavenHandler,
    "pip": PythonHandler,
    "python": PythonHandler,
    "gomodules": GolangHandler,
    "go": GolangHandler,
    "nuget": DotnetHandler,
    "dotnet": DotnetHandler,
}


def detect_ecosystem(repo_path: str) -> Optional[str]:
    for name, handler_cls in HANDLERS.items():
        handler = handler_cls()
        if handler.detect(repo_path):
            return name
    return None


def get_handler(ecosystem: str) -> EcosystemHandler:
    handler_cls = HANDLERS.get(ecosystem)
    if handler_cls is None:
        raise ValueError(f"Unsupported ecosystem: {ecosystem}")
    return handler_cls()
