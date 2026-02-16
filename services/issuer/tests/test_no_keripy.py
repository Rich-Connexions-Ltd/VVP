"""Import guard: verify issuer has no direct keripy or app.keri.* dependencies.

Sprint 68c: Ensures the KERI decoupling is complete — all KERI operations
must go through KeriAgentClient, not direct keripy imports.
"""

import ast
import os
from pathlib import Path

import pytest

# Issuer app directory
ISSUER_APP_DIR = Path(__file__).parent.parent / "app"


def _collect_python_files(directory: Path) -> list[Path]:
    """Collect all .py files in directory tree."""
    return sorted(directory.rglob("*.py"))


def _find_keripy_imports(filepath: Path) -> list[str]:
    """Find direct keripy imports in a Python file.

    Detects:
    - from keri.* import ...
    - import keri.*
    - from app.keri.* import ... (deleted module)
    - import app.keri.* (deleted module)

    Allows:
    - from app.keri_client import ... (the sanctioned client)
    - import app.keri_client
    """
    violations = []
    try:
        source = filepath.read_text()
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return []

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                # Block: from keri.* import ...
                if node.module == "keri" or node.module.startswith("keri."):
                    violations.append(
                        f"{filepath.name}:{node.lineno}: from {node.module} import ..."
                    )
                # Block: from app.keri.* import ... (but allow app.keri_client)
                if (node.module.startswith("app.keri.")
                        and not node.module.startswith("app.keri_client")):
                    violations.append(
                        f"{filepath.name}:{node.lineno}: from {node.module} import ..."
                    )

        elif isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                # Block: import keri / import keri.*
                if name == "keri" or name.startswith("keri."):
                    violations.append(
                        f"{filepath.name}:{node.lineno}: import {name}"
                    )
                # Block: import app.keri.* (but allow app.keri_client)
                if (name.startswith("app.keri.")
                        and not name.startswith("app.keri_client")):
                    violations.append(
                        f"{filepath.name}:{node.lineno}: import {name}"
                    )

    return violations


class TestNoKeripy:
    """Verify no direct keripy or app.keri.* imports in issuer app code."""

    def test_no_keripy_imports_in_app(self):
        """No file in app/ should import from keri.* or app.keri.* directly."""
        py_files = _collect_python_files(ISSUER_APP_DIR)
        assert len(py_files) > 0, "No Python files found in app/"

        all_violations = []
        for filepath in py_files:
            violations = _find_keripy_imports(filepath)
            all_violations.extend(violations)

        if all_violations:
            msg = "Direct keripy/app.keri.* imports found:\n"
            msg += "\n".join(f"  - {v}" for v in all_violations)
            msg += "\n\nAll KERI operations must go through app.keri_client."
            pytest.fail(msg)

    def test_no_lmdb_imports_in_app(self):
        """No file in app/ should import lmdb directly."""
        py_files = _collect_python_files(ISSUER_APP_DIR)

        all_violations = []
        for filepath in py_files:
            try:
                source = filepath.read_text()
                tree = ast.parse(source)
            except (SyntaxError, UnicodeDecodeError):
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module == "lmdb":
                    all_violations.append(
                        f"{filepath.name}:{node.lineno}: from lmdb import ..."
                    )
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "lmdb":
                            all_violations.append(
                                f"{filepath.name}:{node.lineno}: import lmdb"
                            )

        if all_violations:
            msg = "Direct lmdb imports found:\n"
            msg += "\n".join(f"  - {v}" for v in all_violations)
            msg += "\n\nIssuer should not depend on LMDB directly."
            pytest.fail(msg)

    def test_app_keri_directory_deleted(self):
        """The app/keri/ directory should not exist after decoupling."""
        keri_dir = ISSUER_APP_DIR / "keri"
        assert not keri_dir.exists(), (
            f"app/keri/ directory still exists at {keri_dir}. "
            "It should have been deleted in Sprint 68c Stage 1f."
        )
