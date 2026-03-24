"""Lint tests for secretscreen architectural constraints.

Encodes invariants of a zero-dependency pure security library:
- Import graph: _core.py imports layers; layers never import each other or _core
- Zero external dependencies (stdlib only)
- Frozen dataclasses for immutable findings
- Broad except containment
- No logging (risk of leaking detected secrets)
- No side effects in detection layers
- Stable public API surface
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

SRC = Path(__file__).parent.parent / "src" / "secretscreen"

# Detection layer modules (no cross-imports allowed)
DETECTION_LAYERS = {"_keys.py", "_formats.py", "_entropy.py", "_parsers.py", "_urls.py"}

# Known stdlib top-level modules used by secretscreen
_STDLIB_ALLOWLIST = {
    "math",
    "collections",
    "re",
    "json",
    "ast",
    "configparser",
    "urllib",
    "enum",
    "dataclasses",
    "importlib",
    "tomllib",
    "warnings",
    "__future__",
    "typing",
}


def _source_files(exclude: set[str] | None = None) -> list[Path]:
    """All .py files in src/secretscreen/, excluding specified filenames."""
    exclude = exclude or set()
    return [
        p
        for p in SRC.glob("*.py")
        if p.name not in exclude and p.name != "__init__.py"
    ]


def _all_imports(tree: ast.Module) -> list[tuple[int, str]]:
    """Yield (lineno, top-level module name) for every import in an AST."""
    results = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                results.append((node.lineno, alias.name.split(".")[0]))
        elif isinstance(node, ast.ImportFrom) and node.module:
            results.append((node.lineno, node.module.split(".")[0]))
    return results


class TestImportGraph:
    """Detection layers never import each other or _core.

    _core.py is the only module that imports detection layers.
    Each detection layer is independently testable.
    """

    def test_detection_layers_no_cross_imports(self):
        violations = []
        for path in _source_files():
            if path.name not in DETECTION_LAYERS:
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom) or not node.module:
                    continue
                if not node.module.startswith("secretscreen."):
                    continue
                # Detection layers may not import _core or other layers
                imported = node.module.split(".")[-1] + ".py"
                if imported == "_core.py" or imported in DETECTION_LAYERS:
                    # A layer importing itself is fine (relative import)
                    if imported == path.name:
                        continue
                    violations.append(
                        f"{path.name}:{node.lineno} imports {node.module}"
                    )
        assert not violations, (
            "Detection layer cross-import detected "
            "(layers must be independently testable):\n"
            + "\n".join(violations)
        )

    def test_core_imports_all_layers(self):
        """_core.py must import from every detection layer."""
        tree = ast.parse((SRC / "_core.py").read_text())
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith("secretscreen._"):
                    imported_modules.add(node.module.split(".")[-1] + ".py")

        missing = DETECTION_LAYERS - imported_modules
        assert not missing, (
            f"_core.py does not import detection layers: {missing}"
        )


class TestZeroDependencies:
    """Every import must resolve to stdlib or secretscreen.*.

    secretscreen is a zero-dependency library. Adding an external
    dependency would break users who vendor it directly.
    """

    def test_no_external_imports(self):
        violations = []
        # Build stdlib module set from known allowlist + stdlib itself
        stdlib_names = set(sys.stdlib_module_names) | _STDLIB_ALLOWLIST
        for path in _source_files():
            tree = ast.parse(path.read_text())
            for lineno, top_module in _all_imports(tree):
                if top_module == "secretscreen":
                    continue
                if top_module in stdlib_names:
                    continue
                violations.append(
                    f"{path.name}:{lineno}: import {top_module}"
                )
        assert not violations, (
            "External dependency detected (secretscreen must be zero-dependency):\n"
            + "\n".join(violations)
        )


class TestFrozenDataclasses:
    """Finding and FormatRule must be frozen. ScreenConfig is mutable.

    Immutable findings prevent accidental mutation of audit results.
    ScreenConfig is mutable for __post_init__ processing.
    """

    _MUST_BE_FROZEN = {"Finding", "FormatRule"}
    _MUTABLE_ALLOWED = {"ScreenConfig"}

    def test_frozen_where_required(self):
        violations = []
        for path in _source_files():
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                if node.name not in self._MUST_BE_FROZEN:
                    continue
                frozen = False
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call):
                        func = decorator.func
                        if isinstance(func, ast.Name) and func.id == "dataclass":
                            frozen = any(
                                kw.arg == "frozen"
                                and isinstance(kw.value, ast.Constant)
                                and kw.value.value is True
                                for kw in decorator.keywords
                            )
                if not frozen:
                    violations.append(
                        f"{path.name}:{node.lineno}: {node.name} must be frozen"
                    )
        assert not violations, (
            "Required-frozen dataclass is mutable:\n"
            + "\n".join(violations)
        )

    def test_mutable_only_where_allowed(self):
        """Non-allowlisted dataclasses must be frozen."""
        violations = []
        for path in _source_files():
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                for decorator in node.decorator_list:
                    is_dataclass = False
                    frozen = False
                    if isinstance(decorator, ast.Call):
                        func = decorator.func
                        if isinstance(func, ast.Name) and func.id == "dataclass":
                            is_dataclass = True
                            frozen = any(
                                kw.arg == "frozen"
                                and isinstance(kw.value, ast.Constant)
                                and kw.value.value is True
                                for kw in decorator.keywords
                            )
                    elif isinstance(decorator, ast.Name) and decorator.id == "dataclass":
                        is_dataclass = True
                    if is_dataclass and not frozen and node.name not in self._MUTABLE_ALLOWED:
                        violations.append(
                            f"{path.name}:{node.lineno}: {node.name} is not frozen"
                        )
        assert not violations, (
            "Dataclass not frozen (add frozen=True or add to _MUTABLE_ALLOWED):\n"
            + "\n".join(violations)
        )


class TestBroadExceptContainment:
    """Broad except only in _parsers.py.

    Parser errors may leak secret values in tracebacks, so broad
    except is justified there. No other module should need it.
    """

    _ALLOWED = {"_parsers.py"}

    def test_no_broad_except_outside_parsers(self):
        violations = []
        for path in _source_files():
            if path.name in self._ALLOWED:
                continue
            for i, line in enumerate(path.read_text().splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("except Exception"):
                    violations.append(f"{path.name}:{i}: {stripped}")
        assert not violations, (
            "Broad except outside _parsers.py "
            "(catch specific exceptions or move to _parsers.py):\n"
            + "\n".join(violations)
        )


class TestNoLogging:
    """No logging in a security library.

    Log messages risk leaking detected secrets. Callers decide
    what to log from structured Finding results.
    """

    def test_no_logging_import(self):
        violations = []
        for path in _source_files():
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "logging":
                            violations.append(f"{path.name}:{node.lineno}")
                elif (
                    isinstance(node, ast.ImportFrom)
                    and node.module
                    and node.module.startswith("logging")
                ):
                    violations.append(f"{path.name}:{node.lineno}")
        assert not violations, (
            "Logging import detected (security library must not log — "
            "risk of leaking secrets):\n" + "\n".join(violations)
        )


class TestNoSideEffects:
    """Detection layers must be pure data transformation.

    No subprocess, network, or filesystem writes. The only exception
    is importlib.resources in _formats.py for reading vendored data.
    """

    _FORBIDDEN_MODULES = {"subprocess", "socket", "http"}
    # os.system is checked via attribute access, not as an import
    _FORBIDDEN_ATTRS = {("os", "system")}
    # importlib.resources is allowed in _formats.py for vendored data
    _ALLOWED_EXCEPTIONS = {("_formats.py", "importlib")}

    def test_no_side_effect_imports(self):
        violations = []
        for path in _source_files():
            tree = ast.parse(path.read_text())
            for lineno, top_module in _all_imports(tree):
                if top_module in self._FORBIDDEN_MODULES:
                    violations.append(
                        f"{path.name}:{lineno}: import {top_module}"
                    )
                if (
                    top_module == "importlib"
                    and (path.name, "importlib") not in self._ALLOWED_EXCEPTIONS
                ):
                    violations.append(
                        f"{path.name}:{lineno}: import importlib "
                        "(only allowed in _formats.py)"
                    )
        assert not violations, (
            "Side-effect-capable import in detection module:\n"
            + "\n".join(violations)
        )

    def test_no_pathlib_writes(self):
        """No Path.write_text/write_bytes calls."""
        violations = []
        for path in _source_files():
            source = path.read_text()
            for i, line in enumerate(source.splitlines(), 1):
                if ".write_text(" in line or ".write_bytes(" in line:
                    violations.append(f"{path.name}:{i}: {line.strip()}")
        assert not violations, (
            "Filesystem write in library module:\n"
            + "\n".join(violations)
        )


class TestPublicAPI:
    """__init__.py exports exactly the intended public API.

    Prevents accidental surface expansion. New exports must be
    a deliberate decision.
    """

    _EXPECTED_EXPORTS = {
        "Finding",
        "Mode",
        "audit_dict",
        "audit_pair",
        "redact_dict",
        "redact_pair",
    }

    def test_public_api_surface(self):
        tree = ast.parse((SRC / "__init__.py").read_text())
        actual_exports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "__all__":
                        if isinstance(node.value, ast.List):
                            for elt in node.value.elts:
                                if isinstance(elt, ast.Constant):
                                    actual_exports.add(elt.value)

        missing = self._EXPECTED_EXPORTS - actual_exports
        extra = actual_exports - self._EXPECTED_EXPORTS
        # Allow __version__ in the module but not necessarily in __all__
        errors = []
        if missing:
            errors.append(f"Missing from __all__: {missing}")
        if extra:
            errors.append(f"Unexpected in __all__: {extra}")
        assert not errors, (
            "Public API surface mismatch:\n" + "\n".join(errors)
        )
