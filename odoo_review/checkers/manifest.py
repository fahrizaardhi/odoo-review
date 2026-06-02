"""
OR040 – OR047: Manifest and addon dependency checks.

Parses __manifest__.py and cross-references:
  OR040 – missing required keys (name, version, depends)
  OR041 – depends on 'base' explicitly (implicit, redundant)
  OR042 – version format not matching Odoo convention (X.Y.Z.Z.Z), or series prefix not matching the target version
  OR043 – auto_install=True without explicit installable=True
  OR044 – license key missing
  OR045 – external dependency declared in 'depends' (should be in external_dependencies)
  OR046 – circular/self dependency
  OR047 – manifest missing or unparseable
"""
from __future__ import annotations
import ast
import re
from pathlib import Path
from typing import Generator, Any, Optional

from odoo_review.models import Category, Finding, Severity

# Known Odoo built-in module prefixes (not exhaustive but covers common ones)
_PYTHON_STDLIB = {
    "os", "sys", "re", "json", "datetime", "logging", "collections",
    "itertools", "functools", "pathlib", "io", "base64", "hashlib",
    "hmac", "copy", "math", "time", "uuid", "traceback", "csv",
    "xlrd", "xlwt", "openpyxl", "requests", "lxml", "psycopg2",
}

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+\.\d+$")


_MANIFEST_VAR_NAMES = ("manifest", "__manifest__", "_manifest")


def _literal_or_none(node: ast.expr) -> Any:
    """Best-effort literal evaluation; returns None for non-literal values
    (e.g. ``'version': SERIES + '.1.0'``) instead of aborting the whole parse."""
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _dict_from_node(dict_node: ast.Dict) -> dict[str, Any]:
    """Build a dict from an ast.Dict, evaluating each value independently so a
    single computed entry does not discard the rest of the manifest."""
    result: dict[str, Any] = {}
    for key_node, val_node in zip(dict_node.keys, dict_node.values):
        if key_node is None:          # dict unpacking: {**other}
            continue
        key = _literal_or_none(key_node)
        if isinstance(key, str):
            # Value may be None when it is a non-literal expression — the key
            # is still recorded as present so "missing key" stays accurate.
            result[key] = _literal_or_none(val_node)
    return result


def _eval_manifest(source: str) -> Optional[dict[str, Any]]:
    """Extract the manifest dict from a __manifest__.py source.

    Returns the parsed dict (possibly with None values for computed entries),
    or None if the file cannot be parsed / contains no manifest dict.
    """
    try:
        mod = ast.parse(source)
    except SyntaxError:
        return None

    for node in mod.body:
        # Most common: a bare dict literal as a module-level expression.
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Dict):
            return _dict_from_node(node.value)
        # Some manifests assign the dict to a variable.
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            if any(
                isinstance(t, ast.Name) and t.id in _MANIFEST_VAR_NAMES
                for t in node.targets
            ):
                return _dict_from_node(node.value)
    return None


# Plausible Odoo series range. Guards against reading a 3-segment app version
# like "1.0.0" as "Odoo v1"; Odoo majors realistically sit between these.
_MIN_ODOO_SERIES = 7
_MAX_ODOO_SERIES = 30


def _version_major(version: Any) -> Optional[int]:
    """Leading dotted segment of a version string as int, or None."""
    if not isinstance(version, str):
        return None
    head = version.split(".", 1)[0].strip()
    if not head.isdigit():
        return None
    return int(head)


def detect_odoo_version(filepath: Path) -> Optional[int]:
    """Best-effort detection of the target Odoo series from a manifest's
    ``version`` key. Returns the major (e.g. 17) only when it falls inside the
    plausible Odoo range, otherwise None so callers fall back gracefully."""
    try:
        source = filepath.read_text(encoding="utf-8")
    except OSError:
        return None
    manifest = _eval_manifest(source)
    if not manifest:
        return None
    major = _version_major(manifest.get("version"))
    if major is not None and _MIN_ODOO_SERIES <= major <= _MAX_ODOO_SERIES:
        return major
    return None


def check_manifest(
    filepath: Path, target_version: Optional[int] = None
) -> Generator[Finding, None, None]:
    """Entry point: check a single __manifest__.py file."""
    try:
        source = filepath.read_text(encoding="utf-8")
    except OSError:
        return

    fp = str(filepath)
    manifest = _eval_manifest(source)

    if manifest is None:
        yield Finding(
            rule_id="OR047",
            severity=Severity.HIGH,
            category=Category.DEPENDENCY,
            message="[OR047] Could not parse __manifest__.py — no manifest dict found or file is invalid.",
            filepath=fp, line=1,
            suggestion="The manifest must be a single dict literal, e.g. { 'name': ..., 'version': ..., 'depends': [...] }.",
        )
        return

    # OR040: required keys
    for key in ("name", "version", "depends"):
        if key not in manifest:
            yield Finding(
                rule_id="OR040",
                severity=Severity.MEDIUM,
                category=Category.DEPENDENCY,
                message=f"[OR040] __manifest__.py is missing required key: '{key}'.",
                filepath=fp, line=1,
                suggestion=f"Add '{key}' to your manifest dict.",
            )

    depends: list[str] = manifest.get("depends") or []

    # OR041: explicit 'base' in depends
    if "base" in depends:
        yield Finding(
            rule_id="OR041",
            severity=Severity.INFO,
            category=Category.DEPENDENCY,
            message="[OR041] 'base' listed in depends — it is implicit and can be removed.",
            filepath=fp, line=1,
            suggestion="Remove 'base' from depends list; all Odoo modules depend on it implicitly.",
        )

    # OR046: self-referential dependency
    addon_name = filepath.parent.name
    if addon_name in depends:
        yield Finding(
            rule_id="OR046",
            severity=Severity.HIGH,
            category=Category.DEPENDENCY,
            message=f"[OR046] Module '{addon_name}' lists itself in depends — circular dependency.",
            filepath=fp, line=1,
        )

    # OR042: version format + (when a target version is known) series match.
    version = manifest.get("version", "")
    if version:
        version = str(version)
        example = f"{target_version or 17}.0.1.0.0"
        if not _VERSION_RE.match(version):
            yield Finding(
                rule_id="OR042",
                severity=Severity.LOW,
                category=Category.DEPENDENCY,
                message=f"[OR042] Version '{version}' does not follow Odoo convention (MAJOR.MINOR.X.Y.Z, e.g. {example}).",
                filepath=fp, line=1,
                suggestion=f"Use format: <odoo_series>.0.<major>.<minor>.<patch>, e.g. '{example}'",
            )
        elif target_version is not None:
            # Format is fine; verify the declared series matches the target.
            major = _version_major(version)
            if major is not None and major != target_version:
                yield Finding(
                    rule_id="OR042",
                    severity=Severity.MEDIUM,
                    category=Category.DEPENDENCY,
                    message=(
                        f"[OR042] Version '{version}' declares Odoo series v{major}, "
                        f"but the target is v{target_version} — version prefix mismatch."
                    ),
                    filepath=fp, line=1,
                    suggestion=f"Set the manifest version prefix to the target series, e.g. '{example}'.",
                )

    # OR043: auto_install without installable
    if manifest.get("auto_install") and not manifest.get("installable", True):
        yield Finding(
            rule_id="OR043",
            severity=Severity.MEDIUM,
            category=Category.DEPENDENCY,
            message="[OR043] auto_install=True but installable=False — module will never be installed.",
            filepath=fp, line=1,
        )

    # OR044: license missing
    if "license" not in manifest:
        yield Finding(
            rule_id="OR044",
            severity=Severity.INFO,
            category=Category.BEST_PRACTICE,
            message="[OR044] __manifest__.py is missing 'license' key.",
            filepath=fp, line=1,
            suggestion="Add e.g.  'license': 'LGPL-3'  or  'license': 'OPL-1'  to your manifest.",
        )

    # OR045: Python stdlib / third-party in 'depends' (should be external_dependencies)
    for dep in depends:
        normalized = dep.lower().replace("-", "_")
        if normalized in _PYTHON_STDLIB:
            yield Finding(
                rule_id="OR045",
                severity=Severity.MEDIUM,
                category=Category.DEPENDENCY,
                message=f"[OR045] '{dep}' in depends looks like a Python package, not an Odoo module.",
                filepath=fp, line=1,
                suggestion=(
                    f"Move '{dep}' to external_dependencies:\n"
                    "  'external_dependencies': {'python': ['" + dep + "']}"
                ),
            )
