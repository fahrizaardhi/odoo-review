"""
OR050: new models without an ir.model.access rule.

This is an addon-level check (it must look across every model file and the
``security/`` directory at once), so it is a plain function rather than a
per-file BaseChecker. A model that defines ``_name`` but has no matching access
rule is only usable by the superuser — a classic OCA review finding.

Detection of "granted" is intentionally loose: any file under ``security/``
(CSV access lines or XML ``ir.model.access`` records) that mentions the model's
access token ``model_<name_with_underscores>`` counts as granted.
"""
from __future__ import annotations
import ast
import re
from pathlib import Path
from typing import Generator, List, Tuple

from odoo_review.models import Category, Finding, Severity

_SKIP_DIRS = {"__pycache__", ".git", "node_modules", "static", "migrations", "tests"}
_ABSTRACT_BASES = {"AbstractModel"}  # models.AbstractModel needs no access rules


def _is_abstract(classdef: ast.ClassDef) -> bool:
    for base in classdef.bases:
        if isinstance(base, ast.Attribute) and base.attr in _ABSTRACT_BASES:
            return True
        if isinstance(base, ast.Name) and base.id in _ABSTRACT_BASES:
            return True
    return False


def _model_name(classdef: ast.ClassDef) -> str | None:
    """Return the literal ``_name`` of a model class, or None."""
    for stmt in classdef.body:
        if not isinstance(stmt, ast.Assign):
            continue
        for target in stmt.targets:
            if isinstance(target, ast.Name) and target.id == "_name":
                if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                    return stmt.value.value
    return None


def _collect_models(addon_path: Path) -> List[Tuple[str, str, int]]:
    """List (model_name, filepath, lineno) for every concrete model in the addon."""
    models: List[Tuple[str, str, int]] = []
    for py_file in sorted(addon_path.rglob("*.py")):
        rel_parts = py_file.relative_to(addon_path).parts
        if any(part in _SKIP_DIRS for part in rel_parts):
            continue
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or _is_abstract(node):
                continue
            name = _model_name(node)
            if name:
                models.append((name, str(py_file), node.lineno))
    return models


def _granted_tokens(addon_path: Path) -> str:
    """Concatenated text of everything under ``security/`` (csv + xml)."""
    security_dir = addon_path / "security"
    if not security_dir.is_dir():
        return ""
    chunks = []
    for f in sorted(security_dir.rglob("*")):
        if f.is_file():
            try:
                chunks.append(f.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                continue
    return "\n".join(chunks)


def check_access_rules(addon_path: Path) -> Generator[Finding, None, None]:
    """Yield OR050 for each concrete model missing an ir.model.access rule."""
    models = _collect_models(addon_path)
    if not models:
        return
    granted = _granted_tokens(addon_path)

    # First match per model wins, so a model declared in several files (rare) is
    # only reported once.
    seen: set[str] = set()
    for name, filepath, lineno in models:
        if name in seen:
            continue
        seen.add(name)
        token = "model_" + name.replace(".", "_")
        if re.search(r"\b" + re.escape(token) + r"\b", granted):
            continue
        yield Finding(
            rule_id="OR050",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            message=(
                f"[OR050] Model '{name}' has no ir.model.access rule — only the "
                f"superuser can access it, which usually breaks normal users."
            ),
            filepath=filepath, line=lineno,
            suggestion=(
                f"Add a line to security/ir.model.access.csv referencing '{token}', e.g.\n"
                f"  access_{name.replace('.', '_')}_user,{name}.user,{token},base.group_user,1,1,1,1"
            ),
        )
