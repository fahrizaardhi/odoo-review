"""
OR020 – OR026: Odoo ORM best-practice checks.

Covers:
  OR020 – sudo(True): legacy API forcing superuser context
  OR021 – bare sudo(): privilege escalation, confirm it is justified
  OR022 – hardcoded database IDs (ref() should be used)
  OR023 – missing _description on new model (_name without _description)
  OR024 – _inherit used with _name creating new model (should document intent)
  OR025 – compute method without depends decorator
  OR026 – eval() / exec() / compile() builtin usage
"""
from __future__ import annotations
import ast
from pathlib import Path
from typing import Generator, Optional

from odoo_review.checkers import BaseChecker
from odoo_review.models import Category, Finding, ScanContext, Severity


class ORMBestPracticeChecker(BaseChecker):

    def check_file(
        self, filepath: Path, tree: ast.Module, source: str,
        context: Optional[ScanContext] = None,
    ) -> Generator[Finding, None, None]:
        lines = source.splitlines()
        fp = str(filepath)
        odoo_version = context.odoo_version if context else None

        yield from self._check_sudo(tree, lines, fp, odoo_version)
        yield from self._check_eval_exec(tree, lines, fp)
        yield from self._check_hardcoded_ids(tree, lines, fp)
        yield from self._check_model_class(tree, fp)
        yield from self._check_compute_depends(tree, lines, fp)

    # ------------------------------------------------------------------ #
    # OR020: sudo() usage analysis
    # ------------------------------------------------------------------ #
    def _check_sudo(self, tree, lines, fp, odoo_version: Optional[int] = None):
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "sudo"):
                continue

            snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else None

            # sudo(True): the boolean-argument form forces superuser context.
            sudo_true = any(
                isinstance(arg, ast.Constant) and arg.value is True
                for arg in node.args
            )
            if sudo_true:
                # Version context sharpens this: the sudo(flag) signature was
                # removed in Odoo 13, so on v13+ it is a hard error, while on
                # v12 and earlier it is valid-but-discouraged. Unknown version
                # stays HIGH (conservative).
                if odoo_version is not None and odoo_version >= 13:
                    severity = Severity.HIGH
                    message = (
                        f"[OR020] sudo(True) uses the boolean argument form, removed in "
                        f"Odoo 13 (target: v{odoo_version}) — this will break and bypasses all access control."
                    )
                elif odoo_version is not None and odoo_version < 13:
                    severity = Severity.MEDIUM
                    message = (
                        f"[OR020] sudo(True) forces superuser context (legacy API, still valid on "
                        f"v{odoo_version}) — escalates to root, bypassing all access control."
                    )
                else:
                    severity = Severity.HIGH
                    message = (
                        "[OR020] sudo(True) forces superuser context (legacy API) — "
                        "escalates to root, bypassing all access control."
                    )
                yield Finding(
                    rule_id="OR020",
                    severity=severity,
                    category=Category.SECURITY,
                    message=message,
                    filepath=fp, line=node.lineno, snippet=snippet,
                    suggestion="Drop the boolean argument; use a bare self.sudo() only where justified, or self.with_user(user) for a specific user.",
                )
                continue

            # Bare sudo() escalates privileges too; flag it lower so reviewers
            # can confirm each use is justified (the most common real risk).
            if not node.args and not node.keywords:
                yield Finding(
                    rule_id="OR021",
                    severity=Severity.LOW,
                    category=Category.SECURITY,
                    message="[OR021] sudo() escalates to superuser and bypasses access rules — confirm this call is justified.",
                    filepath=fp, line=node.lineno, snippet=snippet,
                    suggestion="Use sudo() only when access control must be bypassed intentionally; otherwise keep the caller's rights or use with_user().",
                )

    # ------------------------------------------------------------------ #
    # OR026: eval / exec
    # ------------------------------------------------------------------ #
    def _check_eval_exec(self, tree, lines, fp):
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Only flag the builtins eval()/exec()/compile() (bare names).
            # Attribute calls like self.eval(...) or node.compile(...) are
            # unrelated methods and were causing false-positive CRITICALs.
            name = func.id if isinstance(func, ast.Name) else None

            if name in ("eval", "exec", "compile"):
                snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else None
                yield Finding(
                    rule_id="OR026",
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    message=f"[OR026] Use of {name}() detected — serious security risk in multi-tenant Odoo.",
                    filepath=fp, line=node.lineno, snippet=snippet,
                    suggestion="Avoid eval/exec. Use safe_eval from odoo.tools.safe_eval if dynamic expression evaluation is required.",
                )

    # ------------------------------------------------------------------ #
    # OR022: hardcoded integer IDs passed to browse() or id comparisons
    # ------------------------------------------------------------------ #
    def _check_hardcoded_ids(self, tree, lines, fp):
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "browse"):
                continue
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, int) and arg.value > 0:
                    snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else None
                    yield Finding(
                        rule_id="OR022",
                        severity=Severity.MEDIUM,
                        category=Category.BEST_PRACTICE,
                        message=f"[OR022] Hardcoded ID ({arg.value}) passed to browse() — IDs differ between databases.",
                        filepath=fp, line=node.lineno, snippet=snippet,
                        suggestion="Use self.env.ref('module.xml_id') to resolve records portably.",
                    )

    # ------------------------------------------------------------------ #
    # OR023 / OR024: model class introspection
    # ------------------------------------------------------------------ #
    def _check_model_class(self, tree, fp):
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            assigns = {
                n.targets[0].id: n.value
                for n in ast.walk(node)
                if isinstance(n, ast.Assign)
                and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)
            }

            has_name        = "_name"        in assigns
            has_inherit     = "_inherit"     in assigns
            has_description = "_description" in assigns

            # OR023: _name present but _description missing
            if has_name and not has_description:
                yield Finding(
                    rule_id="OR023",
                    severity=Severity.LOW,
                    category=Category.BEST_PRACTICE,
                    message=f"[OR023] Class '{node.name}' defines _name but is missing _description.",
                    filepath=fp, line=node.lineno,
                    suggestion="Add  _description = 'Human readable model name'  to avoid Odoo warnings.",
                )

            # OR024: both _name and _inherit → creating new model, document it
            if has_name and has_inherit and not has_description:
                yield Finding(
                    rule_id="OR024",
                    severity=Severity.INFO,
                    category=Category.BEST_PRACTICE,
                    message=f"[OR024] Class '{node.name}' uses both _name and _inherit (new model from mixin) without _description.",
                    filepath=fp, line=node.lineno,
                    suggestion="Add _description to clarify intent of inheriting and renaming.",
                )

    # ------------------------------------------------------------------ #
    # OR025: @api.depends missing on compute methods
    # ------------------------------------------------------------------ #
    def _check_compute_depends(self, tree, lines, fp):
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for item in node.body:
                if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                name = item.name
                # Heuristic: method named _compute_* without @api.depends
                if not name.startswith("_compute_"):
                    continue
                has_depends = any(
                    (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "depends")
                    or (isinstance(d, ast.Attribute) and d.attr == "depends")
                    for d in item.decorator_list
                )
                if not has_depends:
                    snippet = lines[item.lineno - 1].strip() if item.lineno <= len(lines) else None
                    # LOW, not MEDIUM: plenty of compute methods legitimately
                    # omit @api.depends (non-stored, context-based, or recomputed
                    # manually), so this is a reminder rather than a hard error.
                    yield Finding(
                        rule_id="OR025",
                        severity=Severity.LOW,
                        category=Category.ORM,
                        message=f"[OR025] Compute method '{name}' has no @api.depends() — confirm it does not need automatic recomputation.",
                        filepath=fp, line=item.lineno, snippet=snippet,
                        suggestion="Add @api.depends('field1', 'field2') for stored/dependent computes; ignore for non-stored or context-driven ones.",
                    )
