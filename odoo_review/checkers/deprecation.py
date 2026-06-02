"""
OR060 – OR063: deprecated / removed Odoo API usage (version-aware).

  OR060 – @api.multi / @api.one decorators (removed in Odoo 13)
  OR061 – cr.commit() inside addon code (breaks the transaction)
  OR062 – pre-v10 legacy API: `from openerp`, osv.osv base, _columns,
          fields.function
  OR063 – self.pool / self.pool.get() (old API, replaced by self.env)

Severity scales with the target series (`context.odoo_version`): once a feature
is actually removed it becomes HIGH (it will break), before that it is an
advisory, and with an unknown version we stay at MEDIUM.
"""
from __future__ import annotations
import ast
from pathlib import Path
from typing import Generator, Optional

from odoo_review.checkers import BaseChecker
from odoo_review.models import Category, Finding, ScanContext, Severity

_CURSOR_NAMES = {"cr", "_cr", "cursor"}


def _scaled(version: Optional[int], removed_in: int) -> Severity:
    """HIGH once removed, INFO while still supported, MEDIUM if version unknown."""
    if version is None:
        return Severity.MEDIUM
    return Severity.HIGH if version >= removed_in else Severity.INFO


class DeprecationChecker(BaseChecker):

    def check_file(
        self, filepath: Path, tree: ast.Module, source: str,
        context: Optional[ScanContext] = None,
    ) -> Generator[Finding, None, None]:
        lines = source.splitlines()
        fp = str(filepath)
        version = context.odoo_version if context else None

        def snippet(lineno: int):
            return lines[lineno - 1].strip() if lineno <= len(lines) else None

        for node in ast.walk(tree):
            # OR060: @api.multi / @api.one (removed in v13)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Attribute) and dec.attr in ("multi", "one"):
                        if isinstance(dec.value, ast.Name) and dec.value.id == "api":
                            yield Finding(
                                rule_id="OR060",
                                severity=_scaled(version, 13),
                                category=Category.MAINTAINABILITY,
                                message=f"[OR060] @api.{dec.attr} was removed in Odoo 13 — methods now operate on recordsets directly.",
                                filepath=fp, line=dec.lineno, snippet=snippet(dec.lineno),
                                suggestion="Drop the decorator; iterate `for rec in self:` where you need a single record.",
                            )

            # OR061: cursor .commit() inside addon code
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "commit":
                recv = node.func.value
                is_cursor = (
                    (isinstance(recv, ast.Attribute) and recv.attr in _CURSOR_NAMES)
                    or (isinstance(recv, ast.Name) and recv.id in _CURSOR_NAMES)
                )
                if is_cursor:
                    yield Finding(
                        rule_id="OR061",
                        severity=Severity.MEDIUM,
                        category=Category.ORM,
                        message="[OR061] Explicit cr.commit() inside addon code breaks Odoo's transaction handling and can corrupt data on errors.",
                        filepath=fp, line=node.lineno, snippet=snippet(node.lineno),
                        suggestion="Let Odoo manage the transaction; only commit in tightly-scoped jobs/crons with savepoints if truly required.",
                    )

            # OR062: legacy `from openerp ...` / `import openerp`
            if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "openerp":
                yield self._legacy(version, fp, node.lineno, snippet(node.lineno),
                                   "`from openerp` import (renamed to `odoo` in v10)")
            if isinstance(node, ast.Import) and any(a.name.split(".")[0] == "openerp" for a in node.names):
                yield self._legacy(version, fp, node.lineno, snippet(node.lineno),
                                   "`import openerp` (renamed to `odoo` in v10)")

            # OR062: osv.osv / osv.Model base class
            if isinstance(node, ast.ClassDef):
                for base in node.bases:
                    if isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name) and base.value.id == "osv":
                        yield self._legacy(version, fp, node.lineno, snippet(node.lineno),
                                           f"osv.{base.attr} base class (old API; use models.Model)")

            # OR062: _columns = {...}
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "_columns":
                        yield self._legacy(version, fp, node.lineno, snippet(node.lineno),
                                           "_columns dict (old API; declare fields as class attributes)")

            # OR062: fields.function(...)
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "function"
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "fields"):
                yield self._legacy(version, fp, node.lineno, snippet(node.lineno),
                                   "fields.function (old API; use a computed field with @api.depends)")

            # OR063: self.pool / self.pool.get()
            if (isinstance(node, ast.Attribute) and node.attr == "pool"
                    and isinstance(node.value, ast.Name) and node.value.id == "self"):
                yield Finding(
                    rule_id="OR063",
                    severity=_scaled(version, 10),
                    category=Category.MAINTAINABILITY,
                    message="[OR063] self.pool is the old API (pre-v8) — use self.env['model'] instead.",
                    filepath=fp, line=node.lineno, snippet=snippet(node.lineno),
                    suggestion="Replace self.pool.get('model') with self.env['model'].",
                )

    def _legacy(self, version, fp, lineno, snippet, what: str) -> Finding:
        return Finding(
            rule_id="OR062",
            severity=_scaled(version, 10),
            category=Category.MAINTAINABILITY,
            message=f"[OR062] Legacy Odoo API: {what}.",
            filepath=fp, line=lineno, snippet=snippet,
            suggestion="Port to the modern Odoo API (odoo namespace, models.Model, computed fields, self.env).",
        )
