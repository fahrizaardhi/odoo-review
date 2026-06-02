"""
OR010 – OR012: N+1 Query / loop-ORM anti-patterns.

Detects expensive ORM method calls (search, search_count, browse, read,
write, create, unlink, copy) and registry lookups inside for/while loops —
the classic N+1 pattern.
"""
from __future__ import annotations
import ast
from pathlib import Path
from typing import Generator, Set

from odoo_review.checkers import BaseChecker
from odoo_review.models import Category, Finding, Severity

# ORM methods that are expensive when called per-record inside a loop
_SEARCH_METHODS: Set[str] = {"search", "search_count", "browse", "read"}
_WRITE_METHODS:  Set[str] = {"write", "create", "unlink", "copy"}

_ALL_ORM = _SEARCH_METHODS | _WRITE_METHODS


def _enclosing_loop(node: ast.AST, parents: list[ast.AST]) -> bool:
    """Return True if any ancestor is a For or While loop."""
    for p in reversed(parents):
        if isinstance(p, (ast.For, ast.While)):
            return True
        if isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            break
    return False


class NPlusOneChecker(BaseChecker):
    """
    OR010 – search/search_count/browse/read inside a loop.
    OR011 – write/create/unlink/copy inside a loop (should be batched).
    OR012 – self.env['Model'] registry lookup inside a loop.
    """

    def check_file(
        self, filepath: Path, tree: ast.Module, source: str, context=None
    ) -> Generator[Finding, None, None]:
        lines = source.splitlines()
        yield from self._walk_with_parents(tree, lines, str(filepath))

    # ------------------------------------------------------------------ #
    def _walk_with_parents(
        self, tree: ast.Module, lines: list[str], filepath: str
    ) -> Generator[Finding, None, None]:
        """Walk AST keeping a parent stack to detect loop nesting."""

        def _walk(node: ast.AST, parents: list[ast.AST]):
            for child in ast.iter_child_nodes(node):
                yield from _check_node(child, parents)
                yield from _walk(child, parents + [node])

        def _check_node(node: ast.AST, parents: list[ast.AST]):
            if not isinstance(node, ast.Call):
                return
            func = node.func
            if not isinstance(func, ast.Attribute):
                return

            method = func.attr
            snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else None

            # OR012: self.env['Model'] registry lookup inside loop.
            # Only report it when the call on the subscript is NOT itself an
            # expensive ORM op — otherwise OR010/OR011 already cover the same
            # line and we would emit a duplicate finding.
            if isinstance(func.value, ast.Subscript) and method not in _ALL_ORM:
                val = func.value.value
                if isinstance(val, ast.Attribute) and val.attr == "env":
                    if _enclosing_loop(node, parents):
                        yield Finding(
                            rule_id="OR012",
                            severity=Severity.MEDIUM,
                            category=Category.PERFORMANCE,
                            message="[OR012] self.env['Model'] accessed inside a loop — move registry lookup outside loop.",
                            filepath=filepath,
                            line=node.lineno,
                            snippet=snippet,
                            suggestion="Cache  Model = self.env['your.model']  before the loop.",
                        )

            # OR010 / OR011: ORM calls inside loops
            if method in _SEARCH_METHODS and _enclosing_loop(node, parents):
                yield Finding(
                    rule_id="OR010",
                    severity=Severity.HIGH,
                    category=Category.PERFORMANCE,
                    message=f"[OR010] .{method}() called inside a loop — N+1 query risk.",
                    filepath=filepath,
                    line=node.lineno,
                    snippet=snippet,
                    suggestion=(
                        f"Collect all IDs/domains first, then call .{method}() once outside the loop. "
                        "Use mapped() or prefetch_fields for field traversal."
                    ),
                )

            if method in _WRITE_METHODS and _enclosing_loop(node, parents):
                yield Finding(
                    rule_id="OR011",
                    severity=Severity.MEDIUM,
                    category=Category.PERFORMANCE,
                    message=f"[OR011] .{method}() called inside a loop — consider batching.",
                    filepath=filepath,
                    line=node.lineno,
                    snippet=snippet,
                    suggestion=(
                        "Batch writes with a list of vals dicts and call create([...]) once, "
                        "or collect records and call write({...}) on the recordset."
                    ),
                )

        yield from _walk(tree, [])
