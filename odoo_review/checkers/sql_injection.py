"""
OR001 – OR002: SQL Injection checks.

Detects unsafe use of self.env.cr.execute() / self._cr.execute()
where the query is built via %-formatting, f-strings, or .format().
"""
from __future__ import annotations
import ast
from pathlib import Path
from typing import Generator

from odoo_review.checkers import BaseChecker
from odoo_review.models import Category, Finding, Severity


# Patterns that indicate dynamic SQL construction
_UNSAFE_NODE_TYPES = (ast.BinOp, ast.JoinedStr, ast.Call)


def _is_format_call(node: ast.expr) -> bool:
    """Detect  'SELECT %s' % val  or  'SELECT {}'.format(val)"""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            return True
    return False


def _is_unsafe_query(arg: ast.expr) -> bool:
    if isinstance(arg, ast.JoinedStr):          # f-string
        return True
    if _is_format_call(arg):
        return True
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add,)):
        return True                             # string concatenation
    return False


# Receiver names that identify an actual SQL cursor, e.g.
#   self.env.cr.execute(...) / self._cr.execute(...) / cr.execute(...)
_CURSOR_NAMES = {"cr", "_cr", "cursor"}


def _is_cursor_execute(func: ast.Attribute) -> bool:
    """True only when ``.execute()`` is called on something that looks like a
    database cursor. Prevents flagging unrelated ``.execute()`` APIs as SQL."""
    receiver = func.value
    if isinstance(receiver, ast.Attribute):
        return receiver.attr in _CURSOR_NAMES
    if isinstance(receiver, ast.Name):
        return receiver.id in _CURSOR_NAMES
    return False


class SQLInjectionChecker(BaseChecker):
    """
    OR001 – Unsafe cr.execute() call (high/critical SQL injection risk).
    OR002 – String concatenation inside cr.execute() query argument.
    """

    _EXECUTE_CALLERS = {"execute"}

    def check_file(
        self, filepath: Path, tree: ast.Module, source: str, context=None
    ) -> Generator[Finding, None, None]:
        lines = source.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            # Match  self.env.cr.execute(...)  /  self._cr.execute(...)
            if not (isinstance(func, ast.Attribute) and func.attr in self._EXECUTE_CALLERS):
                continue
            if not _is_cursor_execute(func):
                continue
            if not node.args:
                continue

            query_arg = node.args[0]

            if _is_unsafe_query(query_arg):
                snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else None

                if isinstance(query_arg, ast.JoinedStr):
                    rule_id = "OR001"
                    severity = Severity.CRITICAL
                    detail = "f-string used as SQL query — direct injection risk"
                else:
                    rule_id = "OR002"
                    severity = Severity.HIGH
                    detail = "dynamic string passed to cr.execute() — use parameterized queries"

                yield Finding(
                    rule_id=rule_id,
                    severity=severity,
                    category=Category.SECURITY,
                    message=f"[{rule_id}] Potential SQL injection: {detail}.",
                    filepath=str(filepath),
                    line=node.lineno,
                    col=node.col_offset,
                    snippet=snippet,
                    suggestion=(
                        "Use parameterized queries:\n"
                        "  self.env.cr.execute('SELECT * FROM table WHERE id = %s', (record_id,))"
                    ),
                )
