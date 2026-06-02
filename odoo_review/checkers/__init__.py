"""
Checker base class. All Odoo-specific checkers inherit from BaseChecker.
"""
from __future__ import annotations
import ast
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Generator, Optional

from odoo_review.models import Finding, ScanContext


class BaseChecker(ABC):
    """AST-based checker base. Override `check_file` or `visit_*` methods."""

    @abstractmethod
    def check_file(
        self,
        filepath: Path,
        tree: ast.Module,
        source: str,
        context: Optional[ScanContext] = None,
    ) -> Generator[Finding, None, None]:
        """Yield Finding objects for the given AST tree.

        `context` carries cross-cutting info (e.g. the target Odoo version).
        It is optional so checkers can still be called standalone in tests.
        """
        ...
