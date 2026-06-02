"""
Core data models for odoo-review findings.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Category(str, Enum):
    SECURITY      = "Security"
    PERFORMANCE   = "Performance"
    ORM           = "ORM Usage"
    MAINTAINABILITY = "Maintainability"
    DEPENDENCY    = "Dependency"
    BEST_PRACTICE = "Best Practice"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
    Severity.INFO:     4,
}


@dataclass
class ScanContext:
    """Per-addon context shared with every checker for one scan.

    `odoo_version` is the resolved target Odoo major series (e.g. 17). It is
    None when neither the --odoo-version flag nor the manifest yielded a usable
    value; checkers must treat None as "version unknown" and stay conservative.
    """
    odoo_version: Optional[int] = None


@dataclass
class Finding:
    rule_id:    str
    severity:   Severity
    category:   Category
    message:    str
    filepath:   str
    line:       int
    col:        int = 0
    snippet:    Optional[str] = None
    suggestion: Optional[str] = None
    source:     str = "odoo-review"   # or "bandit"

    def __lt__(self, other: "Finding") -> bool:
        return SEVERITY_ORDER[self.severity] < SEVERITY_ORDER[other.severity]


@dataclass
class ScanResult:
    addon_path: str
    findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0
    errors: list[str] = field(default_factory=list)
    odoo_version: Optional[int] = None
    # How `odoo_version` was resolved: "flag", "manifest", or "unknown".
    odoo_version_source: str = "unknown"
    # Count of findings dropped by inline `# noqa` / `.odoo-review` disables.
    suppressed: int = 0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result

    @property
    def summary(self) -> dict:
        return {
            "total": len(self.findings),
            "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
            "high":     sum(1 for f in self.findings if f.severity == Severity.HIGH),
            "medium":   sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
            "low":      sum(1 for f in self.findings if f.severity == Severity.LOW),
            "info":     sum(1 for f in self.findings if f.severity == Severity.INFO),
        }
