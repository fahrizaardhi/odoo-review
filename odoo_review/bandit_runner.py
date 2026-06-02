"""
Bandit integration: runs bandit programmatically and converts results
to odoo-review Finding objects.

Bandit severity/confidence → odoo-review Severity mapping:
  bandit HIGH   → CRITICAL (if confidence HIGH) else HIGH
  bandit MEDIUM → MEDIUM
  bandit LOW    → LOW
"""
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path
from typing import Generator, Iterable, Optional

from odoo_review.models import Category, Finding, Severity


_BANDIT_SEVERITY_MAP = {
    ("HIGH",   "HIGH"):   Severity.CRITICAL,
    ("HIGH",   "MEDIUM"): Severity.HIGH,
    ("HIGH",   "LOW"):    Severity.HIGH,
    ("MEDIUM", "HIGH"):   Severity.MEDIUM,
    ("MEDIUM", "MEDIUM"): Severity.MEDIUM,
    ("MEDIUM", "LOW"):    Severity.LOW,
    ("LOW",    "HIGH"):   Severity.LOW,
    ("LOW",    "MEDIUM"): Severity.LOW,
    ("LOW",    "LOW"):    Severity.INFO,
}

# Bandit test IDs we skip because our own checkers cover them better
_SKIP_TEST_IDS = {
    "B608",  # SQL injection — OR001/OR002 are Odoo-aware
    "B307",  # eval — OR026 covers this
}


def run_bandit(
    target_path: Path,
    exclude_dirs: Optional[Iterable[str]] = None,
) -> Generator[Finding, None, None]:
    """
    Run bandit on *target_path* and yield Finding objects.
    Returns nothing if bandit is not installed.

    exclude_dirs : directory names (e.g. {"tests", "static"}) to skip so the
    Bandit scan stays consistent with the AST scan.
    """
    cmd = [
        sys.executable, "-m", "bandit",
        "-r",                        # recursive
        "-f", "json",                # machine-readable output
        "-q",                        # quiet (no progress bar)
        "--skip", ",".join(_SKIP_TEST_IDS),
    ]
    if exclude_dirs:
        # Bandit --exclude takes comma-separated glob patterns.
        patterns = [f"*/{d}/*" for d in sorted(exclude_dirs)]
        cmd += ["--exclude", ",".join(patterns)]
    cmd.append(str(target_path))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        return  # bandit not installed — silently skip
    except subprocess.TimeoutExpired:
        return

    stdout = result.stdout.strip()
    if not stdout:
        return

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return

    for issue in data.get("results", []):
        sev_str  = issue.get("issue_severity", "LOW").upper()
        conf_str = issue.get("issue_confidence", "LOW").upper()
        severity = _BANDIT_SEVERITY_MAP.get((sev_str, conf_str), Severity.LOW)

        test_id   = issue.get("test_id", "B000")
        test_name = issue.get("test_name", "")
        text      = issue.get("issue_text", "")
        filepath  = issue.get("filename", "")
        line      = issue.get("line_number", 0)
        code      = (issue.get("code") or "").strip()

        # Map bandit categories to ours
        category = _map_category(test_id)

        yield Finding(
            rule_id=test_id,
            severity=severity,
            category=category,
            message=f"[{test_id}] {test_name}: {text}",
            filepath=filepath,
            line=line,
            snippet=code,
            suggestion=issue.get("more_info", ""),
            source="bandit",
        )


def _map_category(test_id: str) -> Category:
    # Bandit test IDs look like "B608" / "B101" → the family prefix is the
    # first 2 characters ("B6", "B1"), NOT the first 3.
    prefix = test_id[:2]
    _MAP = {
        "B1": Category.SECURITY,   # general / injection
        "B2": Category.SECURITY,   # misc
        "B3": Category.SECURITY,   # crypto / deserialization
        "B4": Category.SECURITY,   # xml
        "B5": Category.SECURITY,   # net / tls
        "B6": Category.SECURITY,   # injection (sql, shell, ...)
        "B7": Category.SECURITY,   # crypto
    }
    # Specific overrides (assert / try-except-pass are quality, not security)
    if test_id in ("B101", "B110"):
        return Category.BEST_PRACTICE
    return _MAP.get(prefix, Category.SECURITY)
