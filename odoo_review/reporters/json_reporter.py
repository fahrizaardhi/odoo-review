"""
JSON reporter: serializes ScanResult(s) to JSON for CI/CD integration.
"""
from __future__ import annotations
import json
from dataclasses import asdict
from odoo_review.models import ScanResult, Finding


def _finding_to_dict(f: Finding) -> dict:
    return {
        "rule_id":    f.rule_id,
        "severity":   f.severity.value,
        "category":   f.category.value,
        "message":    f.message,
        "filepath":   f.filepath,
        "line":       f.line,
        "col":        f.col,
        "snippet":    f.snippet,
        "suggestion": f.suggestion,
        "source":     f.source,
    }


def result_to_dict(result: ScanResult) -> dict:
    return {
        "addon_path":    result.addon_path,
        "scanned_files": result.scanned_files,
        "odoo_version":  result.odoo_version,
        "odoo_version_source": result.odoo_version_source,
        "suppressed":    result.suppressed,
        "summary":       result.summary,
        "findings":      [_finding_to_dict(f) for f in sorted(result.findings)],
        "errors":        result.errors,
    }


def to_json(results: list[ScanResult], indent: int = 2) -> str:
    return json.dumps(
        {
            "version": "0.1.0",
            "addons":  [result_to_dict(r) for r in results],
            "totals": {
                "addons":    len(results),
                "files":     sum(r.scanned_files for r in results),
                "findings":  sum(len(r.findings) for r in results),
                "suppressed": sum(r.suppressed for r in results),
                "critical":  sum(r.summary["critical"] for r in results),
                "high":      sum(r.summary["high"]     for r in results),
                "medium":    sum(r.summary["medium"]   for r in results),
                "low":       sum(r.summary["low"]      for r in results),
                "info":      sum(r.summary["info"]     for r in results),
            },
        },
        indent=indent,
        ensure_ascii=False,
    )
