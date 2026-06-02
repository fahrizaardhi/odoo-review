"""
Console reporter: pretty-prints findings to stdout with ANSI colors.
"""
from __future__ import annotations
import sys
from odoo_review.models import Finding, ScanResult, Severity, SEVERITY_ORDER

# ANSI color codes
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"

_COLORS = {
    Severity.CRITICAL: "\033[91m",   # bright red
    Severity.HIGH:     "\033[31m",   # red
    Severity.MEDIUM:   "\033[33m",   # yellow
    Severity.LOW:      "\033[36m",   # cyan
    Severity.INFO:     "\033[37m",   # white
}

_ICONS = {
    Severity.CRITICAL: "💀",
    Severity.HIGH:     "🔴",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "ℹ️ ",
}


def _color(text: str, severity: Severity, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_COLORS[severity]}{text}{_RESET}"


def _bold(text: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_BOLD}{text}{_RESET}"


def print_result(result: ScanResult, use_color: bool = True, verbose: bool = False) -> None:
    out = sys.stdout
    addon_name = result.addon_path.split("/")[-1]

    print(f"\n{'='*70}", file=out)
    print(_bold(f"  📦 Addon: {addon_name}", use_color), file=out)
    print(f"  Path   : {result.addon_path}", file=out)
    print(f"  Files  : {result.scanned_files} file(s) scanned (Python + XML)", file=out)
    if result.odoo_version is not None:
        print(f"  Odoo   : v{result.odoo_version} (from {result.odoo_version_source})", file=out)
    if result.suppressed:
        print(f"  Muted  : {result.suppressed} finding(s) suppressed via noqa/.odoo-review", file=out)
    print(f"{'='*70}", file=out)

    if not result.findings:
        print("  ✅  No issues found!", file=out)
        return

    # Group by severity
    by_sev = result.by_severity
    for severity in sorted(Severity, key=lambda s: SEVERITY_ORDER[s]):
        findings = by_sev[severity]
        if not findings:
            continue

        icon = _ICONS[severity]
        label = _color(f"{icon} {severity.value} ({len(findings)})", severity, use_color)
        print(f"\n  {label}", file=out)
        print(f"  {'─'*60}", file=out)

        for f in sorted(findings, key=lambda x: (x.filepath, x.line)):
            loc  = f"{f.filepath}:{f.line}"
            src  = f"[{f.source}]" if f.source != "odoo-review" else ""
            line = f"  {_color(f.rule_id, severity, use_color)} {src}  {loc}"
            print(line, file=out)
            print(f"    {f.message}", file=out)

            if f.snippet and verbose:
                print(f"    {_DIM}Code: {f.snippet}{_RESET}", file=out)

            if f.suggestion and verbose:
                print(f"    💡 {f.suggestion}", file=out)
            print(file=out)

    # Summary bar
    s = result.summary
    print(f"\n{'─'*70}", file=out)
    parts = []
    for key in ("critical", "high", "medium", "low", "info"):
        sev = Severity(key.upper())
        val = s[key]
        if val:
            parts.append(_color(f"{key.capitalize()}: {val}", sev, use_color))
    print("  Summary: " + "  |  ".join(parts) + f"  |  Total: {s['total']}", file=out)

    if result.errors:
        print(f"\n  ⚠️  Errors during scan:", file=out)
        for e in result.errors:
            print(f"    - {e}", file=out)


def print_multi_results(results: list[ScanResult], use_color: bool = True, verbose: bool = False) -> None:
    for r in results:
        print_result(r, use_color=use_color, verbose=verbose)

    # Grand total
    total_findings = sum(len(r.findings) for r in results)
    total_files    = sum(r.scanned_files for r in results)
    print(f"\n{'='*70}", flush=True)
    print(_bold(f"  Grand Total: {len(results)} addon(s), {total_files} files, {total_findings} findings", use_color))
    print(f"{'='*70}\n")
