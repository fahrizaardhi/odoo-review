"""
odoo-review CLI

Usage:
  odoo-review path/to/addon
  odoo-review path/to/addons_dir --all
  odoo-review path/to/addon --format json --output report.json
  odoo-review path/to/addon --no-bandit --verbose
  odoo-review path/to/addon --fail-on HIGH
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from odoo_review import __version__
from odoo_review.scanner import scan_addon, scan_directory
from odoo_review.reporters.console import print_result, print_multi_results
from odoo_review.reporters.json_reporter import to_json
from odoo_review.models import Severity, SEVERITY_ORDER


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="odoo-review",
        description="Static analysis for Odoo addons — SQL injection, N+1, ORM issues, manifest deps, and more.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  odoo-review ./my_addon
  odoo-review ./addons --all
  odoo-review ./my_addon --format json -o report.json
  odoo-review ./my_addon --no-bandit --verbose
  odoo-review ./my_addon --fail-on HIGH
        """,
    )
    p.add_argument(
        "paths",
        nargs="+",
        help="Addon dir(s), a dir of addons (with --all), or individual files "
             "(each file is mapped to its containing addon — handy for pre-commit).",
    )
    p.add_argument("--all",       action="store_true", help="Scan all addons found recursively under PATH")
    p.add_argument("--no-bandit", action="store_true", help="Skip Bandit security scan")
    p.add_argument("--format",    choices=["console", "json"], default="console", help="Output format (default: console)")
    p.add_argument("--output","-o", metavar="FILE", help="Write output to FILE instead of stdout")
    p.add_argument("--verbose","-v", action="store_true", help="Show code snippets and suggestions")
    p.add_argument("--no-color",  action="store_true", help="Disable ANSI colors")
    p.add_argument(
        "--odoo-version",
        type=int,
        default=None,
        metavar="N",
        help="Target Odoo major series (e.g. 17). Auto-detected from __manifest__.py when omitted.",
    )
    p.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        metavar="SEVERITY",
        help="Exit with code 1 if any finding at this severity or higher is found (useful for CI)",
    )
    p.add_argument("--version", action="version", version=f"odoo-review {__version__}")
    return p


def _find_addon_root(path: Path) -> Optional[Path]:
    """Walk up from a file to the nearest directory containing __manifest__.py."""
    for d in (path.parent, *path.parent.parents):
        if (d / "__manifest__.py").is_file():
            return d
    return None


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    run_bandit = not args.no_bandit
    use_color  = not args.no_color and sys.stdout.isatty()

    # Resolve every input path into addons to scan. Files map to their addon;
    # directories are scanned directly (or recursively with --all / when they
    # are not themselves an addon). Addon roots are de-duplicated.
    dir_results = []
    addon_targets: list[Path] = []
    seen: set[Path] = set()
    missing = False

    def queue_addon(p: Path) -> None:
        if p not in seen:
            seen.add(p)
            addon_targets.append(p)

    for raw in args.paths:
        target = Path(raw).resolve()
        if not target.exists():
            print(f"❌  Path not found: {target}", file=sys.stderr)
            missing = True
            continue
        if target.is_file():
            root = _find_addon_root(target)
            if root is not None:
                queue_addon(root)
            # A file outside any addon is silently ignored (e.g. repo-level files).
        elif args.all or not (target / "__manifest__.py").exists():
            dir_results.extend(scan_directory(target, run_bandit_scan=run_bandit, odoo_version=args.odoo_version))
        else:
            queue_addon(target)

    results = dir_results + [
        scan_addon(a, run_bandit_scan=run_bandit, odoo_version=args.odoo_version)
        for a in addon_targets
    ]

    if not results:
        if missing:
            return 2
        print("⚠️  No Odoo addons found in the given path(s)", file=sys.stderr)
        return 0

    # Output
    if args.format == "json":
        output_text = to_json(results)
        if args.output:
            Path(args.output).write_text(output_text, encoding="utf-8")
            print(f"✅  Report written to {args.output}")
        else:
            print(output_text)
    else:
        if args.output:
            # Write console output to file (no color)
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                print_multi_results(results, use_color=False, verbose=args.verbose)
            Path(args.output).write_text(buf.getvalue(), encoding="utf-8")
            print(f"✅  Report written to {args.output}")
        else:
            print_multi_results(results, use_color=use_color, verbose=args.verbose)

    # Exit code for CI
    if args.fail_on:
        threshold = SEVERITY_ORDER[Severity(args.fail_on)]
        for r in results:
            for f in r.findings:
                if SEVERITY_ORDER[f.severity] <= threshold:
                    return 1

    return 0


def cli_entry():
    sys.exit(main())


if __name__ == "__main__":
    cli_entry()
