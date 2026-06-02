"""
Scanner engine: walks an addon directory, applies all checkers,
runs Bandit, and returns a unified ScanResult.
"""
from __future__ import annotations
import ast
from pathlib import Path
from typing import Optional

from odoo_review.checkers import BaseChecker
from odoo_review.models import Category, Finding, ScanContext, ScanResult, Severity
from odoo_review.bandit_runner import run_bandit
from odoo_review.checkers.sql_injection import SQLInjectionChecker
from odoo_review.checkers.n_plus_one import NPlusOneChecker
from odoo_review.checkers.orm_best_practice import ORMBestPracticeChecker
from odoo_review.checkers.manifest import check_manifest, detect_odoo_version
from odoo_review.suppressions import (
    is_suppressed,
    load_config_disabled,
    parse_inline_suppressions,
)

# Entry-point group third-party packages register custom checkers under.
_PLUGIN_GROUP = "odoo_review.checkers"

_BUILTIN_CHECKERS: list[BaseChecker] = [
    SQLInjectionChecker(),
    NPlusOneChecker(),
    ORMBestPracticeChecker(),
]


def _load_plugin_checkers() -> list[BaseChecker]:
    """Discover third-party checkers registered via the
    ``odoo_review.checkers`` entry-point group. A broken plugin is skipped
    rather than allowed to crash the whole scan."""
    checkers: list[BaseChecker] = []
    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover - importlib.metadata is stdlib >=3.8
        return checkers

    try:
        eps = entry_points(group=_PLUGIN_GROUP)
    except TypeError:  # pragma: no cover - very old selectable API
        eps = entry_points().get(_PLUGIN_GROUP, [])  # type: ignore[attr-defined]

    for ep in eps:
        try:
            obj = ep.load()
            checker = obj() if isinstance(obj, type) else obj
            if isinstance(checker, BaseChecker):
                checkers.append(checker)
        except Exception:
            # Ignore plugins that fail to import or instantiate.
            continue
    return checkers


def get_python_checkers() -> list[BaseChecker]:
    """Built-in checkers plus any discovered plugins (computed fresh each call
    so tests / long-running processes can pick up newly installed plugins)."""
    return _BUILTIN_CHECKERS + _load_plugin_checkers()


# Files/dirs to skip during the AST scan. `tests` is skipped because test
# code deliberately contains anti-patterns and would only add noise.
_SKIP_DIRS  = {"__pycache__", ".git", "node_modules", "static", "migrations", "tests"}
_SKIP_FILES = {"__init__.py"}


def scan_addon(
    addon_path: Path,
    run_bandit_scan: bool = True,
    skip_dirs: Optional[set[str]] = None,
    odoo_version: Optional[int] = None,
    disabled_rules: Optional[set[str]] = None,
) -> ScanResult:
    """
    Scan a single Odoo addon directory.

    Parameters
    ----------
    addon_path : Path
        Root directory of the addon (contains __manifest__.py).
    run_bandit_scan : bool
        Whether to also run Bandit on the addon.
    skip_dirs : set[str] | None
        Additional directory names to skip.
    odoo_version : int | None
        Target Odoo major series. When None, it is auto-detected from the
        addon's __manifest__.py version key; version-aware rules fall back to
        conservative behaviour if neither source yields a value.
    disabled_rules : set[str] | None
        Rule ids to drop globally. Merged with any found in a `.odoo-review`
        config file discovered by walking up from the addon directory.
    """
    result = ScanResult(addon_path=str(addon_path))
    effective_skip = _SKIP_DIRS | (skip_dirs or set())
    checkers = get_python_checkers()

    manifest_file = addon_path / "__manifest__.py"

    # Resolve the target version: explicit flag wins, else auto-detect.
    if odoo_version is not None:
        result.odoo_version = odoo_version
        result.odoo_version_source = "flag"
    elif manifest_file.exists():
        detected = detect_odoo_version(manifest_file)
        if detected is not None:
            result.odoo_version = detected
            result.odoo_version_source = "manifest"
    context = ScanContext(odoo_version=result.odoo_version)

    # 1. Manifest checks. The series-mismatch part of OR042 is only meaningful
    # against an explicit flag (auto-detection reads the same version string,
    # so it would always match) — pass the flag value, not the resolved one.
    if manifest_file.exists():
        for finding in check_manifest(manifest_file, target_version=odoo_version):
            result.add(finding)
    else:
        result.add(Finding(
            rule_id="OR047",
            severity=Severity.HIGH,
            category=Category.DEPENDENCY,
            message="[OR047] No __manifest__.py found — is this a valid Odoo addon?",
            filepath=str(addon_path),
            line=0,
        ))

    # 2. Python file AST checks
    for py_file in sorted(addon_path.rglob("*.py")):
        # Skip unwanted dirs — compare only the path *inside* the addon so a
        # skip-named directory in the absolute prefix doesn't hide everything.
        rel_parts = py_file.relative_to(addon_path).parts
        if any(part in effective_skip for part in rel_parts):
            continue
        if py_file.name in _SKIP_FILES:
            continue

        result.scanned_files += 1

        try:
            source = py_file.read_text(encoding="utf-8")
        except OSError as e:
            result.errors.append(f"Cannot read {py_file}: {e}")
            continue

        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError as e:
            result.errors.append(f"SyntaxError in {py_file}: {e}")
            continue

        for checker in checkers:
            for finding in checker.check_file(py_file, tree, source, context):
                result.add(finding)

    # 3. Bandit scan (whole addon at once), excluding the same dirs.
    if run_bandit_scan:
        for finding in run_bandit(addon_path, exclude_dirs=effective_skip):
            result.add(finding)

    # 4. Suppression pass: drop findings disabled via `.odoo-review` config or
    # an inline `# noqa` on the offending line. Applies to all findings above.
    disabled = set(disabled_rules or set()) | load_config_disabled(addon_path)
    _apply_suppressions(result, disabled)

    return result


# Cache of per-file inline `# noqa` maps so each source file is tokenized once.
def _apply_suppressions(result: ScanResult, disabled: set[str]) -> None:
    inline_cache: dict[str, dict] = {}

    def inline_for(filepath: str) -> dict:
        if filepath not in inline_cache:
            try:
                src = Path(filepath).read_text(encoding="utf-8")
                inline_cache[filepath] = parse_inline_suppressions(src)
            except OSError:
                inline_cache[filepath] = {}
        return inline_cache[filepath]

    kept: list[Finding] = []
    for f in result.findings:
        if is_suppressed(f.rule_id, f.line, inline_for(f.filepath), disabled):
            result.suppressed += 1
            continue
        kept.append(f)
    result.findings = kept


def scan_directory(
    root: Path,
    run_bandit_scan: bool = True,
    odoo_version: Optional[int] = None,
    disabled_rules: Optional[set[str]] = None,
) -> list[ScanResult]:
    """
    Auto-discover and scan all addons under *root*.
    An addon is identified by having a __manifest__.py file.

    `odoo_version` forces a target series for every addon; when None each
    addon's version is detected from its own manifest independently.
    `disabled_rules` is forwarded to every addon scan.
    """
    results = []
    for manifest in sorted(root.rglob("__manifest__.py")):
        addon_dir = manifest.parent
        results.append(scan_addon(
            addon_dir,
            run_bandit_scan=run_bandit_scan,
            odoo_version=odoo_version,
            disabled_rules=disabled_rules,
        ))
    return results
