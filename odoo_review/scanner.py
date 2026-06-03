"""
Scanner engine: walks an addon directory, applies all checkers,
runs Bandit, and returns a unified ScanResult.
"""
from __future__ import annotations
import ast
import fnmatch
from pathlib import Path
from typing import Optional

from odoo_review.checkers import BaseChecker
from odoo_review.config import ScanConfig, load_config
from odoo_review.models import Category, Finding, ScanContext, ScanResult, Severity
from odoo_review.bandit_runner import run_bandit
from odoo_review.checkers.sql_injection import SQLInjectionChecker
from odoo_review.checkers.n_plus_one import NPlusOneChecker
from odoo_review.checkers.orm_best_practice import ORMBestPracticeChecker
from odoo_review.checkers.deprecation import DeprecationChecker
from odoo_review.checkers.manifest import check_manifest, detect_odoo_version
from odoo_review.checkers.access import check_access_rules
from odoo_review.checkers.xml_view import check_xml, iter_xml_files
from odoo_review.suppressions import is_suppressed, parse_inline_suppressions
from odoo_review.versions import validate_target_version

# Entry-point group third-party packages register custom checkers under.
_PLUGIN_GROUP = "odoo_review.checkers"

_BUILTIN_CHECKERS: list[BaseChecker] = [
    SQLInjectionChecker(),
    NPlusOneChecker(),
    ORMBestPracticeChecker(),
    DeprecationChecker(),
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
        Rule ids to drop globally. Merged with any disabled in the project's
        `.odoo-review` / pyproject config discovered from the addon directory.
    """
    result = ScanResult(addon_path=str(addon_path))
    effective_skip = _SKIP_DIRS | (skip_dirs or set())
    checkers = get_python_checkers()
    cfg = load_config(addon_path)

    manifest_file = addon_path / "__manifest__.py"

    # Resolve the target version: explicit flag > config > manifest auto-detect.
    # An explicit version (flag or config) is validated and raises on an
    # unsupported value; an auto-detected manifest version stays lenient.
    explicit_version = odoo_version if odoo_version is not None else cfg.target_version
    if odoo_version is not None:
        validate_target_version(odoo_version, source="--odoo-version")
        result.odoo_version = odoo_version
        result.odoo_version_source = "flag"
    elif cfg.target_version is not None:
        validate_target_version(cfg.target_version, source=cfg.source or "config target-version")
        result.odoo_version = cfg.target_version
        result.odoo_version_source = "config"
    elif manifest_file.exists():
        detected = detect_odoo_version(manifest_file)
        if detected is not None:
            result.odoo_version = detected
            result.odoo_version_source = "manifest"
    context = ScanContext(odoo_version=result.odoo_version)

    # 1. Manifest checks. The series-mismatch part of OR042 is only meaningful
    # against an explicit version (flag or config) — auto-detection reads the
    # same version string, so it would always match.
    if manifest_file.exists():
        for finding in check_manifest(manifest_file, target_version=explicit_version):
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
        rel = py_file.relative_to(addon_path)
        if any(part in effective_skip for part in rel.parts):
            continue
        if py_file.name in _SKIP_FILES:
            continue
        # Config-driven path excludes (glob, relative to the addon root).
        if any(fnmatch.fnmatch(rel.as_posix(), pat) for pat in cfg.exclude):
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

    # 3. Addon-level security check: models without an ir.model.access rule.
    for finding in check_access_rules(addon_path):
        result.add(finding)

    # 3b. XML / view-layer checks (deprecated attrs, t-raw XSS, duplicate ids,
    # broken actions, malformed files). Honours the same exclude globs.
    xml_files = iter_xml_files(addon_path, cfg.exclude)
    result.scanned_files += len(xml_files)
    for finding in check_xml(xml_files, context):
        result.add(finding)

    # 4. Bandit scan (whole addon at once), excluding the same dirs.
    if run_bandit_scan:
        for finding in run_bandit(addon_path, exclude_dirs=effective_skip):
            result.add(finding)

    # 5. Finalize: apply select/disable filtering, inline `# noqa`, and per-rule
    # severity overrides. Applies uniformly to AST, ACL, manifest and Bandit.
    disabled = set(disabled_rules or set()) | cfg.disable
    _finalize(result, disabled, cfg.select, cfg.severity)

    return result


def _finalize(result, disabled, select, severity):
    """Drop disabled/unselected/inline-suppressed findings, then remap severity.

    `select` (when not None) is an allow-list: only those rule ids survive.
    Per-file inline `# noqa` maps are cached so each source file is read once.
    """
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
        if select is not None and f.rule_id not in select:
            result.suppressed += 1
            continue
        if is_suppressed(f.rule_id, f.line, inline_for(f.filepath), disabled):
            result.suppressed += 1
            continue
        if f.rule_id in severity:
            f.severity = severity[f.rule_id]
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
