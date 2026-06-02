"""
Project configuration for odoo-review.

A `.odoo-review` (INI) file or a `[tool.odoo-review]` table in `pyproject.toml`,
discovered by walking up from the addon directory, can tune a scan:

    [odoo-review]
    target-version = 17
    disable  = OR025, OR044
    select   = OR001, OR002, OR026        ; if set, ONLY these rules run
    severity = OR021:INFO, OR010:CRITICAL  ; per-rule severity overrides
    exclude  = legacy/*, scratch/*         ; glob paths skipped during the scan

The equivalent in pyproject.toml (needs a TOML reader: stdlib tomllib on
Python 3.11+, or the `tomli` backport — pyproject config is simply ignored if
neither is available):

    [tool.odoo-review]
    target-version = 17
    disable  = ["OR025", "OR044"]
    select   = ["OR001"]
    severity = { OR021 = "INFO" }
    exclude  = ["legacy/*"]
"""
from __future__ import annotations
import configparser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from odoo_review.models import Severity
from odoo_review.suppressions import _rule_ids

_CONFIG_FILENAME = ".odoo-review"
_PYPROJECT = "pyproject.toml"
_TOOL_SECTION = "odoo-review"


@dataclass
class ScanConfig:
    """Resolved configuration for one scan. All fields are optional; an empty
    ScanConfig (the default) means "no config found, use built-in behaviour"."""
    disable: Set[str] = field(default_factory=set)
    select: Optional[Set[str]] = None          # None => all rules enabled
    severity: Dict[str, Severity] = field(default_factory=dict)
    exclude: List[str] = field(default_factory=list)
    target_version: Optional[int] = None
    source: Optional[str] = None               # path of the file it came from


def _coerce_version(raw) -> Optional[int]:
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return None


def _coerce_severity_map(pairs) -> Dict[str, Severity]:
    """Accept ``{"OR021": "INFO"}`` or an iterable of ``"OR021:INFO"`` strings."""
    out: Dict[str, Severity] = {}
    items = pairs.items() if isinstance(pairs, dict) else (
        (p.split(":", 1) if ":" in str(p) else (p, "")) for p in pairs
    )
    for rule, sev in items:
        rule = str(rule).strip().upper()
        try:
            out[rule] = Severity(str(sev).strip().upper())
        except ValueError:
            continue  # unknown severity name -> ignore that override
    return out


def _as_list(raw) -> List[str]:
    if isinstance(raw, (list, tuple)):
        return [str(x).strip() for x in raw if str(x).strip()]
    return [x.strip() for x in str(raw).replace("\n", ",").split(",") if x.strip()]


def _parse_ini(path: Path) -> Optional[ScanConfig]:
    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except (configparser.Error, OSError):
        return None
    if not parser.has_section(_TOOL_SECTION):
        return None
    sec = parser[_TOOL_SECTION]
    cfg = ScanConfig(source=str(path))
    cfg.disable = _rule_ids(sec.get("disable", ""))
    if "select" in sec:
        cfg.select = _rule_ids(sec.get("select", ""))
    cfg.severity = _coerce_severity_map(_as_list(sec.get("severity", "")))
    cfg.exclude = _as_list(sec.get("exclude", ""))
    cfg.target_version = _coerce_version(sec.get("target-version")) if "target-version" in sec else None
    return cfg


def _load_toml(path: Path) -> Optional[dict]:
    try:
        import tomllib as toml  # Python 3.11+
    except ModuleNotFoundError:
        try:
            import tomli as toml  # backport for 3.8-3.10
        except ModuleNotFoundError:
            return None  # no TOML reader available -> skip pyproject config
    try:
        with open(path, "rb") as fh:
            return toml.load(fh)
    except (OSError, ValueError):
        return None


def _parse_pyproject(path: Path) -> Optional[ScanConfig]:
    data = _load_toml(path)
    if not data:
        return None
    tool = (data.get("tool") or {}).get(_TOOL_SECTION)
    if not isinstance(tool, dict):
        return None
    cfg = ScanConfig(source=str(path))
    cfg.disable = _rule_ids(",".join(_as_list(tool.get("disable", []))))
    if "select" in tool:
        cfg.select = _rule_ids(",".join(_as_list(tool.get("select", []))))
    cfg.severity = _coerce_severity_map(tool.get("severity", {}))
    cfg.exclude = _as_list(tool.get("exclude", []))
    cfg.target_version = _coerce_version(tool.get("target-version"))
    return cfg


def load_config(start: Path) -> ScanConfig:
    """Discover and parse the nearest config by walking up from *start*.

    `.odoo-review` takes precedence over `pyproject.toml` within the same
    directory. Returns an empty ScanConfig when nothing is found."""
    base = start if start.is_dir() else start.parent
    for directory in (base, *base.parents):
        ini = directory / _CONFIG_FILENAME
        if ini.is_file():
            cfg = _parse_ini(ini)
            if cfg is not None:
                return cfg
        pyproject = directory / _PYPROJECT
        if pyproject.is_file():
            cfg = _parse_pyproject(pyproject)
            if cfg is not None:
                return cfg
    return ScanConfig()
