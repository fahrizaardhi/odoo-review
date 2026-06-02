"""
OR070 – OR079: XML / view-layer checks.

Half of a typical Odoo addon is XML (views, QWeb templates, data, actions), yet
the AST checkers never see it. This addon-level pass parses every ``*.xml`` file
and flags the issues most often caught in OCA review:

  OR070 – ``attrs="..."``   deprecated in Odoo 17, removed in 18 (version-aware)
  OR071 – ``states="..."``  deprecated in Odoo 17, removed in 18 (version-aware)
  OR072 – ``<tree>``        renamed to ``<list>`` in Odoo 17 (version-aware)
  OR073 – ``t-raw``         QWeb directive — XSS risk; removed in 17 (use t-out)
  OR074 – duplicate XML id within the same addon (second hit breaks the load)
  OR075 – ``ir.actions.act_window`` record with no ``res_model``
  OR079 – malformed XML (the file cannot be parsed)

Parsing prefers ``lxml`` (it exposes ``.sourceline`` for precise line numbers
and is already standard in any Odoo environment); when it is unavailable we fall
back to the stdlib ``xml.etree.ElementTree`` and report ``line = 0``. Either way
the findings still fire — only the line precision degrades.

This is an addon-level check (OR074 needs to see every file at once), so it is a
plain function rather than a per-file :class:`BaseChecker`, mirroring
:func:`odoo_review.checkers.access.check_access_rules`.
"""
from __future__ import annotations
import fnmatch
from pathlib import Path
from typing import Generator, List, Optional, Tuple

from odoo_review.models import Category, Finding, ScanContext, Severity

# Try lxml first (precise line numbers); degrade to the stdlib parser otherwise.
try:  # pragma: no cover - import path depends on the environment
    from lxml import etree as _LXML
    _HAVE_LXML = True
except ImportError:  # pragma: no cover
    import xml.etree.ElementTree as _ET
    _HAVE_LXML = False

_SKIP_DIRS = {"__pycache__", ".git", "node_modules", "static", "migrations", "tests"}

# Definition elements that carry an ``id`` and must be unique within a module.
_ID_TAGS = {"record", "template", "menuitem", "act_window", "report"}

# Version milestones for the view-layer deprecations.
_ATTRS_REMOVED_IN = 18   # attrs/states removed
_ATTRS_DEPRECATED_IN = 17
_LIST_RENAMED_IN = 17    # <tree> -> <list>
_TRAW_REMOVED_IN = 17    # t-raw -> t-out


# ── parsing helpers ────────────────────────────────────────────────────────────

def iter_xml_files(addon_path: Path, exclude: Optional[List[str]] = None) -> List[Path]:
    """Every ``*.xml`` under the addon, skipping vendored/irrelevant dirs and
    any config ``exclude`` globs (matched on the addon-relative posix path)."""
    exclude = exclude or []
    out: List[Path] = []
    for xml_file in sorted(addon_path.rglob("*.xml")):
        rel = xml_file.relative_to(addon_path)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        if any(fnmatch.fnmatch(rel.as_posix(), pat) for pat in exclude):
            continue
        out.append(xml_file)
    return out


def _localname(tag) -> str:
    """Tag name without its ``{namespace}`` prefix; '' for comments/PIs whose
    tag is not a string (lxml represents those with a callable tag)."""
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _line_of(el) -> int:
    """Source line of an element (lxml exposes ``sourceline``; 0 otherwise)."""
    return getattr(el, "sourceline", None) or 0


def _parse(path: Path):
    """Return the root element, or raise to signal a malformed file.

    We parse addon XML that may be hostile, so both backends are hardened
    against the classic XML attacks: external-entity resolution (XXE), network
    fetches, and DTD loading are all disabled.
    """
    if _HAVE_LXML:
        parser = _LXML.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
        return _LXML.parse(str(path), parser).getroot()
    # Stdlib ElementTree never resolves external entities or hits the network,
    # so it is not exposed to XXE; we only read local, developer-owned files.
    return _ET.parse(str(path)).getroot()  # nosec B314 - hardened: no external entities


def _parse_error_types() -> tuple:
    if _HAVE_LXML:  # pragma: no cover - depends on environment
        return (_LXML.XMLSyntaxError, OSError)
    return (_ET.ParseError, OSError)  # pragma: no cover


# ── severity scaling ─────────────────────────────────────────────────────────

def _attrs_severity(version: Optional[int]) -> Optional[Severity]:
    """attrs/states: HIGH once removed (>=18), INFO while merely deprecated (17).

    Returns None — i.e. *do not flag* — for older or unknown versions, where
    ``attrs`` is still the correct idiom and flagging it would only be noise.
    """
    if version is None:
        return None
    if version >= _ATTRS_REMOVED_IN:
        return Severity.HIGH
    if version >= _ATTRS_DEPRECATED_IN:
        return Severity.INFO
    return None


# ── the check ──────────────────────────────────────────────────────────────────

def check_xml(
    xml_files: List[Path],
    context: Optional[ScanContext] = None,
) -> Generator[Finding, None, None]:
    """Yield OR070–OR079 findings for the given list of XML files (already
    filtered by :func:`iter_xml_files`)."""
    version = context.odoo_version if context else None
    parse_errors = _parse_error_types()

    # (id_value -> first (filepath, line)) so we can report later collisions.
    seen_ids: dict[str, Tuple[str, int]] = {}

    for path in xml_files:
        fp = str(path)
        try:
            root = _parse(path)
        except parse_errors as exc:
            yield Finding(
                rule_id="OR079",
                severity=Severity.HIGH,
                category=Category.VIEW,
                message=f"[OR079] Malformed XML — Odoo will refuse to load it: {exc}",
                filepath=fp, line=getattr(exc, "lineno", 0) or 0,
                suggestion="Fix the XML so it is well-formed (matching tags, quoted attributes).",
            )
            continue

        for el in root.iter():
            tag = _localname(el.tag)
            if not tag:
                continue
            line = _line_of(el)

            # OR070 / OR071: attrs= / states= attributes
            for attr_name, rule in (("attrs", "OR070"), ("states", "OR071")):
                if attr_name in el.attrib:
                    sev = _attrs_severity(version)
                    if sev is not None:
                        verb = "removed in Odoo 18" if version and version >= _ATTRS_REMOVED_IN else "deprecated in Odoo 17"
                        yield Finding(
                            rule_id=rule,
                            severity=sev,
                            category=Category.VIEW,
                            message=(
                                f"[{rule}] `{attr_name}=` on <{tag}> was {verb} — move the "
                                f"condition into the field/element attributes directly."
                            ),
                            filepath=fp, line=line,
                            suggestion=(
                                "Replace e.g. attrs=\"{'invisible': [('state','=','done')]}\" "
                                "with invisible=\"state == 'done'\" (Odoo 17+ Python-domain syntax)."
                            ),
                        )

            # OR073: t-raw QWeb directive (any element may carry it)
            traw = "t-raw" in el.attrib or any(_localname(k) == "t-raw" for k in el.attrib)
            if traw:
                sev = Severity.HIGH if (version and version >= _TRAW_REMOVED_IN) else Severity.MEDIUM
                removed = " and was removed in Odoo 17" if (version and version >= _TRAW_REMOVED_IN) else ""
                yield Finding(
                    rule_id="OR073",
                    severity=sev,
                    category=Category.SECURITY,
                    message=(
                        f"[OR073] `t-raw` renders unescaped HTML — an XSS risk{removed}."
                    ),
                    filepath=fp, line=line,
                    suggestion="Use `t-out` (Odoo 17+) or `t-esc` to escape output; reserve raw HTML for trusted, sanitized values.",
                )

            # OR072: <tree> renamed to <list> in v17
            if tag == "tree" and version is not None and version >= _LIST_RENAMED_IN:
                yield Finding(
                    rule_id="OR072",
                    severity=Severity.INFO,
                    category=Category.VIEW,
                    message="[OR072] `<tree>` was renamed to `<list>` in Odoo 17 — update the view tag.",
                    filepath=fp, line=line,
                    suggestion="Rename <tree>…</tree> to <list>…</list> (and view_mode 'tree' to 'list').",
                )

            # OR074: duplicate XML id within the addon
            if tag in _ID_TAGS:
                rec_id = el.get("id")
                if rec_id:
                    if rec_id in seen_ids:
                        first_fp, first_line = seen_ids[rec_id]
                        yield Finding(
                            rule_id="OR074",
                            severity=Severity.HIGH,
                            category=Category.VIEW,
                            message=(
                                f"[OR074] Duplicate XML id '{rec_id}' — already defined at "
                                f"{first_fp}:{first_line}. The second definition overwrites the first."
                            ),
                            filepath=fp, line=line,
                            suggestion="Give each record a unique id within the module.",
                        )
                    else:
                        seen_ids[rec_id] = (fp, line)

            # OR075: act_window record with no res_model
            if tag == "record" and el.get("model") == "ir.actions.act_window":
                has_res_model = any(
                    _localname(child.tag) == "field" and child.get("name") == "res_model"
                    for child in el
                )
                if not has_res_model:
                    yield Finding(
                        rule_id="OR075",
                        severity=Severity.HIGH,
                        category=Category.VIEW,
                        message=(
                            "[OR075] ir.actions.act_window record has no <field name=\"res_model\"> "
                            "— the action cannot open any view."
                        ),
                        filepath=fp, line=line,
                        suggestion="Add <field name=\"res_model\">your.model</field> to the action record.",
                    )
            # OR075: <act_window .../> shorthand uses a res_model attribute
            if tag == "act_window" and not el.get("res_model"):
                yield Finding(
                    rule_id="OR075",
                    severity=Severity.HIGH,
                    category=Category.VIEW,
                    message="[OR075] <act_window> shorthand has no res_model attribute — the action is broken.",
                    filepath=fp, line=line,
                    suggestion="Add res_model=\"your.model\" to the <act_window/> element.",
                )
