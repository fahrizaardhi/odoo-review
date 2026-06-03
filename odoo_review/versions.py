"""
Single source of truth for Odoo version knowledge.

odoo-review's version-aware rules need two things: the set of Odoo majors the
tool actually understands, and the milestone version at which each
feature/API was deprecated or removed. Both live here so that supporting a new
Odoo release (19, 20, …) is a one-line edit — bump ``LATEST_SUPPORTED`` and add
the relevant milestone constants — instead of a hunt through every checker.

Two scaling helpers translate "the addon targets version X" + "the feature
changed at milestone Y" into a Severity:

* :func:`severity_for_legacy` — for constructs that were already legacy even on
  older versions (old API, ``self.pool``). Always at least advisory.
* :func:`severity_for_deprecation` — for constructs that are the *correct*
  idiom until they are deprecated (``attrs=``, ``name_get``). Silent below the
  deprecation milestone so we never nag about code that is still right.
"""
from __future__ import annotations
from typing import Optional

from odoo_review.models import Severity

# ── supported range ──────────────────────────────────────────────────────────
# Odoo majors odoo-review knows how to reason about. Adding a new release is a
# one-line change: bump LATEST_SUPPORTED (and add its milestones below).
MIN_SUPPORTED = 12
LATEST_SUPPORTED = 18
SUPPORTED_VERSIONS = range(MIN_SUPPORTED, LATEST_SUPPORTED + 1)  # 12..18 inclusive


# ── feature / API milestones (the Odoo major where the change landed) ─────────
# Old-API constructs (legacy even on old versions):
LEGACY_API_RENAMED_IN = 10   # `openerp` namespace renamed to `odoo`
SELF_POOL_REMOVED_IN = 10    # self.pool / self.pool.get() -> self.env
API_MULTI_REMOVED_IN = 13    # @api.multi / @api.one decorators

# Correct-until-deprecated constructs:
NAME_GET_DEPRECATED_IN = 17  # name_get() -> _compute_display_name (no removal date asserted)
ATTRS_DEPRECATED_IN = 17     # attrs= / states= view attributes
ATTRS_REMOVED_IN = 18
LIST_RENAMED_IN = 17         # <tree> -> <list>
TRAW_REMOVED_IN = 17         # t-raw -> t-out


class UnsupportedVersionError(ValueError):
    """Raised when an *explicit* target version (``--odoo-version`` flag or a
    ``target-version`` config key) names an Odoo major odoo-review does not
    support. Auto-detected manifest versions never raise — they degrade to the
    conservative "unknown version" behaviour instead."""


def is_supported(version: Optional[int]) -> bool:
    return version is not None and version in SUPPORTED_VERSIONS


def validate_target_version(version: Optional[int], source: str = "--odoo-version") -> None:
    """Raise :class:`UnsupportedVersionError` if *version* is set but outside the
    supported range. ``None`` (no explicit version) always passes.

    *source* is woven into the message so the user knows whether the offending
    value came from the flag or from their config file.
    """
    if version is None or is_supported(version):
        return
    supported = f"{MIN_SUPPORTED}–{LATEST_SUPPORTED}"
    if version > LATEST_SUPPORTED:
        hint = (
            f"If Odoo {version} is released, upgrade odoo-review (or add {version} "
            f"to SUPPORTED_VERSIONS in odoo_review/versions.py)."
        )
    else:
        hint = f"odoo-review only reasons about Odoo {supported}."
    raise UnsupportedVersionError(
        f"Odoo version {version} (from {source}) is not supported. "
        f"Supported: {supported} (latest {LATEST_SUPPORTED}). {hint}"
    )


def severity_for_legacy(version: Optional[int], removed_in: int) -> Severity:
    """Severity for an old-API construct that is legacy even on older versions:
    HIGH once *removed_in* is reached, INFO while still tolerated, and MEDIUM
    when the target version is unknown (flag it conservatively)."""
    if version is None:
        return Severity.MEDIUM
    return Severity.HIGH if version >= removed_in else Severity.INFO


def severity_for_deprecation(
    version: Optional[int], deprecated_in: int, removed_in: Optional[int] = None
) -> Optional[Severity]:
    """Severity for a construct that is the *correct* idiom until *deprecated_in*.

    Returns ``None`` — meaning *do not flag* — for versions before the
    deprecation and for an unknown version, so we never warn about code that is
    still idiomatic. INFO once deprecated, HIGH once *removed_in* is reached
    (omit *removed_in* when the removal version is not known for certain)."""
    if version is None:
        return None
    if removed_in is not None and version >= removed_in:
        return Severity.HIGH
    if version >= deprecated_in:
        return Severity.INFO
    return None
