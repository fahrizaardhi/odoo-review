"""
Inline finding suppression via trailing `# noqa` comments:

    something()            # noqa             (all rules on this line)
    cr.execute(q)          # noqa: OR001      (only OR001)
    cr.execute(q)          # noqa: OR001,B608 (several rules)

Applied as a post-filter over collected findings, so it covers Bandit results
as well as the AST checkers. Project-wide rule disabling lives in
`odoo_review.config` (the `.odoo-review` / pyproject config file).
"""
from __future__ import annotations
import io
import re
import tokenize
from typing import Dict, Optional, Set

# A trailing `# noqa` with an optional `: id, id` list. We only read the id
# list loosely here and validate each token below, so trailing prose like
# `# noqa: OR001 (intentional)` still resolves to just OR001.
_NOQA_RE = re.compile(r"#\s*noqa\b(?:\s*:\s*(?P<ids>[A-Za-z0-9_,\s]+))?", re.IGNORECASE)
_RULE_TOKEN = re.compile(r"^[A-Z]+\d+$")

# Sentinel: this line suppresses *all* rules (a bare `# noqa`).
ALL = None


def _rule_ids(raw: str) -> Set[str]:
    """Extract valid rule ids (e.g. OR001, B608) from a free-form id list."""
    out: Set[str] = set()
    for tok in re.split(r"[,\s]+", raw.strip()):
        tok = tok.strip().upper()
        if _RULE_TOKEN.match(tok):
            out.add(tok)
    return out


def parse_inline_suppressions(source: str) -> Dict[int, Optional[Set[str]]]:
    """Map line number -> set of suppressed rule ids, or ``ALL`` (None) for a
    bare ``# noqa``. Only real COMMENT tokens are inspected, so a ``# noqa``
    appearing inside a string literal does not accidentally suppress anything.
    """
    result: Dict[int, Optional[Set[str]]] = {}
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for tok in tokens:
            if tok.type != tokenize.COMMENT:
                continue
            m = _NOQA_RE.search(tok.string)
            if not m:
                continue
            lineno = tok.start[0]
            if lineno in result and result[lineno] is ALL:
                continue  # already suppressing everything on this line
            ids_raw = m.group("ids")
            ids = _rule_ids(ids_raw) if ids_raw else set()
            if not ids:
                result[lineno] = ALL  # bare `# noqa` (or unparsable id list)
            else:
                existing = result.get(lineno) or set()
                result[lineno] = existing | ids
    except (tokenize.TokenError, IndentationError):
        # Best effort: a file odd enough to break the tokenizer simply gets no
        # inline suppressions rather than failing the whole scan.
        pass
    return result


def is_suppressed(
    rule_id: str,
    line: int,
    inline: Dict[int, Optional[Set[str]]],
    disabled: Set[str],
) -> bool:
    """True if a finding should be dropped by config or an inline comment."""
    if rule_id in disabled:
        return True
    if line in inline:
        rules = inline[line]
        if rules is ALL or rule_id in rules:
            return True
    return False
