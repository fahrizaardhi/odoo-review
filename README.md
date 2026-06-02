# odoo-review

Static analysis tool for Odoo addons. Combines **Bandit** security scanning with **Odoo-specific AST checks** for SQL injection, N+1 queries, ORM anti-patterns, manifest dependency issues, and more.

## Installation

```bash
pip install odoo-review
# or from source:
pip install -e .
```

## Usage

```bash
# Scan a single addon
odoo-review ./my_addon

# Scan all addons in a directory
odoo-review ./addons --all

# Verbose output (show code snippets + suggestions)
odoo-review ./my_addon --verbose

# JSON output (for CI/CD)
odoo-review ./my_addon --format json -o report.json

# Skip Bandit (faster, Odoo checks only)
odoo-review ./my_addon --no-bandit

# Force a target Odoo series (otherwise auto-detected from __manifest__.py)
odoo-review ./my_addon --odoo-version 17

# Fail CI if any HIGH or CRITICAL finding exists
odoo-review ./my_addon --fail-on HIGH
```

### Odoo version awareness

Some rules depend on the target Odoo series. The version is resolved as:

1. `--odoo-version N` if passed (explicit override), else
2. auto-detected from the addon's `__manifest__.py` `version` key, else
3. unknown — version-aware rules fall back to conservative defaults.

When the version is known it sharpens results, e.g.:

- **OR020** — `sudo(True)` is reported `HIGH` ("removed in Odoo 13") on v13+, but
  downgraded to `MEDIUM` (legacy-but-valid) on v12 and earlier.
- **OR042** — with an explicit `--odoo-version`, a manifest whose version prefix
  does not match the target series is flagged as a mismatch.

## Suppressing findings

There are two ways to silence findings you have reviewed and accepted. Both are
applied as a final filter, so they cover Bandit results (`B###`) as well as the
built-in `OR###` rules.

### Inline — `# noqa`

A trailing comment on the offending line:

```python
self.env.cr.execute(query)          # noqa: OR001      # one rule
self.env.cr.execute(query)          # noqa: OR001,B608 # several rules
self.sudo()                         # noqa             # everything on this line
```

`# noqa` must be a real comment — a `"# noqa"` inside a string does not count.
Trailing prose is fine: `# noqa: OR026 — intentional, validated input`.

### Project-wide — `.odoo-review`

Drop a `.odoo-review` INI file at your repo root (discovered by walking up from
each addon, like Bandit's `.bandit`):

```ini
[odoo-review]
disable = OR025, OR044
```

A `Muted: N finding(s) suppressed …` line in the report (and a `suppressed`
field in JSON output) shows how many findings were filtered.

## GitHub Actions Integration

```yaml
- name: Run odoo-review
  run: |
    pip install odoo-review
    odoo-review ./addons --all --format json -o review.json --fail-on HIGH

- name: Upload review report
  uses: actions/upload-artifact@v4
  with:
    name: odoo-review-report
    path: review.json
```

## Rules

### Security
| Rule  | Severity | Description |
|-------|----------|-------------|
| OR001 | CRITICAL | f-string used directly in `cr.execute()` — SQL injection |
| OR002 | HIGH     | `%`-format, `.format()`, or string concat in `cr.execute()` — SQL injection |
| OR020 | HIGH     | `sudo(True)` forces superuser context (legacy API) |
| OR021 | LOW      | bare `sudo()` escalates privileges — confirm it is justified |
| OR026 | CRITICAL | `eval()` / `exec()` / `compile()` builtin usage — use `safe_eval` instead |

### Performance (N+1)
| Rule  | Severity | Description |
|-------|----------|-------------|
| OR010 | HIGH     | `search()` / `search_count()` / `browse()` / `read()` called inside a loop |
| OR011 | MEDIUM   | `write()` / `create()` / `unlink()` / `copy()` inside a loop (should batch) |
| OR012 | MEDIUM   | `self.env['Model']` registry lookup inside a loop |

### ORM Best Practices
| Rule  | Severity | Description |
|-------|----------|-------------|
| OR022 | MEDIUM   | Hardcoded integer ID passed to `browse()` — use `env.ref()` |
| OR023 | LOW      | Model class missing `_description` |
| OR024 | INFO     | `_name` + `_inherit` without `_description` |
| OR025 | LOW      | `_compute_*` method missing `@api.depends()` |

### Manifest & Dependencies
| Rule  | Severity | Description |
|-------|----------|-------------|
| OR040 | MEDIUM   | Missing required manifest keys (`name`, `version`, `depends`) |
| OR041 | INFO     | `'base'` in `depends` — implicit, can be removed |
| OR042 | LOW      | Version not following `XX.0.X.X.X` convention |
| OR043 | MEDIUM   | `auto_install=True` with `installable=False` |
| OR044 | INFO     | Missing `license` key |
| OR045 | MEDIUM   | Python package listed in `depends` (should be `external_dependencies`) |
| OR046 | HIGH     | Module lists itself in `depends` (circular) |
| OR047 | HIGH     | `__manifest__.py` missing or unparseable |

> **Scan scope:** `__pycache__`, `.git`, `node_modules`, `static`, `migrations`, and `tests`
> directories are skipped by both the AST checks and Bandit. Test code intentionally
> contains anti-patterns, so scanning it only adds noise.

### Bandit (via integration)
All Bandit rules run automatically unless `--no-bandit` is passed.
Rules OR001/OR002/OR026 are excluded from Bandit to avoid duplicates with our Odoo-aware versions.

## Output Example

```
======================================================================
  📦 Addon: sale_attachment_mandatory
  Files  : 3 Python file(s) scanned
======================================================================

  💀 CRITICAL (1)
  ──────────────────────────────────────────────────────────
  OR001   models/sale_order.py:42
    [OR001] Potential SQL injection: f-string used as SQL query

  🔴 HIGH (2)
  ──────────────────────────────────────────────────────────
  OR010   models/sale_order.py:67
    [OR010] .search() called inside a loop — N+1 query risk.

  Summary: Critical: 1  |  High: 2  |  Medium: 3  |  Total: 6
```

## Extending with Custom Rules

```python
# my_checker.py
import ast
from pathlib import Path
from typing import Generator
from odoo_review.checkers import BaseChecker
from odoo_review.models import Finding, Severity, Category

class MyCustomChecker(BaseChecker):
    def check_file(self, filepath: Path, tree: ast.Module, source: str) -> Generator[Finding, None, None]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # ... your logic
                yield Finding(
                    rule_id="CX001",
                    severity=Severity.MEDIUM,
                    category=Category.BEST_PRACTICE,
                    message="[CX001] Custom rule triggered",
                    filepath=str(filepath),
                    line=node.lineno,
                )
```

Then expose it through the `odoo_review.checkers` **entry-point group** in your own
package's `pyproject.toml` — no need to edit `odoo-review` itself:

```toml
# pyproject.toml of your plugin package
[project.entry-points."odoo_review.checkers"]
my_custom = "my_package.my_checker:MyCustomChecker"
```

After `pip install`-ing your package, `odoo-review` auto-discovers the checker and
runs it alongside the built-ins. The entry point may point to a `BaseChecker`
subclass (instantiated automatically) or to an already-instantiated checker.
A plugin that fails to import or instantiate is skipped without aborting the scan.

## License

MIT

