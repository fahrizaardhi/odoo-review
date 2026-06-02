# Changelog

All notable changes to this project are documented here. The format loosely
follows [Keep a Changelog](https://keepachangelog.com/), and the project uses
[semantic versioning](https://semver.org/).

## [0.3.0]

### Added
- **XML / view-layer checks** — a new addon-level pass parses every `*.xml`
  file (the previous releases scanned only Python):
  - **OR070** — `attrs="..."` attribute (deprecated in Odoo 17, removed in 18).
    Version-aware: `HIGH` on v18+, `INFO` on v17, not flagged on older/unknown.
  - **OR071** — `states="..."` attribute (same deprecation path as OR070).
  - **OR072** — `<tree>` element renamed to `<list>` in Odoo 17 (v17+, `INFO`).
  - **OR073** — `t-raw` QWeb directive — unescaped HTML / XSS risk; also removed
    in Odoo 17 in favour of `t-out`. Flagged on every version (`MEDIUM`, `HIGH`
    on v17+).
  - **OR074** — duplicate XML record `id` within the same addon (the second
    definition silently overwrites the first).
  - **OR075** — `ir.actions.act_window` record (or `<act_window/>` shorthand)
    with no `res_model` — a broken action.
  - **OR079** — malformed XML that Odoo would refuse to load.
- New `XML/View` finding category.
- Optional `lxml` dependency (`pip install odoo-review[xml]`) for precise line
  numbers in XML findings; without it the checks still run, reporting line 0.

## [0.2.0]

### Added
- **OR050** — flags new models (`_name`) that have no `ir.model.access` rule
  (AbstractModel is exempt). Reads the addon's `security/` CSV and XML.
- **Deprecation checks (version-aware):**
  - **OR060** — `@api.multi` / `@api.one` (removed in Odoo 13).
  - **OR061** — explicit `cr.commit()` in addon code.
  - **OR062** — legacy API: `from openerp`, `osv.osv`, `_columns`, `fields.function`.
  - **OR063** — `self.pool` / `self.pool.get()`.
- **Richer config** in `.odoo-review` and `pyproject.toml [tool.odoo-review]`:
  `target-version`, `disable`, `select` (allow-list), `severity` overrides, and
  `exclude` path globs.
- **pre-commit support** via `.pre-commit-hooks.yaml` — usable as a hook in any
  Odoo addon repo.
- CLI now accepts **multiple paths** and individual **files**, mapping each file
  to its containing addon (so pre-commit can pass changed files).

### Changed
- Target Odoo version now resolves as: `--odoo-version` flag → config
  `target-version` → manifest auto-detect.

## [0.1.0]

### Added
- Initial release: SQL injection (OR001/OR002), N+1 (OR010–OR012), ORM
  best-practice (OR020–OR026), manifest/dependency (OR040–OR047) checks, plus
  Bandit integration.
- Odoo version awareness (`--odoo-version` + manifest auto-detect).
- Inline `# noqa` suppression and `.odoo-review` rule disabling.
- Console and JSON reporters; plugin checkers via the `odoo_review.checkers`
  entry-point group.
