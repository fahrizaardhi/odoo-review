"""
Tests for odoo-review checkers.
"""
from __future__ import annotations  # keep `set[str]` etc. valid on Python 3.8
import ast
from pathlib import Path
import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "sample_addon"


# ── Helpers ──────────────────────────────────────────────────────────────────

def parse_fixture(filename: str):
    fpath = FIXTURE_DIR / filename
    source = fpath.read_text(encoding="utf-8")
    tree = ast.parse(source)
    return fpath, tree, source


def rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# ── SQL Injection ─────────────────────────────────────────────────────────────

class TestSQLInjectionChecker:
    def setup_method(self):
        from odoo_review.checkers.sql_injection import SQLInjectionChecker
        self.checker = SQLInjectionChecker()

    def test_detects_fstring_injection(self):
        fpath, tree, source = parse_fixture("models.py")
        findings = list(self.checker.check_file(fpath, tree, source))
        assert any(f.rule_id == "OR001" for f in findings), "Expected OR001 (f-string)"

    def test_detects_percent_formatting(self):
        fpath, tree, source = parse_fixture("models.py")
        findings = list(self.checker.check_file(fpath, tree, source))
        assert any(f.rule_id == "OR002" for f in findings), "Expected OR002 (% format)"

    def test_clean_parameterized_query(self):
        source = """
self.env.cr.execute('SELECT id FROM res_partner WHERE name = %s', (name,))
"""
        tree = ast.parse(source)
        findings = list(self.checker.check_file(Path("test.py"), tree, source))
        assert not findings, "Parameterized query should not trigger"


# ── N+1 ───────────────────────────────────────────────────────────────────────

class TestNPlusOneChecker:
    def setup_method(self):
        from odoo_review.checkers.n_plus_one import NPlusOneChecker
        self.checker = NPlusOneChecker()

    def test_detects_search_in_loop(self):
        fpath, tree, source = parse_fixture("models.py")
        findings = list(self.checker.check_file(fpath, tree, source))
        assert any(f.rule_id == "OR010" for f in findings)

    def test_detects_write_in_loop(self):
        fpath, tree, source = parse_fixture("models.py")
        findings = list(self.checker.check_file(fpath, tree, source))
        assert any(f.rule_id == "OR011" for f in findings)

    def test_no_false_positive_outside_loop(self):
        source = """
records = self.env['res.partner'].search([('active', '=', True)])
records.write({'active': False})
"""
        tree = ast.parse(source)
        findings = list(self.checker.check_file(Path("test.py"), tree, source))
        assert not findings


# ── ORM Best Practice ─────────────────────────────────────────────────────────

class TestORMBestPracticeChecker:
    def setup_method(self):
        from odoo_review.checkers.orm_best_practice import ORMBestPracticeChecker
        self.checker = ORMBestPracticeChecker()

    def test_detects_eval(self):
        fpath, tree, source = parse_fixture("models.py")
        findings = list(self.checker.check_file(fpath, tree, source))
        assert any(f.rule_id == "OR026" for f in findings)

    def test_detects_missing_description(self):
        fpath, tree, source = parse_fixture("models.py")
        findings = list(self.checker.check_file(fpath, tree, source))
        assert any(f.rule_id == "OR023" for f in findings)

    def test_detects_missing_compute_depends(self):
        fpath, tree, source = parse_fixture("models.py")
        findings = list(self.checker.check_file(fpath, tree, source))
        assert any(f.rule_id == "OR025" for f in findings)

    def test_detects_hardcoded_browse_id(self):
        fpath, tree, source = parse_fixture("models.py")
        findings = list(self.checker.check_file(fpath, tree, source))
        assert any(f.rule_id == "OR022" for f in findings)

    def test_detects_sudo_true(self):
        fpath, tree, source = parse_fixture("models.py")
        findings = list(self.checker.check_file(fpath, tree, source))
        assert any(f.rule_id == "OR020" for f in findings)

    def test_detects_bare_sudo(self):
        fpath, tree, source = parse_fixture("models.py")
        findings = list(self.checker.check_file(fpath, tree, source))
        assert any(f.rule_id == "OR021" for f in findings), "Expected OR021 (bare sudo)"

    def test_sudo_true_is_not_reported_as_bare(self):
        source = "def f(self):\n    return self.sudo(True).search([])\n"
        tree = ast.parse(source)
        findings = list(self.checker.check_file(Path("test.py"), tree, source))
        ids = rule_ids(findings)
        assert "OR020" in ids and "OR021" not in ids

    def test_no_false_positive_attribute_eval(self):
        # self.eval(...) is an unrelated method, not the eval() builtin.
        source = "def f(self):\n    return self.eval('1 + 1')\n"
        tree = ast.parse(source)
        findings = list(self.checker.check_file(Path("test.py"), tree, source))
        assert "OR026" not in rule_ids(findings)


# ── Regression guards ─────────────────────────────────────────────────────────

class TestNoFalsePositives:
    def test_non_cursor_execute_not_flagged(self):
        from odoo_review.checkers.sql_injection import SQLInjectionChecker
        source = "def f(self):\n    return some_api.execute(f'do {thing}')\n"
        tree = ast.parse(source)
        findings = list(SQLInjectionChecker().check_file(Path("test.py"), tree, source))
        assert not findings, "Non-cursor .execute() must not trigger SQL injection rules"

    def test_cursor_execute_still_flagged(self):
        from odoo_review.checkers.sql_injection import SQLInjectionChecker
        source = "def f(self):\n    self.env.cr.execute(f'SELECT {x}')\n"
        tree = ast.parse(source)
        findings = list(SQLInjectionChecker().check_file(Path("test.py"), tree, source))
        assert any(f.rule_id == "OR001" for f in findings)

    def test_env_subscript_search_in_loop_not_duplicated(self):
        from odoo_review.checkers.n_plus_one import NPlusOneChecker
        source = (
            "def f(self):\n"
            "    for r in self:\n"
            "        self.env['res.partner'].search([('id', '=', r.id)])\n"
        )
        tree = ast.parse(source)
        findings = list(NPlusOneChecker().check_file(Path("test.py"), tree, source))
        ids = [f.rule_id for f in findings]
        assert ids == ["OR010"], f"Expected only OR010, got {ids}"


# ── Bandit category mapping ───────────────────────────────────────────────────

class TestBanditCategoryMap:
    def test_prefix_maps_to_security(self):
        from odoo_review.bandit_runner import _map_category
        from odoo_review.models import Category
        assert _map_category("B608") == Category.SECURITY
        assert _map_category("B324") == Category.SECURITY

    def test_assert_and_try_pass_are_best_practice(self):
        from odoo_review.bandit_runner import _map_category
        from odoo_review.models import Category
        assert _map_category("B101") == Category.BEST_PRACTICE
        assert _map_category("B110") == Category.BEST_PRACTICE


# ── Manifest ──────────────────────────────────────────────────────────────────

class TestManifestChecker:
    def test_detects_base_in_depends(self):
        from odoo_review.checkers.manifest import check_manifest
        findings = list(check_manifest(FIXTURE_DIR / "__manifest__.py"))
        assert any(f.rule_id == "OR041" for f in findings)

    def test_detects_bad_version(self):
        from odoo_review.checkers.manifest import check_manifest
        findings = list(check_manifest(FIXTURE_DIR / "__manifest__.py"))
        assert any(f.rule_id == "OR042" for f in findings)

    def test_detects_auto_install_not_installable(self):
        from odoo_review.checkers.manifest import check_manifest
        findings = list(check_manifest(FIXTURE_DIR / "__manifest__.py"))
        assert any(f.rule_id == "OR043" for f in findings)

    def test_detects_external_dep_in_depends(self):
        from odoo_review.checkers.manifest import check_manifest
        findings = list(check_manifest(FIXTURE_DIR / "__manifest__.py"))
        assert any(f.rule_id == "OR045" for f in findings)

    def test_unparseable_manifest_reports_or047(self, tmp_path):
        from odoo_review.checkers.manifest import check_manifest
        bad = tmp_path / "__manifest__.py"
        bad.write_text("this is not valid python ===", encoding="utf-8")
        ids = rule_ids(check_manifest(bad))
        assert "OR047" in ids

    def test_computed_value_does_not_break_parsing(self, tmp_path):
        # A non-literal value must not discard the rest of the manifest:
        # 'version' is present (so no missing-key) but unevaluated (so no OR042).
        from odoo_review.checkers.manifest import check_manifest
        m = tmp_path / "__manifest__.py"
        m.write_text(
            "SERIES = '17.0'\n"
            "{\n"
            "    'name': 'X',\n"
            "    'version': SERIES + '.1.0.0',\n"
            "    'depends': ['sale'],\n"
            "    'license': 'LGPL-3',\n"
            "}\n",
            encoding="utf-8",
        )
        ids = rule_ids(check_manifest(m))
        assert "OR040" not in ids   # name/version/depends all present
        assert "OR042" not in ids   # version is non-literal → not validated
        assert "OR047" not in ids   # file parsed fine


# ── Plugins / scan scope ──────────────────────────────────────────────────────

class TestPluginsAndScope:
    def test_builtin_checkers_present(self):
        from odoo_review.scanner import get_python_checkers
        from odoo_review.checkers import BaseChecker
        checkers = get_python_checkers()
        assert len(checkers) >= 3
        assert all(isinstance(c, BaseChecker) for c in checkers)

    def test_load_plugins_never_raises(self):
        from odoo_review.scanner import _load_plugin_checkers
        # No plugins installed → empty list, but must not raise.
        assert isinstance(_load_plugin_checkers(), list)

    def test_tests_dir_is_skipped(self, tmp_path):
        from odoo_review.scanner import scan_addon
        (tmp_path / "__manifest__.py").write_text(
            "{'name': 'a', 'version': '17.0.1.0.0', 'depends': ['base'], 'license': 'LGPL-3'}",
            encoding="utf-8",
        )
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_thing.py").write_text(
            "def f(self):\n    eval('1')\n", encoding="utf-8"
        )
        result = scan_addon(tmp_path, run_bandit_scan=False)
        assert "OR026" not in rule_ids(result.findings), "tests/ must not be scanned"


# ── Integration ───────────────────────────────────────────────────────────────

class TestScanner:
    def test_scan_addon_returns_results(self):
        from odoo_review.scanner import scan_addon
        result = scan_addon(FIXTURE_DIR, run_bandit_scan=False)
        assert result.scanned_files >= 1
        assert len(result.findings) > 0

    def test_scan_produces_json(self):
        from odoo_review.scanner import scan_addon
        from odoo_review.reporters.json_reporter import to_json
        import json
        result = scan_addon(FIXTURE_DIR, run_bandit_scan=False)
        output = to_json([result])
        data = json.loads(output)
        assert "addons" in data
        assert data["totals"]["findings"] > 0


# ── Odoo version awareness ──────────────────────────────────────────────────────

def _orm_findings(source: str, odoo_version=None):
    from odoo_review.checkers.orm_best_practice import ORMBestPracticeChecker
    from odoo_review.models import ScanContext
    tree = ast.parse(source)
    ctx = ScanContext(odoo_version=odoo_version)
    return list(ORMBestPracticeChecker().check_file(Path("m.py"), tree, source, ctx))


class TestDetectOdooVersion:
    def test_detects_series_from_5segment(self, tmp_path):
        from odoo_review.checkers.manifest import detect_odoo_version
        m = tmp_path / "__manifest__.py"
        m.write_text("{'name': 'x', 'version': '17.0.1.0.0', 'depends': ['base']}", encoding="utf-8")
        assert detect_odoo_version(m) == 17

    def test_implausible_app_version_is_ignored(self, tmp_path):
        # '1.0' is an app version, not an Odoo series → must not be read as v1.
        from odoo_review.checkers.manifest import detect_odoo_version
        m = tmp_path / "__manifest__.py"
        m.write_text("{'name': 'x', 'version': '1.0', 'depends': ['base']}", encoding="utf-8")
        assert detect_odoo_version(m) is None

    def test_non_literal_version_returns_none(self, tmp_path):
        from odoo_review.checkers.manifest import detect_odoo_version
        m = tmp_path / "__manifest__.py"
        m.write_text("S = '16.0'\n{'name': 'x', 'version': S + '.1.0.0'}\n", encoding="utf-8")
        assert detect_odoo_version(m) is None


class TestVersionAwareSudo:
    SRC = "def f(self):\n    return self.sudo(True).search([])\n"

    def test_v13plus_is_high_and_mentions_removed(self):
        findings = [f for f in _orm_findings(self.SRC, odoo_version=17) if f.rule_id == "OR020"]
        assert findings and findings[0].severity.value == "HIGH"
        assert "removed" in findings[0].message.lower()

    def test_v12_is_downgraded_to_medium(self):
        findings = [f for f in _orm_findings(self.SRC, odoo_version=12) if f.rule_id == "OR020"]
        assert findings and findings[0].severity.value == "MEDIUM"

    def test_unknown_version_stays_high(self):
        findings = [f for f in _orm_findings(self.SRC, odoo_version=None) if f.rule_id == "OR020"]
        assert findings and findings[0].severity.value == "HIGH"


class TestVersionAwareManifest:
    def test_series_mismatch_flagged_against_flag(self, tmp_path):
        from odoo_review.checkers.manifest import check_manifest
        m = tmp_path / "__manifest__.py"
        m.write_text("{'name': 'x', 'version': '16.0.1.0.0', 'depends': ['sale'], 'license': 'LGPL-3'}", encoding="utf-8")
        findings = [f for f in check_manifest(m, target_version=17) if f.rule_id == "OR042"]
        assert findings and "mismatch" in findings[0].message.lower()

    def test_matching_series_not_flagged(self, tmp_path):
        from odoo_review.checkers.manifest import check_manifest
        m = tmp_path / "__manifest__.py"
        m.write_text("{'name': 'x', 'version': '17.0.1.0.0', 'depends': ['sale'], 'license': 'LGPL-3'}", encoding="utf-8")
        assert "OR042" not in rule_ids(check_manifest(m, target_version=17))


class TestVersionWiring:
    def test_flag_overrides_manifest(self, tmp_path):
        from odoo_review.scanner import scan_addon
        (tmp_path / "__manifest__.py").write_text(
            "{'name': 'x', 'version': '16.0.1.0.0', 'depends': ['base'], 'license': 'LGPL-3'}",
            encoding="utf-8",
        )
        result = scan_addon(tmp_path, run_bandit_scan=False, odoo_version=18)
        assert result.odoo_version == 18
        assert result.odoo_version_source == "flag"

    def test_autodetect_from_manifest(self, tmp_path):
        from odoo_review.scanner import scan_addon
        (tmp_path / "__manifest__.py").write_text(
            "{'name': 'x', 'version': '15.0.1.0.0', 'depends': ['base'], 'license': 'LGPL-3'}",
            encoding="utf-8",
        )
        result = scan_addon(tmp_path, run_bandit_scan=False)
        assert result.odoo_version == 15
        assert result.odoo_version_source == "manifest"


# ── Suppression: inline noqa + .odoo-review config ──────────────────────────────

class TestInlineSuppressionParsing:
    def test_bare_noqa_suppresses_all(self):
        from odoo_review.suppressions import parse_inline_suppressions, ALL
        out = parse_inline_suppressions("a = 1  # noqa\n")
        assert out == {1: ALL}

    def test_noqa_with_ids(self):
        from odoo_review.suppressions import parse_inline_suppressions
        out = parse_inline_suppressions("a = 1  # noqa: OR001, B608\n")
        assert out == {1: {"OR001", "B608"}}

    def test_trailing_prose_is_ignored(self):
        from odoo_review.suppressions import parse_inline_suppressions
        out = parse_inline_suppressions("a = 1  # noqa: OR026 intentional eval\n")
        assert out == {1: {"OR026"}}

    def test_noqa_inside_string_is_not_a_comment(self):
        from odoo_review.suppressions import parse_inline_suppressions
        assert parse_inline_suppressions("a = '# noqa'\n") == {}

    def test_is_suppressed_logic(self):
        from odoo_review.suppressions import is_suppressed, ALL
        inline = {5: {"OR001"}, 9: ALL}
        assert is_suppressed("OR001", 5, inline, set())
        assert not is_suppressed("OR002", 5, inline, set())   # other rule, same line
        assert is_suppressed("OR026", 9, inline, set())       # bare noqa
        assert is_suppressed("OR025", 1, {}, {"OR025"})       # config-disabled


def _addon_with_models(tmp_path, models_src):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "__manifest__.py").write_text(
        "{'name': 'x', 'version': '17.0.1.0.0', 'depends': ['base'], 'license': 'LGPL-3'}",
        encoding="utf-8",
    )
    (tmp_path / "models.py").write_text(models_src, encoding="utf-8")
    return tmp_path


class TestSuppressionIntegration:
    def test_inline_noqa_drops_finding_and_counts(self, tmp_path):
        from odoo_review.scanner import scan_addon
        addon = _addon_with_models(
            tmp_path,
            "def f(self):\n"
            "    a = eval('1')  # noqa: OR026\n"
            "    b = eval('2')\n",
        )
        result = scan_addon(addon, run_bandit_scan=False)
        or026 = [f for f in result.findings if f.rule_id == "OR026"]
        assert len(or026) == 1                 # only the un-annotated eval remains
        assert or026[0].line == 3
        assert result.suppressed >= 1

    def test_noqa_specific_id_keeps_other_rules(self, tmp_path):
        from odoo_review.scanner import scan_addon
        addon = _addon_with_models(
            tmp_path,
            "def f(self):\n"
            "    return eval('1')  # noqa: OR099\n",  # non-matching id
        )
        result = scan_addon(addon, run_bandit_scan=False)
        assert any(f.rule_id == "OR026" for f in result.findings)

    def test_config_file_disables_rule(self, tmp_path):
        from odoo_review.scanner import scan_addon
        addon = _addon_with_models(tmp_path, "def f(self):\n    return eval('1')\n")
        (tmp_path / ".odoo-review").write_text(
            "[odoo-review]\ndisable = OR026\n", encoding="utf-8"
        )
        result = scan_addon(addon, run_bandit_scan=False)
        assert not any(f.rule_id == "OR026" for f in result.findings)
        assert result.suppressed >= 1

    def test_config_discovered_walking_up(self, tmp_path):
        # .odoo-review at repo root applies to a nested addon.
        from odoo_review.scanner import scan_addon
        (tmp_path / ".odoo-review").write_text(
            "[odoo-review]\ndisable = OR026\n", encoding="utf-8"
        )
        addon = _addon_with_models(tmp_path / "addons" / "mod", "def f(self):\n    return eval('1')\n")
        result = scan_addon(addon, run_bandit_scan=False)
        assert not any(f.rule_id == "OR026" for f in result.findings)

    def test_disabled_rules_param(self, tmp_path):
        from odoo_review.scanner import scan_addon
        addon = _addon_with_models(tmp_path, "def f(self):\n    return eval('1')\n")
        result = scan_addon(addon, run_bandit_scan=False, disabled_rules={"OR026"})
        assert not any(f.rule_id == "OR026" for f in result.findings)


# ── OR050: ir.model.access ──────────────────────────────────────────────────────

def _model_addon(tmp_path, model_src, csv=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "__manifest__.py").write_text(
        "{'name': 'm', 'version': '17.0.1.0.0', 'depends': ['base'], 'license': 'LGPL-3'}",
        encoding="utf-8",
    )
    (tmp_path / "models.py").write_text(model_src, encoding="utf-8")
    if csv is not None:
        (tmp_path / "security").mkdir(exist_ok=True)
        (tmp_path / "security" / "ir.model.access.csv").write_text(csv, encoding="utf-8")
    return tmp_path


_MODEL = "from odoo import models\nclass M(models.Model):\n    _name = 'my.model'\n"


class TestAccessChecker:
    def test_model_without_access_is_flagged(self, tmp_path):
        from odoo_review.checkers.access import check_access_rules
        addon = _model_addon(tmp_path, _MODEL)
        ids = {f.rule_id for f in check_access_rules(addon)}
        assert "OR050" in ids

    def test_model_with_access_csv_is_clean(self, tmp_path):
        from odoo_review.checkers.access import check_access_rules
        csv = ("id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\n"
               "access_my_model,my.model,model_my_model,base.group_user,1,1,1,1\n")
        addon = _model_addon(tmp_path, _MODEL, csv=csv)
        assert not list(check_access_rules(addon))

    def test_substring_model_does_not_falsely_grant(self, tmp_path):
        # Access for `my.model.line` must NOT satisfy `my.model`.
        from odoo_review.checkers.access import check_access_rules
        csv = "id,name,model_id:id\naccess_x,x,model_my_model_line\n"
        addon = _model_addon(tmp_path, _MODEL, csv=csv)
        assert any(f.rule_id == "OR050" for f in check_access_rules(addon))

    def test_abstract_model_not_flagged(self, tmp_path):
        from odoo_review.checkers.access import check_access_rules
        addon = _model_addon(
            tmp_path,
            "from odoo import models\nclass A(models.AbstractModel):\n    _name = 'a.mixin'\n",
        )
        assert not list(check_access_rules(addon))


# ── OR060-063: deprecation (version-aware) ──────────────────────────────────────

def _dep(src, version=None):
    from odoo_review.checkers.deprecation import DeprecationChecker
    from odoo_review.models import ScanContext
    tree = ast.parse(src)
    ctx = ScanContext(odoo_version=version)
    return list(DeprecationChecker().check_file(Path("m.py"), tree, src, ctx))


class TestDeprecationChecker:
    def test_api_multi_scales_with_version(self):
        src = "import api\nclass C:\n    @api.multi\n    def f(self): pass\n"
        hi = [f for f in _dep(src, 17) if f.rule_id == "OR060"]
        lo = [f for f in _dep(src, 12) if f.rule_id == "OR060"]
        un = [f for f in _dep(src, None) if f.rule_id == "OR060"]
        assert hi and hi[0].severity.value == "HIGH"
        assert lo and lo[0].severity.value == "INFO"
        assert un and un[0].severity.value == "MEDIUM"

    def test_cr_commit(self):
        assert any(f.rule_id == "OR061" for f in _dep("def f(self):\n    self.env.cr.commit()\n"))

    def test_legacy_openerp_import(self):
        assert any(f.rule_id == "OR062" for f in _dep("from openerp import models\n"))

    def test_legacy_osv_and_columns_and_function(self):
        src = ("class C(osv.osv):\n"
               "    _columns = {}\n"
               "    x = fields.function(lambda s: 1)\n")
        ids = [f.rule_id for f in _dep(src, 16)]
        assert ids.count("OR062") >= 3

    def test_self_pool(self):
        assert any(f.rule_id == "OR063" for f in _dep("def f(self):\n    return self.pool.get('x')\n"))


# ── Config: .odoo-review / pyproject richness ───────────────────────────────────

class TestConfig:
    def test_ini_parses_all_keys(self, tmp_path):
        from odoo_review.config import load_config
        from odoo_review.models import Severity
        (tmp_path / ".odoo-review").write_text(
            "[odoo-review]\n"
            "target-version = 17\n"
            "disable = OR025, OR044\n"
            "select = OR001, OR026\n"
            "severity = OR050:LOW, OR010:CRITICAL\n"
            "exclude = legacy/*, scratch/*\n",
            encoding="utf-8",
        )
        cfg = load_config(tmp_path)
        assert cfg.target_version == 17
        assert cfg.disable == {"OR025", "OR044"}
        assert cfg.select == {"OR001", "OR026"}
        assert cfg.severity == {"OR050": Severity.LOW, "OR010": Severity.CRITICAL}
        assert cfg.exclude == ["legacy/*", "scratch/*"]

    def test_pyproject_tool_section(self, tmp_path):
        # tomllib is stdlib on 3.11+; skip cleanly on older without a backend.
        try:
            import tomllib  # noqa: F401
        except ModuleNotFoundError:
            pytest.skip("no TOML reader for pyproject config on this Python")
        from odoo_review.config import load_config
        (tmp_path / "pyproject.toml").write_text(
            "[tool.odoo-review]\ndisable = [\"OR026\"]\ntarget-version = 18\n",
            encoding="utf-8",
        )
        cfg = load_config(tmp_path)
        assert cfg.disable == {"OR026"} and cfg.target_version == 18

    def test_config_target_version_feeds_scan(self, tmp_path):
        from odoo_review.scanner import scan_addon
        addon = _addon_with_models(tmp_path, "def f(self): pass\n")
        (tmp_path / ".odoo-review").write_text("[odoo-review]\ntarget-version = 18\n", encoding="utf-8")
        result = scan_addon(addon, run_bandit_scan=False)
        assert result.odoo_version == 18 and result.odoo_version_source == "config"

    def test_select_is_allowlist(self, tmp_path):
        from odoo_review.scanner import scan_addon
        addon = _model_addon(tmp_path, _MODEL + "\ndef g(self):\n    return eval('1')\n")
        (tmp_path / ".odoo-review").write_text("[odoo-review]\nselect = OR026\n", encoding="utf-8")
        result = scan_addon(addon, run_bandit_scan=False)
        ids = {f.rule_id for f in result.findings}
        assert ids == {"OR026"}  # OR050 and everything else dropped

    def test_severity_override(self, tmp_path):
        from odoo_review.scanner import scan_addon
        addon = _model_addon(tmp_path, _MODEL)
        (tmp_path / ".odoo-review").write_text("[odoo-review]\nseverity = OR050:LOW\n", encoding="utf-8")
        result = scan_addon(addon, run_bandit_scan=False)
        or050 = [f for f in result.findings if f.rule_id == "OR050"]
        assert or050 and or050[0].severity.value == "LOW"

    def test_exclude_path(self, tmp_path):
        from odoo_review.scanner import scan_addon
        tmp_path.mkdir(parents=True, exist_ok=True)
        (tmp_path / "__manifest__.py").write_text(
            "{'name': 'm', 'version': '17.0.1.0.0', 'depends': ['base'], 'license': 'LGPL-3'}",
            encoding="utf-8",
        )
        (tmp_path / "scratch").mkdir()
        (tmp_path / "scratch" / "junk.py").write_text("def f(self):\n    return eval('1')\n", encoding="utf-8")
        (tmp_path / ".odoo-review").write_text("[odoo-review]\nexclude = scratch/*\n", encoding="utf-8")
        result = scan_addon(tmp_path, run_bandit_scan=False)
        assert not any(f.rule_id == "OR026" for f in result.findings)


# ── OR070-079: XML / view-layer ─────────────────────────────────────────────────

def _xml(tmp_path, files: dict, version=None):
    """Write {relative_name: content} XML files and run check_xml over them."""
    from odoo_review.checkers.xml_view import check_xml, iter_xml_files
    from odoo_review.models import ScanContext
    tmp_path.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    ctx = ScanContext(odoo_version=version)
    return list(check_xml(iter_xml_files(tmp_path), ctx))


class TestXmlViewChecker:
    def test_attrs_high_on_v18(self, tmp_path):
        xml = "<odoo><record id='v' model='ir.ui.view'><field name='arch' type='xml'>" \
              "<field name='x' attrs=\"{'invisible': [('y','=',1)]}\"/></field></record></odoo>"
        f = [x for x in _xml(tmp_path, {"views/v.xml": xml}, version=18) if x.rule_id == "OR070"]
        assert f and f[0].severity.value == "HIGH"

    def test_attrs_info_on_v17(self, tmp_path):
        xml = "<odoo><field name='x' attrs=\"{'invisible': [('y','=',1)]}\"/></odoo>"
        f = [x for x in _xml(tmp_path, {"v.xml": xml}, version=17) if x.rule_id == "OR070"]
        assert f and f[0].severity.value == "INFO"

    def test_attrs_not_flagged_pre_v17_or_unknown(self, tmp_path):
        xml = "<odoo><field name='x' attrs=\"{'invisible': [('y','=',1)]}\"/></odoo>"
        assert not [x for x in _xml(tmp_path, {"v.xml": xml}, version=16) if x.rule_id == "OR070"]
        assert not [x for x in _xml(tmp_path, {"v.xml": xml}, version=None) if x.rule_id == "OR070"]

    def test_states_attribute(self, tmp_path):
        xml = "<odoo><button name='go' states='draft,done'/></odoo>"
        assert any(x.rule_id == "OR071" for x in _xml(tmp_path, {"v.xml": xml}, version=18))

    def test_tree_renamed_on_v17(self, tmp_path):
        xml = "<odoo><tree><field name='name'/></tree></odoo>"
        assert any(x.rule_id == "OR072" for x in _xml(tmp_path, {"v.xml": xml}, version=17))
        assert not [x for x in _xml(tmp_path, {"v.xml": xml}, version=16) if x.rule_id == "OR072"]

    def test_t_raw_xss_always_flagged(self, tmp_path):
        xml = "<templates><t t-name='x'><span t-raw='record.body'/></t></templates>"
        # Security finding fires regardless of version; HIGH once removed in v17+.
        un = [x for x in _xml(tmp_path, {"v.xml": xml}, version=None) if x.rule_id == "OR073"]
        hi = [x for x in _xml(tmp_path, {"v.xml": xml}, version=17) if x.rule_id == "OR073"]
        assert un and un[0].severity.value == "MEDIUM"
        assert hi and hi[0].severity.value == "HIGH"
        assert hi[0].category.value == "Security"

    def test_duplicate_id_across_files(self, tmp_path):
        a = "<odoo><record id='my_view' model='ir.ui.view'/></odoo>"
        b = "<odoo><record id='my_view' model='ir.ui.view'/></odoo>"
        dups = [x for x in _xml(tmp_path, {"views/a.xml": a, "views/b.xml": b}) if x.rule_id == "OR074"]
        assert len(dups) == 1  # only the second occurrence is reported

    def test_unique_ids_clean(self, tmp_path):
        xml = "<odoo><record id='a' model='ir.ui.view'/><record id='b' model='ir.ui.view'/></odoo>"
        assert not [x for x in _xml(tmp_path, {"v.xml": xml}) if x.rule_id == "OR074"]

    def test_act_window_without_res_model(self, tmp_path):
        xml = "<odoo><record id='act' model='ir.actions.act_window'>" \
              "<field name='name'>X</field></record></odoo>"
        assert any(x.rule_id == "OR075" for x in _xml(tmp_path, {"v.xml": xml}))

    def test_act_window_with_res_model_clean(self, tmp_path):
        xml = "<odoo><record id='act' model='ir.actions.act_window'>" \
              "<field name='res_model'>res.partner</field></record></odoo>"
        assert not [x for x in _xml(tmp_path, {"v.xml": xml}) if x.rule_id == "OR075"]

    def test_malformed_xml_reports_or079(self, tmp_path):
        assert any(x.rule_id == "OR079" for x in _xml(tmp_path, {"bad.xml": "<odoo><record></odoo>"}))

    def test_static_dir_is_skipped(self, tmp_path):
        xml = "<templates><t t-name='x'><span t-raw='v'/></t></templates>"
        assert not _xml(tmp_path, {"static/src/xml/tmpl.xml": xml}, version=17)


class TestXmlScanIntegration:
    def test_scan_addon_runs_xml_checks(self, tmp_path):
        from odoo_review.scanner import scan_addon
        (tmp_path / "__manifest__.py").write_text(
            "{'name': 'm', 'version': '18.0.1.0.0', 'depends': ['base'], 'license': 'LGPL-3'}",
            encoding="utf-8",
        )
        (tmp_path / "views").mkdir()
        (tmp_path / "views" / "v.xml").write_text(
            "<odoo><field name='x' attrs=\"{'invisible': [('y','=',1)]}\"/></odoo>",
            encoding="utf-8",
        )
        result = scan_addon(tmp_path, run_bandit_scan=False)
        assert any(f.rule_id == "OR070" for f in result.findings)

    def test_xml_finding_respects_disable_config(self, tmp_path):
        from odoo_review.scanner import scan_addon
        (tmp_path / "__manifest__.py").write_text(
            "{'name': 'm', 'version': '18.0.1.0.0', 'depends': ['base'], 'license': 'LGPL-3'}",
            encoding="utf-8",
        )
        (tmp_path / "v.xml").write_text(
            "<odoo><field name='x' attrs=\"{'invisible': []}\"/></odoo>", encoding="utf-8"
        )
        (tmp_path / ".odoo-review").write_text("[odoo-review]\ndisable = OR070\n", encoding="utf-8")
        result = scan_addon(tmp_path, run_bandit_scan=False)
        assert not any(f.rule_id == "OR070" for f in result.findings)

    def test_xml_exclude_glob(self, tmp_path):
        from odoo_review.scanner import scan_addon
        (tmp_path / "__manifest__.py").write_text(
            "{'name': 'm', 'version': '18.0.1.0.0', 'depends': ['base'], 'license': 'LGPL-3'}",
            encoding="utf-8",
        )
        (tmp_path / "legacy").mkdir()
        (tmp_path / "legacy" / "old.xml").write_text(
            "<odoo><field name='x' attrs=\"{'invisible': []}\"/></odoo>", encoding="utf-8"
        )
        (tmp_path / ".odoo-review").write_text("[odoo-review]\nexclude = legacy/*\n", encoding="utf-8")
        result = scan_addon(tmp_path, run_bandit_scan=False)
        assert not any(f.rule_id == "OR070" for f in result.findings)


# ── CLI path resolution ─────────────────────────────────────────────────────────

class TestCliResolution:
    def test_find_addon_root_from_file(self, tmp_path):
        from odoo_review.cli import _find_addon_root
        (tmp_path / "__manifest__.py").write_text("{}", encoding="utf-8")
        sub = tmp_path / "models"
        sub.mkdir()
        f = sub / "m.py"
        f.write_text("x = 1\n", encoding="utf-8")
        assert _find_addon_root(f) == tmp_path

    def test_find_addon_root_none_outside_addon(self, tmp_path):
        from odoo_review.cli import _find_addon_root
        f = tmp_path / "loose.py"
        f.write_text("x = 1\n", encoding="utf-8")
        assert _find_addon_root(f) is None
