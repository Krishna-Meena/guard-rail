"""
tests.test_scanners
~~~~~~~~~~~~~~~~~~~
Unit tests for the scanner engines and codebase walker.

Structure
---------
* TestFinding         — dataclass behaviour and serialisation
* TestRegexScanner    — per-rule regex detection against fixture files
* TestAstScanner      — AST detection (Python) and JS fallback per rule
* TestWalker          — integration: scan() over the fixtures directory
* TestCleanFiles      — ensure benign files produce zero findings
* TestEdgeCases       — binary files, large files, missing files, unknown type
"""

# ruff: noqa: S101  (assert is correct in pytest test files)

from __future__ import annotations

from pathlib import Path

import pytest

from rules import default_ruleset, load_ruleset
from rules.schema import DetectionType, Rule, RuleSet, Severity
from scanners.ast_scanner import AstScanner
from scanners.models import Finding
from scanners.regex_scanner import RegexScanner
from scanners.walker import scan

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> Path:
    """Return the absolute path to a fixture file."""
    return FIXTURES / name


# ---------------------------------------------------------------------------
# Shared ruleset fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def bfsi() -> RuleSet:  # type: ignore[name-defined]  # noqa: F821
    return default_ruleset()


def rule(bfsi_rs: RuleSet, rule_id: str) -> Rule:  # type: ignore[name-defined]  # noqa: F821
    return bfsi_rs.by_id(rule_id)


# ---------------------------------------------------------------------------
# TestFinding
# ---------------------------------------------------------------------------


class TestFinding:
    def test_as_dict_keys(self) -> None:
        f = Finding(
            file=Path("app.py"),
            line=42,
            rule_id="GR-BFSI-001",
            severity=Severity.CRITICAL,
            explanation="test exp",
            fix="test fix",
            match_text="password = 'x'",
        )
        d = f.as_dict()
        assert set(d.keys()) == {
            "file",
            "line",
            "rule_id",
            "severity",
            "explanation",
            "fix",
            "match_text",
        }

    def test_severity_value_is_string(self) -> None:
        f = Finding(
            file=Path("app.py"),
            line=1,
            rule_id="GR-BFSI-001",
            severity=Severity.HIGH,
            explanation="x",
            fix="y",
        )
        assert isinstance(f.as_dict()["severity"], str)

    def test_frozen_immutable(self) -> None:
        f = Finding(
            file=Path("app.py"),
            line=1,
            rule_id="GR-BFSI-001",
            severity=Severity.LOW,
            explanation="x",
            fix="y",
        )
        with pytest.raises((AttributeError, TypeError)):
            f.line = 99  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TestRegexScanner — GR-BFSI-001 through GR-BFSI-007
# ---------------------------------------------------------------------------


class TestRegexScanner:
    @pytest.fixture(autouse=True)
    def setup(self, bfsi: RuleSet) -> None:  # type: ignore[name-defined]  # noqa: F821
        self.scanner = RegexScanner()
        self.bfsi = bfsi

    def _scan(self, rule_id: str, filepath: Path) -> list[Finding]:
        r = self.bfsi.by_id(rule_id)
        return self.scanner.scan_file(filepath, r)

    # GR-BFSI-001 — Hardcoded Credentials
    def test_001_detects_hardcoded_credentials_py(self) -> None:
        findings = self._scan("GR-BFSI-001", fixture("vuln_001_credentials.py"))
        assert len(findings) >= 1, "Expected at least one credential finding in .py fixture"
        assert all(f.rule_id == "GR-BFSI-001" for f in findings)
        assert all(f.severity == Severity.CRITICAL for f in findings)

    def test_001_detects_hardcoded_credentials_js(self) -> None:
        findings = self._scan("GR-BFSI-001", fixture("vuln_001_credentials.js"))
        assert len(findings) >= 1, "Expected at least one credential finding in .js fixture"

    def test_001_no_false_positive_on_env_var(self, tmp_path: Path) -> None:
        clean = tmp_path / "config.py"
        clean.write_text('password = os.environ.get("SECRET")\n', encoding="utf-8")
        findings = self._scan("GR-BFSI-001", clean)
        assert len(findings) == 0, "os.environ.get should not trigger GR-BFSI-001"

    # GR-BFSI-002 — SQL Injection
    def test_002_detects_sqli_py(self) -> None:
        findings = self._scan("GR-BFSI-002", fixture("vuln_002_sqli.py"))
        assert len(findings) >= 1

    def test_002_detects_sqli_js(self) -> None:
        findings = self._scan("GR-BFSI-002", fixture("vuln_002_sqli.js"))
        assert len(findings) >= 1

    def test_002_no_false_positive_on_orm(self, tmp_path: Path) -> None:
        clean = tmp_path / "safe.py"
        clean.write_text(
            'session.query(Account).filter(Account.id == user_id).first()\n',
            encoding="utf-8",
        )
        findings = self._scan("GR-BFSI-002", clean)
        assert len(findings) == 0

    # GR-BFSI-003 — Missing Input Validation
    def test_003_detects_unvalidated_input_py(self) -> None:
        findings = self._scan("GR-BFSI-003", fixture("vuln_003_input_validation.py"))
        assert len(findings) >= 1

    def test_003_detects_unvalidated_input_js(self) -> None:
        findings = self._scan("GR-BFSI-003", fixture("vuln_003_input_validation.js"))
        assert len(findings) >= 1

    # GR-BFSI-004 — Weak Hashing
    def test_004_detects_md5_py(self) -> None:
        findings = self._scan("GR-BFSI-004", fixture("vuln_004_weak_hash.py"))
        rule_ids = {f.rule_id for f in findings}
        assert "GR-BFSI-004" in rule_ids

    def test_004_detects_sha1_js(self) -> None:
        findings = self._scan("GR-BFSI-004", fixture("vuln_004_weak_hash.js"))
        assert len(findings) >= 1

    def test_004_no_finding_on_bcrypt(self, tmp_path: Path) -> None:
        clean = tmp_path / "safe.py"
        src = "import bcrypt\nhashed = bcrypt.hashpw(pw, bcrypt.gensalt())\n"
        clean.write_text(src, encoding="utf-8")
        findings = self._scan("GR-BFSI-004", clean)
        assert len(findings) == 0

    # GR-BFSI-005 — Missing Audit Log
    def test_005_detects_audit_log_py(self) -> None:
        findings = self._scan("GR-BFSI-005", fixture("vuln_005_audit_log.py"))
        assert len(findings) >= 1

    def test_005_detects_audit_log_js(self) -> None:
        findings = self._scan("GR-BFSI-005", fixture("vuln_005_audit_log.js"))
        assert len(findings) >= 1

    # GR-BFSI-006 — Unencrypted PII
    def test_006_detects_pii_py(self) -> None:
        findings = self._scan("GR-BFSI-006", fixture("vuln_006_pii_storage.py"))
        assert len(findings) >= 1

    def test_006_detects_pii_js(self) -> None:
        findings = self._scan("GR-BFSI-006", fixture("vuln_006_pii_storage.js"))
        assert len(findings) >= 1

    # GR-BFSI-007 — Missing Rate Limit
    def test_007_detects_rate_limit_py(self) -> None:
        findings = self._scan("GR-BFSI-007", fixture("vuln_007_rate_limit.py"))
        assert len(findings) >= 1

    def test_007_detects_rate_limit_js(self) -> None:
        findings = self._scan("GR-BFSI-007", fixture("vuln_007_rate_limit.js"))
        assert len(findings) >= 1

    # Engine type guard — regex scanner ignores AST rules
    def test_regex_scanner_ignores_ast_rule(self, bfsi: RuleSet) -> None:  # type: ignore[name-defined]  # noqa: F821
        ast_rule = bfsi.by_id("GR-BFSI-008")
        assert ast_rule.detection.type == DetectionType.AST
        findings = self.scanner.scan_file(fixture("vuln_008_eval_exec.py"), ast_rule)
        assert findings == []


# ---------------------------------------------------------------------------
# TestAstScanner — GR-BFSI-008 and GR-BFSI-009
# ---------------------------------------------------------------------------


class TestAstScanner:
    @pytest.fixture(autouse=True)
    def setup(self, bfsi: RuleSet) -> None:  # type: ignore[name-defined]  # noqa: F821
        self.scanner = AstScanner()
        self.bfsi = bfsi

    def _scan(self, rule_id: str, filepath: Path) -> list[Finding]:
        r = self.bfsi.by_id(rule_id)
        return self.scanner.scan_file(filepath, r)

    # GR-BFSI-008 — Dangerous eval / subprocess
    def test_008_detects_eval_py(self) -> None:
        findings = self._scan("GR-BFSI-008", fixture("vuln_008_eval_exec.py"))
        rule_ids = {f.rule_id for f in findings}
        assert "GR-BFSI-008" in rule_ids

    def test_008_findings_have_line_numbers_py(self) -> None:
        findings = self._scan("GR-BFSI-008", fixture("vuln_008_eval_exec.py"))
        for f in findings:
            assert f.line > 0, f"Expected positive line number, got {f.line}"

    def test_008_detects_shell_true_py(self) -> None:
        findings = self._scan("GR-BFSI-008", fixture("vuln_008_eval_exec.py"))
        assert len(findings) >= 2, "Expected findings for both eval and shell=True"

    def test_008_detects_eval_js(self) -> None:
        findings = self._scan("GR-BFSI-008", fixture("vuln_008_eval_exec.js"))
        assert len(findings) >= 1

    def test_008_no_finding_on_safe_py(self, tmp_path: Path) -> None:
        safe = tmp_path / "safe.py"
        safe.write_text(
            "import ast\nresult = ast.literal_eval(user_input)\n",
            encoding="utf-8",
        )
        findings = self._scan("GR-BFSI-008", safe)
        assert len(findings) == 0

    # GR-BFSI-009 — TLS Cert Verification Disabled
    def test_009_detects_verify_false_py(self) -> None:
        findings = self._scan("GR-BFSI-009", fixture("vuln_009_tls_verify.py"))
        rule_ids = {f.rule_id for f in findings}
        assert "GR-BFSI-009" in rule_ids

    def test_009_detects_check_hostname_py(self) -> None:
        findings = self._scan("GR-BFSI-009", fixture("vuln_009_tls_verify.py"))
        assert len(findings) >= 2, "Expected findings for both verify=False and check_hostname"

    def test_009_detects_verify_false_js(self) -> None:
        findings = self._scan("GR-BFSI-009", fixture("vuln_009_tls_verify.js"))
        assert len(findings) >= 1

    def test_009_no_finding_on_safe_py(self, tmp_path: Path) -> None:
        safe = tmp_path / "safe.py"
        safe.write_text(
            "import requests\nresponse = requests.get(url, verify=True)\n",
            encoding="utf-8",
        )
        findings = self._scan("GR-BFSI-009", safe)
        assert len(findings) == 0

    # Engine type guard — AST scanner ignores regex rules
    def test_ast_scanner_ignores_regex_rule(self, bfsi: RuleSet) -> None:  # type: ignore[name-defined]  # noqa: F821
        regex_rule = bfsi.by_id("GR-BFSI-001")
        assert regex_rule.detection.type == DetectionType.REGEX
        findings = self.scanner.scan_file(fixture("vuln_001_credentials.py"), regex_rule)
        assert findings == []

    # AST syntax error — should not crash
    def test_ast_scanner_handles_syntax_error(self, tmp_path: Path, bfsi: RuleSet) -> None:  # type: ignore[name-defined]  # noqa: F821
        broken = tmp_path / "broken.py"
        broken.write_text("def bad_syntax(:\n    pass\n", encoding="utf-8")
        r = bfsi.by_id("GR-BFSI-008")
        findings = self.scanner.scan_file(broken, r)
        assert findings == []


# ---------------------------------------------------------------------------
# TestWalker — integration scan over fixtures directory
# ---------------------------------------------------------------------------


class TestWalker:
    def test_scan_fixtures_returns_findings(self, bfsi: RuleSet) -> None:
        findings = scan(FIXTURES, bfsi)
        assert len(findings) > 0, "Expected findings when scanning vulnerable fixture directory"

    def test_scan_findings_sorted_by_file_line_rule(self, bfsi: RuleSet) -> None:
        findings = scan(FIXTURES, bfsi)
        keys = [(str(f.file), f.line, f.rule_id) for f in findings]
        assert keys == sorted(keys)

    def test_scan_covers_all_nine_rules(self, bfsi: RuleSet) -> None:
        findings = scan(FIXTURES, bfsi)
        triggered = {f.rule_id for f in findings}
        expected = {f"GR-BFSI-{i:03d}" for i in range(1, 10)}
        missing = expected - triggered
        assert not missing, f"Rules not triggered by any fixture: {missing}"

    def test_scan_no_duplicates(self, bfsi: RuleSet) -> None:
        findings = scan(FIXTURES, bfsi)
        keys = [(str(f.file), f.line, f.rule_id) for f in findings]
        assert len(keys) == len(set(keys)), "Duplicate findings detected"

    def test_scan_single_file(self, bfsi: RuleSet) -> None:
        findings = scan(fixture("vuln_001_credentials.py"), bfsi)
        assert all(f.rule_id == "GR-BFSI-001" for f in findings)

    def test_scan_min_severity_filters(self, bfsi: RuleSet) -> None:
        all_findings = scan(FIXTURES, bfsi)
        critical_only = scan(FIXTURES, bfsi, min_severity="CRITICAL")
        assert len(critical_only) <= len(all_findings)
        assert all(f.severity == Severity.CRITICAL for f in critical_only)

    def test_scan_nonexistent_root_returns_empty(self, bfsi: RuleSet, tmp_path: Path) -> None:
        empty_dir = tmp_path / "does_not_exist"
        findings = scan(empty_dir, bfsi)
        assert findings == []

    def test_scan_respects_exclude_dirs(self, bfsi: RuleSet, tmp_path: Path) -> None:
        # Put a vulnerable file inside an excluded directory
        sub = tmp_path / "node_modules"
        sub.mkdir()
        vuln = sub / "vuln.py"
        vuln.write_text('password = "abc123"\n', encoding="utf-8")
        findings = scan(tmp_path, bfsi)
        paths = [str(f.file) for f in findings]
        assert not any("node_modules" in p for p in paths)


# ---------------------------------------------------------------------------
# TestCleanFiles — benign code should produce zero findings
# ---------------------------------------------------------------------------


class TestCleanFiles:
    @pytest.fixture(autouse=True)
    def setup(self, bfsi: RuleSet) -> None:  # type: ignore[name-defined]  # noqa: F821
        self.regex = RegexScanner()
        self.ast = AstScanner()
        self.bfsi = bfsi

    def test_clean_python_no_credentials(self, tmp_path: Path) -> None:
        f = tmp_path / "clean.py"
        f.write_text(
            'import os\npwd = os.environ["DB_PASS"]\n',
            encoding="utf-8",
        )
        r = self.bfsi.by_id("GR-BFSI-001")
        assert self.regex.scan_file(f, r) == []

    def test_clean_python_orm_query(self, tmp_path: Path) -> None:
        f = tmp_path / "clean.py"
        f.write_text(
            'results = session.query(Account).filter(Account.id == uid).all()\n',
            encoding="utf-8",
        )
        r = self.bfsi.by_id("GR-BFSI-002")
        assert self.regex.scan_file(f, r) == []

    def test_clean_python_safe_subprocess(self, tmp_path: Path) -> None:
        f = tmp_path / "clean.py"
        f.write_text(
            'subprocess.run(["convert", filename], shell=False)\n',
            encoding="utf-8",
        )
        r = self.bfsi.by_id("GR-BFSI-008")
        assert self.ast.scan_file(f, r) == []

    def test_clean_python_verify_true(self, tmp_path: Path) -> None:
        f = tmp_path / "clean.py"
        f.write_text(
            'requests.get(url, verify=True)\n',
            encoding="utf-8",
        )
        r = self.bfsi.by_id("GR-BFSI-009")
        assert self.ast.scan_file(f, r) == []


# ---------------------------------------------------------------------------
# TestEdgeCases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    @pytest.fixture(autouse=True)
    def setup(self, bfsi: RuleSet) -> None:  # type: ignore[name-defined]  # noqa: F821
        self.regex = RegexScanner()
        self.ast = AstScanner()
        self.bfsi = bfsi

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        missing = tmp_path / "no_such_file.py"
        r = self.bfsi.by_id("GR-BFSI-001")
        assert self.regex.scan_file(missing, r) == []
        assert self.ast.scan_file(missing, r) == []

    def test_binary_file_skipped_by_walker(self, bfsi: RuleSet, tmp_path: Path) -> None:
        binary = tmp_path / "data.bin"
        binary.write_bytes(b"\x00\x01\x02password=secret")
        findings = scan(tmp_path, bfsi)
        assert findings == []

    def test_large_file_skipped_by_walker(self, bfsi: RuleSet, tmp_path: Path) -> None:
        big = tmp_path / "huge.py"
        # Write a file just over 1 MiB
        big.write_bytes(b'password = "x"\n' * 80_000)
        findings = scan(tmp_path, bfsi, max_file_bytes=100)
        assert findings == []

    def test_finding_fields_populated(self, bfsi: RuleSet) -> None:
        r = bfsi.by_id("GR-BFSI-001")
        findings = self.regex.scan_file(fixture("vuln_001_credentials.py"), r)
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule_id == "GR-BFSI-001"
        assert f.line >= 1
        assert f.explanation.strip()
        assert f.fix.strip()
        assert isinstance(f.severity, Severity)

    def test_regex_scanner_caches_patterns(self, bfsi: RuleSet) -> None:
        r = bfsi.by_id("GR-BFSI-001")
        # Call twice — second call should use cache
        scanner = RegexScanner()
        scanner.scan_file(fixture("vuln_001_credentials.py"), r)
        scanner.scan_file(fixture("vuln_001_credentials.py"), r)
        assert r.id in scanner._cache  # noqa: SLF001

    def test_walker_custom_ruleset(self, tmp_path: Path) -> None:
        """Walker works with a custom single-rule YAML."""
        import textwrap

        rule_file = tmp_path / "custom.yaml"
        rule_file.write_text(
            textwrap.dedent("""\
                ruleset:
                  version: "1.0"
                  name: "Custom"
                  description: "Custom test rule set."
                rules:
                  - id: GR-TEST-001
                    name: Test Credential
                    category: Secrets
                    severity: CRITICAL
                    frameworks: [CWE-798]
                    detection:
                      type: regex
                      patterns:
                        - '(?i)password\\s*=\\s*["\\''][^"\\''\\s]{4,}["\\'']'
                    explanation: "Hardcoded password."
                    fix: "Use env vars."
            """),
            encoding="utf-8",
        )
        rs = load_ruleset(rule_file)

        vuln = tmp_path / "app.py"
        vuln.write_text('password = "abc1234"\n', encoding="utf-8")

        findings = scan(tmp_path, rs)
        assert len(findings) >= 1
        assert findings[0].rule_id == "GR-TEST-001"
