"""
tests.test_reports
~~~~~~~~~~~~~~~~~~
Unit tests for the Markdown and SARIF report generators.

Coverage
--------
* TestMarkdownReport   — render(), write(), grouping, compliance notes
* TestSarifReport      — render() structure, SARIF 2.1.0 schema shape, write()
* TestCLI              — Click command integration via CliRunner
"""

# ruff: noqa: S101  (assert is correct in pytest test files)

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from cli.main import main
from reports import impact_summary, markdown_report, sarif_report
from rules import default_ruleset
from rules.schema import Severity
from scanners.models import Finding

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

SAMPLE_APP = Path(__file__).parent.parent / "sample-app"


def _make_finding(
    *,
    file: str = "app.py",
    line: int = 22,
    rule_id: str = "GR-BFSI-001",
    severity: Severity = Severity.CRITICAL,
    explanation: str = "Hard-coded credential detected.",
    fix: str = "Move to env vars.",
    match_text: str = 'DB_PASSWORD = "secret"',
) -> Finding:
    return Finding(
        file=Path(file),
        line=line,
        rule_id=rule_id,
        severity=severity,
        explanation=explanation,
        fix=fix,
        match_text=match_text,
    )


@pytest.fixture()
def ruleset():  # type: ignore[return]
    return default_ruleset()


@pytest.fixture()
def single_finding() -> Finding:
    return _make_finding()


@pytest.fixture()
def multi_findings() -> list[Finding]:
    return [
        _make_finding(severity=Severity.CRITICAL, line=22),
        _make_finding(
            rule_id="GR-BFSI-004",
            severity=Severity.HIGH,
            line=83,
            explanation="Insecure hash (MD5).",
            fix="Use bcrypt.",
            match_text="hashlib.md5(password)",
        ),
        _make_finding(
            rule_id="GR-BFSI-003",
            severity=Severity.HIGH,
            line=166,
            explanation="Missing input validation.",
            fix="Validate amount.",
            match_text="float(request.json.get",
        ),
    ]


# ---------------------------------------------------------------------------
# TestMarkdownReport
# ---------------------------------------------------------------------------


class TestMarkdownReport:
    def test_render_returns_string(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        md = markdown_report.render([single_finding], ruleset)  # type: ignore[arg-type]
        assert isinstance(md, str)

    def test_render_contains_rule_id(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        md = markdown_report.render([single_finding], ruleset)  # type: ignore[arg-type]
        assert "GR-BFSI-001" in md

    def test_render_contains_severity_section(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        md = markdown_report.render([single_finding], ruleset)  # type: ignore[arg-type]
        assert "CRITICAL" in md

    def test_render_compliance_note_present(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        md = markdown_report.render([single_finding], ruleset)  # type: ignore[arg-type]
        # The BFSI-001 rule maps to PCI-DSS
        assert "PCI-DSS" in md
        assert "maps to" in md

    def test_render_empty_findings(self, ruleset: object) -> None:  # type: ignore[type-arg]
        md = markdown_report.render([], ruleset)  # type: ignore[arg-type]
        assert "No findings" in md
        assert "✅" in md

    def test_render_grouped_by_severity_order(self, ruleset: object, multi_findings: list) -> None:  # type: ignore[type-arg]
        md = markdown_report.render(multi_findings, ruleset)  # type: ignore[arg-type]
        crit_pos = md.index("CRITICAL")
        high_pos = md.index("HIGH")
        assert crit_pos < high_pos, "CRITICAL section should appear before HIGH"

    def test_render_summary_counts(self, ruleset: object, multi_findings: list) -> None:  # type: ignore[type-arg]
        md = markdown_report.render(multi_findings, ruleset)  # type: ignore[arg-type]
        # 1 CRITICAL + 2 HIGH
        assert "| 🔴 CRITICAL | 1 |" in md
        assert "| 🟠 HIGH | 2 |" in md

    def test_write_creates_file(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "report.md"
            result = markdown_report.write([single_finding], ruleset, out)  # type: ignore[arg-type]
            assert result == out
            assert out.exists()
            content = out.read_text(encoding="utf-8")
            assert "GR-BFSI-001" in content

    def test_render_match_text_truncated(self, ruleset: object) -> None:  # type: ignore[type-arg]
        long_match = "x" * 200
        f = _make_finding(match_text=long_match)
        md = markdown_report.render([f], ruleset)  # type: ignore[arg-type]
        # Should be truncated to ≤120 chars in the markdown
        lines_with_match = [l for l in md.splitlines() if "Match" in l]
        assert lines_with_match, "Expected a Match line"
        assert len(lines_with_match[0]) < 200


# ---------------------------------------------------------------------------
# TestImpactSummary
# ---------------------------------------------------------------------------


class TestImpactSummary:
    def test_compute_severity_counts(self, ruleset: object, multi_findings: list) -> None:  # type: ignore[type-arg]
        summary = impact_summary.compute(multi_findings, ruleset)  # type: ignore[arg-type]
        assert summary.counts[Severity.CRITICAL] == 1
        assert summary.counts[Severity.HIGH] == 2

    def test_minutes_saved_critical_and_high(self, ruleset: object, multi_findings: list) -> None:  # type: ignore[type-arg]
        # 1 CRITICAL + 2 HIGH = 3 billable × 15 = 45 min
        summary = impact_summary.compute(multi_findings, ruleset)  # type: ignore[arg-type]
        assert summary.minutes_saved == 45

    def test_minutes_saved_zero_for_low_only(self, ruleset: object) -> None:  # type: ignore[type-arg]
        f = _make_finding(severity=Severity.LOW, rule_id="GR-BFSI-005")
        summary = impact_summary.compute([f], ruleset)  # type: ignore[arg-type]
        assert summary.minutes_saved == 0

    def test_frameworks_covered_includes_pci(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        # GR-BFSI-001 maps to PCI-DSS
        summary = impact_summary.compute([single_finding], ruleset)  # type: ignore[arg-type]
        assert "PCI-DSS" in summary.frameworks_covered

    def test_frameworks_empty_for_unknown_rule(self, ruleset: object) -> None:  # type: ignore[type-arg]
        f = _make_finding(rule_id="GR-BFSI-999")  # does not exist in ruleset
        summary = impact_summary.compute([f], ruleset)  # type: ignore[arg-type]
        assert summary.frameworks_covered == []

    def test_as_markdown_contains_impact_heading(self, ruleset: object, multi_findings: list) -> None:  # type: ignore[type-arg]
        summary = impact_summary.compute(multi_findings, ruleset)  # type: ignore[arg-type]
        md = summary.as_markdown()
        assert "Impact Summary" in md

    def test_as_markdown_contains_time_saved(self, ruleset: object, multi_findings: list) -> None:  # type: ignore[type-arg]
        summary = impact_summary.compute(multi_findings, ruleset)  # type: ignore[arg-type]
        md = summary.as_markdown()
        assert "45m" in md

    def test_as_markdown_contains_coverage_line(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        summary = impact_summary.compute([single_finding], ruleset)  # type: ignore[arg-type]
        md = summary.as_markdown()
        assert "compliance framework" in md
        assert "PCI-DSS" in md

    def test_severity_line_no_findings(self, ruleset: object) -> None:  # type: ignore[type-arg]
        summary = impact_summary.compute([], ruleset)  # type: ignore[arg-type]
        assert summary.severity_line() == "0 findings"

    def test_markdown_report_contains_impact_block(self, ruleset: object, multi_findings: list) -> None:  # type: ignore[type-arg]
        md = markdown_report.render(multi_findings, ruleset)  # type: ignore[arg-type]
        assert "Impact Summary" in md
        # Verify it appears before the detail findings section
        impact_pos = md.index("Impact Summary")
        findings_pos = md.index("## Findings")
        assert impact_pos < findings_pos

    def test_cli_output_contains_impact_summary(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(SAMPLE_APP), "--no-report"])
        assert "Impact Summary" in result.output
        assert "Est. review time saved" in result.output or "time saved" in result.output.lower()


# ---------------------------------------------------------------------------
# TestSarifReport
# ---------------------------------------------------------------------------


class TestSarifReport:
    def test_render_returns_dict(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        doc = sarif_report.render([single_finding], ruleset)  # type: ignore[arg-type]
        assert isinstance(doc, dict)

    def test_sarif_version(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        doc = sarif_report.render([single_finding], ruleset)  # type: ignore[arg-type]
        assert doc["version"] == "2.1.0"

    def test_sarif_schema_key_present(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        doc = sarif_report.render([single_finding], ruleset)  # type: ignore[arg-type]
        assert "$schema" in doc
        assert "sarif-schema-2.1.0" in doc["$schema"]

    def test_sarif_has_one_run(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        doc = sarif_report.render([single_finding], ruleset)  # type: ignore[arg-type]
        assert len(doc["runs"]) == 1

    def test_sarif_tool_name(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        doc = sarif_report.render([single_finding], ruleset)  # type: ignore[arg-type]
        assert doc["runs"][0]["tool"]["driver"]["name"] == "GuardRail"

    def test_sarif_results_count(self, ruleset: object, multi_findings: list) -> None:  # type: ignore[type-arg]
        doc = sarif_report.render(multi_findings, ruleset)  # type: ignore[arg-type]
        assert len(doc["runs"][0]["results"]) == len(multi_findings)

    def test_sarif_result_rule_id(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        doc = sarif_report.render([single_finding], ruleset)  # type: ignore[arg-type]
        result = doc["runs"][0]["results"][0]
        assert result["ruleId"] == "GR-BFSI-001"

    def test_sarif_critical_maps_to_error(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        doc = sarif_report.render([single_finding], ruleset)  # type: ignore[arg-type]
        result = doc["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_sarif_medium_maps_to_warning(self, ruleset: object) -> None:  # type: ignore[type-arg]
        f = _make_finding(severity=Severity.MEDIUM, rule_id="GR-BFSI-005")
        doc = sarif_report.render([f], ruleset)  # type: ignore[arg-type]
        result = doc["runs"][0]["results"][0]
        assert result["level"] == "warning"

    def test_sarif_location_line(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        doc = sarif_report.render([single_finding], ruleset)  # type: ignore[arg-type]
        region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == single_finding.line

    def test_sarif_deduplicated_rules(self, ruleset: object, multi_findings: list) -> None:  # type: ignore[type-arg]
        # multi_findings has 3 findings but BFSI-001 appears once
        doc = sarif_report.render(multi_findings, ruleset)  # type: ignore[arg-type]
        rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
        assert len(rule_ids) == len(set(rule_ids)), "Rule IDs in driver should be unique"

    def test_sarif_empty_findings(self, ruleset: object) -> None:  # type: ignore[type-arg]
        doc = sarif_report.render([], ruleset)  # type: ignore[arg-type]
        assert doc["runs"][0]["results"] == []

    def test_write_creates_valid_json(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "report.sarif.json"
            result = sarif_report.write([single_finding], ruleset, out)  # type: ignore[arg-type]
            assert result == out
            assert out.exists()
            parsed = json.loads(out.read_text(encoding="utf-8"))
            assert parsed["version"] == "2.1.0"

    def test_sarif_security_severity_in_properties(self, ruleset: object, single_finding: Finding) -> None:  # type: ignore[type-arg]
        doc = sarif_report.render([single_finding], ruleset)  # type: ignore[arg-type]
        rule_entry = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "security-severity" in rule_entry["properties"]
        assert rule_entry["properties"]["security-severity"] == "9.8"  # CRITICAL


# ---------------------------------------------------------------------------
# TestCLI
# ---------------------------------------------------------------------------


class TestCLI:
    def test_scan_sample_app_exits_nonzero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(SAMPLE_APP)])
        # sample-app is deliberately vulnerable — expect non-zero exit
        assert result.exit_code != 0, "Expected non-zero exit for vulnerable sample-app"

    def test_scan_sample_app_has_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(SAMPLE_APP)])
        assert "GR-BFSI" in result.output

    def test_scan_severity_filter_reduces_findings(self) -> None:
        runner = CliRunner()
        result_all = runner.invoke(main, ["scan", str(SAMPLE_APP), "--severity", "INFO"])
        result_crit = runner.invoke(main, ["scan", str(SAMPLE_APP), "--severity", "CRITICAL"])
        # The CRITICAL-only run should have fewer or equal findings
        crit_lines = result_crit.output.count("GR-BFSI")
        all_lines = result_all.output.count("GR-BFSI")
        assert crit_lines <= all_lines

    def test_scan_writes_md_report(self) -> None:
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(
                main, ["scan", str(SAMPLE_APP), "--output-dir", tmpdir]
            )
            md_path = Path(tmpdir) / "guardrail-report.md"
            assert md_path.exists(), f"Expected {md_path}; output:\n{result.output}"

    def test_scan_writes_sarif_report(self) -> None:
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(
                main, ["scan", str(SAMPLE_APP), "--output-dir", tmpdir]
            )
            sarif_path = Path(tmpdir) / "guardrail-report.sarif.json"
            assert sarif_path.exists(), f"Expected {sarif_path}; output:\n{result.output}"

    def test_no_report_flag_skips_files(self) -> None:
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.invoke(
                main,
                ["scan", str(SAMPLE_APP), "--output-dir", tmpdir, "--no-report"],
            )
            assert not (Path(tmpdir) / "guardrail-report.md").exists()

    def test_scan_missing_path_fails(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "/nonexistent/path/xyz"])
        assert result.exit_code != 0
