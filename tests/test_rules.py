"""
tests.test_rules
~~~~~~~~~~~~~~~~
Unit tests for the rules module: YAML loading, schema validation, and
helper methods on RuleSet / Rule objects.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from rules import Severity, default_ruleset, load_ruleset
from rules.schema import DetectionType, Rule, RuleSet


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def bfsi_ruleset() -> RuleSet:
    """Load the built-in BFSI rule set once for all tests in this module."""
    return default_ruleset()


# ---------------------------------------------------------------------------
# Loader tests
# ---------------------------------------------------------------------------


class TestLoader:
    def test_default_ruleset_loads(self, bfsi_ruleset: RuleSet) -> None:
        assert bfsi_ruleset is not None

    def test_ruleset_has_expected_rule_count(self, bfsi_ruleset: RuleSet) -> None:
        assert len(bfsi_ruleset.rules) == 9

    def test_ruleset_meta_name(self, bfsi_ruleset: RuleSet) -> None:
        assert "BFSI" in bfsi_ruleset.ruleset.name

    def test_ruleset_meta_version(self, bfsi_ruleset: RuleSet) -> None:
        assert bfsi_ruleset.ruleset.version == "1.0"

    def test_load_ruleset_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_ruleset(tmp_path / "nonexistent.yaml")

    def test_load_ruleset_invalid_yaml_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(": invalid: yaml: [\n", encoding="utf-8")
        with pytest.raises(yaml.YAMLError):
            load_ruleset(bad)


# ---------------------------------------------------------------------------
# Rule id & schema tests
# ---------------------------------------------------------------------------


class TestRuleSchema:
    _EXPECTED_IDS = [
        "GR-BFSI-001",
        "GR-BFSI-002",
        "GR-BFSI-003",
        "GR-BFSI-004",
        "GR-BFSI-005",
        "GR-BFSI-006",
        "GR-BFSI-007",
        "GR-BFSI-008",
        "GR-BFSI-009",
    ]

    def test_all_expected_ids_present(self, bfsi_ruleset: RuleSet) -> None:
        ids = {r.id for r in bfsi_ruleset.rules}
        for expected in self._EXPECTED_IDS:
            assert expected in ids, f"Missing rule {expected}"

    def test_all_rules_have_non_empty_explanation(self, bfsi_ruleset: RuleSet) -> None:
        for rule in bfsi_ruleset.rules:
            assert rule.explanation.strip(), f"Rule {rule.id} has empty explanation"

    def test_all_rules_have_non_empty_fix(self, bfsi_ruleset: RuleSet) -> None:
        for rule in bfsi_ruleset.rules:
            assert rule.fix.strip(), f"Rule {rule.id} has empty fix"

    def test_all_rules_have_at_least_one_detection_pattern(self, bfsi_ruleset: RuleSet) -> None:
        for rule in bfsi_ruleset.rules:
            assert rule.detection.patterns, f"Rule {rule.id} has no detection patterns"

    def test_all_rules_have_valid_severity(self, bfsi_ruleset: RuleSet) -> None:
        valid = {s.value for s in Severity}
        for rule in bfsi_ruleset.rules:
            assert rule.severity.value in valid, f"Rule {rule.id} has invalid severity"

    def test_all_rules_reference_at_least_one_framework(self, bfsi_ruleset: RuleSet) -> None:
        for rule in bfsi_ruleset.rules:
            assert rule.frameworks, f"Rule {rule.id} has no framework references"

    def test_detection_type_is_known_enum(self, bfsi_ruleset: RuleSet) -> None:
        valid = {dt.value for dt in DetectionType}
        for rule in bfsi_ruleset.rules:
            assert rule.detection.type.value in valid, (
                f"Rule {rule.id} has unknown detection type '{rule.detection.type}'"
            )


# ---------------------------------------------------------------------------
# Specific rule content tests
# ---------------------------------------------------------------------------


class TestRuleContent:
    def test_gr_bfsi_001_is_critical(self, bfsi_ruleset: RuleSet) -> None:
        rule = bfsi_ruleset.by_id("GR-BFSI-001")
        assert rule.severity == Severity.CRITICAL

    def test_gr_bfsi_001_name_mentions_credentials(self, bfsi_ruleset: RuleSet) -> None:
        rule = bfsi_ruleset.by_id("GR-BFSI-001")
        assert "Credential" in rule.name or "credential" in rule.name.lower()

    def test_gr_bfsi_002_is_critical(self, bfsi_ruleset: RuleSet) -> None:
        rule = bfsi_ruleset.by_id("GR-BFSI-002")
        assert rule.severity == Severity.CRITICAL

    def test_gr_bfsi_004_mentions_md5_sha1(self, bfsi_ruleset: RuleSet) -> None:
        rule = bfsi_ruleset.by_id("GR-BFSI-004")
        combined = " ".join(rule.detection.patterns).upper()
        assert "MD5" in combined
        assert "SHA1" in combined or "SHA-1" in combined

    def test_gr_bfsi_005_audit_log_is_high(self, bfsi_ruleset: RuleSet) -> None:
        rule = bfsi_ruleset.by_id("GR-BFSI-005")
        assert rule.severity == Severity.HIGH

    def test_gr_bfsi_006_is_critical(self, bfsi_ruleset: RuleSet) -> None:
        rule = bfsi_ruleset.by_id("GR-BFSI-006")
        assert rule.severity == Severity.CRITICAL

    def test_gr_bfsi_007_rate_limit_is_high(self, bfsi_ruleset: RuleSet) -> None:
        rule = bfsi_ruleset.by_id("GR-BFSI-007")
        assert rule.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# RuleSet helper method tests
# ---------------------------------------------------------------------------


class TestRuleSetHelpers:
    def test_by_id_raises_key_error_for_missing(self, bfsi_ruleset: RuleSet) -> None:
        with pytest.raises(KeyError):
            bfsi_ruleset.by_id("GR-BFSI-999")

    def test_by_severity_returns_correct_subset(self, bfsi_ruleset: RuleSet) -> None:
        criticals = bfsi_ruleset.by_severity(Severity.CRITICAL)
        assert all(r.severity == Severity.CRITICAL for r in criticals)
        assert len(criticals) >= 1

    def test_at_or_above_high_excludes_info_and_low(self, bfsi_ruleset: RuleSet) -> None:
        high_plus = bfsi_ruleset.at_or_above(Severity.HIGH)
        severities = {r.severity for r in high_plus}
        assert Severity.INFO not in severities
        assert Severity.LOW not in severities
        assert Severity.MEDIUM not in severities

    def test_at_or_above_info_returns_all(self, bfsi_ruleset: RuleSet) -> None:
        all_rules = bfsi_ruleset.at_or_above(Severity.INFO)
        assert len(all_rules) == len(bfsi_ruleset.rules)

    def test_gr_bfsi_008_is_ast_type(self, bfsi_ruleset: RuleSet) -> None:
        from rules.schema import DetectionType

        rule = bfsi_ruleset.by_id("GR-BFSI-008")
        assert rule.detection.type == DetectionType.AST
        assert rule.severity == Severity.CRITICAL

    def test_gr_bfsi_009_is_ast_type(self, bfsi_ruleset: RuleSet) -> None:
        from rules.schema import DetectionType

        rule = bfsi_ruleset.by_id("GR-BFSI-009")
        assert rule.detection.type == DetectionType.AST
        assert rule.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Custom YAML loading test
# ---------------------------------------------------------------------------


class TestCustomRuleset:
    _MINIMAL_YAML = textwrap.dedent("""\
        ruleset:
          version: "1.0"
          name: "Test Set"
          description: "Minimal rule set for unit testing."
        rules:
          - id: GR-TEST-001
            name: Test Rule
            category: Test
            severity: LOW
            frameworks:
              - CWE-0
            detection:
              type: regex
              patterns:
                - 'test_pattern'
            explanation: "This is a test explanation."
            fix: "This is a test fix."
            references:
              - "https://example.com"
    """)

    def test_load_custom_yaml(self, tmp_path: Path) -> None:
        rule_file = tmp_path / "custom_rules.yaml"
        rule_file.write_text(self._MINIMAL_YAML, encoding="utf-8")
        rs = load_ruleset(rule_file)
        assert len(rs.rules) == 1
        assert rs.rules[0].id == "GR-TEST-001"
        assert rs.rules[0].severity == Severity.LOW

    def test_invalid_id_format_raises_validation_error(self, tmp_path: Path) -> None:
        from pydantic import ValidationError

        bad_yaml = self._MINIMAL_YAML.replace("GR-TEST-001", "INVALID-ID")
        rule_file = tmp_path / "bad_id.yaml"
        rule_file.write_text(bad_yaml, encoding="utf-8")
        with pytest.raises(ValidationError):
            load_ruleset(rule_file)

    def test_missing_explanation_raises_validation_error(self, tmp_path: Path) -> None:
        from pydantic import ValidationError

        bad_yaml = self._MINIMAL_YAML.replace(
            'explanation: "This is a test explanation."', ""
        )
        rule_file = tmp_path / "no_explanation.yaml"
        rule_file.write_text(bad_yaml, encoding="utf-8")
        with pytest.raises(ValidationError):
            load_ruleset(rule_file)
