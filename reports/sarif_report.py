"""
reports.sarif_report
~~~~~~~~~~~~~~~~~~~~
Produces a SARIF 2.1.0 JSON report for CI/CD integration.

SARIF (Static Analysis Results Interchange Format) is the standard format
used by GitHub Advanced Security, Azure DevOps, and other CI platforms for
displaying inline code annotations from static analysis tools.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rules.schema import RuleSet, Severity
from scanners.models import Finding

# SARIF severity levels mapped from our internal Severity enum.
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

# SARIF security-severity (CVSS-like scores) for each level.
_SARIF_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.8",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.5",
    Severity.INFO: "0.0",
}

_TOOL_NAME = "GuardRail"
_TOOL_URI = "https://github.com/Krishna-Meena/guard-rail"
_TOOL_VERSION = "0.1.0"


def render(
    findings: Sequence[Finding],
    ruleset: RuleSet,
    *,
    scan_root: str | Path = ".",
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document (as a Python dict) from *findings*.

    Parameters
    ----------
    findings:
        Findings produced by :func:`scanners.walker.scan`.
    ruleset:
        The rule set used for the scan (populates the ``rules`` section of the
        SARIF ``driver``).
    scan_root:
        Root path that was scanned (used to construct relative artifact URIs).
    """
    scan_root = Path(scan_root).resolve()

    # Build the driver rules list (deduplicated, ordered).
    seen_rule_ids: set[str] = set()
    sarif_rules: list[dict[str, Any]] = []
    for finding in findings:
        if finding.rule_id in seen_rule_ids:
            continue
        seen_rule_ids.add(finding.rule_id)

        try:
            rule = ruleset.by_id(finding.rule_id)
            help_text = rule.fix.strip()
            rule_name = rule.name
            frameworks = rule.frameworks
            references = rule.references
        except KeyError:
            help_text = finding.fix.strip()
            rule_name = finding.rule_id
            frameworks = []
            references = []

        tags = [*frameworks]
        sarif_rule: dict[str, Any] = {
            "id": finding.rule_id,
            "name": rule_name,
            "shortDescription": {"text": rule_name},
            "fullDescription": {"text": finding.explanation.strip()},
            "help": {"text": help_text, "markdown": f"**Remediation:**\n\n{help_text}"},
            "properties": {
                "security-severity": _SARIF_SECURITY_SEVERITY[finding.severity],
                "tags": tags,
            },
            "defaultConfiguration": {
                "level": _SARIF_LEVEL[finding.severity],
            },
        }
        if references:
            sarif_rule["helpUri"] = references[0]
        sarif_rules.append(sarif_rule)

    # Build results list.
    results: list[dict[str, Any]] = []
    for finding in findings:
        try:
            artifact_uri = _make_uri(finding.file, scan_root)
        except ValueError:
            artifact_uri = str(finding.file).replace("\\", "/")

        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": finding.explanation.strip()},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": artifact_uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line,
                            "startColumn": 1,
                        },
                    }
                }
            ],
        }
        if finding.match_text:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": finding.match_text.strip()[:500]
            }

        results.append(result)

    timestamp = datetime.now(tz=UTC).isoformat()

    sarif_doc: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "informationUri": _TOOL_URI,
                        "rules": sarif_rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": timestamp,
                        "endTimeUtc": timestamp,
                    }
                ],
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "uri": "./",
                        "description": {"text": "Root of the scanned source tree."},
                    }
                },
                "results": results,
                "properties": {
                    "ruleset": ruleset.ruleset.name,
                    "rulesetVersion": ruleset.ruleset.version,
                },
            }
        ],
    }
    return sarif_doc


def write(
    findings: Sequence[Finding],
    ruleset: RuleSet,
    output_path: str | Path,
    *,
    scan_root: str | Path = ".",
    indent: int = 2,
) -> Path:
    """Render the SARIF document and write it to *output_path* as JSON."""
    output_path = Path(output_path)
    sarif_doc = render(findings, ruleset, scan_root=scan_root)
    output_path.write_text(
        json.dumps(sarif_doc, indent=indent, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_path


def _make_uri(file_path: Path, scan_root: Path) -> str:
    """Return a forward-slash relative URI for *file_path* relative to *scan_root*."""
    try:
        rel = file_path.resolve().relative_to(scan_root)
    except ValueError:
        rel = file_path
    return str(rel).replace("\\", "/")
