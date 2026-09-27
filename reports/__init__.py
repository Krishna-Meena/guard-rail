"""
reports
~~~~~~~
Report formatters for GuardRail scan results.

Available formatters
--------------------
markdown_report
    Produces a human-readable Markdown summary grouped by severity,
    with compliance-mapping notes per finding.

sarif_report
    Produces a SARIF 2.1.0 JSON document for CI/CD integration
    (GitHub Advanced Security, Azure DevOps, etc.).

Usage
-----
    from rules import default_ruleset
    from scanners import scan
    from reports import markdown_report, sarif_report

    ruleset = default_ruleset()
    findings = scan("/path/to/project", ruleset)

    markdown_report.write(findings, ruleset, "report.md", scan_root="/path/to/project")
    sarif_report.write(findings, ruleset, "report.sarif.json", scan_root="/path/to/project")
"""

from reports import markdown_report, sarif_report

__all__ = ["markdown_report", "sarif_report"]
