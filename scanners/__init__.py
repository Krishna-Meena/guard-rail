"""
scanners
~~~~~~~~
Public API for GuardRail scanner engines.

Usage
-----
    from rules import default_ruleset
    from scanners import scan, Finding, Severity

    ruleset = default_ruleset()
    findings = scan("/path/to/project", ruleset)

    for finding in findings:
        print(finding.rule_id, finding.severity.value, finding.file, finding.line)
        print("  !", finding.explanation)
        print("  Fix:", finding.fix)

Individual engine access
------------------------
    from scanners.regex_scanner import RegexScanner
    from scanners.ast_scanner import AstScanner

    scanner = RegexScanner()
    findings = scanner.scan_file(Path("app.py"), some_rule)
"""

from __future__ import annotations

from scanners.ast_scanner import AstScanner
from scanners.base import BaseScanner
from scanners.models import Finding
from scanners.regex_scanner import RegexScanner
from scanners.walker import count_files, scan

__all__ = [
    "scan",
    "count_files",
    "Finding",
    "BaseScanner",
    "RegexScanner",
    "AstScanner",
]
