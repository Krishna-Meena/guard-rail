"""
scanners.regex_scanner
~~~~~~~~~~~~~~~~~~~~~~
Pattern-based scanner engine.

For every rule whose ``detection.type`` is ``"regex"`` the engine compiles
each pattern and runs it against every line of the source file.  A match on
any pattern produces a :class:`~scanners.models.Finding`.

Design notes
------------
* Patterns are compiled once per :class:`RegexScanner` instance and cached by
  rule id, so repeated calls to :meth:`scan_file` for the same rule are cheap.
* Line numbers are 1-based to match editor conventions and SARIF spec.
* Multi-line patterns (``re.DOTALL``) are *not* used — each line is tested
  independently which gives accurate line numbers and avoids quadratic
  backtracking on large files.
"""

from __future__ import annotations

import re
from pathlib import Path

from rules.schema import DetectionType, Rule
from scanners.base import BaseScanner
from scanners.models import Finding


class RegexScanner(BaseScanner):
    """Scan a file using the compiled regex patterns from a rule's detection block."""

    def __init__(self) -> None:
        # compiled pattern cache: rule_id -> list[re.Pattern]
        self._cache: dict[str, list[re.Pattern[str]]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_file(self, path: Path, rule: Rule) -> list[Finding]:
        """Return all regex-pattern matches in *path* for *rule*.

        Returns an empty list if the rule is not of type ``regex`` or the
        file cannot be read.
        """
        if rule.detection.type != DetectionType.REGEX:
            return []

        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        patterns = self._get_patterns(rule)
        findings: list[Finding] = []

        for lineno, line in enumerate(source.splitlines(), start=1):
            for pattern in patterns:
                m = pattern.search(line)
                if m:
                    findings.append(
                        Finding(
                            file=path,
                            line=lineno,
                            rule_id=rule.id,
                            severity=rule.severity,
                            explanation=rule.explanation,
                            fix=rule.fix,
                            match_text=m.group(0).strip(),
                        )
                    )
                    # One finding per line per rule — first pattern wins.
                    break

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_patterns(self, rule: Rule) -> list[re.Pattern[str]]:
        """Return compiled patterns for *rule*, building the cache on first call."""
        if rule.id not in self._cache:
            compiled: list[re.Pattern[str]] = []
            for raw in rule.detection.patterns:
                try:
                    compiled.append(re.compile(raw, re.IGNORECASE))
                except re.error:
                    # Skip malformed patterns rather than crashing the whole scan.
                    pass
            self._cache[rule.id] = compiled
        return self._cache[rule.id]
