"""
scanners.models
~~~~~~~~~~~~~~~
Core data-transfer objects emitted by all scanner engines.

A ``Finding`` is the single unit of output produced by every scanner —
file path, line number, matched rule, and a copy of the rule's explanation
and fix text so consumers never need to re-join back to the rule set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from rules.schema import Severity


@dataclass(frozen=True, order=True)
class Finding:
    """A single compliance / security issue discovered by a scanner.

    Attributes
    ----------
    file:
        Path to the file in which the issue was found (relative to the
        scanned root, when available).
    line:
        1-based line number of the triggering code.
    rule_id:
        The GuardRail rule identifier that fired (e.g. ``GR-BFSI-001``).
    severity:
        Severity level copied from the rule.
    explanation:
        Plain-language description of *why* this is a problem.
    fix:
        Concrete remediation steps.
    match_text:
        The exact snippet of source text that triggered the rule.
        Empty string when not available (e.g. pure AST detections).
    """

    file: Path
    line: int
    rule_id: str
    severity: Severity
    explanation: str
    fix: str
    match_text: str = field(default="", compare=False)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable dict representation."""
        return {
            "file": str(self.file),
            "line": self.line,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "explanation": self.explanation,
            "fix": self.fix,
            "match_text": self.match_text,
        }
