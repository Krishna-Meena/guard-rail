"""
reports.impact_summary
~~~~~~~~~~~~~~~~~~~~~~
Computes a short, scannable "Impact Summary" block from a list of
:class:`~scanners.models.Finding` objects and a :class:`~rules.schema.RuleSet`.

The block is designed to be placed at the very top of every report so that
reviewers — and competition judges — see the most important numbers first:

* Findings by severity (CRITICAL → INFO)
* Estimated manual-review time saved (15 min per CRITICAL/HIGH finding)
* Compliance coverage: the distinct framework *families* flagged by this scan
  (e.g. "PCI-DSS", "GDPR" — normalised from the verbose framework strings
  stored in each rule).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from rules.schema import RuleSet, Severity
from scanners.models import Finding

# Severities that count toward the "time saved" estimate.
_BILLABLE_SEVERITIES: frozenset[Severity] = frozenset({Severity.CRITICAL, Severity.HIGH})

# Minutes saved per CRITICAL/HIGH finding caught automatically.
_MINUTES_PER_FINDING: int = 15

# The four canonical framework families used in the coverage line.
# Matching is case-insensitive substring; order is display order.
_FRAMEWORK_FAMILIES: list[tuple[str, str]] = [
    ("PCI-DSS", "PCI-DSS"),
    ("GDPR", "GDPR"),
    ("SOC", "SOC2"),  # matches "SOC 2", "SOC2", "SOC Type II" …
    ("RBI", "RBI guidelines"),
]

_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def compute(
    findings: Sequence[Finding],
    ruleset: RuleSet,
) -> ImpactSummary:
    """Return an :class:`ImpactSummary` computed from *findings* + *ruleset*."""
    counts: Counter[Severity] = Counter(f.severity for f in findings)

    billable = sum(counts.get(s, 0) for s in _BILLABLE_SEVERITIES)
    minutes_saved = billable * _MINUTES_PER_FINDING

    # Collect all framework strings referenced by the triggered rules.
    triggered_rule_ids: set[str] = {f.rule_id for f in findings}
    all_framework_strings: list[str] = []
    for rule_id in triggered_rule_ids:
        try:
            rule = ruleset.by_id(rule_id)
            all_framework_strings.extend(rule.frameworks)
        except KeyError:
            pass

    covered: list[str] = []
    for needle, label in _FRAMEWORK_FAMILIES:
        if any(needle.upper() in fw.upper() for fw in all_framework_strings):
            covered.append(label)

    return ImpactSummary(
        counts=counts,
        minutes_saved=minutes_saved,
        frameworks_covered=covered,
    )


class ImpactSummary:
    """Holds pre-computed impact metrics for a single scan result."""

    def __init__(
        self,
        counts: Counter[Severity],
        minutes_saved: int,
        frameworks_covered: list[str],
    ) -> None:
        self.counts = counts
        self.minutes_saved = minutes_saved
        self.frameworks_covered = frameworks_covered

    # ------------------------------------------------------------------
    # Rendering helpers
    # ------------------------------------------------------------------

    def as_markdown(self) -> str:
        """Return a Markdown string for the Impact Summary block."""
        lines: list[str] = []
        lines.append("## ⚡ Impact Summary")
        lines.append("")

        # Severity breakdown
        parts: list[str] = []
        for sev in _SEVERITY_ORDER:
            c = self.counts.get(sev, 0)
            if c:
                parts.append(f"**{c} {sev.value}**")
        total = sum(self.counts.values())
        breakdown = ", ".join(parts) if parts else "0 findings"
        lines.append(f"- **Findings:** {total} total — {breakdown}")

        # Time saved
        if self.minutes_saved > 0:
            hours, mins = divmod(self.minutes_saved, 60)
            if hours:
                time_str = f"{hours}h {mins}m" if mins else f"{hours}h"
            else:
                time_str = f"{mins}m"
            billable = sum(self.counts.get(s, 0) for s in _BILLABLE_SEVERITIES)
            lines.append(
                f"- **Estimated review time saved:** ~{time_str} "
                f"({billable} CRITICAL/HIGH × 15 min avg manual catch)"
            )
        else:
            lines.append("- **Estimated review time saved:** n/a (no CRITICAL/HIGH findings)")

        # Compliance coverage
        if self.frameworks_covered:
            fw_list = ", ".join(self.frameworks_covered)
            n = len(self.frameworks_covered)
            lines.append(
                f"- **Compliance coverage:** Flags issues mapped to "
                f"{n} compliance framework{'s' if n != 1 else ''}: {fw_list}"
            )
        else:
            lines.append("- **Compliance coverage:** No framework mappings triggered")

        lines.append("")
        lines.append("---")
        lines.append("")
        return "\n".join(lines)

    def severity_line(self) -> str:
        """Single-line severity breakdown string for terminal output."""
        parts: list[str] = []
        for sev in _SEVERITY_ORDER:
            c = self.counts.get(sev, 0)
            if c:
                parts.append(f"{c} {sev.value}")
        return "  •  ".join(parts) if parts else "0 findings"

    def time_saved_line(self) -> str:
        """Human-readable 'time saved' string for terminal output."""
        if self.minutes_saved == 0:
            return "n/a (no CRITICAL/HIGH findings)"
        hours, mins = divmod(self.minutes_saved, 60)
        if hours:
            return f"~{hours}h {mins}m" if mins else f"~{hours}h"
        return f"~{mins}m"

    def coverage_line(self) -> str:
        """Compliance coverage string for terminal output."""
        if not self.frameworks_covered:
            return "No framework mappings triggered"
        fw_list = ", ".join(self.frameworks_covered)
        n = len(self.frameworks_covered)
        return f"Flags issues mapped to {n} compliance framework{'s' if n != 1 else ''}: {fw_list}"
