"""
reports.markdown_report
~~~~~~~~~~~~~~~~~~~~~~~
Produces a Markdown compliance summary from a list of :class:`~scanners.models.Finding`
objects.

The report is grouped by severity (CRITICAL → INFO) and includes a
compliance-mapping note for each finding derived from the rule's
``frameworks`` field (e.g. "maps to PCI-DSS v4.0 Req 8.2.1").

An **Impact Summary** block is rendered at the very top of the report,
before the per-severity detail, so reviewers see the key numbers first.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from reports import impact_summary as _impact
from rules.schema import RuleSet, Severity
from scanners.models import Finding

_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def render(
    findings: Sequence[Finding],
    ruleset: RuleSet,
    *,
    scan_root: str | Path = ".",
    title: str = "GuardRail Compliance Report",
) -> str:
    """Return a Markdown string summarising *findings*.

    Parameters
    ----------
    findings:
        Findings produced by :func:`scanners.walker.scan`.
    ruleset:
        The rule set used for the scan (provides framework metadata).
    scan_root:
        The path that was scanned — included in the report header.
    title:
        Report title.
    """
    scan_root_path = Path(scan_root).resolve()
    by_severity: dict[Severity, list[Finding]] = defaultdict(list)
    for f in findings:
        by_severity[f.severity].append(f)

    total = len(findings)
    ts = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    summary = _impact.compute(findings, ruleset)

    lines: list[str] = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"**Scan target:** `{scan_root_path.name}`  ")
    lines.append(f"**Generated:** {ts}  ")
    lines.append(f"**Total findings:** {total}  ")
    lines.append("")

    # ── Impact Summary (judges / reviewers see this first) ────────────────────
    lines.append(summary.as_markdown())

    # ── Summary table ─────────────────────────────────────────────────────────
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in _SEVERITY_ORDER:
        count = len(by_severity.get(sev, []))
        if count:
            emoji = _SEVERITY_EMOJI[sev]
            lines.append(f"| {emoji} {sev.value} | {count} |")
    lines.append("")

    if total == 0:
        lines.append("> ✅ No findings — codebase is clean.")
        return "\n".join(lines)

    # ── Findings by severity ──────────────────────────────────────────────────
    lines.append("## Findings")
    lines.append("")

    for sev in _SEVERITY_ORDER:
        group = by_severity.get(sev, [])
        if not group:
            continue

        emoji = _SEVERITY_EMOJI[sev]
        lines.append(f"### {emoji} {sev.value} ({len(group)})")
        lines.append("")

        for finding in group:
            # Look up framework mappings from the rule set.
            try:
                rule = ruleset.by_id(finding.rule_id)
                compliance_note = "maps to " + ", ".join(rule.frameworks) if rule.frameworks else ""
            except KeyError:
                compliance_note = ""

            rel_path = _relative_path(finding.file, scan_root_path)
            lines.append(f"#### `{finding.rule_id}` — {_rule_name(finding, ruleset)}")
            lines.append("")
            lines.append(f"- **File:** `{rel_path}` line {finding.line}")
            if finding.match_text:
                snippet = finding.match_text.strip()[:120]
                lines.append(f"- **Match:** `{snippet}`")
            if compliance_note:
                lines.append(f"- **Compliance:** {compliance_note}")
            lines.append(f"- **Why:** {finding.explanation.strip()}")
            lines.append(f"- **Fix:** {finding.fix.strip()}")
            lines.append("")

    return "\n".join(lines)


def write(
    findings: Sequence[Finding],
    ruleset: RuleSet,
    output_path: str | Path,
    *,
    scan_root: str | Path = ".",
    title: str = "GuardRail Compliance Report",
) -> Path:
    """Render the Markdown report and write it to *output_path*."""
    output_path = Path(output_path)
    output_path.write_text(
        render(findings, ruleset, scan_root=scan_root, title=title),
        encoding="utf-8",
    )
    return output_path


def _rule_name(finding: Finding, ruleset: RuleSet) -> str:
    try:
        return ruleset.by_id(finding.rule_id).name
    except KeyError:
        return finding.rule_id


def _relative_path(file_path: Path, scan_root: Path) -> str:
    """Return a portable path relative to the scanned project where possible."""
    try:
        return str(file_path.resolve().relative_to(scan_root)).replace("\\", "/")
    except ValueError:
        return str(file_path)
