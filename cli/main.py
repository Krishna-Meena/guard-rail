"""
cli.main
~~~~~~~~
The ``guardrail`` command-line interface.

Commands
--------
guardrail scan <path>
    Run the BFSI/FinTech scanner against a file or directory, print a
    colour-coded terminal summary, and write both Markdown and SARIF reports.

Options
-------
--severity   Minimum severity level to report (CRITICAL/HIGH/MEDIUM/LOW/INFO).
             Defaults to INFO (all findings).
--output-dir Directory for report files. Defaults to the current directory.
--no-report  Skip writing report files (terminal output only).
--ruleset    Path to a custom rule YAML file. Defaults to the built-in BFSI set.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from reports import impact_summary as _impact
from reports import markdown_report, sarif_report
from rules import default_ruleset, load_ruleset
from rules.schema import Severity
from scanners import count_files, scan

# ── Shared Rich console ───────────────────────────────────────────────────────
# safe_box avoids Unicode box-drawing chars on Windows legacy consoles.
# Reconfigure stdout/stderr to UTF-8 on Windows so emoji in panel titles
# are not rejected by the legacy cp1252 console codec.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001, S110
        pass

console = Console(highlight=False, safe_box=True)

# ── Severity → Rich style mapping ────────────────────────────────────────────

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_BADGE: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}

_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

# ── Click group ───────────────────────────────────────────────────────────────


@click.group()
def main() -> None:
    """GuardRail — BFSI/FinTech compliance & security scanner."""


# ── scan command ─────────────────────────────────────────────────────────────


@main.command("scan")
@click.argument("path", type=click.Path(exists=True, file_okay=True, dir_okay=True))
@click.option(
    "--severity",
    "-s",
    default="INFO",
    show_default=True,
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    help="Minimum severity level to include in output and reports.",
)
@click.option(
    "--output-dir",
    "-o",
    default=".",
    show_default=True,
    type=click.Path(file_okay=False, dir_okay=True),
    help="Directory where report files are written.",
)
@click.option(
    "--no-report",
    is_flag=True,
    default=False,
    help="Skip writing Markdown and SARIF report files.",
)
@click.option(
    "--ruleset",
    "ruleset_path",
    default=None,
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    help="Path to a custom rule YAML. Defaults to built-in BFSI rule set.",
)
def scan_command(
    path: str,
    severity: str,
    output_dir: str,
    no_report: bool,
    ruleset_path: str | None,
) -> None:
    """Scan PATH for BFSI/FinTech compliance and security issues.

    PATH may be a file or a directory. Both a Markdown summary report and a
    SARIF JSON report are written to OUTPUT_DIR (default: current directory).
    """
    scan_root = Path(path).resolve()

    # ── Banner ───────────────────────────────────────────────────────────────
    console.print()
    console.print(
        Panel.fit(
            "[bold white]GuardRail[/]  [dim]BFSI / FinTech Compliance & Security Scanner[/]",
            border_style="blue",
            padding=(0, 2),
        )
    )
    console.print()

    # ── Load rule set ────────────────────────────────────────────────────────
    with console.status("[bold blue]Loading rule set..."):
        ruleset = load_ruleset(ruleset_path) if ruleset_path else default_ruleset()

    # ── Scan metadata table ──────────────────────────────────────────────────
    meta = Table(box=None, show_header=False, padding=(0, 1), expand=False)
    meta.add_column("label", style="dim", min_width=18)
    meta.add_column("value", style="bold white")
    meta.add_row("Target", str(scan_root))
    meta.add_row(
        "Rule set",
        f"{ruleset.ruleset.name} v{ruleset.ruleset.version}  [{len(ruleset.rules)} rules]",
    )
    sev_display = severity if severity != "INFO" else "INFO (all)"
    meta.add_row("Min severity", sev_display)
    console.print(meta)
    console.print()

    # ── Run scan ─────────────────────────────────────────────────────────────
    with console.status("[bold blue]Scanning..."):
        files_scanned = count_files(str(scan_root))
        findings = scan(str(scan_root), ruleset, min_severity=severity)

    total = len(findings)
    summary = _impact.compute(findings, ruleset)  # type: ignore[arg-type]

    # ── Write reports (before printing findings so paths appear at the end) ──
    md_path: Path | None = None
    sarif_path: Path | None = None
    if not no_report:
        md_path, sarif_path = _write_reports(findings, ruleset, scan_root, output_dir)

    if total == 0:
        console.print(
            Panel(
                _build_pass_content(files_scanned, md_path, sarif_path),
                border_style="green",
                padding=(0, 2),
            )
        )
        sys.exit(0)

    # ── Impact Summary panel ─────────────────────────────────────────────────
    _print_impact_summary(summary)

    # ── Findings grouped by severity ─────────────────────────────────────────
    _print_findings(findings, ruleset, scan_root)

    # ── Final results panel ───────────────────────────────────────────────────
    _print_results_panel(findings, files_scanned, md_path, sarif_path, summary)

    # Exit with a non-zero code when any HIGH or CRITICAL findings are present
    # (so CI pipelines can fail the build).
    worst = max(f.severity.rank for f in findings)
    exit_code = 2 if worst >= Severity.HIGH.rank else 1
    sys.exit(exit_code)


# ── Internal helpers ──────────────────────────────────────────────────────────


def _build_pass_content(
    files_scanned: int,
    md_path: Path | None,
    sarif_path: Path | None,
) -> Table:
    """Build the content table for the clean-scan (PASS) panel."""
    t = Table(box=None, show_header=False, padding=(0, 1), expand=False)
    t.add_column("k", style="bold green", min_width=20)
    t.add_column("v", style="white")
    noun = "file" if files_scanned == 1 else "files"
    t.add_row("PASS", f"No findings  ({files_scanned} {noun} scanned)")
    if md_path:
        t.add_row("Markdown report", str(md_path))
    if sarif_path:
        t.add_row("SARIF report", str(sarif_path))
    return t


def _print_impact_summary(summary: _impact.ImpactSummary) -> None:
    """Print a compact Impact Summary panel above the per-finding detail."""
    table = Table(
        box=box.SIMPLE,
        show_header=False,
        padding=(0, 1),
        expand=False,
    )
    table.add_column("Label", style="dim", min_width=28)
    table.add_column("Value", style="bold white")

    # Row 1 — severity breakdown
    table.add_row("Findings by severity", summary.severity_line())

    # Row 2 — time saved
    billable = sum(summary.counts.get(s, 0) for s in (Severity.CRITICAL, Severity.HIGH))
    time_val = summary.time_saved_line()
    if billable:
        time_val += f"  [dim]({billable} CRITICAL/HIGH x 15 min)[/]"
    table.add_row("Est. review time saved", time_val)

    # Row 3 — compliance coverage
    table.add_row("Compliance coverage", summary.coverage_line())

    console.print(
        Panel(
            table,
            title="[bold cyan]Impact Summary[/]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    console.print()


def _print_findings(findings: list, ruleset: object, scan_root: Path) -> None:  # type: ignore[type-arg]
    from collections import defaultdict

    from rules.schema import RuleSet

    assert isinstance(ruleset, RuleSet)  # noqa: S101

    by_sev: dict[Severity, list] = defaultdict(list)
    for f in findings:
        by_sev[f.severity].append(f)

    for sev in _SEVERITY_ORDER:
        group = by_sev.get(sev, [])
        if not group:
            continue

        badge = _SEVERITY_BADGE[sev]
        style = _SEVERITY_STYLE[sev]
        n = len(group)

        # Section header
        console.print(Rule(style="dim"))
        header = Text()
        header.append(f" {badge} ", style=f"bold {style}")
        header.append(f"  {n} finding{'s' if n != 1 else ''}", style="dim")
        console.print(header)
        console.print()

        for finding in group:
            try:
                rule = ruleset.by_id(finding.rule_id)
                rule_name = rule.name
                frameworks = rule.frameworks
            except KeyError:
                rule_name = finding.rule_id
                frameworks = []

            # Try to show a path relative to the scan root for readability.
            try:
                display_path = finding.file.relative_to(scan_root)
            except ValueError:
                display_path = finding.file

            # Rule ID + name
            id_text = Text()
            id_text.append(f"  {finding.rule_id}", style=f"bold {_SEVERITY_STYLE[sev]}")
            id_text.append(f"  {rule_name}", style="bold white")
            console.print(id_text)

            # Location
            console.print(f"  [dim]Location:[/] [cyan]{display_path}[/][dim]:{finding.line}[/]")

            # Match snippet
            if finding.match_text:
                snippet = finding.match_text.strip()[:100]
                console.print(f"  [dim]Match:   [/] [italic dim]{snippet}[/]")

            # Compliance mapping
            if frameworks:
                maps_to = ", ".join(frameworks[:3])
                console.print(f"  [dim]Maps to: [/] [green]{maps_to}[/]")

            # Explanation (first sentence only in terminal)
            expl = finding.explanation.strip().split(".")[0] + "."
            console.print(f"  [dim]{expl}[/]")
            console.print()


def _print_results_panel(
    findings: list,  # type: ignore[type-arg]
    files_scanned: int,
    md_path: Path | None,
    sarif_path: Path | None,
    summary: _impact.ImpactSummary,
) -> None:
    """Print the final results panel with verdict, counts, and report paths."""
    from collections import Counter

    counts: Counter[Severity] = Counter(f.severity for f in findings)
    total = len(findings)

    worst = max(f.severity.rank for f in findings)
    failed = worst >= Severity.HIGH.rank

    table = Table(
        box=box.SIMPLE,
        show_header=False,
        padding=(0, 1),
        expand=False,
    )
    table.add_column("label", style="dim", min_width=22)
    table.add_column("value", style="bold white")

    # Verdict row
    if failed:
        verdict_text = Text("FAIL", style="bold red")
        verdict_text.append("  Critical or high-severity issues require remediation.", style="dim")
    else:
        verdict_text = Text("PASS", style="bold green")
        verdict_text.append("  No critical/high findings; review remaining issues.", style="dim")
    table.add_row("Result", verdict_text)

    table.add_row("Files scanned", str(files_scanned))
    table.add_row("Total findings", str(total))

    # Severity breakdown
    sev_parts: list[str] = []
    for sev in _SEVERITY_ORDER:
        c = counts.get(sev, 0)
        if c:
            sev_parts.append(f"[{_SEVERITY_STYLE[sev]}]{c} {_SEVERITY_BADGE[sev]}[/]")
    table.add_row("By severity", "  ".join(sev_parts) if sev_parts else "—")

    # Impact
    table.add_row("Est. time saved", summary.time_saved_line())
    table.add_row("Compliance flags", summary.coverage_line())

    # Report paths
    if md_path:
        table.add_row("Markdown report", str(md_path))
    if sarif_path:
        table.add_row("SARIF report", str(sarif_path))

    border = "red" if failed else "green"
    title = "[bold red]Scan Failed[/]" if failed else "[bold green]Scan Complete[/]"
    console.print(Rule(style="dim"))
    console.print(
        Panel(
            table,
            title=title,
            border_style=border,
            padding=(0, 2),
        )
    )
    console.print()


def _write_reports(
    findings: list,  # type: ignore[type-arg]
    ruleset: object,
    scan_root: Path,
    output_dir: str,
) -> tuple[Path, Path]:
    """Write Markdown and SARIF reports; return (md_path, sarif_path)."""
    from rules.schema import RuleSet

    assert isinstance(ruleset, RuleSet)  # noqa: S101
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    md_path = out / "guardrail-report.md"
    sarif_path = out / "guardrail-report.sarif.json"

    with console.status("[bold blue]Writing reports..."):
        markdown_report.write(findings, ruleset, md_path, scan_root=scan_root)
        sarif_report.write(findings, ruleset, sarif_path, scan_root=scan_root)

    return md_path, sarif_path
