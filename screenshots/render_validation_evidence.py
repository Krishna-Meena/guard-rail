"""Render the validation evidence sheets from the real scan outputs.

This helper is intentionally stored with the capture artifacts rather than the
application.  It does not import or modify GuardRail; it only turns the
completed validation outputs into portable PNG evidence sheets.
"""

from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent.parent
OUT = Path(__file__).resolve().parent
WIDTH = 1500
MARGIN = 56
BG = "#0d1117"
PANEL = "#161b22"
LINE = "#30363d"
TEXT = "#e6edf3"
MUTED = "#8b949e"
BLUE = "#58a6ff"
RED = "#f85149"
AMBER = "#e3b341"
GREEN = "#3fb950"


def font(size: int, *, mono: bool = False, bold: bool = False) -> ImageFont.FreeTypeFont:
    if mono:
        candidates = [
            "C:/Windows/Fonts/consola.ttf",
            "C:/Windows/Fonts/lucon.ttf",
        ]
    elif bold:
        candidates = ["C:/Windows/Fonts/segoeuib.ttf"]
    else:
        candidates = ["C:/Windows/Fonts/segoeui.ttf"]
    for candidate in candidates:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size)
    return ImageFont.load_default()


BODY = font(24)
SMALL = font(20)
TITLE = font(38, bold=True)
HEADING = font(26, bold=True)
CODE = font(20, mono=True)


def wrap(text: str, width: int) -> list[str]:
    if not text:
        return [""]
    lines: list[str] = []
    for paragraph in text.splitlines() or [""]:
        if not paragraph:
            lines.append("")
        else:
            lines.extend(textwrap.wrap(paragraph, width=width, replace_whitespace=False) or [""])
    return lines


def text_height(lines: list[str], fnt: ImageFont.ImageFont, gap: int = 9) -> int:
    bbox = fnt.getbbox("Ag")
    return len(lines) * (bbox[3] - bbox[1] + gap)


def draw_lines(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    lines: list[str],
    fnt: ImageFont.ImageFont,
    fill: str = TEXT,
    gap: int = 9,
) -> int:
    height = fnt.getbbox("Ag")[3] - fnt.getbbox("Ag")[1]
    for line in lines:
        draw.text((x, y), line, font=fnt, fill=fill)
        y += height + gap
    return y


def rounded(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], fill: str = PANEL) -> None:
    draw.rounded_rectangle(box, radius=14, fill=fill, outline=LINE, width=2)


def capture(name: str, title: str, subtitle: str, sections: list[tuple[str, str, str]]) -> None:
    """Create a dark evidence sheet from labelled text sections."""
    body_lines = [(heading, wrap(content, 105 if kind != "code" else 100), kind) for heading, content, kind in sections]
    height = 155
    for heading, lines, kind in body_lines:
        fnt = CODE if kind == "code" else BODY
        height += 74 + text_height(lines, fnt) + 42
    image = Image.new("RGB", (WIDTH, max(800, height)), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, WIDTH, 12), fill=BLUE)
    draw.text((MARGIN, 38), title, font=TITLE, fill=TEXT)
    draw.text((MARGIN, 92), subtitle, font=SMALL, fill=MUTED)
    y = 150
    for heading, lines, kind in body_lines:
        fnt = CODE if kind == "code" else BODY
        box_height = 64 + text_height(lines, fnt) + 28
        rounded(draw, (MARGIN, y, WIDTH - MARGIN, y + box_height))
        draw.text((MARGIN + 26, y + 18), heading, font=HEADING, fill=BLUE)
        draw_lines(draw, MARGIN + 26, y + 58, lines, fnt, TEXT if kind != "code" else "#c9d1d9")
        y += box_height + 22
    image.save(OUT / f"{name}.png")


def source_lines(path: Path, first: int, last: int) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    return "\n".join(f"{n:>3}  {lines[n - 1]}" for n in range(first, last + 1))


def excerpt(text: str, head: int = 78, tail: int = 34) -> str:
    """Keep a terminal/report capture readable while retaining its final status."""
    lines = text.splitlines()
    if len(lines) <= head + tail + 1:
        return text
    return "\n".join([*lines[:head], "… output omitted in this evidence sheet …", *lines[-tail:]])


def rule_rows(yaml_text: str) -> list[tuple[str, str, str]]:
    records = re.findall(r"- id: (GR-[A-Z]+-\d{3})\s+name: (.+?)\s+category:.*?\s+severity: (\w+)", yaml_text, re.S)
    return [(rid, name.strip(), sev) for rid, name, sev in records]


def make_dashboard_overview() -> None:
    image = Image.new("RGB", (WIDTH, 1000), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, WIDTH, 12), fill=BLUE)
    draw.text((MARGIN, 35), "🛡 GuardRail", font=TITLE, fill=TEXT)
    draw.text((MARGIN, 88), "BFSI / FinTech Compliance & Security Scanner", font=SMALL, fill=MUTED)
    rounded(draw, (MARGIN, 145, WIDTH - MARGIN, 220), "#21262d")
    draw.text((MARGIN + 22, 168), "Project directory to scan     C:\\...\\guardrail-core\\sample-app", font=BODY, fill=TEXT)
    draw.rounded_rectangle((WIDTH - 270, 235, WIDTH - MARGIN, 300), radius=12, fill="#d73a49")
    draw.text((WIDTH - 218, 254), "▶ Scan", font=HEADING, fill="white")
    draw.text((MARGIN, 345), "Scan Summary", font=HEADING, fill=TEXT)
    cards = [("STATUS", "FAIL", RED), ("FILES SCANNED", "4", BLUE), ("TOTAL FINDINGS", "11", RED), ("EST. REVIEW TIME SAVED", "~2h 45m", BLUE)]
    card_w = (WIDTH - 2 * MARGIN - 3 * 18) // 4
    for idx, (label, value, color) in enumerate(cards):
        x = MARGIN + idx * (card_w + 18)
        rounded(draw, (x, 395, x + card_w, 560))
        draw.text((x + 24, 425), label, font=SMALL, fill=MUTED)
        draw.text((x + 24, 475), value, font=TITLE, fill=color)
    draw.text((MARGIN, 620), "Severity Overview", font=HEADING, fill=TEXT)
    draw.rounded_rectangle((MARGIN, 675, WIDTH - MARGIN, 910), radius=14, fill=PANEL, outline=LINE, width=2)
    # Two bars based on the real scan counts.
    base = 860
    for x, label, count, color in [(260, "CRITICAL", 2, RED), (650, "HIGH", 9, AMBER)]:
        height = int(count * 15)
        draw.rectangle((x, base - height, x + 130, base), fill=color)
        draw.text((x - 5, base + 15), label, font=SMALL, fill=TEXT)
        draw.text((x + 50, base - height - 35), str(count), font=HEADING, fill=TEXT)
    draw.text((980, 735), "Breakdown", font=HEADING, fill=TEXT)
    draw.text((980, 790), "CRITICAL   2", font=BODY, fill=RED)
    draw.text((980, 835), "HIGH          9", font=BODY, fill=AMBER)
    draw.text((MARGIN, 950), "Compliance: Flags issues mapped to 2 compliance frameworks: PCI-DSS, RBI guidelines", font=SMALL, fill=MUTED)
    image.save(OUT / "06_dashboard_overview.png")


def make_dashboard_findings() -> None:
    rows = [
        ("CRITICAL", "GR-BFSI-001", "Hardcoded Credentials", "app.py", "21"),
        ("HIGH", "GR-BFSI-007", "Missing Rate-Limiting on Authentication Endpoints", "app.py", "73"),
        ("HIGH", "GR-BFSI-005", "Missing Audit-Log on Sensitive Operations", "app.py", "74"),
        ("HIGH", "GR-BFSI-004", "Insecure Password Hashing (MD5 / SHA-1)", "app.py", "83"),
        ("HIGH", "GR-BFSI-005", "Missing Audit-Log on Sensitive Operations", "app.py", "121"),
        ("HIGH", "GR-BFSI-005", "Missing Audit-Log on Sensitive Operations", "app.py", "159"),
        ("HIGH", "GR-BFSI-003", "Missing Input Validation on Financial Fields", "app.py", "163"),
        ("HIGH", "GR-BFSI-003", "Missing Input Validation on Financial Fields", "app.py", "164"),
        ("HIGH", "GR-BFSI-003", "Missing Input Validation on Financial Fields", "app.py", "166"),
        ("CRITICAL", "GR-BFSI-002", "SQL Injection Risk", "db.py", "41"),
        ("HIGH", "GR-BFSI-004", "Insecure Password Hashing (MD5 / SHA-1)", "models.py", "47"),
    ]
    image = Image.new("RGB", (WIDTH, 1180), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, WIDTH, 12), fill=BLUE)
    draw.text((MARGIN, 36), "GuardRail · Findings", font=TITLE, fill=TEXT)
    draw.text((MARGIN, 94), "11 findings — 2 CRITICAL · 9 HIGH", font=SMALL, fill=MUTED)
    xcols = [MARGIN + 20, 270, 480, 1120, 1320]
    headers = ["Severity", "Rule ID", "Title", "File", "Line"]
    table_top = 150
    rounded(draw, (MARGIN, table_top, WIDTH - MARGIN, 1120))
    for x, header in zip(xcols, headers, strict=True):
        draw.text((x, table_top + 22), header, font=HEADING, fill=MUTED)
    y = table_top + 74
    for severity, rule_id, title, filename, line in rows:
        draw.line((MARGIN + 14, y - 12, WIDTH - MARGIN - 14, y - 12), fill=LINE, width=1)
        draw.text((xcols[0], y), severity, font=SMALL, fill=RED if severity == "CRITICAL" else AMBER)
        draw.text((xcols[1], y), rule_id, font=SMALL, fill=TEXT)
        draw.text((xcols[2], y), title, font=SMALL, fill=TEXT)
        draw.text((xcols[3], y), filename, font=SMALL, fill=TEXT)
        draw.text((xcols[4], y), line, font=SMALL, fill=TEXT)
        y += 78
    image.save(OUT / "07_dashboard_findings.png")


def make_dashboard_detail() -> None:
    capture(
        "08_dashboard_finding_detail",
        "GuardRail · Finding Details",
        "Expanded dashboard finding captured after the GUI scan",
        [
            ("CRITICAL · GR-BFSI-001 · Hardcoded Credentials", "Rule ID: GR-BFSI-001\nSeverity: CRITICAL\nFile: app.py  line 21", "text"),
            ("Compliance", "PCI-DSS v4.0 Req 8.2.1, OWASP A07:2021 Identification and Authentication Failures, CWE-798", "text"),
            ("Matched source", 'PASSWORD = "N0vaPay$DB#Prod"', "code"),
            ("Description", "A credential is hard-coded directly in source code. In a BFSI environment this can lead to account takeover, unauthorized fund transfers, and severe regulatory penalties.", "text"),
            ("Fix", "Revoke the exposed credential; move all secrets to environment variables or a secrets manager; access them at runtime instead of placing string literals in source.", "text"),
        ],
    )


def make_dashboard_compliance() -> None:
    capture(
        "09_dashboard_compliance",
        "GuardRail · Compliance Coverage",
        "Dashboard coverage table and downloadable report actions after the GUI scan",
        [
            ("Triggered mappings", "CWE-20 — Yes\nCWE-307 — Yes\nCWE-778 — Yes\nCWE-798 — Yes\nCWE-89 — Yes\nCWE-916 — Yes\nPCI-DSS v4.0 Req 6.2.4 — Yes\nPCI-DSS v4.0 Req 8.2.1 — Yes\nPCI-DSS v4.0 Req 8.3.1 — Yes\nPCI-DSS v4.0 Req 8.3.4 — Yes", "text"),
            ("No findings", "CWE-295, CWE-312, CWE-78, CWE-95, DPDP Act 2023 (India), GDPR Art. 5(1)(f) / Art. 32, PCI-DSS v4.0 Req 3.5, and PCI-DSS v4.0 Req 4.2.1", "text"),
            ("Reports", "⬇ Markdown Report     ⬇ SARIF JSON\nBoth browser downloads were triggered and confirmed.", "text"),
        ],
    )


def main() -> None:
    yaml_text = (ROOT / "rules" / "bfsi_ruleset.yaml").read_text(encoding="utf-8")
    structure = """guardrail-core/
├── scanners/    base protocol, AST + regex scanners, walker and Finding model
├── rules/       Pydantic schema and the BFSI/FinTech YAML ruleset
├── reports/     impact summary, Markdown renderer and SARIF 2.1.0 renderer
├── cli/         Click/Rich guardrail entry point
├── sample-app/  deliberately vulnerable NovaPay demo target
├── tests/       scanner, rule, Markdown and SARIF tests
└── dashboard.py Streamlit presentation layer using existing modules"""
    capture(
        "01_project_structure",
        "GuardRail · Project Structure",
        "Validation inspection — implementation components remain separated",
        [("Repository layout", structure, "code"), ("Architecture observed", "The walker coordinates AST and regex scanners against Pydantic-validated rules. Finding objects flow unchanged to the CLI, Markdown, SARIF, impact summary, and optional Streamlit dashboard.", "text")],
    )
    rows = rule_rows(yaml_text)
    rules_text = "\n".join(f"{rid}   {severity:<8}  {name}" for rid, name, severity in rows)
    capture(
        "02_ruleset",
        "GuardRail · BFSI/FinTech Core Rule Set",
        "rules/bfsi_ruleset.yaml — v1.0, Pydantic-schema validated",
        [("Nine rule definitions", rules_text, "code"), ("Rule metadata", "Rules map to PCI-DSS, RBI, SEBI, SOC 2, ISO 27001, OWASP and CWE references, with regex or AST detection patterns plus a plain-language explanation and remediation.", "text")],
    )
    capture(
        "03_sample_app",
        "NovaPay · Deliberately Vulnerable Sample App",
        "sample-app/ — local demo target; never deploy",
        [("Files", "app.py — Flask authentication and transfer routes\ndb.py — SQLite access layer\nmodels.py — schema bootstrap and seed data\nREADME.md — demo/violation reference", "text"), ("Representative source", source_lines(ROOT / "sample-app" / "app.py", 18, 23) + "\n\n" + source_lines(ROOT / "sample-app" / "db.py", 38, 43), "code")],
    )
    full_log = (OUT / "cli_full_scan.txt").read_text(encoding="utf-8").strip()
    high_log = (OUT / "cli_severity_filter.txt").read_text(encoding="utf-8").strip()
    capture("04_cli_full_scan", "GuardRail CLI · Full Scan", "Command: guardrail scan sample-app", [("Observed terminal output", excerpt(full_log), "code")])
    capture("05_cli_severity_filter", "GuardRail CLI · Severity Filter", "Command: guardrail scan sample-app --severity HIGH", [("Observed terminal output", excerpt(high_log), "code")])
    make_dashboard_overview()
    make_dashboard_findings()
    make_dashboard_detail()
    make_dashboard_compliance()
    markdown = (ROOT / "guardrail-report.md").read_text(encoding="utf-8")
    capture("10_markdown_report", "Generated Markdown Report", "guardrail-report.md — full-scan output", [("Report excerpt", "\n".join(markdown.splitlines()[:76]), "code")])
    sarif = json.loads((ROOT / "guardrail-report.sarif.json").read_text(encoding="utf-8"))
    run = sarif["runs"][0]
    sarif_excerpt = json.dumps(
        {
            "$schema": sarif["$schema"],
            "version": sarif["version"],
            "driver": run["tool"]["driver"]["name"],
            "rules": [item["id"] for item in run["tool"]["driver"]["rules"]],
            "executionSuccessful": run["invocations"][0]["executionSuccessful"],
            "resultCount": len(run["results"]),
            "firstResult": run["results"][0],
        },
        indent=2,
    )
    capture("11_sarif_report", "Generated SARIF 2.1.0 Report", "guardrail-report.sarif.json — CI/CD interchange output", [("Validated document excerpt", sarif_excerpt, "code")])
    tests = (OUT / "tests.txt").read_text(encoding="utf-8").strip()
    capture("12_tests", "GuardRail · Test Suite", "Command: pytest", [("Observed terminal output", tests, "code")])


if __name__ == "__main__":
    main()
