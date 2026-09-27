# GuardRail Dashboard Guide

The GuardRail dashboard is a Streamlit web application that provides an interactive graphical interface over the same scan engine used by the CLI. It is intended for users who prefer a visual interface or need to present scan results to a non-technical audience.

---

## Prerequisites

Streamlit must be installed. It is included in the standard dependencies:

```bash
pip install -r requirements.txt
# or
pip install -e ".[dev]"
```

---

## Launching the Dashboard

```bash
python -m streamlit run dashboard.py
```

Streamlit will print a local URL (typically `http://localhost:8501`). Open this URL in any modern browser.

> **Note:** The dashboard runs entirely locally. No data is sent to external services.

---

## Interface Overview

### Header

The top of the page displays the GuardRail name and subtitle:

```
🛡️ GuardRail
BFSI / FinTech Compliance & Security Scanner
```

---

### Scan Controls

Two controls appear at the top of the page:

| Control | Description |
|---|---|
| **Project directory to scan** (text input) | Path to the directory or file to scan. Defaults to the `sample-app/` directory in this repository. Any valid file system path may be entered. |
| **▶ Scan** (primary button) | Executes the scan using the built-in BFSI/FinTech rule set. Results are cached in the Streamlit session until a new scan is run. |

To scan a different target, edit the path field and click **▶ Scan** again.

---

### Summary Cards (post-scan)

After a scan completes, a row of metric cards appears:

| Card | Value shown |
|---|---|
| **Result** | `PASS` (green) if no CRITICAL/HIGH findings; `FAIL` (red) if any CRITICAL or HIGH findings present |
| **Findings** | Total finding count across all severities |
| **Files scanned** | Number of eligible (non-binary, ≤1 MiB) files examined |
| **Time saved** | Estimated manual review time saved (~2h 45m for 11 CRITICAL/HIGH findings) |

---

### Severity Bar Chart

A Vega-Lite horizontal bar chart displays the count of findings per severity level. Only severity levels with at least one finding are shown. Colour coding:

| Severity | Colour |
|---|---|
| CRITICAL | Red (`#f85149`) |
| HIGH | Amber (`#e3b341`) |
| MEDIUM | Yellow (`#d29922`) |
| LOW | Blue (`#58a6ff`) |
| INFO | Grey (`#8b949e`) |

---

### Per-Severity Count Badges

Below the chart, individual severity badges show the count per level:

```
CRITICAL  2    HIGH  9    MEDIUM  0    LOW  0    INFO  0
```

---

### Findings Table

A styled, scrollable DataFrame showing all findings. Columns:

| Column | Description |
|---|---|
| Severity | Coloured severity badge |
| Rule ID | GuardRail rule identifier (e.g., `GR-BFSI-001`) |
| Rule | Rule name (e.g., `Hardcoded Credentials`) |
| File | File path relative to the scan target |
| Line | 1-based line number |
| Compliance | First two compliance framework references for the rule |

Row colours match the severity of each finding. The table is interactive — click column headers to sort.

---

### Finding Detail Panels

Below the findings table, each finding is listed as an expandable panel. Click to expand:

**Panel label:** `SEVERITY  ·  GR-BFSI-NNN  ·  Rule Name`

**Expanded content:**

| Field | Content |
|---|---|
| **File / Line** | Relative path and line number |
| **Match** | The triggering code snippet (if available) |
| **Explanation** | Full plain-language description of the risk |
| **Fix** | Concrete remediation guidance |
| **Compliance** | All compliance framework references for the rule |

---

### Compliance Coverage Grid

A section titled **Compliance Coverage** shows a table of all regulatory frameworks referenced in the rule set, with a column indicating whether any triggered finding maps to each framework.

| Column | Description |
|---|---|
| Framework | Compliance framework name |
| Status | ✅ Triggered (finding maps to this framework) or — Not triggered |
| Rules covering it | Which rule IDs reference this framework |

This section is useful for demonstrating regulatory breadth to reviewers and judges.

---

### Download Buttons

Two download buttons appear at the bottom of the scan results:

| Button | File downloaded | Format |
|---|---|---|
| **Download Markdown Report** | `guardrail-report.md` | Markdown |
| **Download SARIF Report** | `guardrail-report.sarif.json` | SARIF 2.1.0 JSON |

The downloaded content is generated from the current scan session's findings. These files are not written to disk by the dashboard (unlike the CLI); they are delivered only via the browser download.

---

## Demo Usage (Quick Reference)

```bash
# Launch from the repository root
python -m streamlit run dashboard.py

# In browser:
# 1. Confirm scan target shows sample-app/ path
# 2. Click ▶ Scan
# 3. Review summary cards (FAIL, 11 findings, ~2h 45m)
# 4. Review severity bar chart
# 5. Review findings table
# 6. Expand GR-BFSI-001 to show hardcoded credentials detail
# 7. Review compliance coverage grid
# 8. Click Download Markdown Report
```

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| `ModuleNotFoundError: streamlit` | Streamlit not installed | `pip install streamlit` or `pip install -e ".[dev]"` |
| Dashboard loads but **▶ Scan** does nothing | JavaScript not enabled in browser | Use a standard browser (Chrome, Firefox, Edge) |
| Scan shows 0 findings | Wrong path entered | Verify the path points to a directory containing Python or JS source files |
| `No module named 'scanners'` | Dashboard run from wrong directory | Run `python -m streamlit run dashboard.py` from the repository root |
| Port 8501 already in use | Another Streamlit instance is running | `python -m streamlit run dashboard.py --server.port 8502` |
