"""
dashboard.py
~~~~~~~~~~~~
GuardRail web dashboard — Streamlit frontend.

Launch:
    cd guardrail-core
    python -m streamlit run dashboard.py

All scanning is done by the existing guardrail-core modules; this file only
adds a UI layer and never modifies any scanner, rule, or report logic.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import streamlit as st

# ---------------------------------------------------------------------------
# Ensure guardrail-core packages are importable when running from this file
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent.resolve()
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from reports import impact_summary as _impact  # noqa: E402
from reports import markdown_report, sarif_report  # noqa: E402
from rules import default_ruleset  # noqa: E402
from rules.schema import RuleSet, Severity  # noqa: E402
from scanners import count_files, scan  # noqa: E402

# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="GuardRail",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# Custom CSS — dark security-tool aesthetic
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    /* ── Base ── */
    html, body, [class*="css"] { font-family: 'Segoe UI', system-ui, sans-serif; }
    .main .block-container { padding-top: 1.4rem; padding-bottom: 2rem; max-width: 1200px; }

    /* ── Header ── */
    .gr-header { border-bottom: 1px solid #1e3a5f; padding-bottom: 0.75rem; margin-bottom: 1rem; }
    .gr-title  { font-size: 1.9rem; font-weight: 700; color: #e6edf3;
                 letter-spacing: -0.5px; margin: 0; }
    .gr-sub    { font-size: 0.85rem; color: #8b949e; margin: 0.1rem 0 0; }

    /* ── Summary cards ── */
    .gr-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 1rem 1.25rem;
        text-align: center;
    }
    .gr-card-label { font-size: 0.72rem; color: #8b949e; text-transform: uppercase;
                     letter-spacing: 0.05em; }
    .gr-card-value { font-size: 1.75rem; font-weight: 700; color: #e6edf3; line-height: 1.2; }
    .gr-card-value.pass  { color: #3fb950; }
    .gr-card-value.fail  { color: #f85149; }
    .gr-card-value.info  { color: #58a6ff; }

    /* ── Severity badges ── */
    .sev-CRITICAL { background:#3d1114; color:#f85149; padding:2px 8px; border-radius:4px;
                    font-size:0.75rem; font-weight:600; }
    .sev-HIGH     { background:#2e1d07; color:#e3b341; padding:2px 8px; border-radius:4px;
                    font-size:0.75rem; font-weight:600; }
    .sev-MEDIUM   { background:#2a2010; color:#d29922; padding:2px 8px; border-radius:4px;
                    font-size:0.75rem; font-weight:600; }
    .sev-LOW      { background:#0e2233; color:#58a6ff; padding:2px 8px; border-radius:4px;
                    font-size:0.75rem; font-weight:600; }
    .sev-INFO     { background:#1c1c1c; color:#8b949e; padding:2px 8px; border-radius:4px;
                    font-size:0.75rem; font-weight:600; }

    /* ── Findings table ── */
    .gr-table-row { border-bottom: 1px solid #21262d; }
    div[data-testid="stDataFrame"] { background: #0d1117; }

    /* ── Expander / detail panel ── */
    details summary { font-weight: 600; color: #c9d1d9; }
    details { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
               padding: 0.5rem 1rem; margin-bottom: 0.5rem; }

    /* ── Buttons ── */
    div[data-testid="stDownloadButton"] > button {
        background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
        border-radius: 6px; font-size: 0.82rem; padding: 0.3rem 0.9rem;
    }
    div[data-testid="stDownloadButton"] > button:hover { background: #30363d; }

    /* ── Section headers ── */
    .gr-section { font-size: 1.0rem; font-weight: 600; color: #c9d1d9;
                   border-bottom: 1px solid #21262d; padding-bottom: 0.3rem;
                   margin: 1.2rem 0 0.6rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Severity metadata
# ---------------------------------------------------------------------------
_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_SEV_COLOURS = {
    Severity.CRITICAL: "#f85149",
    Severity.HIGH: "#e3b341",
    Severity.MEDIUM: "#d29922",
    Severity.LOW: "#58a6ff",
    Severity.INFO: "#8b949e",
}

_SEV_BAR_COLOURS = {
    Severity.CRITICAL: "#f85149",
    Severity.HIGH: "#e3b341",
    Severity.MEDIUM: "#d29922",
    Severity.LOW: "#58a6ff",
    Severity.INFO: "#6e7681",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sev_badge(sev: str) -> str:
    return f'<span class="sev-{sev}">{sev}</span>'


def _load_ruleset() -> RuleSet:
    """Load the default ruleset, cached per session."""
    if "ruleset" not in st.session_state:
        st.session_state["ruleset"] = default_ruleset()
    return st.session_state["ruleset"]


def _run_scan(target: str) -> None:
    """Run a full scan and store results in session_state."""
    ruleset = _load_ruleset()
    with st.spinner("Scanning…"):
        files = count_files(target)
        findings = scan(target, ruleset)

    st.session_state["scan_done"] = True
    st.session_state["scan_target"] = target
    st.session_state["files_scanned"] = files
    st.session_state["findings"] = findings
    st.session_state["summary"] = _impact.compute(findings, ruleset)


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="gr-header">
      <p class="gr-title">🛡️ GuardRail</p>
      <p class="gr-sub">BFSI / FinTech Compliance &amp; Security Scanner</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Scan target + button
# ---------------------------------------------------------------------------
col_path, col_btn = st.columns([5, 1], vertical_alignment="bottom")

with col_path:
    default_target = str(_HERE / "sample-app")
    target_input = st.text_input(
        "Project directory to scan",
        value=default_target,
        placeholder="/path/to/project",
        label_visibility="visible",
    )

with col_btn:
    scan_clicked = st.button("▶ Scan", type="primary", use_container_width=True)

if scan_clicked:
    if not target_input or not Path(target_input).exists():
        st.error(f"Path not found: {target_input!r}")
    else:
        _run_scan(target_input)

# ---------------------------------------------------------------------------
# Results (only shown after a scan)
# ---------------------------------------------------------------------------
if not st.session_state.get("scan_done"):
    st.info("Enter a project directory above and click **▶ Scan** to begin.")
    st.stop()

# ── Pull state ────────────────────────────────────────────────────────────────
findings: list = st.session_state["findings"]
summary: _impact.ImpactSummary = st.session_state["summary"]
files_scanned: int = st.session_state["files_scanned"]
scan_target: str = st.session_state["scan_target"]
ruleset = _load_ruleset()

total = len(findings)
counts: Counter = Counter(f.severity for f in findings)
worst_rank = max((f.severity.rank for f in findings), default=-1)
passed = worst_rank < Severity.HIGH.rank

# ---------------------------------------------------------------------------
# 4 — Summary cards
# ---------------------------------------------------------------------------
st.markdown('<p class="gr-section">Scan Summary</p>', unsafe_allow_html=True)

c1, c2, c3, c4 = st.columns(4)

with c1:
    verdict = "PASS" if passed else "FAIL"
    vclass = "pass" if passed else "fail"
    st.markdown(
        f'<div class="gr-card"><div class="gr-card-label">Status</div>'
        f'<div class="gr-card-value {vclass}">{verdict}</div></div>',
        unsafe_allow_html=True,
    )

with c2:
    st.markdown(
        f'<div class="gr-card"><div class="gr-card-label">Files Scanned</div>'
        f'<div class="gr-card-value info">{files_scanned}</div></div>',
        unsafe_allow_html=True,
    )

with c3:
    st.markdown(
        f'<div class="gr-card"><div class="gr-card-label">Total Findings</div>'
        f'<div class="gr-card-value {"fail" if total else "pass"}">{total}</div></div>',
        unsafe_allow_html=True,
    )

with c4:
    time_saved = summary.time_saved_line()
    st.markdown(
        f'<div class="gr-card"><div class="gr-card-label">Est. Review Time Saved</div>'
        f'<div class="gr-card-value info">{time_saved}</div></div>',
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------------
# 5 — Severity overview chart
# ---------------------------------------------------------------------------
if total > 0:
    st.markdown('<p class="gr-section">Severity Overview</p>', unsafe_allow_html=True)

    import pandas as pd

    sev_labels = [s.value for s in _SEVERITY_ORDER if counts.get(s, 0) > 0]
    sev_values = [counts.get(s, 0) for s in _SEVERITY_ORDER if counts.get(s, 0) > 0]
    sev_colors = [_SEV_BAR_COLOURS[s] for s in _SEVERITY_ORDER if counts.get(s, 0) > 0]

    chart_df = pd.DataFrame({"Severity": sev_labels, "Count": sev_values})

    # Use Streamlit's built-in bar chart with color mapping
    col_chart, col_breakdown = st.columns([2, 1])

    with col_chart:
        # Build a simple vega-lite spec via st.vega_lite_chart for colour control
        vega_spec = {
            "mark": {"type": "bar", "cornerRadiusTopLeft": 4, "cornerRadiusTopRight": 4},
            "encoding": {
                "x": {
                    "field": "Severity",
                    "type": "ordinal",
                    "sort": sev_labels,
                    "axis": {
                        "labelColor": "#8b949e",
                        "titleColor": "#8b949e",
                        "gridColor": "#21262d",
                    },
                },
                "y": {
                    "field": "Count",
                    "type": "quantitative",
                    "axis": {
                        "labelColor": "#8b949e",
                        "titleColor": "#8b949e",
                        "gridColor": "#21262d",
                        "tickMinStep": 1,
                    },
                },
                "color": {
                    "field": "Severity",
                    "type": "ordinal",
                    "scale": {
                        "domain": sev_labels,
                        "range": sev_colors,
                    },
                    "legend": None,
                },
                "tooltip": [
                    {"field": "Severity", "type": "ordinal"},
                    {"field": "Count", "type": "quantitative"},
                ],
            },
            "config": {
                "background": "#0d1117",
                "view": {"stroke": None},
                "axis": {"domainColor": "#30363d"},
            },
        }
        st.vega_lite_chart(chart_df, vega_spec, width="stretch")

    with col_breakdown:
        st.markdown("**Breakdown**")
        for sev in _SEVERITY_ORDER:
            c = counts.get(sev, 0)
            if c:
                st.markdown(
                    f"{_sev_badge(sev.value)}&nbsp;&nbsp;<b>{c}</b>",
                    unsafe_allow_html=True,
                )
        st.markdown(
            f"<br><span style='color:#8b949e;font-size:0.8rem;'>"
            f"Compliance: {summary.coverage_line()}</span>",
            unsafe_allow_html=True,
        )

# ---------------------------------------------------------------------------
# 6 — Findings table
# ---------------------------------------------------------------------------
if total > 0:
    st.markdown('<p class="gr-section">Findings</p>', unsafe_allow_html=True)

    import pandas as pd

    rows = []
    for f in findings:
        try:
            rule = ruleset.by_id(f.rule_id)
            title = rule.name
            compliance = ", ".join(rule.frameworks[:2]) if rule.frameworks else "—"
        except KeyError:
            title = f.rule_id
            compliance = "—"

        try:
            rel = f.file.relative_to(Path(scan_target))
        except ValueError:
            rel = f.file

        rows.append(
            {
                "Severity": f.severity.value,
                "Rule ID": f.rule_id,
                "Title": title,
                "File": str(rel).replace("\\", "/"),
                "Line": f.line,
                "Compliance": compliance,
            }
        )

    df = pd.DataFrame(rows)

    # Colour map for severity column
    def _colour_row(row: pd.Series) -> list[str]:  # type: ignore[type-arg]
        sev = row.get("Severity", "")
        colour_map = {
            "CRITICAL": "color: #f85149",
            "HIGH": "color: #e3b341",
            "MEDIUM": "color: #d29922",
            "LOW": "color: #58a6ff",
            "INFO": "color: #8b949e",
        }
        style = colour_map.get(sev, "")
        return [style if col == "Severity" else "" for col in row.index]

    styled_df = df.style.apply(_colour_row, axis=1)
    st.dataframe(styled_df, width="stretch", hide_index=True)

# ---------------------------------------------------------------------------
# 7 — Finding details (expandable)
# ---------------------------------------------------------------------------
if total > 0:
    st.markdown('<p class="gr-section">Finding Details</p>', unsafe_allow_html=True)

    for f in findings:
        try:
            rule = ruleset.by_id(f.rule_id)
            title = rule.name
            compliance = rule.frameworks
            description = rule.explanation if hasattr(rule, "explanation") else f.explanation
        except KeyError:
            title = f.rule_id
            compliance = []
            description = f.explanation

        try:
            rel = f.file.relative_to(Path(scan_target))
        except ValueError:
            rel = f.file

        label = f"{f.severity.value}  ·  {f.rule_id}  ·  {title}"
        with st.expander(label, expanded=False):
            d1, d2 = st.columns(2)
            with d1:
                st.markdown(f"**Rule ID:** `{f.rule_id}`")
                st.markdown(f"**Severity:** {_sev_badge(f.severity.value)}", unsafe_allow_html=True)
                st.markdown(f"**File:** `{str(rel).replace(chr(92), '/')}`  line **{f.line}**")
            with d2:
                if compliance:
                    st.markdown(f"**Compliance:** {', '.join(compliance)}")
                else:
                    st.markdown("**Compliance:** —")
                if f.match_text:
                    st.markdown(f"**Match:** `{f.match_text.strip()[:120]}`")

            st.markdown(f"**Description:** {f.explanation.strip()}")
            st.markdown(f"**Fix:** {f.fix.strip()}")

# ---------------------------------------------------------------------------
# 8 — Compliance section
# ---------------------------------------------------------------------------
st.markdown('<p class="gr-section">Compliance Coverage</p>', unsafe_allow_html=True)

# Collect ALL distinct frameworks from the RULESET (not just triggered rules)
all_frameworks: set[str] = set()
for rule in ruleset.rules:
    all_frameworks.update(rule.frameworks)

triggered_rule_ids = {f.rule_id for f in findings}
triggered_frameworks: set[str] = set()
for rid in triggered_rule_ids:
    try:
        triggered_frameworks.update(ruleset.by_id(rid).frameworks)
    except KeyError:
        pass

if all_frameworks:
    import pandas as pd

    fw_rows = []
    for fw in sorted(all_frameworks):
        fw_rows.append(
            {
                "Framework": fw,
                "Triggered": "⚠️ Yes" if fw in triggered_frameworks else "✅ No findings",
            }
        )
    fw_df = pd.DataFrame(fw_rows)
    st.dataframe(fw_df, width="stretch", hide_index=True)
else:
    st.info("No compliance frameworks defined in the active ruleset.")

# ---------------------------------------------------------------------------
# 9 — Reports (download buttons)
# ---------------------------------------------------------------------------
st.markdown('<p class="gr-section">Reports</p>', unsafe_allow_html=True)

_col_md, _col_sarif, _spacer = st.columns([1, 1, 4])

with _col_md:
    md_content = markdown_report.render(findings, ruleset, scan_root=scan_target)
    st.download_button(
        label="⬇ Markdown Report",
        data=md_content.encode("utf-8"),
        file_name="guardrail-report.md",
        mime="text/markdown",
        use_container_width=True,
    )

with _col_sarif:
    sarif_doc = sarif_report.render(findings, ruleset, scan_root=scan_target)
    sarif_content = json.dumps(sarif_doc, indent=2, ensure_ascii=False)
    st.download_button(
        label="⬇ SARIF JSON",
        data=sarif_content.encode("utf-8"),
        file_name="guardrail-report.sarif.json",
        mime="application/json",
        use_container_width=True,
    )

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown(
    """
    <hr style="border:none; border-top:1px solid #21262d; margin-top:2rem;">
    <p style="text-align:center; color:#484f58; font-size:0.75rem; margin:0.4rem 0 1rem;">
        GuardRail · BFSI/FinTech Compliance &amp; Security Scanner · v0.1.0
    </p>
    """,
    unsafe_allow_html=True,
)
