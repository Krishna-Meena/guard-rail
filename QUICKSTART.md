# GuardRail — Quick Start

**Requirements:** Python 3.11+  |  Run from the repository root

---

## Install

```bash
pip install -e ".[dev]"
```

---

## Test

```bash
pytest
# Expected: 120 passed
```

---

## Scan (full)

```bash
guardrail scan sample-app/
```

**Expected result:**
```
Files scanned:   4
Total findings:  11
By severity:     2 CRITICAL  9 HIGH
Est. time saved: ~2h 45m
Compliance:      PCI-DSS, RBI guidelines
Exit code:       2  (CRITICAL/HIGH present)
```

---

## Scan (CRITICAL only)

```bash
guardrail scan sample-app/ --severity CRITICAL
# → 2 findings: GR-BFSI-001, GR-BFSI-002
```

---

## Dashboard

```bash
python -m streamlit run dashboard.py
# Open: http://localhost:8501
# Click ▶ Scan  →  11 findings, severity chart, compliance grid
```

---

## Reports

Generated automatically on every scan (current directory):

| File | Format |
|---|---|
| `guardrail-report.md` | Markdown — human-readable |
| `guardrail-report.sarif.json` | SARIF 2.1.0 — machine-readable |

Pre-generated sample reports:
```bash
cat sample-app-reports/guardrail-report.md
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — no findings at threshold |
| `1` | Findings, none CRITICAL/HIGH |
| `2` | CRITICAL or HIGH findings — CI gate fails |

---

## More

- Full documentation: `docs/`
- Demo script: `DEMO_SCRIPT.md`
- Demo checklist: `docs/DEMO_CHECKLIST.md`
- Judge Q&A: `JUDGE_QA.md`
