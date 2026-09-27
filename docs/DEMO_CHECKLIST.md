# GuardRail — Demo Checklist

Printable pre-demo preparation checklist. Check every item before presenting.

---

## BEFORE THE DEMO

### Environment

- [ ] Repository is open in file manager / editor
- [ ] Correct Python virtual environment is activated
- [ ] `guardrail --help` returns expected output (no error)
- [ ] All dependencies installed: `pip install -e ".[dev]"` completed without errors

### Verification

- [ ] Tests pass: `pytest` → **120 passed**
- [ ] CLI tested: `guardrail scan sample-app/` → **11 findings, 2 CRITICAL, 9 HIGH**
- [ ] Severity filter tested: `guardrail scan sample-app/ --severity CRITICAL` → **2 findings**
- [ ] Dashboard tested: `python -m streamlit run dashboard.py` → opens at http://localhost:8501
- [ ] Dashboard scan verified: clicked **▶ Scan** → results loaded correctly

### Files

- [ ] `sample-app/` directory is present and contains `app.py`, `db.py`, `models.py`
- [ ] Pre-generated reports available: `sample-app-reports/guardrail-report.md`
- [ ] Pre-generated reports available: `sample-app-reports/guardrail-report.sarif.json`
- [ ] Fallback screenshots available: `screenshots/cli_full_scan.txt`

### System

- [ ] Browser is open to http://localhost:8501 (Streamlit dashboard loaded)
- [ ] Terminal window is open in the repository root
- [ ] Terminal font size is readable from a distance (14pt minimum)
- [ ] Notifications disabled (Do Not Disturb / Focus mode on)
- [ ] Unrelated applications closed or minimised
- [ ] Screen resolution / zoom appropriate for the display

---

## DURING THE DEMO

Work through these beats in order. Do not skip ahead.

### Introduction

- [ ] State the problem: security reviews in BFSI/FinTech are slow and inconsistent
- [ ] State GuardRail's purpose in one sentence
- [ ] Mention the BFSI/FinTech regulatory context (PCI-DSS, RBI, SEBI)

### Architecture

- [ ] Explain the three-layer architecture: rules → detection engines → presentation
- [ ] Mention the YAML rule set, dual-engine detection (regex + AST), and report formats
- [ ] Note the separation of detection from presentation

### Rules

- [ ] Show or describe the 9 BFSI-specific rules
- [ ] Highlight compliance framework mappings (PCI-DSS, RBI IT Framework, OWASP)
- [ ] Show that rules are declarative YAML — no code change needed to add a rule

### Sample App

- [ ] Identify `sample-app/` as NovaPay — deliberately vulnerable, never deploy
- [ ] Mention it embeds violations that look like real developer mistakes

### Full Scan

- [ ] Run: `guardrail scan sample-app/`
- [ ] Point out the Impact Summary: **11 findings, 2 CRITICAL, 9 HIGH**
- [ ] Point out the time estimate: **~2h 45m**
- [ ] Point out the compliance coverage: **PCI-DSS, RBI guidelines**

### Critical Finding

- [ ] Highlight GR-BFSI-001: file, line number, exact match text
- [ ] State the compliance mapping: PCI-DSS Requirement 8.2.1
- [ ] State the CI implication: exit code 2 → build fails

### SARIF / Reports

- [ ] Mention both report files: `guardrail-report.md` and `guardrail-report.sarif.json`
- [ ] Explain SARIF: industry standard, GitHub Code Scanning compatible
- [ ] Do NOT claim tested GitHub Actions integration unless asked

### Severity Filter

- [ ] Run: `guardrail scan sample-app/ --severity CRITICAL`
- [ ] Show it returns only 2 findings
- [ ] Explain the exit code convention (0 / 1 / 2)

### Dashboard

- [ ] Switch to browser: http://localhost:8501
- [ ] Click **▶ Scan** (or describe pre-loaded results)
- [ ] Show: verdict card, severity chart, findings table, finding detail panel
- [ ] Show: compliance coverage grid
- [ ] Show: Download Markdown / Download SARIF buttons

### Validation

- [ ] Run: `pytest` → **120 passed**
- [ ] State what the tests cover: all scanners, rules, reports

---

## AFTER THE DEMO

### Q&A

- [ ] Ready to explain the architecture in more depth
- [ ] Ready to explain why deterministic rules (not AI inference) in the scan engine
- [ ] Ready to explain each compliance framework mapping
- [ ] Ready to explain the impact metric methodology (15 min × findings)
- [ ] Ready to explain the roadmap (semgrep, suppression comments, VS Code extension)

### Responsible Statements

- [ ] Do NOT claim GuardRail provides legal compliance certification
- [ ] Do NOT claim GuardRail replaces security engineers
- [ ] Do NOT claim the CI/CD integration has been tested against live GitHub Actions runners
- [ ] Do NOT claim the 2h 45m figure represents measured productivity data
- [ ] DO say that compliance mappings indicate *relevance to* requirements, not certification

---

## Fallback Reference

| Scenario | Action |
|---|---|
| Dashboard fails | Use CLI only — same results |
| CLI output garbled | `chcp 65001` then re-run |
| Unexpected 0 findings | Check that the terminal is at the repository root |
| Need to show reports | `cat sample-app-reports/guardrail-report.md` |
| Need to show test results | `cat screenshots/tests.txt` |
| Need to show scan output | `cat screenshots/cli_full_scan.txt` |
