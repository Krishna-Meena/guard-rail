# GuardRail — Demo Script

This is the concise 2–3 minute live demo script. All commands are verified against the actual repository.

> Full demo guide with timing, judge cues, and fallback plan: `docs/DEMO_GUIDE.md`

---

## Pre-Demo Setup (do this before the presentation)

```bash
# Verify tests pass
pytest
# → 120 passed

# Verify CLI works
guardrail scan sample-app/ --no-report
# → 11 findings

# Launch dashboard (leave running)
python -m streamlit run dashboard.py
# → http://localhost:8501
```

---

## The Demo

### 1. Problem (20 s — speak only)

> "Every day, financial services developers commit hardcoded secrets, forget to parameterise queries, skip audit logs. General-purpose linters miss these. GuardRail is domain-specific — it catches BFSI violations automatically and maps them to PCI-DSS and RBI requirements."

---

### 2. Show the Rule Set (20 s)

```bash
head -35 rules/bfsi_ruleset.yaml
```

> "Nine BFSI-specific rules — pure YAML, validated by Pydantic. Severity, compliance mappings, explanation, fix guidance. No code change needed to add a rule."

---

### 3. Full Scan (30 s)

```bash
guardrail scan sample-app/
```

> "Four files, 11 findings — 2 CRITICAL, 9 HIGH. Impact summary: approximately 2 hours 45 minutes of manual review time saved. Two compliance frameworks flagged: PCI-DSS and RBI IT Framework."

Point to: `GR-BFSI-001  Hardcoded Credentials  app.py:21  PASSWORD = "N0vaPay$DB#Prod"`

> "Exact file, exact line, exact match text, exact compliance requirement: PCI-DSS Requirement 8.2.1. Exit code 2 — a CI gate configured on this would have stopped this commit."

---

### 4. Severity Filter (15 s)

```bash
guardrail scan sample-app/ --severity CRITICAL
```

> "Filter to CRITICAL only — two findings. Exit code 0 for clean scans, code 2 for CRITICAL/HIGH. One flag and it's a CI gate."

---

### 5. Reports (15 s)

```bash
ls sample-app-reports/
```

> "Two reports every scan: Markdown for humans, SARIF 2.1.0 for machines. SARIF uploads directly to GitHub Code Scanning — findings appear as PR annotations."

---

### 6. Dashboard (20 s)

*Switch to browser at http://localhost:8501*

> "Same scan engine, graphical interface. Scan target, click Scan: verdict card, severity bar chart, sortable findings table, per-finding detail with full explanation and fix, compliance coverage grid, and direct report downloads."

---

### 7. Tests (10 s)

```bash
pytest
```

> "120 tests, 1.2 seconds. Every scanner, every rule, every report module covered."

---

### Closing (10 s)

> "GuardRail is a production-quality, domain-specific compliance scanner. It finds what general linters miss, maps directly to the regulatory frameworks BFSI developers are accountable to, and integrates into CI/CD with a single command."

---

## Emergency Fallback

| Failure | Recovery |
|---|---|
| Dashboard won't start | CLI only — `guardrail scan sample-app/` |
| CLI garbled (Windows) | `chcp 65001` then re-run |
| Unexpected findings count | `cat screenshots/cli_full_scan.txt` |
| Tests fail | `cat screenshots/tests.txt` |

**Rule:** Never troubleshoot live. Use pre-captured evidence and keep moving.

---

## Key Numbers

| Fact | Value |
|---|---|
| Rules | 9 |
| Sample-app findings | 11 (2 CRITICAL, 9 HIGH) |
| Files scanned | 4 |
| Time saved estimate | ~2h 45m |
| Compliance frameworks flagged | 2 (PCI-DSS, RBI guidelines) |
| Test count | 120 passing |
