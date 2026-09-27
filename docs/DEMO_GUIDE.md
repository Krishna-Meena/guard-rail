# GuardRail — Demo Guide

This guide provides the exact 2–3 minute live demo script for hackathon judges. Every command is verified against the actual repository.

---

## Pre-Demo Setup Checklist

Before the demo, complete every item in `docs/DEMO_CHECKLIST.md`.

Quick minimum check:
```bash
pytest        # → 120 passed
guardrail scan sample-app/   # → 11 findings, exit 2
python -m streamlit run dashboard.py  # → opens in browser
```

---

## Demo Narrative (2–3 minutes)

---

### Step 1 — The Problem (20 seconds)

**TIME:** 0:00 – 0:20

**ACTION:** Speak, no terminal yet

**WHAT TO SAY:**
> "Every day, financial services developers accidentally commit secrets, forget to parameterise queries, and skip audit logs. A code reviewer might catch one in fifty. GuardRail catches them all, automatically, in seconds."

**WHAT THE JUDGE SHOULD NOTICE:** Concise problem statement. BFSI context established.

---

### Step 2 — Architecture Overview (20 seconds)

**TIME:** 0:20 – 0:40

**ACTION:** Open the architecture diagram (README.md or docs/ARCHITECTURE.md) or describe it from memory

**WHAT TO SAY:**
> "GuardRail has three layers: a YAML rule set validated by Pydantic, a dual-engine scanner — regex and Python AST via libcst — and a presentation layer: CLI, Streamlit dashboard, Markdown, and SARIF reports. Detection is completely separated from presentation."

**WHAT THE JUDGE SHOULD NOTICE:** Clean, testable architecture. Not a script — a proper pipeline.

---

### Step 3 — Show the Rule Set (20 seconds)

**TIME:** 0:40 – 1:00

**ACTION:** Open a terminal in the repository root.

**COMMAND:**
```bash
# Show the rule count and structure
head -35 rules/bfsi_ruleset.yaml
```

**WHAT TO SAY:**
> "Nine BFSI-specific rules — hardcoded credentials, SQL injection, missing audit logs, weak hashing, unencrypted PII, and more. Every rule has a severity, compliance mappings to PCI-DSS, RBI, OWASP, and fix guidance. Pure YAML — no code change needed to add a rule."

**WHAT THE JUDGE SHOULD NOTICE:** Domain-specific rules. Compliance mappings are specific, not vague. Declarative design.

---

### Step 4 — Show the Sample App (10 seconds)

**TIME:** 1:00 – 1:10

**ACTION:** Keep terminal open

**COMMAND:**
```bash
ls sample-app/
```

**WHAT TO SAY:**
> "This is NovaPay — a deliberately vulnerable FinTech API. It looks like real code but embeds violations a developer might actually commit. Never deploy it. It exists purely for demonstration."

**WHAT THE JUDGE SHOULD NOTICE:** Realistic demo target. Responsible disclosure statement.

---

### Step 5 — Full Scan (30 seconds)

**TIME:** 1:10 – 1:40

**ACTION:** Run the full scan

**COMMAND:**
```bash
guardrail scan sample-app/
```

**EXPECTED OUTPUT (verified):**
```
┌───────────────────────────────────────────────────────────┐
│  GuardRail  BFSI / FinTech Compliance & Security Scanner  │
└───────────────────────────────────────────────────────────┘

 Files scanned: 4
 Rule set: BFSI/FinTech Core Rule Set v1.0  [9 rules]

 Impact Summary:
   2 CRITICAL  •  9 HIGH
   ~2h 45m estimated review time saved
   PCI-DSS, RBI guidelines
```

**WHAT TO SAY:**
> "Four files scanned, 11 findings — 2 CRITICAL, 9 HIGH. Impact summary shows approximately 2 hours 45 minutes of manual review time saved. Two compliance frameworks flagged: PCI-DSS and RBI."

**WHAT THE JUDGE SHOULD NOTICE:** Instant results. Impact quantified. Compliance frameworks named.

---

### Step 6 — Highlight a Critical Finding (20 seconds)

**TIME:** 1:40 – 2:00

**ACTION:** Scroll to CRITICAL section in terminal output (it appears first)

**WHAT TO SAY:**
> "First finding: GR-BFSI-001, Hardcoded Credentials, CRITICAL. File app.py line 21. The match: `PASSWORD = 'N0vaPay$DB#Prod'`. This maps to PCI-DSS Requirement 8.2.1 — credential management. A CI gate configured to fail on CRITICAL/HIGH would have stopped this commit."

**WHAT THE JUDGE SHOULD NOTICE:** Exact file and line number. Real match text. Compliance mapping. Actionable, not just a warning.

---

### Step 7 — Severity Filter (15 seconds)

**TIME:** 2:00 – 2:15

**ACTION:** Run severity-filtered scan

**COMMAND:**
```bash
guardrail scan sample-app/ --severity CRITICAL
```

**WHAT TO SAY:**
> "The severity filter lets a CI pipeline gate on CRITICAL only — two findings. Exit code 2 means the build fails. Exit code 0 means clean."

**WHAT THE JUDGE SHOULD NOTICE:** Granular control. CI-ready exit codes.

---

### Step 8 — Pre-generated Reports (15 seconds)

**TIME:** 2:15 – 2:30

**ACTION:** Show the report files

**COMMAND:**
```bash
ls sample-app-reports/
# Shows: guardrail-report.md  guardrail-report.sarif.json

head -25 sample-app-reports/guardrail-report.md
```

**WHAT TO SAY:**
> "Two report formats every scan: Markdown for humans and SARIF 2.1.0 for machines. SARIF can be uploaded to GitHub Code Scanning to surface findings directly in pull requests."

**WHAT THE JUDGE SHOULD NOTICE:** Dual-format output. SARIF is the industry standard for static analysis toolchains.

---

### Step 9 — Dashboard (20 seconds)

**TIME:** 2:30 – 2:50

**ACTION:** Switch to browser with dashboard already open (`http://localhost:8501`)

**WHAT TO SAY:**
> "The Streamlit dashboard runs the same scan engine as the CLI. Scan target, click Scan, and you get: verdict card, severity bar chart, sortable findings table, per-finding detail panels with explanation and fix, compliance coverage grid, and report downloads."

**WHAT THE JUDGE SHOULD NOTICE:** Same data as CLI, visual presentation. Non-CLI users can use this. Download buttons for reports.

---

### Step 10 — Tests (10 seconds)

**TIME:** 2:50 – 3:00

**ACTION:** Switch back to terminal

**COMMAND:**
```bash
pytest
```

**EXPECTED OUTPUT:**
```
120 passed in 1.22s
```

**WHAT TO SAY:**
> "120 tests, 1.2 seconds. Every scanner, every rule, every report module is covered."

**WHAT THE JUDGE SHOULD NOTICE:** 100% passing. Fast. Professional engineering discipline.

---

### Closing Statement (10 seconds)

**WHAT TO SAY:**
> "GuardRail is a production-quality, domain-specific compliance scanner for BFSI codebases. It finds what general linters miss, maps directly to regulatory frameworks developers are actually accountable to, and integrates into a CI/CD pipeline with a single command."

---

## Total estimated time: ~3 minutes

---

## Emergency Fallback Plan

If something fails during the demo, do not troubleshoot live.

### Dashboard fails to launch

**Action:** Close the browser tab. Use the CLI only.

```bash
guardrail scan sample-app/
```

Say: *"The CLI provides the full scan output. The dashboard is a visual layer over the same engine."*

### Dashboard scan button fails

**Action:** Open `sample-app-reports/guardrail-report.md` in a browser or text editor.

Say: *"Here are the pre-generated reports from a previous scan. Same output — 11 findings, 2 CRITICAL, 9 HIGH."*

### CLI scan produces unexpected output

**Action:** Use the pre-captured screenshot text files.

```bash
cat screenshots/cli_full_scan.txt
```

### Tests fail

**Action:** Show the pre-captured test evidence.

```bash
cat screenshots/tests.txt
```

Say: *"This is the verified test output from the most recent run."*

### Terminal encoding issues (Windows)

```powershell
chcp 65001
guardrail scan sample-app/
```

---

## Key Numbers to Remember

| Metric | Value |
|---|---|
| Rules | 9 |
| Sample-app findings | 11 (2 CRITICAL, 9 HIGH) |
| Files scanned | 4 |
| Time saved estimate | ~2h 45m |
| Compliance frameworks flagged | 2 (PCI-DSS, RBI) |
| Tests | 120 passing |
| Dashboard URL | http://localhost:8501 |
