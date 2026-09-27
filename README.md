# GuardRail

**BFSI / FinTech Compliance & Security Scanner**

[![Live Demo](https://img.shields.io/badge/🛡️_Live_Demo-Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://guard-rail.streamlit.app)
[![Tests](https://img.shields.io/badge/tests-120_passing-brightgreen?style=flat-square)](https://github.com/Krishna-Meena/guard-rail/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](https://opensource.org/licenses/MIT)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-informational?style=flat-square)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)

> Catch production-grade security and compliance violations in financial-services codebases before they reach production — in seconds, not sprints.

**[▶ Try the Live Dashboard](https://guard-rail.streamlit.app)** · [Quick Start](QUICKSTART.md) · [Demo Script](DEMO_SCRIPT.md) · [Judge Q&A](JUDGE_QA.md)

---

## Table of Contents

1. [Problem](#problem)
2. [Solution](#solution)
3. [Key Capabilities](#key-capabilities)
4. [Architecture](#architecture)
5. [Repository Structure](#repository-structure)
6. [Installation](#installation)
7. [CLI Usage](#cli-usage)
8. [Severity Filtering](#severity-filtering)
9. [Dashboard](#dashboard)
10. [Streamlit Cloud Deployment](#streamlit-cloud-deployment)
11. [Reports](#reports)
12. [Exit Codes](#exit-codes)
13. [Rule Set](#rule-set)
14. [Sample Application](#sample-application)
15. [Validation & Test Results](#validation--test-results)
16. [Example Output](#example-output)
17. [CI/CD Integration](#cicd-integration)
18. [Compliance Mapping](#compliance-mapping)
19. [Impact Metric Methodology](#impact-metric-methodology)
20. [Limitations](#limitations)
21. [Security & Disclaimer](#security--disclaimer)
22. [Roadmap](#roadmap)
23. [Hackathon Demo](#hackathon-demo)

---

## Problem

Security reviews in Banking, Financial Services, and Insurance (BFSI) and FinTech organisations are expensive, slow, and inconsistent. A single CRITICAL vulnerability — a hardcoded database password, an un-parameterised SQL query, disabled TLS verification — can result in a regulatory breach, mandatory disclosure to the RBI or SEBI, PCI-DSS audit failure, and direct financial loss.

Existing general-purpose linters (bandit, semgrep community rules) are not domain-aware: they flag generic Python issues but do not surface BFSI-specific risk patterns, provide compliance-framework mappings, or present findings in a format that a developer, compliance officer, or security engineer can act on immediately.

---

## Solution

GuardRail is a **domain-specific static analysis tool** designed for BFSI/FinTech codebases. It combines:

- A curated, YAML-driven rule set covering the nine most critical BFSI violation categories
- Dual-engine detection (regex + Python AST)
- Compliance mapping to PCI-DSS, RBI IT Framework, OWASP, SEBI CSCRF, ISO 27001, NIST, GDPR, and DPDP Act 2023
- A rich terminal CLI with colour-coded findings and an actionable impact summary
- Structured SARIF 2.1.0 output for integration with GitHub Code Scanning, VS Code, and other security toolchains
- An interactive Streamlit dashboard for non-CLI users

---

## Key Capabilities

| Capability | Detail |
|---|---|
| 9 BFSI-specific rules | Hardcoded credentials, SQL injection, missing input validation, weak hashing, missing audit logs, unencrypted PII, missing rate-limiting, dangerous eval/exec, disabled TLS verification |
| Dual detection engine | Regex scanner for pattern-based rules; Python AST scanner for structural patterns (eval, subprocess shell=True, SSL attribute assignments) |
| Compliance mapping | Every finding maps to one or more of: PCI-DSS v4.0, RBI IT Framework, OWASP Top 10, SEBI CSCRF, ISO 27001, NIST SP 800-131A, CWE, GDPR, DPDP Act 2023 |
| Severity tiers | CRITICAL / HIGH / MEDIUM / LOW / INFO with ordered filtering |
| Markdown report | Human-readable, developer-friendly report with fix guidance |
| SARIF 2.1.0 report | Machine-readable for IDE and CI integration |
| Impact summary | Estimated manual review time saved (15 min/CRITICAL-HIGH finding) and compliance framework coverage |
| Streamlit dashboard | Interactive web UI for scan execution, visualisation, and report download |
| 120 automated tests | Unit + integration test suite covering every scanner, rule, and report module |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Input (Target)                          │
│                  File, Directory, or Path Glob                  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    scanners/walker.py                           │
│  - Discovers eligible files (non-binary, ≤1 MiB)               │
│  - Skips build / VCS / vendor directories                       │
│  - Matches each file against rule file_glob                     │
│  - Dispatches to appropriate engine per rule.detection.type     │
└────────────────┬────────────────────────────┬───────────────────┘
                 │ DetectionType.REGEX        │ DetectionType.AST
                 ▼                            ▼
┌────────────────────────┐   ┌───────────────────────────────────┐
│  scanners/             │   │  scanners/                        │
│  regex_scanner.py      │   │  ast_scanner.py                   │
│  Line-by-line regex    │   │  libcst-based AST traversal       │
│  pattern matching      │   │  (eval, exec, subprocess, SSL)    │
└────────────┬───────────┘   └─────────────────┬─────────────────┘
             │                                  │
             └────────────┬─────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    scanners/models.py                           │
│  Finding(file, line, rule_id, severity, explanation, fix,       │
│          match_text)                                            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ▼                           ▼
┌─────────────────────────┐   ┌───────────────────────────────────┐
│  CLI (cli/main.py)      │   │  Dashboard (dashboard.py)         │
│  Rich terminal output   │   │  Streamlit web interface          │
│  Impact summary panel   │   │  Interactive findings table       │
│  Findings by severity   │   │  Severity bar chart               │
│  Scan metadata          │   │  Compliance coverage grid         │
└──────────┬──────────────┘   └──────────────┬────────────────────┘
           │                                  │
           └──────────────┬───────────────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
┌─────────────────────┐   ┌───────────────────────────────────────┐
│  reports/           │   │  reports/                             │
│  markdown_report.py │   │  sarif_report.py                      │
│  guardrail-report   │   │  guardrail-report.sarif.json          │
│  .md                │   │  (SARIF 2.1.0)                        │
└─────────────────────┘   └───────────────────────────────────────┘
```

**Rules are loaded from** `rules/bfsi_ruleset.yaml`, validated by the Pydantic schema in `rules/schema.py`. Detection logic, presentation, and rule definitions are fully separated: scanners emit `Finding` objects with no knowledge of report format; reporters consume `Finding` lists with no knowledge of detection.

---

## Repository Structure

```
guard-rail/
├── cli/
│   └── main.py              # guardrail CLI entry point (Click)
├── scanners/
│   ├── walker.py            # File discovery + scan orchestration
│   ├── regex_scanner.py     # Line-by-line regex engine
│   ├── ast_scanner.py       # libcst AST engine (Python)
│   ├── base.py              # Abstract scanner base class
│   └── models.py            # Finding dataclass
├── rules/
│   ├── bfsi_ruleset.yaml    # 9 BFSI/FinTech rules (YAML)
│   ├── schema.py            # Pydantic rule model + RuleSet
│   └── __init__.py          # default_ruleset() / load_ruleset()
├── reports/
│   ├── markdown_report.py   # Markdown report writer
│   ├── sarif_report.py      # SARIF 2.1.0 report writer
│   └── impact_summary.py    # Impact metrics computation
├── dashboard.py             # Streamlit web dashboard
├── sample-app/
│   ├── app.py               # Deliberately vulnerable Flask API
│   ├── db.py                # Vulnerable DB access layer
│   ├── models.py            # Vulnerable ORM models
│   └── README.md            # Sample-app documentation
├── sample-app-reports/
│   ├── guardrail-report.md          # Pre-generated Markdown report
│   └── guardrail-report.sarif.json  # Pre-generated SARIF report
├── tests/
│   ├── test_scanners.py     # Scanner unit + integration tests
│   ├── test_rules.py        # Rule loading + schema tests
│   ├── test_reports.py      # Report generation tests
│   └── fixtures/            # Minimal vulnerable fixture files (18 files)
├── screenshots/             # Demo evidence screenshots + text captures
├── pyproject.toml           # Project configuration
└── requirements.txt         # Runtime + dev dependencies
```

---

## Installation

**Requirements:** Python 3.11+

```bash
# Clone the repository and enter its root directory
git clone https://github.com/Krishna-Meena/guard-rail.git
cd guard-rail

# Install in editable mode with all dev dependencies
pip install -e ".[dev]"

# Verify the CLI is available
guardrail --help
```

Alternatively, install runtime dependencies only:

```bash
pip install -r requirements.txt
pip install -e .
```

> **Windows note:** The CLI reconfigures stdout/stderr to UTF-8 automatically. If you see encoding errors in legacy terminals, run: `chcp 65001` before invoking the CLI.

---

## CLI Usage

All commands are run from the repository root.

### Full scan (all severities)

```bash
guardrail scan sample-app/
```

### Scan with output directory

```bash
guardrail scan sample-app/ --output-dir ./reports-out/
```

### Skip report file generation (terminal only)

```bash
guardrail scan sample-app/ --no-report
```

### Custom rule set

```bash
guardrail scan sample-app/ --ruleset /path/to/custom-rules.yaml
```

### Help

```bash
guardrail --help
guardrail scan --help
```

---

## Severity Filtering

The `--severity` / `-s` option sets the **minimum** severity level. Only rules at or above the threshold are applied.

```bash
# Show only CRITICAL findings
guardrail scan sample-app/ --severity CRITICAL

# Show CRITICAL + HIGH (recommended for CI/CD gates)
guardrail scan sample-app/ --severity HIGH

# Show CRITICAL + HIGH + MEDIUM
guardrail scan sample-app/ --severity MEDIUM
```

Valid values (case-insensitive): `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` (default: `INFO` — all findings).

---

## Dashboard

The interactive Streamlit dashboard provides a web UI over the same scan engine as the CLI.

```bash
python -m streamlit run dashboard.py
```

Open `http://localhost:8501` in your browser.

**Dashboard features:**

| Section | Description |
|---|---|
| Scan target input | Enter any file system path; defaults to `sample-app/` |
| ▶ Scan button | Triggers a live scan via the GuardRail scan engine |
| Summary cards | Verdict (PASS/FAIL), total findings, files scanned, time saved |
| Severity bar chart | Vega-Lite bar chart with colour-coded severity breakdown |
| Per-severity counts | CRITICAL / HIGH / MEDIUM / LOW / INFO badges with counts |
| Findings table | Sortable DataFrame: severity, rule ID, rule name, file, line, compliance |
| Finding detail | Expandable panel per finding: full explanation, fix guidance, compliance frameworks |
| Compliance coverage | Grid showing all frameworks in the rule set vs. triggered frameworks |
| Download Markdown | Download `guardrail-report.md` for the current scan |
| Download SARIF | Download `guardrail-report.sarif.json` for the current scan |

---

## Streamlit Cloud Deployment

The interactive dashboard is **live** on Streamlit Community Cloud:

> **[🛡️ https://guard-rail.streamlit.app](https://guard-rail.streamlit.app)**

To deploy your own instance, select this repository on [share.streamlit.io](https://share.streamlit.io/) with these settings:

| Setting | Value |
|---|---|
| Main file path | `dashboard.py` |
| Python version | 3.11 or later |
| Dependency file | `requirements.txt` |

The cloud deployment scans only the repository files available in its isolated runtime. The default
sample application remains safe to demonstrate because it is a deliberately vulnerable static code
fixture and is never executed by the dashboard.

---

## Reports

Two report files are written automatically on every scan (unless `--no-report` is used).

| File | Format | Purpose |
|---|---|---|
| `guardrail-report.md` | Markdown | Human-readable report with impact summary, findings, fix guidance |
| `guardrail-report.sarif.json` | SARIF 2.1.0 JSON | Machine-readable for GitHub Code Scanning, VS Code SARIF viewer, security toolchains |

Reports are written to the current directory by default. Use `--output-dir` to change the location.

Pre-generated reports for the sample application are available in `sample-app-reports/`.

### Markdown report structure

```
# GuardRail Compliance Report
  Scan target, timestamp, total findings

## ⚡ Impact Summary
  Severity breakdown, estimated review time, compliance coverage

## Summary (table)
  Severity | Count

## Findings
  ### CRITICAL
    Rule ID — Rule Name
    File, line, match text, compliance mapping, explanation, fix

  ### HIGH
    ...
```

### SARIF 2.1.0 structure

The SARIF report conforms to the [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/). Key fields:

- `runs[0].tool.driver.name`: `"GuardRail"`
- `runs[0].tool.driver.rules[]`: rule definitions with `id`, `name`, `shortDescription`, `fullDescription`, `helpText` (fix guidance)
- `runs[0].results[]`: each finding with `ruleId`, `level` (mapped from severity), `message.text`, `locations[].physicalLocation` (file + line)

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings at the configured severity threshold — clean scan |
| `1` | Findings present, but none CRITICAL or HIGH |
| `2` | One or more CRITICAL or HIGH findings detected — CI gate should fail |

```bash
guardrail scan sample-app/
echo "Exit code: $?"   # 2 (CRITICAL/HIGH findings present)

guardrail scan sample-app/ --severity CRITICAL
# Exit code 2 if CRITICAL findings exist
```

---

## Rule Set

GuardRail ships with nine BFSI/FinTech rules in `rules/bfsi_ruleset.yaml` (ruleset name: **BFSI/FinTech Core Rule Set v1.0**).

| Rule ID | Name | Severity | Detection | Key Compliance |
|---|---|---|---|---|
| GR-BFSI-001 | Hardcoded Credentials | CRITICAL | Regex | PCI-DSS 8.2.1, CWE-798 |
| GR-BFSI-002 | SQL Injection Risk | CRITICAL | Regex | OWASP A03, PCI-DSS 6.2.4, CWE-89, RBI 6.2 |
| GR-BFSI-003 | Missing Input Validation on Financial Fields | HIGH | Regex | OWASP A03, PCI-DSS 6.2.4, CWE-20 |
| GR-BFSI-004 | Insecure Password Hashing (MD5 / SHA-1) | HIGH | Regex | PCI-DSS 8.3.1, OWASP A02, NIST SP 800-131A, CWE-916 |
| GR-BFSI-005 | Missing Audit-Log on Sensitive Operations | HIGH | Regex | PCI-DSS 10.2.1, RBI 7, SEBI CSCRF, ISO 27001 A.12.4, CWE-778 |
| GR-BFSI-006 | Unencrypted PII Storage | CRITICAL | Regex | PCI-DSS 3.5, GDPR Art. 32, RBI 4, DPDP Act 2023, CWE-312 |
| GR-BFSI-007 | Missing Rate-Limiting on Authentication Endpoints | HIGH | Regex | OWASP A07, PCI-DSS 8.3.4, RBI 5.3, CWE-307 |
| GR-BFSI-008 | Dangerous subprocess / eval Usage | CRITICAL | AST | OWASP A03, PCI-DSS 6.2.4, CWE-78/95 |
| GR-BFSI-009 | TLS Certificate Verification Disabled | HIGH | AST | OWASP A02, PCI-DSS 4.2.1, CWE-295, RBI 4.3 |

Rules are validated against the Pydantic schema in `rules/schema.py` at load time. Custom rule files can be loaded via `--ruleset`. Rule IDs must match `^GR-[A-Z]+-\d{3}$`.

---

## Sample Application

`sample-app/` contains **NovaPay** — a deliberately vulnerable mini FinTech API designed to demonstrate GuardRail catching real BFSI violations.

> ⚠️ **Do NOT deploy this application anywhere.** It contains intentional, unmitigated security vulnerabilities. It exists solely for demonstration and test validation.

The sample app (`app.py`, `db.py`, `models.py`) embeds violations that look like ordinary developer mistakes — no comments or flags within the source files themselves.

**Violations embedded in sample-app:**

| Rule | Severity | File | Embedded Pattern |
|---|---|---|---|
| GR-BFSI-001 | CRITICAL | `app.py:21` | `DB_PASSWORD = "N0vaPay$DB#Prod"` |
| GR-BFSI-002 | CRITICAL | `db.py:41` | SQL string concatenation |
| GR-BFSI-007 | HIGH | `app.py:73` | `/api/v1/login` route, no rate-limit decorator |
| GR-BFSI-005 | HIGH | `app.py:74`, `app.py:121`, `app.py:159` | `def login(`, `def transfer(`, `def fund_transfer(` — no audit log |
| GR-BFSI-004 | HIGH | `app.py:83`, `models.py:47` | `hashlib.md5(` |
| GR-BFSI-003 | HIGH | `app.py:163-166` | `int(body.`, `float(request.` |

---

## Validation & Test Results

```
pytest tests/
120 passed in 1.22s
```

The test suite covers:

- `test_scanners.py` — `TestFinding`, `TestRegexScanner`, `TestAstScanner`, `TestWalker`, `TestCleanFiles`, `TestEdgeCases`
- `test_rules.py` — Rule loading, schema validation, Severity ordering, RuleSet lookup
- `test_reports.py` — Markdown report rendering, SARIF 2.1.0 structure, Impact summary computation

Fixture files in `tests/fixtures/` provide targeted, minimal vulnerable inputs for each of the nine rules (Python + JavaScript variants).

---

## Example Output

Scan of `sample-app/` with default settings:

```
┌───────────────────────────────────────────────────────────┐
│  GuardRail  BFSI / FinTech Compliance & Security Scanner  │
└───────────────────────────────────────────────────────────┘

 Target              .../guard-rail/sample-app
 Rule set            BFSI/FinTech Core Rule Set v1.0  [9 rules]
 Min severity        INFO (all)

┌────────────────────────────── Impact Summary ──────────────────────────────┐
│  Findings by severity     2 CRITICAL  •  9 HIGH                            │
│  Est. review time saved   ~2h 45m  (11 CRITICAL/HIGH x 15 min)             │
│  Compliance coverage      Flags issues mapped to 2 compliance              │
│                           frameworks: PCI-DSS, RBI guidelines              │
└────────────────────────────────────────────────────────────────────────────┘

 CRITICAL   2 findings

  GR-BFSI-001  Hardcoded Credentials
  Location: app.py:21
  Match:    PASSWORD = "N0vaPay$DB#Prod"
  Maps to:  PCI-DSS v4.0 Req 8.2.1, OWASP A07:2021, CWE-798

  GR-BFSI-002  SQL Injection Risk
  Location: db.py:41
  Match:    "SELECT ... WHERE holder_name = " +
  Maps to:  OWASP A03:2021, PCI-DSS v4.0 Req 6.2.4, CWE-89

 HIGH   9 findings
  ...

┌──────────────────────── Scan Failed ────────────────────────────────────────┐
│  Result           FAIL  Critical or high-severity issues require remediation │
│  Files scanned    4                                                           │
│  Total findings   11                                                          │
│  By severity      2 CRITICAL  9 HIGH                                          │
│  Est. time saved  ~2h 45m                                                     │
│  Markdown report  guardrail-report.md                                         │
│  SARIF report     guardrail-report.sarif.json                                 │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## CI/CD Integration

GuardRail's exit codes are designed for CI gates:

- `exit 0` → pass (no findings at threshold)
- `exit 2` → fail (CRITICAL or HIGH findings)

**Example GitHub Actions step:**

```yaml
- name: GuardRail Security Scan
  working-directory: .
  run: |
    pip install -e ".[dev]"
    guardrail scan . --severity HIGH --output-dir ./guardrail-results/
  # The step fails automatically when exit code is 2
```

**Upload SARIF to GitHub Code Scanning:**

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: guardrail-results/guardrail-report.sarif.json
```

> **Note:** GuardRail has been developed and validated locally. CI provider integration is illustrative and has not been tested against a live GitHub Actions runner in this version.

---

## Compliance Mapping

GuardRail maps findings to regulatory frameworks as a reference aid for developers and security teams. **These mappings are not a certification of compliance.** They indicate that the detected code pattern is relevant to the cited requirement — remediation of the finding is a necessary but not sufficient condition for compliance.

Frameworks referenced in the current rule set:

| Framework | Rules that reference it |
|---|---|
| PCI-DSS v4.0 | GR-BFSI-001, 002, 003, 004, 005, 006, 007, 008, 009 |
| OWASP Top 10 (2021) | GR-BFSI-001, 002, 003, 004, 007, 008, 009 |
| RBI IT Framework | GR-BFSI-002, 003, 005, 006, 007, 009 |
| SEBI CSCRF | GR-BFSI-005 |
| ISO 27001 | GR-BFSI-005 |
| NIST SP 800-131A Rev 2 | GR-BFSI-004 |
| GDPR Art. 5 / Art. 32 | GR-BFSI-006 |
| DPDP Act 2023 (India) | GR-BFSI-006 |
| CWE (various) | All rules |

---

## Impact Metric Methodology

The "estimated review time saved" figure is computed as:

```
time_saved = (count_of_CRITICAL_findings + count_of_HIGH_findings) × 15 minutes
```

The 15-minute baseline is a conservative estimate of the manual effort required to identify, document, and communicate a single CRITICAL or HIGH severity finding during a code review or security audit. GuardRail does not claim this represents measured productivity data from production deployments. It is an illustrative estimate intended to contextualise the value of automated detection.

For the sample application scan: **11 CRITICAL/HIGH findings × 15 min = 165 min ≈ 2h 45m**.

---

## Limitations

- **Python and JavaScript/TypeScript source files only.** Java, Go, Ruby, and PHP patterns are defined in rules but only fully exercised on Python inputs; AST detection is Python-only.
- **Regex detection has false positive potential.** The patterns are tuned for typical BFSI code but may flag test fixtures, commented-out code, or documentation strings.
- **`DetectionType.SEMGREP` is not yet implemented.** Rules may list `semgrep` as a detection type; these are silently skipped.
- **No inter-procedural analysis.** GuardRail operates file-by-file; it cannot trace tainted data flows across function boundaries.
- **No network or runtime analysis.** Only static source code is examined.
- **Not a replacement for a full security audit.** GuardRail catches known-bad patterns; it cannot prove the absence of vulnerabilities.

---

## Security & Disclaimer

- `sample-app/` is **intentionally and permanently vulnerable**. Never deploy it to any network-accessible environment.
- GuardRail output is informational. It does not provide legal compliance certification for any regulatory framework.
- GuardRail does not replace qualified security engineers or formal penetration testing.
- False positives are possible; every finding should be reviewed by a developer before remediation is acted upon.

---

## Roadmap

- Semgrep engine integration for dataflow-aware rules
- Additional rule categories: cloud misconfiguration (GR-CLOUD-\*), container/IaC scanning
- IDE plugin (VS Code extension consuming SARIF output)
- CI/CD pre-built Docker image
- Expanded language support: Java, Go
- Suppression comments (`# guardrail: disable GR-BFSI-001`)
- Baseline / diff mode (report only new findings vs. last scan)

---

## Hackathon Demo

For the 2–3 minute live demo, follow `docs/DEMO_GUIDE.md`. The quick reference:

```bash
# 1. Run the test suite (proof of correctness)
pytest

# 2. Full scan of the sample app
guardrail scan sample-app/

# 3. Severity-filtered scan (CRITICAL only)
guardrail scan sample-app/ --severity CRITICAL

# 4. Launch the dashboard
python -m streamlit run dashboard.py

# 5. View pre-generated reports
cat sample-app-reports/guardrail-report.md
```

See `docs/DEMO_CHECKLIST.md` for a printable pre-demo preparation checklist.
