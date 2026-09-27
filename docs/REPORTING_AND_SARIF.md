# GuardRail — Reporting and SARIF Reference

GuardRail produces two report files on every scan: a human-readable Markdown report and a machine-readable SARIF 2.1.0 JSON report. Both are generated from the same list of `Finding` objects produced by the scan engine.

---

## Overview

| Report | File name | Format | Primary use |
|---|---|---|---|
| Markdown | `guardrail-report.md` | Markdown | Developer review, stakeholder communication, demo |
| SARIF | `guardrail-report.sarif.json` | SARIF 2.1.0 JSON | IDE integration, GitHub Code Scanning, CI pipelines |

Reports are written to the current directory by default. Use `--output-dir DIR` to specify a different location.

Pre-generated reports for the sample application are in `sample-app-reports/`.

---

## Markdown Report

### Generation

```bash
guardrail scan sample-app/
# Writes: guardrail-report.md
```

To write to a custom directory:
```bash
guardrail scan sample-app/ --output-dir ./reports/
# Writes: ./reports/guardrail-report.md
```

### Structure

```markdown
# GuardRail Compliance Report

**Scan target:** `<absolute path>`
**Generated:** <UTC timestamp>
**Total findings:** <count>

## ⚡ Impact Summary

- **Findings:** 11 total — **2 CRITICAL**, **9 HIGH**
- **Estimated review time saved:** ~2h 45m (11 CRITICAL/HIGH × 15 min avg manual catch)
- **Compliance coverage:** Flags issues mapped to 2 compliance frameworks: PCI-DSS, RBI guidelines

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 9 |

## Findings

### 🔴 CRITICAL (2)

#### `GR-BFSI-001` — Hardcoded Credentials

- **File:** `<path>` line <n>
- **Match:** `PASSWORD = "N0vaPay$DB#Prod"`
- **Compliance:** maps to PCI-DSS v4.0 Req 8.2.1, OWASP A07:2021, CWE-798
- **Why:** <explanation>
- **Fix:** <remediation steps>

...
```

### Finding Fields

Every finding in the Markdown report contains:

| Field | Description |
|---|---|
| `GR-BFSI-NNN` | Rule identifier |
| File + line | Absolute file path and 1-based line number |
| Match | The exact code snippet that triggered the rule |
| Compliance | All compliance framework references for the rule |
| Why | Full plain-language risk explanation |
| Fix | Concrete remediation steps |

---

## SARIF 2.1.0 Report

### Generation

```bash
guardrail scan sample-app/
# Writes: guardrail-report.sarif.json
```

### SARIF Version

The report conforms to [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/), the industry standard for static analysis results interchange. It is compatible with:

- GitHub Code Scanning (upload via `github/codeql-action/upload-sarif`)
- VS Code SARIF Viewer extension
- Azure DevOps pipeline results
- Any SARIF 2.1.0-compliant viewer

### Document Structure

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "GuardRail",
          "version": "0.1.0",
          "informationUri": "https://github.com/your-org/guardrail",
          "rules": [ ... ]
        }
      },
      "results": [ ... ],
      "artifacts": [ ... ]
    }
  ]
}
```

### Tool Descriptor (`runs[0].tool.driver`)

| Field | Value |
|---|---|
| `name` | `"GuardRail"` |
| `version` | From `pyproject.toml` |
| `rules` | Array of `reportingDescriptor` objects, one per GuardRail rule |

Each rule descriptor:

```json
{
  "id": "GR-BFSI-001",
  "name": "Hardcoded Credentials",
  "shortDescription": { "text": "Hardcoded Credentials" },
  "fullDescription": { "text": "<explanation text>" },
  "help": { "text": "<fix text>", "markdown": "<fix text>" },
  "properties": {
    "tags": ["PCI-DSS v4.0 Req 8.2.1", "OWASP A07:2021 ...", "CWE-798"]
  }
}
```

### Results (`runs[0].results`)

Each finding becomes one SARIF `result`:

```json
{
  "ruleId": "GR-BFSI-001",
  "level": "error",
  "message": {
    "text": "Hardcoded Credentials: PASSWORD = \"N0vaPay$DB#Prod\""
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "sample-app/app.py",
          "uriBaseId": "%SRCROOT%"
        },
        "region": {
          "startLine": 21
        }
      }
    }
  ]
}
```

### Severity → SARIF Level Mapping

| GuardRail Severity | SARIF `level` |
|---|---|
| CRITICAL | `error` |
| HIGH | `error` |
| MEDIUM | `warning` |
| LOW | `note` |
| INFO | `note` |

### Artifacts (`runs[0].artifacts`)

The SARIF report includes an `artifacts` array listing each scanned file:

```json
{
  "location": {
    "uri": "sample-app/app.py",
    "uriBaseId": "%SRCROOT%"
  }
}
```

---

## Finding Structure Reference

The underlying `Finding` dataclass (defined in `scanners/models.py`) is the single unit produced by all scanners:

| Field | Type | Description |
|---|---|---|
| `file` | `Path` | Absolute path to the source file |
| `line` | `int` | 1-based line number of the triggering code |
| `rule_id` | `str` | Rule identifier, e.g. `GR-BFSI-001` |
| `severity` | `Severity` | Enum: CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `explanation` | `str` | Plain-language risk description (copied from rule at scan time) |
| `fix` | `str` | Remediation guidance (copied from rule at scan time) |
| `match_text` | `str` | Triggering code snippet; empty string for pure AST detections |

Findings are frozen (immutable), deduplicated by `(file, line, rule_id)`, and sorted by `(file, line, rule_id)` before output.

---

## Impact Summary

Both reports include an **Impact Summary** section computed by `reports/impact_summary.py`:

### Metrics computed

| Metric | Formula |
|---|---|
| Severity counts | `Counter(finding.severity for finding in findings)` |
| Minutes saved | `(CRITICAL_count + HIGH_count) × 15` |
| Frameworks covered | Distinct framework families from triggered rules: `PCI-DSS`, `GDPR`, `SOC2`, `RBI guidelines` |

### Example (sample-app scan)

```
Findings: 11 total — 2 CRITICAL, 9 HIGH
Estimated review time saved: ~2h 45m (11 CRITICAL/HIGH × 15 min)
Compliance coverage: Flags issues mapped to 2 compliance frameworks: PCI-DSS, RBI guidelines
```

---

## Dashboard Report Downloads

The Streamlit dashboard (`dashboard.py`) generates the same Markdown and SARIF content in-memory and offers them as browser downloads. The dashboard does not write files to disk; downloads are browser-delivered only.

---

## CI/CD Consumption

### Fail the build on CRITICAL/HIGH findings

The CLI exits with code `2` when any CRITICAL or HIGH findings are present. CI systems treat non-zero exit codes as build failures automatically.

```yaml
# GitHub Actions example
- name: GuardRail scan
  working-directory: .
  run: guardrail scan . --severity HIGH --output-dir ./results/
```

### Upload SARIF to GitHub Code Scanning

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results/guardrail-report.sarif.json
```

This makes GuardRail findings appear in the GitHub Security tab as code scanning alerts, with rule names, file locations, and fix guidance visible directly in pull request reviews.

---

## Pre-generated Sample Reports

Pre-generated reports for the NovaPay sample application are available for review without running a scan:

| File | Location |
|---|---|
| Markdown | `sample-app-reports/guardrail-report.md` |
| SARIF | `sample-app-reports/guardrail-report.sarif.json` |

These files are committed to the repository and reflect the expected output of `guardrail scan sample-app/`.
