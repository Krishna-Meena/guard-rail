# GuardRail — CI/CD Integration Guide

GuardRail is designed to integrate into any CI/CD pipeline that can execute a Python command and read exit codes. This document explains how the exit code convention works, how reports are consumed, and provides illustrative pipeline examples.

> **Important:** GuardRail has been developed and tested locally. The CI/CD configurations below are illustrative. They have not been tested against live CI provider runners in this version. Adapt them to your specific pipeline environment.

---

## Exit Code Convention

The `guardrail scan` command uses the following exit codes:

| Exit code | Meaning | Recommended CI action |
|---|---|---|
| `0` | No findings at the configured threshold — clean scan | Pass |
| `1` | Findings present but none CRITICAL or HIGH | Pass with warning (optional) |
| `2` | One or more CRITICAL or HIGH findings detected | Fail the build |

Most CI systems treat any non-zero exit code as a build failure. To fail the build **only on CRITICAL/HIGH findings** (the recommended configuration), use `--severity HIGH`:

```bash
guardrail scan . --severity HIGH
# Exit 0: clean
# Exit 2: CRITICAL or HIGH found → CI fails
```

To fail only on CRITICAL:
```bash
guardrail scan . --severity CRITICAL
```

---

## Basic Integration Pattern

```bash
# From the repository root (or wherever the project is installed)

# Install dependencies (typically cached in CI)
pip install -e ".[dev]"

# Run the scan
guardrail scan /path/to/source/ --severity HIGH --output-dir ./guardrail-results/

# Exit code 2 causes the CI step to fail automatically
```

---

## GitHub Actions

### Minimal workflow — fail on CRITICAL/HIGH

```yaml
name: GuardRail Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  guardrail:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install GuardRail
        working-directory: .
        run: pip install -e ".[dev]"

      - name: Run GuardRail scan
        working-directory: .
        run: |
          guardrail scan . --severity HIGH --output-dir ./guardrail-results/
        # Step fails automatically when exit code is 2
```

### With SARIF upload to GitHub Code Scanning

```yaml
name: GuardRail with SARIF Upload

on: [push, pull_request]

jobs:
  guardrail:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install GuardRail
        working-directory: .
        run: pip install -e ".[dev]"

      - name: Run GuardRail scan
        working-directory: .
        run: |
          guardrail scan . --severity HIGH --output-dir ./guardrail-results/
        continue-on-error: true  # Allow SARIF upload even if scan fails

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: guardrail-results/guardrail-report.sarif.json
```

When SARIF is uploaded, findings appear in the GitHub Security tab as code scanning alerts. Developers can see rule descriptions, file locations, and fix guidance directly in pull request reviews.

### With report artifact retention

```yaml
      - name: Upload reports as artifacts
        if: always()  # Upload even if scan step failed
        uses: actions/upload-artifact@v4
        with:
          name: guardrail-reports
          path: |
            guardrail-results/guardrail-report.md
            guardrail-results/guardrail-report.sarif.json
          retention-days: 30
```

---

## Generic CI System

For any CI system that runs shell commands:

```bash
#!/bin/bash
set -e

# Install (use cached venv in practice)
pip install -e ".[dev]"

# Scan — exit code 2 will halt the script due to set -e
guardrail scan . --severity HIGH --output-dir ./guardrail-results/

echo "GuardRail scan passed — no CRITICAL or HIGH findings"
```

---

## Severity Threshold Recommendations

| Pipeline stage | Recommended threshold | Rationale |
|---|---|---|
| Pull Request gate | `--severity HIGH` | Catch all CRITICAL and HIGH before merge |
| Nightly full scan | `--severity INFO` (default) | Capture all findings for trend tracking |
| Hotfix branch | `--severity CRITICAL` | Fastest feedback for urgent deployments |
| Pre-release | `--severity MEDIUM` | Stricter gate for release candidates |

---

## Output Directory in CI

Always specify `--output-dir` in CI to control where reports land:

```bash
guardrail scan . --severity HIGH --output-dir ./guardrail-results/
```

The directory is created automatically if it does not exist. Both `guardrail-report.md` and `guardrail-report.sarif.json` are written there.

---

## Exit Code Handling on Windows

In PowerShell:

```powershell
guardrail scan . --severity HIGH --output-dir .\guardrail-results\
if ($LASTEXITCODE -eq 2) {
    Write-Host "FAIL: CRITICAL or HIGH findings detected"
    exit 1
}
```

In CMD:

```batch
guardrail scan . --severity HIGH --output-dir .\guardrail-results\
if errorlevel 2 (
    echo FAIL: CRITICAL or HIGH findings detected
    exit /b 1
)
```

---

## Integration Scope

| Aspect | Current status |
|---|---|
| CLI exit codes | ✅ Implemented and verified |
| Markdown report generation | ✅ Implemented and verified |
| SARIF 2.1.0 report generation | ✅ Implemented and verified |
| GitHub Actions (local test) | ⚠️ Illustrative — not tested against live runner |
| GitHub Code Scanning SARIF upload | ⚠️ Illustrative — SARIF structure is valid 2.1.0 |
| Other CI providers (Jenkins, GitLab CI, Azure DevOps) | ⚠️ Same pattern applies; not individually tested |
