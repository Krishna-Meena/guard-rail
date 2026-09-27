# GuardRail CLI Reference

All commands are run from the repository root after installation.

---

## Installation check

```bash
guardrail --help
```

Expected output:
```
Usage: guardrail [OPTIONS] COMMAND [ARGS]...

  GuardRail — BFSI/FinTech compliance & security scanner.

Options:
  --help  Show this message and exit.

Commands:
  scan  Scan PATH for BFSI/FinTech compliance and security issues.
```

---

## `guardrail scan`

Scan a file or directory for BFSI/FinTech compliance and security issues.

### Syntax

```bash
guardrail scan PATH [OPTIONS]
```

### Arguments

| Argument | Required | Description |
|---|---|---|
| `PATH` | Yes | File or directory to scan. The path must exist. |

### Options

| Option | Short | Default | Description |
|---|---|---|---|
| `--severity LEVEL` | `-s` | `INFO` | Minimum severity to report. Only rules at or above this level are applied. |
| `--output-dir DIR` | `-o` | `.` (current directory) | Directory where report files are written. Created if it does not exist. |
| `--no-report` | — | `False` (reports written) | Skip writing Markdown and SARIF report files. |
| `--ruleset PATH` | — | Built-in BFSI set | Path to a custom rule YAML file. |
| `--help` | — | — | Show help and exit. |

### Severity levels

Valid values for `--severity` (case-insensitive):

| Level | Meaning |
|---|---|
| `CRITICAL` | Only CRITICAL findings |
| `HIGH` | CRITICAL + HIGH |
| `MEDIUM` | CRITICAL + HIGH + MEDIUM |
| `LOW` | CRITICAL + HIGH + MEDIUM + LOW |
| `INFO` | All findings (default) |

### Exit codes

| Code | Condition |
|---|---|
| `0` | No findings at the configured severity threshold |
| `1` | Findings present but none are CRITICAL or HIGH |
| `2` | One or more CRITICAL or HIGH findings detected |

---

## Examples

### Scan the sample application (all severities)

```bash
guardrail scan sample-app/
```

**What happens:**
- Loads the built-in BFSI/FinTech Core Rule Set (9 rules)
- Discovers 4 scannable files in `sample-app/`
- Applies all rules
- Prints colour-coded findings grouped by severity (CRITICAL → INFO)
- Prints an Impact Summary panel
- Writes `guardrail-report.md` and `guardrail-report.sarif.json` to the current directory
- Exits with code `2` (CRITICAL/HIGH findings present)

**Expected result:**
```
Files scanned:  4
Total findings: 11
By severity:    2 CRITICAL  9 HIGH
Est. time saved: ~2h 45m
```

---

### Scan with severity filter (CRITICAL only)

```bash
guardrail scan sample-app/ --severity CRITICAL
```

**What happens:**
- Only applies rules with severity CRITICAL
- Reports 2 findings: GR-BFSI-001 and GR-BFSI-002
- Exits with code `2`

---

### Scan with severity filter (HIGH and above)

```bash
guardrail scan sample-app/ --severity HIGH
```

**What happens:**
- Applies rules with severity CRITICAL and HIGH
- Reports all 11 findings (2 CRITICAL + 9 HIGH)
- Exits with code `2`

---

### Write reports to a specific directory

```bash
guardrail scan sample-app/ --output-dir ./my-reports/
```

**Report paths:**
- `./my-reports/guardrail-report.md`
- `./my-reports/guardrail-report.sarif.json`

---

### Terminal output only (no files written)

```bash
guardrail scan sample-app/ --no-report
```

Findings are printed to the terminal. No files are created.

---

### Scan a single file

```bash
guardrail scan sample-app/app.py
```

Scans only `app.py`. All rules whose `file_glob` matches `.py` files are applied.

---

### Use a custom rule set

```bash
guardrail scan /path/to/project/ --ruleset /path/to/my-rules.yaml
```

The custom YAML must conform to the same schema as `rules/bfsi_ruleset.yaml` (validated by the Pydantic model in `rules/schema.py`). Rule IDs must match `^GR-[A-Z]+-\d{3}$`.

---

### Check exit code in a script

```bash
guardrail scan sample-app/ --severity HIGH
if [ $? -eq 2 ]; then
    echo "CRITICAL or HIGH findings detected — build should fail"
fi
```

On Windows PowerShell:
```powershell
guardrail scan sample-app/ --severity HIGH
if ($LASTEXITCODE -eq 2) {
    Write-Host "CRITICAL or HIGH findings detected"
}
```

---

## Terminal output structure

```
┌──────────────────────── Banner ────────────────────────────────┐
│  GuardRail  BFSI / FinTech Compliance & Security Scanner       │
└────────────────────────────────────────────────────────────────┘

 Target        <absolute path>
 Rule set      BFSI/FinTech Core Rule Set v1.0  [9 rules]
 Min severity  INFO (all)

┌──────────────────── Impact Summary ──────────────────────────┐
│  Findings by severity     2 CRITICAL  •  9 HIGH              │
│  Est. review time saved   ~2h 45m  (11 CRITICAL/HIGH x 15m)  │
│  Compliance coverage      ... PCI-DSS, RBI guidelines        │
└──────────────────────────────────────────────────────────────┘

─── CRITICAL  2 findings ──────────────────────────────────────

  GR-BFSI-001  Hardcoded Credentials
  Location: app.py:21
  Match:    PASSWORD = "N0vaPay$DB#Prod"
  Maps to:  PCI-DSS v4.0 Req 8.2.1, ...
  A credential ... is hard-coded directly in source code.

─── HIGH  9 findings ──────────────────────────────────────────
  ...

┌──────────────────── Scan Failed ─────────────────────────────┐
│  Result           FAIL                                        │
│  Files scanned    4                                           │
│  Total findings   11                                          │
│  By severity      2 CRITICAL  9 HIGH                          │
│  Est. time saved  ~2h 45m                                     │
│  Markdown report  guardrail-report.md                         │
│  SARIF report     guardrail-report.sarif.json                 │
└──────────────────────────────────────────────────────────────┘
```

---

## Report file names

Both reports are always named:
- `guardrail-report.md`
- `guardrail-report.sarif.json`

They are written to `--output-dir` (default: current directory). If a file already exists it is overwritten.

---

## Windows encoding note

On Windows with legacy console code pages, emoji and box-drawing characters may be garbled. The CLI attempts to reconfigure stdout/stderr to UTF-8 automatically. If output is still corrupted:

```powershell
chcp 65001
guardrail scan sample-app/
```

Or use Windows Terminal, which defaults to UTF-8.
