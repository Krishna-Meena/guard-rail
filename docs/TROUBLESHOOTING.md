# GuardRail — Troubleshooting Guide

This guide covers the most common issues when installing, running, and demonstrating GuardRail.

---

## Installation Issues

### `pip install -e ".[dev]"` fails with build errors

**Symptom:**
```
ERROR: Failed building wheel for libcst
```

**Cause:** `libcst` requires a Rust compiler (or a pre-built wheel). Pre-built wheels are available for Python 3.11 and 3.12 on common platforms.

**Fix:**
```bash
# Upgrade pip first — older pip may not find the correct wheel
pip install --upgrade pip
pip install -e ".[dev]"
```

If on a platform without a pre-built wheel:
```bash
pip install libcst --no-build-isolation
pip install -e ".[dev]"
```

---

### `ModuleNotFoundError: No module named 'pydantic'` (or any dependency)

**Cause:** Running the CLI from a Python environment that does not have the package installed.

**Fix:**
```bash
# Activate your virtual environment first
source .venv/bin/activate    # macOS/Linux
.venv\Scripts\activate       # Windows PowerShell

# Verify installation
pip show pydantic
```

---

### `pip install -e ".[dev]"` installs but `guardrail` command not found

**Cause:** The console script entry point is not on `PATH` (common when the environment is not activated).

**Fix:**
```bash
# Activate the virtual environment
source .venv/bin/activate

# Verify the script
guardrail --help
```

If the virtual environment is activated and the command is still not found:
```bash
# Reinstall
pip install -e "."
# Or invoke directly
python -m cli.main --help
```

---

## CLI Issues

### Windows: garbled output (box-drawing characters appear as `?` or random symbols)

**Symptom:** The Rich terminal UI displays corrupted characters instead of box lines.

**Fix:**
```powershell
# Set terminal to UTF-8 first
chcp 65001

# Then run the CLI
guardrail scan sample-app/
```

Use Windows Terminal (not the legacy Command Prompt or PowerShell ISE) for best results.

---

### `click.BadParameter: Path 'sample-app/' does not exist`

**Cause:** The CLI is being run from the wrong directory.

**Fix:**
```bash
# Run from the repository root
guardrail scan sample-app/
```

The `sample-app/` directory is at the repository root. The `PATH` argument to `guardrail scan` is resolved relative to the current working directory.

---

### Scan runs but reports 0 findings when scanning a project

**Possible causes:**
1. The scanned directory contains only unsupported file types
2. The directory contains only binary files or files over 1 MiB
3. The `--severity` threshold is set higher than the findings present
4. The scan is running against the wrong directory

**Fix:**
```bash
# Check which files will be discovered
guardrail scan /path/to/project/ --no-report

# Try with default severity (all findings)
guardrail scan /path/to/project/

# Verify Python/JS files are present
ls /path/to/project/*.py
```

---

### Exit code is 1 when expecting 0 or 2

**Exit code 1** means findings were detected but none are CRITICAL or HIGH. This is a valid result for codebases with only MEDIUM/LOW/INFO findings.

To see all findings:
```bash
guardrail scan /path/ --severity INFO   # default — same as no --severity flag
```

---

### Report files not appearing in expected location

**Default behaviour:** Reports are written to the **current working directory** when `--output-dir` is not specified.

**Fix:**
```bash
# Specify an explicit output directory
guardrail scan sample-app/ --output-dir ./my-reports/

# Or check the current directory
ls guardrail-report.*
```

---

## Dashboard Issues

### `ModuleNotFoundError: No module named 'streamlit'`

**Fix:**
```bash
pip install streamlit
# or
pip install -e ".[dev]"   # includes streamlit via requirements.txt
```

---

### `No module named 'scanners'` when launching dashboard

**Cause:** `dashboard.py` is being launched from a directory other than the repository root.

**Fix:**
```bash
python -m streamlit run dashboard.py
```

The dashboard adds the repository root to `sys.path` automatically when it starts.

---

### Streamlit port 8501 already in use

**Fix:**
```bash
python -m streamlit run dashboard.py --server.port 8502
# Open: http://localhost:8502
```

---

### Dashboard loads but ▶ Scan button does nothing

**Cause:** JavaScript may be blocked, or the Streamlit session is stale.

**Fix:**
1. Hard-refresh the browser page (`Ctrl+Shift+R` / `Cmd+Shift+R`)
2. If the issue persists, restart the Streamlit server and reload

---

### Dashboard shows `No findings` for `sample-app/`

**Cause:** The scan target path in the text input field may be incorrect or the dashboard was not restarted after a code change.

**Fix:**
1. Verify the displayed path ends with `sample-app`
2. Click the text input, clear it, and re-enter: `<absolute-path-to-repository>/sample-app`
3. Click **▶ Scan**

---

## Test Failures

### `pytest` reports import errors

**Cause:** Tests must be run from the repository root where the packages are installed.

**Fix:**
```bash
pytest
```

---

### Some tests fail after modifying rules

**Cause:** Tests in `test_scanners.py` validate that specific fixture files produce specific findings. If rules are changed, existing fixture tests may fail.

**Fix:** Do not modify the rules. If rule changes are necessary, update the corresponding fixture files and tests.

---

### `ModuleNotFoundError` during test collection

**Fix:**
```bash
pip install -e ".[dev]"   # Ensure editable install is up to date
pytest
```

---

## Python Version Issues

### `SyntaxError` or `TypeError` on import

**Cause:** GuardRail requires Python 3.11+. Older Python versions do not support some syntax used (e.g., `match` statements, `str | None` union types).

**Fix:**
```bash
python --version
# Must be 3.11 or later

# If using pyenv:
pyenv install 3.11.9
pyenv local 3.11.9
pip install -e ".[dev]"
```

---

## Report Validation Issues

### SARIF viewer shows schema validation errors

**Cause:** Viewing the SARIF file with a strict validator that checks field types.

**Note:** The SARIF report is generated to conform to SARIF 2.1.0. If a viewer reports schema errors, check that the viewer supports SARIF 2.1.0 (not 2.0 or 2.1.0-rtm.4).

The pre-generated report at `sample-app-reports/guardrail-report.sarif.json` can be used as a reference.

---

## Common Demo-Day Issues (Quick Reference)

| Problem | Quick fix |
|---|---|
| Garbled CLI output (Windows) | `chcp 65001` then re-run |
| CLI not found | Activate virtual environment |
| Wrong directory | Run commands from the repository root |
| Dashboard won't start | `pip install streamlit; python -m streamlit run dashboard.py` |
| Dashboard blank after scan | Hard-refresh browser |
| Unexpected 0 findings | Check working directory; check severity flag |
| Tests fail | `pip install -e ".[dev]"; pytest` |
| No time to fix | Use pre-captured evidence in `screenshots/` |
