# GuardRail — Architecture

This document describes the design of the GuardRail scanner: how it discovers files, evaluates rules, produces findings, and renders reports.

---

## Design Philosophy

GuardRail enforces a strict separation of concerns across three layers:

1. **Rule definitions** — declarative YAML, validated by Pydantic, with no logic
2. **Detection engines** — stateless scanners that emit `Finding` objects; they know nothing about reports or the CLI
3. **Presentation layer** — CLI, dashboard, and report formatters that consume `Finding` lists; they know nothing about how findings were produced

This separation means a new rule can be added by editing only the YAML file. A new output format (e.g., HTML) can be added by writing only a new formatter. The scanner engines never need to change.

---

## Data Flow

```
Target path (file or directory)
        │
        ▼
scanners/walker.py          ← scan orchestration
  │  Discovers eligible files (non-binary, ≤1 MiB, not in excluded dirs)
  │  For each rule in the RuleSet:
  │    - Filters files by rule.detection.file_glob
  │    - Dispatches to the appropriate engine
  │
  ├─ DetectionType.REGEX → scanners/regex_scanner.py
  │    Reads each file line by line, compiles and tests each pattern
  │    Returns Finding objects with file, line, match_text
  │
  ├─ DetectionType.AST   → scanners/ast_scanner.py
  │    Parses Python source with libcst
  │    Traverses the CST for call nodes, keyword arguments, attribute assignments
  │    Returns Finding objects (match_text may be empty for pure structural checks)
  │
  └─ DetectionType.SEMGREP → (not yet implemented, silently skipped)
        │
        ▼
  De-duplicated, sorted list of Finding objects
  (keyed on file + line + rule_id to prevent double-counting)
        │
        ├─ cli/main.py          → Rich terminal output + impact summary panel
        ├─ dashboard.py         → Streamlit interactive web UI
        ├─ reports/markdown_report.py  → guardrail-report.md
        └─ reports/sarif_report.py     → guardrail-report.sarif.json
```

---

## Module Responsibilities

### `rules/bfsi_ruleset.yaml`

The single source of truth for all detection rules. Each rule entry contains:

- `id` — unique identifier matching `^GR-[A-Z]+-\d{3}$`
- `name` — short human-readable title
- `category` — logical grouping (Secrets Management, Injection, Cryptography, …)
- `severity` — `CRITICAL | HIGH | MEDIUM | LOW | INFO`
- `frameworks` — list of regulatory framework references (strings)
- `detection.type` — `regex | ast | semgrep`
- `detection.file_glob` — shell glob restricting which files are scanned (e.g., `"**/*.{py,js,ts}"`)
- `detection.patterns` — list of regex strings or AST pattern tokens
- `explanation` — plain-language description of the risk
- `fix` — concrete remediation steps
- `references` — URLs to standards, CWEs, documentation

Rules are loaded at CLI/dashboard startup via `rules.default_ruleset()` or `rules.load_ruleset(path)`.

### `rules/schema.py`

Pydantic v2 models that validate every rule at load time. Key types:

- `Rule` — single rule with all fields validated
- `RuleSet` — container with `ruleset` metadata and `rules` list; provides `by_id(rule_id)` lookup
- `Severity` — enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) with `.rank` property for ordered comparison
- `DetectionType` — enum (`REGEX`, `AST`, `SEMGREP`)

Any YAML that does not match the schema raises `pydantic.ValidationError` at import time, preventing silent misconfiguration.

### `scanners/walker.py`

The top-level orchestrator. Public API:

```python
scan(root, ruleset, *, exclude_dirs=None, max_file_bytes=1_048_576, min_severity=None) -> list[Finding]
count_files(root, *, exclude_dirs=None, max_file_bytes=1_048_576) -> int
```

File discovery logic:
- Skips `.git`, `.hg`, `node_modules`, `__pycache__`, `.venv`, `venv`, `env`, `dist`, `build`, `.mypy_cache`, `.ruff_cache`, `.pytest_cache`, `*.egg-info`
- Skips files containing null bytes (binary check on first 8 KB)
- Skips files larger than 1 MiB
- Expands `{a,b,c}` alternation in `file_glob` patterns (not natively supported by `fnmatch`)

### `scanners/regex_scanner.py`

Reads each source file line-by-line. For each rule pattern, tests the compiled regex against every line. Returns one `Finding` per matching line (de-duplication happens in the walker).

### `scanners/ast_scanner.py`

Uses `libcst` to parse Python source into a Concrete Syntax Tree. Supported pattern tokens:

| Token | What it detects |
|---|---|
| `call:<name>` | Function calls matching the given name (e.g., `call:eval`) |
| `call:<module>.<name>` | Qualified calls (e.g., `call:os.system`) |
| `kw:<name>=<value>` | Keyword arguments with a specific value (e.g., `kw:shell=True`, `kw:verify=False`) |
| `assign_attr:<name>` | Attribute assignments (e.g., `assign_attr:check_hostname`) |

For JavaScript/TypeScript files that match AST rules (e.g., `**/*.{py,js,ts}`), AST detection falls back to a regex check for the pattern string when `libcst` cannot parse the file.

### `scanners/models.py`

The `Finding` frozen dataclass is the single unit of output from all scanners:

```python
@dataclass(frozen=True, order=True)
class Finding:
    file: Path           # Absolute path to the file
    line: int            # 1-based line number
    rule_id: str         # e.g. "GR-BFSI-001"
    severity: Severity   # Severity enum value
    explanation: str     # Copied from rule at detection time
    fix: str             # Copied from rule at detection time
    match_text: str      # Triggering code snippet (may be empty for AST)
```

Findings are frozen (immutable) and carry a copy of rule explanation and fix text. Consumers never need to re-join back to the rule set for display.

### `reports/impact_summary.py`

Computes the `ImpactSummary` object from a list of findings and a ruleset:

- **Severity counts** — `Counter[Severity]`
- **Minutes saved** — `(CRITICAL_count + HIGH_count) × 15`
- **Frameworks covered** — normalised list of framework families (`PCI-DSS`, `GDPR`, `SOC2`, `RBI guidelines`) matched from the triggered rules' framework strings

### `reports/markdown_report.py`

Writes `guardrail-report.md`. Structure:
- Report header (target, timestamp, finding count)
- Impact Summary block (from `ImpactSummary.as_markdown()`)
- Summary table (severity → count)
- Per-finding sections grouped by severity, each with location, match, compliance, explanation, fix

### `reports/sarif_report.py`

Writes `guardrail-report.sarif.json` conforming to SARIF 2.1.0. The tool descriptor (`runs[0].tool.driver`) includes all rules as `reportingDescriptor` entries. Each finding becomes a `result` with SARIF `level` mapped from GuardRail severity.

| GuardRail Severity | SARIF level |
|---|---|
| CRITICAL | `error` |
| HIGH | `error` |
| MEDIUM | `warning` |
| LOW | `note` |
| INFO | `note` |

### `cli/main.py`

Click command group with a single `scan` subcommand. Uses the `rich` library for coloured terminal output. After scanning:

1. Prints the Impact Summary panel
2. Prints findings grouped by severity (CRITICAL → INFO)
3. Prints the final results panel
4. Exits with code 0 (clean), 1 (findings but no CRITICAL/HIGH), or 2 (CRITICAL/HIGH present)

### `dashboard.py`

Streamlit application. Runs the same `scan()` function as the CLI but in a browser context. Session state caches results between Streamlit re-renders. The dashboard never modifies any scanner, rule, or report module.

---

## Why Separation of Detection from Presentation?

1. **Testability** — Scanner tests verify only that the correct `Finding` objects are emitted, independent of how they are displayed.
2. **Extensibility** — A new output format (JSON Lines, JUnit XML, HTML) requires only a new formatter; the scanner pipeline is untouched.
3. **Auditability** — Rule content (explanation, fix, compliance mappings) is entirely in YAML. A compliance officer can review and update rules without reading Python.
4. **Consistency** — The CLI, dashboard, Markdown report, and SARIF report all consume the same `Finding` objects from the same scan call, guaranteeing identical finding counts and content across all output channels.

---

## File Size and Binary Exclusions

The walker uses two heuristics to avoid false positives and performance problems:

- **Binary check:** reads the first 8 KB of each file and rejects it if a null byte (`\x00`) is found
- **Size limit:** files larger than 1 MiB (1,048,576 bytes) are skipped

These thresholds can be overridden via the Python API (`max_file_bytes` parameter) but are not currently exposed as CLI flags.

---

## Extending the Rule Set

To add a new rule:

1. Add a new entry to `rules/bfsi_ruleset.yaml` following the schema
2. Use a new rule ID in the appropriate namespace (e.g., `GR-BFSI-010` or `GR-CLOUD-001`)
3. Set `detection.type` to `regex` or `ast`
4. Add fixture files to `tests/fixtures/` for the new rule
5. Add test cases to `tests/test_scanners.py`

No Python code changes are required for regex rules.
