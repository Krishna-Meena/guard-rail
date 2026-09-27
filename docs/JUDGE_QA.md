# GuardRail — Judge Q&A

Technically accurate answers to likely hackathon judge questions, based on the actual project implementation.

---

## Problem and Context

### What problem are you solving?

Security reviews in BFSI/FinTech codebases are slow, expensive, and inconsistent. Developers commit hardcoded secrets, unparameterised SQL queries, missing audit logs, and disabled TLS verification every day. A manual code reviewer might catch one in ten of these issues. GuardRail catches them automatically, in seconds, with exact file and line references and actionable remediation guidance.

---

### Why BFSI/FinTech specifically?

General-purpose linters (bandit, semgrep community rules) detect generic Python issues. They do not surface BFSI-specific patterns — they do not flag missing audit logs on fund transfers, missing rate-limiting on authentication endpoints, or unencrypted PII storage in Indian regulatory contexts (Aadhaar, PAN numbers). They do not map findings to PCI-DSS, RBI IT Framework, or DPDP Act 2023. The compliance mapping is the differentiator: developers in BFSI need to know which specific regulatory requirement a finding is relevant to, not just that it is "a security issue."

---

### Why not use an existing linter?

Existing tools (bandit, pylint, ruff security rules, semgrep community packs) are:
- Generic across all Python codebases — not tuned for BFSI business logic
- Missing compliance framework mappings that BFSI teams need
- Not designed around the specific vulnerability categories that cause the most harm in financial services (hardcoded credentials leading to fraud, missing audit logs blocking regulatory investigation)
- Often missing the impact quantification layer (estimated review time saved, compliance frameworks triggered)

GuardRail is not a replacement for these tools — it is a domain-specific complement for BFSI codebases.

---

## Design Decisions

### Is it AI-powered?

The detection engine is deterministic — regex patterns and Python AST traversal via libcst. The `openai` dependency is present in `pyproject.toml` for a planned AI-enhanced explanation layer, but the current shipped rules, detection, and reports are entirely rule-based. There is no LLM inference in the current scan pipeline.

This is a deliberate choice: **deterministic rules produce consistent, auditable, reproducible results** — essential in a compliance context where a false positive in a CI gate has real business cost.

---

### Why deterministic rules instead of AI?

1. **Reproducibility** — the same code always produces the same finding. Required for audit trails.
2. **Explainability** — every finding can be traced to a specific regex or AST pattern. No black-box decisions.
3. **Speed** — 120 tests run in 1.2 seconds. An LLM inference call would take seconds per finding.
4. **No data leakage** — source code is never sent to an external API.
5. **Regulatory acceptability** — compliance tools used in BFSI must produce results that can be explained to an auditor.

---

### How does the rules engine work?

Rules are defined in YAML (`rules/bfsi_ruleset.yaml`) and validated by a Pydantic v2 schema at load time. Each rule specifies:
- A severity level
- A detection type (`regex` or `ast`)
- A file glob restricting which files the rule applies to
- One or more detection patterns (regex strings or AST pattern tokens)
- Compliance framework mappings
- Explanation and fix text

The walker (`scanners/walker.py`) discovers eligible files, filters them by the rule's file glob, and dispatches each (file, rule) pair to either the regex engine or the AST engine. Results are deduplicated and sorted.

---

## Findings and Output

### How are findings represented?

Each finding is a frozen Python dataclass (`scanners/models.py`):

```python
Finding(
    file: Path,          # absolute path
    line: int,           # 1-based line number
    rule_id: str,        # e.g. "GR-BFSI-001"
    severity: Severity,  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    explanation: str,    # copied from rule at detection time
    fix: str,            # copied from rule at detection time
    match_text: str      # triggering code snippet
)
```

Findings are deduplicated by `(file, line, rule_id)` and sorted. They carry a copy of the rule's explanation and fix text so consumers never need to rejoin to the rule set.

---

### How does compliance mapping work?

Every rule in `bfsi_ruleset.yaml` has a `frameworks` list containing specific regulatory references (e.g., `"PCI-DSS v4.0 Req 8.2.1"`). When a finding is produced, these framework strings are included in the Markdown and SARIF reports and displayed in the CLI and dashboard.

The impact summary normalises these into framework families (`PCI-DSS`, `GDPR`, `SOC2`, `RBI guidelines`) for the summary line. The full strings are preserved in the detailed finding output.

**Important:** These mappings indicate that the detected pattern is relevant to the cited requirement. They do not constitute a compliance certification or legal opinion.

---

### Why SARIF?

SARIF (Static Analysis Results Interchange Format) 2.1.0 is the industry standard for static analysis tool output. Choosing SARIF means:
- Findings integrate directly into GitHub Code Scanning (Security tab, PR annotations)
- VS Code SARIF Viewer extension can display findings in the IDE
- The format is supported by Azure DevOps, Defect Dojo, and most enterprise security toolchains
- No custom integration work required by the consumer

---

### Can it run in CI/CD?

Yes. The CLI exits with code `2` when CRITICAL or HIGH findings are present (code `0` for clean scans). Any CI system that reads exit codes can use this as a build gate:

```bash
guardrail scan . --severity HIGH
# exit 2 → CI step fails
```

SARIF output can be uploaded to GitHub Code Scanning with `github/codeql-action/upload-sarif`.

---

### What happens when a finding is detected?

1. The scanner adds a `Finding` to the results list
2. After all files are scanned, findings are deduplicated and sorted
3. The CLI prints findings grouped by severity with rule ID, file:line, match text, compliance mapping, and the first sentence of the explanation
4. Reports are written (Markdown + SARIF)
5. The exit code is set based on the worst finding severity
6. The impact summary quantifies the estimate of manual review time saved

---

## Accuracy and Limitations

### How do you handle false positives?

GuardRail's regex patterns are tuned for the typical patterns that represent genuine vulnerabilities in production code, not test fixtures or documentation. However, false positives are possible — for example, a commented-out block with a credential pattern, or a test fixture that deliberately includes a hardcoded value.

Current mitigations:
- Patterns require sufficient context (e.g., credential assignments require quotes and minimum length)
- The `--severity` flag allows filtering out lower-confidence rules in CI gates

Planned: suppression comments (`# guardrail: disable GR-BFSI-001`) to allow rule-specific opt-out at the code level.

---

### Does it replace security engineers?

No. GuardRail automates the detection of known-bad patterns. It cannot:
- Reason about application logic or business context
- Perform inter-procedural taint analysis
- Detect novel or previously unknown vulnerability patterns
- Conduct penetration testing or runtime analysis
- Replace a qualified security engineer or formal audit

It is a developer-facing tool that moves the first line of defence left in the development lifecycle.

---

## Validation and Metrics

### How was it validated?

- 120 automated tests covering every scanner engine, every rule (via fixture files), and every report module
- The test suite runs in 1.22 seconds
- The sample application was manually constructed to produce the expected 11 findings (2 CRITICAL, 9 HIGH) across 4 files
- Scan output and reports have been verified against the pre-generated evidence in `screenshots/`

---

### What does the 2h 45m impact number mean?

It is a computed estimate: `11 CRITICAL/HIGH findings × 15 minutes = 165 minutes ≈ 2h 45m`.

The 15-minute figure is a conservative estimate of the manual effort to identify, document, reproduce, and communicate a single CRITICAL or HIGH severity finding during a code review. It is illustrative, not measured productivity data. GuardRail makes no claim that it has been validated against real-world code review time studies.

---

### What are the limitations?

- Detection is Python-first; AST detection is Python-only. JavaScript patterns for AST rules use a regex fallback.
- No inter-procedural taint analysis — only file-level detection
- No runtime or network analysis
- `semgrep` detection type is defined in the schema but not yet implemented (silently skipped)
- Regex patterns may produce false positives on test fixtures or commented code

---

## Roadmap

### What would you build next?

1. **Semgrep engine** — enable dataflow-aware rules for taint tracking (e.g., user input flowing into SQL without sanitisation across function boundaries)
2. **Suppression comments** — `# guardrail: disable GR-BFSI-001` to allow rule-specific opt-out
3. **Baseline / diff mode** — report only new findings vs. the last committed baseline
4. **VS Code extension** — consume SARIF output directly in the IDE with inline annotations
5. **More rule categories** — cloud misconfiguration (GR-CLOUD-\*), container/IaC scanning
6. **Java and Go support** — extend AST engine to additional languages common in BFSI

---

### How would this scale?

- The current architecture is stateless and per-file — it trivially parallelises across files and rules
- For large codebases, a pre-filter stage (changed files only, `git diff HEAD`) reduces scan time
- For enterprise use, the scanner could run as a microservice exposing a REST API over the same Python core
- The YAML rule set allows a security team to maintain centralised rules distributed to all projects without modifying scanner code

---

### How would you evaluate precision/recall in production?

- **Precision:** track the ratio of confirmed-true findings to total findings raised, measured by developer feedback (accepted vs. dismissed findings)
- **Recall:** requires a labelled dataset of known-vulnerable commits in real BFSI codebases; measure the fraction of known vulnerabilities that GuardRail surfaces
- In practice this would involve partnering with a BFSI security team to run GuardRail over their historical vulnerability database and comparing findings against their audit records
- The current 120-test suite validates detection against minimal, focused fixtures — it does not claim measured precision/recall on production codebases
