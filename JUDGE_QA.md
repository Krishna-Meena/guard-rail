# GuardRail — Judge Q&A (Quick Reference)

Concise, technically accurate answers for hackathon judges. For extended answers see `docs/JUDGE_QA.md`.

---

**What problem are you solving?**  
Security reviews in BFSI/FinTech are slow, expensive, and miss domain-specific violations. GuardRail detects them automatically, at the point of development, mapped to the exact regulatory requirements the team is accountable to.

---

**Why not just use bandit or semgrep?**  
General linters are not BFSI-aware. They do not flag missing audit logs on fund transfers, missing rate-limiting on authentication endpoints, or unencrypted Aadhaar/PAN storage. They do not map to PCI-DSS Requirement 8.3.4 or RBI IT Framework Section 7. GuardRail is domain-specific.

---

**Is it AI-powered?**  
The detection engine is deterministic: regex and Python AST via libcst. The `openai` dependency is present for a planned AI explanation layer; it is not used in the current scan pipeline. Deterministic rules are intentional in a compliance context — results must be reproducible and auditable.

---

**How does the rules engine work?**  
Rules are YAML validated by Pydantic. Each rule has a severity, a detection type (regex or AST), a file glob, patterns, compliance mappings, and fix guidance. The walker discovers eligible files, dispatches each (file, rule) pair to the correct engine, deduplicates, and sorts results.

---

**How does compliance mapping work?**  
Every rule includes a `frameworks` list with specific regulatory references (e.g., `"PCI-DSS v4.0 Req 8.2.1"`). These appear in every report and in the terminal output. They indicate relevance to a requirement, not certification of compliance.

---

**Why SARIF?**  
SARIF 2.1.0 is the industry standard for static analysis results. It integrates natively with GitHub Code Scanning (PR annotations, Security tab), VS Code SARIF Viewer, and most enterprise security toolchains.

---

**Can it run in CI/CD?**  
Yes. Exit code 0 = clean, exit code 2 = CRITICAL/HIGH present. Any CI system reads this. Example: `guardrail scan . --severity HIGH` fails the build on CRITICAL or HIGH findings.

---

**Does it replace security engineers?**  
No. It detects known-bad patterns automatically. It cannot reason about business logic, perform inter-procedural taint analysis, or conduct penetration testing. It is a developer-facing tool that moves the first line of defence left in the lifecycle.

---

**What does the 2h 45m mean?**  
11 CRITICAL/HIGH findings × 15 minutes per finding = 165 minutes. The 15-minute figure is a conservative, illustrative estimate of the effort to identify, document, and communicate one CRITICAL/HIGH finding during a code review. It is not measured productivity data.

---

**What are the limitations?**  
- AST detection is Python-only; JS AST rules fall back to regex
- No inter-procedural analysis
- Semgrep detection type not yet implemented
- Regex may false-positive on commented code or test fixtures

---

**What would you build next?**  
Semgrep dataflow engine, suppression comments (`# guardrail: disable GR-BFSI-001`), VS Code extension, baseline/diff mode, expanded language support (Java, Go).

---

**How would this scale?**  
The scanner is stateless and per-file — trivially parallelisable. For large repos, integrate with `git diff HEAD` to scan only changed files. For enterprise use, expose as a microservice over the Python core.
