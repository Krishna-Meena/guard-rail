# GuardRail — Rules and Compliance Reference

This document describes each rule in the GuardRail BFSI/FinTech Core Rule Set v1.0 and explains how compliance framework mappings work.

> **Important:** Compliance mappings in GuardRail indicate that the detected code pattern is *relevant to* the cited regulatory requirement. They are reference information only. They do not constitute a certification of compliance, a legal opinion, or a complete audit of any regulatory obligation. Remediating a finding is a necessary but not sufficient condition for satisfying the cited requirement.

---

## Rule Set Metadata

| Field | Value |
|---|---|
| Name | BFSI/FinTech Core Rule Set |
| Version | 1.0 |
| Location | `rules/bfsi_ruleset.yaml` |
| Schema | `rules/schema.py` (Pydantic v2) |
| Rule count | 9 |

---

## Rule Reference

### GR-BFSI-001 — Hardcoded Credentials

| Field | Value |
|---|---|
| **Severity** | CRITICAL |
| **Category** | Secrets Management |
| **Detection type** | Regex |
| **File glob** | `**/*.{py,js,ts,java,go,rb,php,env,yaml,yml,toml,properties,xml,json}` |
| **Compliance** | PCI-DSS v4.0 Req 8.2.1 · OWASP A07:2021 · CWE-798 |

**What it detects:**  
- Assignments of passwords, secrets, API keys, auth tokens, or private keys to string literals
- Connection strings with embedded credentials (JDBC, MongoDB, Redis, PostgreSQL, MySQL, MSSQL)
- Cloud provider key patterns (AWS `AKIA…`, GCP `AIza…`, Azure UUID format)
- Hardcoded Bearer or Basic auth tokens in source code

**Risk:** A hardcoded credential exposed in version control or shared code gives an attacker immediate access with no exploitation skill required. In BFSI environments this can enable full account takeover and unauthorised fund transfers.

**Fix:** Revoke the credential immediately. Move all secrets to environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, GCP Secret Manager). Use a pre-commit hook to prevent future commits.

---

### GR-BFSI-002 — SQL Injection Risk

| Field | Value |
|---|---|
| **Severity** | CRITICAL |
| **Category** | Injection |
| **Detection type** | Regex |
| **File glob** | `**/*.{py,js,ts,java,go,rb,php}` |
| **Compliance** | OWASP A03:2021 · PCI-DSS v4.0 Req 6.2.4 · CWE-89 · RBI IT Framework 6.2 |

**What it detects:**  
- String formatting or concatenation fed into `execute()` / `query()` / `raw()`
- Python f-strings or `%`-format in SQL contexts (`SELECT`, `INSERT`, `UPDATE`, `DELETE`)
- Direct string concatenation before a variable name in SQL context
- JS/TS string literal opening with SQL keyword followed by `+`

**Risk:** An attacker can inject arbitrary SQL, extract the entire database, modify balances, or drop tables. The most exploited vulnerability class in financial applications.

**Fix:** Always use parameterised queries or a safe ORM. Never use `str.format()`, f-strings, or `%` interpolation to build SQL queries.

---

### GR-BFSI-003 — Missing Input Validation on Financial Fields

| Field | Value |
|---|---|
| **Severity** | HIGH |
| **Category** | Input Validation |
| **Detection type** | Regex |
| **File glob** | `**/*.{py,js,ts,java}` |
| **Compliance** | OWASP A03:2021 · PCI-DSS v4.0 Req 6.2.4 · RBI IT Framework 6.2 · CWE-20 |

**What it detects:**  
- Financial field names (`amount`, `balance`, `transfer_amount`, `credit`, `debit`, `price`, `fee`) assigned directly from request/body objects
- Unsafe type casting of request data with `float()`, `int()`, or `Decimal()` without prior validation

**Risk:** Negative balance injection, integer overflow in fee calculations, floating-point rounding exploits — all documented real-world attacks on production BFSI systems.

**Fix:** Validate type, range, sign, and precision for every financial field before use. Use `Decimal` (not `float`) for monetary values.

---

### GR-BFSI-004 — Insecure Password Hashing (MD5 / SHA-1)

| Field | Value |
|---|---|
| **Severity** | HIGH |
| **Category** | Cryptography |
| **Detection type** | Regex |
| **File glob** | `**/*.{py,js,ts,java,go,rb,php}` |
| **Compliance** | PCI-DSS v4.0 Req 8.3.1 · OWASP A02:2021 · NIST SP 800-131A Rev 2 · CWE-916 |

**What it detects:**  
- Direct use of `hashlib.md5()`, `hashlib.sha1()`, `md5()`, `sha1()` in Python
- `MessageDigest.getInstance("MD5"/"SHA-1")` in Java
- `crypto.createHash("md5"/"sha1")` in JavaScript
- MD5/SHA-1 references in close proximity to "password" keyword

**Risk:** MD5 and SHA-1 are cryptographically broken. GPU-accelerated brute-force tools can reverse an MD5 password hash in seconds. PCI-DSS v4.0 explicitly prohibits their use for credential storage.

**Fix:** Use bcrypt, argon2, or scrypt for password hashing. Never use MD5, SHA-1, or even SHA-256 without a slow key derivation function for password storage.

---

### GR-BFSI-005 — Missing Audit-Log on Sensitive Operations

| Field | Value |
|---|---|
| **Severity** | HIGH |
| **Category** | Audit & Logging |
| **Detection type** | Regex |
| **File glob** | `**/*.{py,js,ts,java}` |
| **Compliance** | PCI-DSS v4.0 Req 10.2.1 · RBI IT Framework 7 · SEBI CSCRF Annex B-3 · ISO 27001 A.12.4 · CWE-778 |

**What it detects:**  
- Function definitions for sensitive operations by name: `transfer`, `fund_transfer`, `wire_transfer`, `remit`, `debit`, `credit`, `login`, `authenticate`, `verify_otp`, `validate_token`, `change_password`, `reset_password`, `get_pii`, `access_pii`, `fetch_customer`, `get_kyc`, `view_account`

**Risk:** Sensitive operations without audit trails make fraud investigation impossible, cause regulatory audit failures, and violate PCI-DSS Req 10, RBI IT Framework Section 7, and SEBI CSCRF.

**Fix:** Every sensitive function must emit a structured audit event before returning, even on failure. Route audit logs to an append-only, off-system log store.

---

### GR-BFSI-006 — Unencrypted PII Storage

| Field | Value |
|---|---|
| **Severity** | CRITICAL |
| **Category** | Data Protection |
| **Detection type** | Regex |
| **File glob** | `**/*.{py,js,ts,java}` |
| **Compliance** | PCI-DSS v4.0 Req 3.5 · GDPR Art. 5(1)(f) / Art. 32 · RBI IT Framework 4 · DPDP Act 2023 · CWE-312 |

**What it detects:**  
- ORM/model fields for PII (`pan_number`, `aadhaar`, `ssn`, `national_id`, `passport`, `dob`, `phone`, `mobile`, `email`) typed as plain `String`/`Text`/`VARCHAR` columns
- Direct dict/JSON writes of PII field names not followed by an encryption call
- Serialising PII fields to plain JSON via `json.dump()`/`json.dumps()`

**Risk:** Plain-text PII storage violates PCI-DSS, GDPR, RBI Data Localisation norms, and DPDP Act 2023. A single database breach exposes every customer's identity.

**Fix:** Encrypt PII at the field/application level before persisting. Use AES-256-GCM via a secrets manager-backed key. Consider ORM-level encrypted field types.

---

### GR-BFSI-007 — Missing Rate-Limiting on Authentication Endpoints

| Field | Value |
|---|---|
| **Severity** | HIGH |
| **Category** | Access Control |
| **Detection type** | Regex |
| **File glob** | `**/*.{py,js,ts,java}` |
| **Compliance** | OWASP A07:2021 · PCI-DSS v4.0 Req 8.3.4 · RBI IT Framework 5.3 · CWE-307 |

**What it detects:**  
- Flask/FastAPI/Django route decorators on paths containing: `login`, `signin`, `auth`, `otp`, `token`, `password`, `forgot`
- Express.js route registrations for authentication paths
- Spring `@PostMapping`/`@GetMapping` on authentication controllers

**Risk:** Without rate-limiting, credential-stuffing and brute-force attacks can test millions of password combinations against customer accounts. PCI-DSS Req 8.3.4 mandates lockout after 10 failed attempts.

**Fix:** Apply rate-limiting at the framework level (`flask-limiter`, `slowapi`). Implement progressive delays, account lockout after 10 failures, and CAPTCHA after 3–5 failures.

---

### GR-BFSI-008 — Dangerous subprocess / eval Usage

| Field | Value |
|---|---|
| **Severity** | CRITICAL |
| **Category** | Code Injection |
| **Detection type** | AST (Python) |
| **File glob** | `**/*.{py,js,ts,jsx,tsx}` |
| **Compliance** | OWASP A03:2021 · PCI-DSS v4.0 Req 6.2.4 · CWE-78 · CWE-95 |

**What it detects (Python AST patterns):**  
- Bare `eval()` and `exec()` calls
- `subprocess` invocations with `shell=True`
- `os.system()` calls
- `os.popen()` calls

**Risk:** `eval()`, `exec()`, and `subprocess(shell=True)` allow arbitrary code execution if any part of the input is user-controlled. In BFSI this can lead to complete server compromise and data exfiltration.

**Fix:** Replace `eval`/`exec` with `ast.literal_eval()` for safe Python literal parsing. Replace `subprocess(shell=True)` with a list of arguments. Never pass user-controlled data to `os.system()` or `os.popen()`.

---

### GR-BFSI-009 — TLS Certificate Verification Disabled

| Field | Value |
|---|---|
| **Severity** | HIGH |
| **Category** | Cryptography |
| **Detection type** | AST (Python) |
| **File glob** | `**/*.{py,js,ts,jsx,tsx}` |
| **Compliance** | OWASP A02:2021 · PCI-DSS v4.0 Req 4.2.1 · CWE-295 · RBI IT Framework 4.3 |

**What it detects (Python AST patterns):**  
- `requests.get/post/put/patch/delete(..., verify=False)`
- `ssl.SSLContext` assignments to `check_hostname` (typically `= False`)
- `ssl.SSLContext` assignments to `verify_mode` (may be `ssl.CERT_NONE`)

**Risk:** Disabling TLS verification removes protection against man-in-the-middle attacks. In BFSI, an attacker can intercept payment instructions, authentication tokens, and customer PII with no visible indication. PCI-DSS Req 4.2.1 mandates strong TLS with proper certificate validation.

**Fix:** Never disable TLS certificate verification in production. Use `verify=True` (the default) for requests. For self-signed certificates in test environments, provide a CA bundle path rather than disabling verification.

---

## Compliance Framework Summary

The table below shows which frameworks are referenced across the current rule set. This represents the scope of the **current 9-rule set** only.

| Framework | Version referenced | Rules |
|---|---|---|
| PCI-DSS | v4.0 | GR-BFSI-001, 002, 003, 004, 005, 006, 007, 008, 009 |
| OWASP Top 10 | 2021 | GR-BFSI-001, 002, 003, 004, 007, 008, 009 |
| RBI IT Framework | — | GR-BFSI-002, 003, 005, 006, 007, 009 |
| SEBI CSCRF | — | GR-BFSI-005 |
| ISO 27001 | — | GR-BFSI-005 |
| NIST SP 800-131A | Rev 2 | GR-BFSI-004 |
| GDPR | Art. 5(1)(f) / Art. 32 | GR-BFSI-006 |
| DPDP Act | 2023 (India) | GR-BFSI-006 |
| CWE | Various | All rules |

---

## Severity Definitions

| Level | Meaning in GuardRail context |
|---|---|
| CRITICAL | Exploitable, immediate financial or data loss risk; must remediate immediately |
| HIGH | Serious vulnerability; must fix before production deployment |
| MEDIUM | Significant risk; fix within the current sprint |
| LOW | Minor risk or best-practice deviation |
| INFO | Informational or advisory; no immediate action required |

---

## Adding Custom Rules

To extend the rule set with domain-specific rules, create a new YAML file following the same structure as `rules/bfsi_ruleset.yaml`. Load it at scan time:

```bash
guardrail scan /path/to/project/ --ruleset /path/to/custom-rules.yaml
```

Rules in a custom file must:
- Use unique IDs matching `^GR-[A-Z]+-\d{3}$` (e.g., `GR-CLOUD-001` for cloud rules)
- Include all required fields: `id`, `name`, `category`, `severity`, `frameworks`, `detection`, `explanation`, `fix`, `references`
- Use `detection.type` of `regex` or `ast` (semgrep is not yet implemented)
