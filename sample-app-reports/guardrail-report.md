# GuardRail Compliance Report

**Scan target:** `sample-app`  
**Generated:** 2026-09-27 11:12 UTC  
**Total findings:** 11  

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

- **File:** `app.py` line 21
- **Match:** `PASSWORD = "N0vaPay$DB#Prod"`
- **Compliance:** maps to PCI-DSS v4.0 Req 8.2.1, OWASP A07:2021 Identification and Authentication Failures, CWE-798
- **Why:** A credential (password, API key, secret token, or private key) is hard-coded directly in source code. If this repository is ever shared, committed to version control, or inspected by an insider, the secret is immediately exposed — no attack sophistication required. In BFSI environments this can lead to full account takeover, unauthorized fund transfers, and severe regulatory penalties under PCI-DSS and RBI IT Framework.
- **Fix:** 1. Revoke the exposed credential immediately. 2. Move all secrets to an environment variable or a secrets manager
   (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, or
   GCP Secret Manager).
3. Reference secrets at runtime via os.environ.get("SECRET_NAME") or
   the secrets-manager SDK — never interpolate them as string literals.
4. Add a pre-commit hook (e.g. git-secrets, truffleHog, detect-secrets)
   to prevent future accidental commits.

#### `GR-BFSI-002` — SQL Injection Risk

- **File:** `db.py` line 41
- **Match:** `"SELECT id, holder_name, balance, currency FROM accounts WHERE holder_name = " +`
- **Compliance:** maps to OWASP A03:2021 Injection, PCI-DSS v4.0 Req 6.2.4, CWE-89, RBI IT Framework 6.2 (Application Security)
- **Why:** User-supplied or external data is concatenated directly into a SQL statement without parameterisation. An attacker can inject arbitrary SQL, extract the entire database (including account numbers, KYC data, and transaction history), modify balances, or drop tables. This is the most exploited vulnerability class in financial applications and results in mandatory breach disclosure under RBI and GDPR.
- **Fix:** Always use parameterised queries or a safe ORM:

  # Bad
  cursor.execute("SELECT * FROM accounts WHERE id = " + user_id)

  # Good (parameterised)
  cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))

  # Good (SQLAlchemy ORM)
  session.query(Account).filter(Account.id == user_id).first()

If raw SQL is required, use your database driver's parameter placeholder (e.g. %s for psycopg2, ? for sqlite3, :param for SQLAlchemy text()). Never use str.format(), f-strings, or % interpolation to build queries.

### 🟠 HIGH (9)

#### `GR-BFSI-007` — Missing Rate-Limiting on Authentication Endpoints

- **File:** `app.py` line 73
- **Match:** `@app.route("/api/v1/login"`
- **Compliance:** maps to OWASP A07:2021 Identification and Authentication Failures, PCI-DSS v4.0 Req 8.3.4, RBI IT Framework 5.3 (Access Control), CWE-307
- **Why:** Authentication endpoints (login, OTP verification, password reset, token issuance) are defined without any visible rate-limiting or account lockout mechanism. Without rate-limiting, an attacker can perform credential-stuffing or brute-force attacks at machine speed — testing millions of password combinations against customer accounts. PCI-DSS Req 8.3.4 mandates lockout after 10 failed attempts. A successful attack gives full account access and the ability to authorise fraudulent transactions.
- **Fix:** Apply rate-limiting at the framework or infrastructure level:

  # Flask — flask-limiter
  from flask_limiter import Limiter
  limiter = Limiter(app, key_func=get_remote_address)

  @app.route("/login", methods=["POST"])
  @limiter.limit("5 per minute; 20 per hour")
  def login(): ...

  # FastAPI — slowapi
  from slowapi import Limiter
  from slowapi.util import get_remote_address
  limiter = Limiter(key_func=get_remote_address)

  @router.post("/login")
  @limiter.limit("5/minute")
  async def login(request: Request): ...

Additionally implement:
  - Progressive delays after N failed attempts
  - Account lockout after 10 failures (PCI-DSS minimum)
  - CAPTCHA after 3–5 failures
  - Alerting / audit log on repeated failures from same IP

#### `GR-BFSI-005` — Missing Audit-Log on Sensitive Operations

- **File:** `app.py` line 74
- **Match:** `def login(`
- **Compliance:** maps to PCI-DSS v4.0 Req 10.2.1, RBI IT Framework 7 (Audit Trail), SEBI CSCRF Annex B-3, ISO 27001 A.12.4, CWE-778
- **Why:** Sensitive operations (fund transfers, PII access, authentication events, credential changes) appear to be performed without an adjacent audit-log call. Comprehensive, tamper-evident audit trails are mandatory under PCI-DSS Req 10, RBI IT Framework Section 7, and SEBI CSCRF. Without them, fraud investigations are impossible, regulatory audits fail, and incident response is severely hampered.
- **Fix:** Every sensitive operation must emit a structured audit event before returning, even on failure:

  import logging
  import time

  audit_logger = logging.getLogger("guardrail.audit")

  def transfer_funds(from_account: str, to_account: str, amount: Decimal) -> None:
      audit_logger.info(
          "FUND_TRANSFER_INITIATED",
          extra={
              "event_type": "FUND_TRANSFER",
              "from_account": from_account,
              "to_account": to_account,
              "amount": str(amount),
              "user_id": current_user.id,
              "timestamp": time.time(),
              "ip_address": request.remote_addr,
          },
      )
      # ... business logic ...

Route audit logs to an append-only, off-system log store (SIEM, cloud logging) that application code cannot delete or modify.

#### `GR-BFSI-004` — Insecure Password Hashing (MD5 / SHA-1)

- **File:** `app.py` line 83
- **Match:** `hashlib.md5(`
- **Compliance:** maps to PCI-DSS v4.0 Req 8.3.1, OWASP A02:2021 Cryptographic Failures, NIST SP 800-131A Rev 2, CWE-916
- **Why:** MD5 and SHA-1 are cryptographically broken hash functions. Pre-computed rainbow tables and GPU-accelerated brute-force tools can reverse an MD5 or SHA-1 password hash in seconds to minutes. PCI-DSS v4.0 explicitly prohibits their use for credential storage. Using them in a BFSI application exposes every customer password if the database is breached, leading to account takeover, regulatory fines, and reputational damage.
- **Fix:** Use a modern, slow, memory-hard password hashing algorithm:

  # Python — bcrypt (recommended)
  import bcrypt
  hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
  bcrypt.checkpw(password.encode(), hashed)

  # Python — argon2-cffi (NIST-recommended post-2023)
  from argon2 import PasswordHasher
  ph = PasswordHasher()
  hashed = ph.hash(password)
  ph.verify(hashed, password)

Never use MD5, SHA-1, or even SHA-256 without a slow KDF (key derivation function) for password storage. For non-password data integrity use SHA-256 or SHA-3 minimum.

#### `GR-BFSI-005` — Missing Audit-Log on Sensitive Operations

- **File:** `app.py` line 121
- **Match:** `def transfer(`
- **Compliance:** maps to PCI-DSS v4.0 Req 10.2.1, RBI IT Framework 7 (Audit Trail), SEBI CSCRF Annex B-3, ISO 27001 A.12.4, CWE-778
- **Why:** Sensitive operations (fund transfers, PII access, authentication events, credential changes) appear to be performed without an adjacent audit-log call. Comprehensive, tamper-evident audit trails are mandatory under PCI-DSS Req 10, RBI IT Framework Section 7, and SEBI CSCRF. Without them, fraud investigations are impossible, regulatory audits fail, and incident response is severely hampered.
- **Fix:** Every sensitive operation must emit a structured audit event before returning, even on failure:

  import logging
  import time

  audit_logger = logging.getLogger("guardrail.audit")

  def transfer_funds(from_account: str, to_account: str, amount: Decimal) -> None:
      audit_logger.info(
          "FUND_TRANSFER_INITIATED",
          extra={
              "event_type": "FUND_TRANSFER",
              "from_account": from_account,
              "to_account": to_account,
              "amount": str(amount),
              "user_id": current_user.id,
              "timestamp": time.time(),
              "ip_address": request.remote_addr,
          },
      )
      # ... business logic ...

Route audit logs to an append-only, off-system log store (SIEM, cloud logging) that application code cannot delete or modify.

#### `GR-BFSI-005` — Missing Audit-Log on Sensitive Operations

- **File:** `app.py` line 159
- **Match:** `def fund_transfer(`
- **Compliance:** maps to PCI-DSS v4.0 Req 10.2.1, RBI IT Framework 7 (Audit Trail), SEBI CSCRF Annex B-3, ISO 27001 A.12.4, CWE-778
- **Why:** Sensitive operations (fund transfers, PII access, authentication events, credential changes) appear to be performed without an adjacent audit-log call. Comprehensive, tamper-evident audit trails are mandatory under PCI-DSS Req 10, RBI IT Framework Section 7, and SEBI CSCRF. Without them, fraud investigations are impossible, regulatory audits fail, and incident response is severely hampered.
- **Fix:** Every sensitive operation must emit a structured audit event before returning, even on failure:

  import logging
  import time

  audit_logger = logging.getLogger("guardrail.audit")

  def transfer_funds(from_account: str, to_account: str, amount: Decimal) -> None:
      audit_logger.info(
          "FUND_TRANSFER_INITIATED",
          extra={
              "event_type": "FUND_TRANSFER",
              "from_account": from_account,
              "to_account": to_account,
              "amount": str(amount),
              "user_id": current_user.id,
              "timestamp": time.time(),
              "ip_address": request.remote_addr,
          },
      )
      # ... business logic ...

Route audit logs to an append-only, off-system log store (SIEM, cloud logging) that application code cannot delete or modify.

#### `GR-BFSI-003` — Missing Input Validation on Financial Fields

- **File:** `app.py` line 163
- **Match:** `int(body.`
- **Compliance:** maps to OWASP A03:2021 Injection, PCI-DSS v4.0 Req 6.2.4, RBI IT Framework 6.2, CWE-20
- **Why:** Financial amounts, account numbers, or quantities read from user input or an external API are used in calculations without first validating their type, range, sign, and precision. This can cause negative balance injection (transferring a negative amount to add funds), integer overflow in fee calculations, and floating-point rounding exploits — all of which have led to real financial losses and regulatory sanctions in production BFSI systems.
- **Fix:** Validate every financial field before use:

  from decimal import Decimal, InvalidOperation

  def parse_amount(raw: str) -> Decimal:
      try:
          value = Decimal(raw)
      except InvalidOperation:
          raise ValueError("Invalid amount format")
      if value <= 0:
          raise ValueError("Amount must be positive")
      if value > MAX_TRANSFER_LIMIT:
          raise ValueError("Amount exceeds transfer limit")
      # Enforce precision (e.g. max 2 decimal places for INR)
      if value.as_tuple().exponent < -2:
          raise ValueError("Amount has too many decimal places")
      return value

Use Decimal (not float) for all monetary values to avoid floating-point rounding errors. Never accept negative amounts unless the business logic explicitly requires it.

#### `GR-BFSI-003` — Missing Input Validation on Financial Fields

- **File:** `app.py` line 164
- **Match:** `int(body.`
- **Compliance:** maps to OWASP A03:2021 Injection, PCI-DSS v4.0 Req 6.2.4, RBI IT Framework 6.2, CWE-20
- **Why:** Financial amounts, account numbers, or quantities read from user input or an external API are used in calculations without first validating their type, range, sign, and precision. This can cause negative balance injection (transferring a negative amount to add funds), integer overflow in fee calculations, and floating-point rounding exploits — all of which have led to real financial losses and regulatory sanctions in production BFSI systems.
- **Fix:** Validate every financial field before use:

  from decimal import Decimal, InvalidOperation

  def parse_amount(raw: str) -> Decimal:
      try:
          value = Decimal(raw)
      except InvalidOperation:
          raise ValueError("Invalid amount format")
      if value <= 0:
          raise ValueError("Amount must be positive")
      if value > MAX_TRANSFER_LIMIT:
          raise ValueError("Amount exceeds transfer limit")
      # Enforce precision (e.g. max 2 decimal places for INR)
      if value.as_tuple().exponent < -2:
          raise ValueError("Amount has too many decimal places")
      return value

Use Decimal (not float) for all monetary values to avoid floating-point rounding errors. Never accept negative amounts unless the business logic explicitly requires it.

#### `GR-BFSI-003` — Missing Input Validation on Financial Fields

- **File:** `app.py` line 166
- **Match:** `float(request.`
- **Compliance:** maps to OWASP A03:2021 Injection, PCI-DSS v4.0 Req 6.2.4, RBI IT Framework 6.2, CWE-20
- **Why:** Financial amounts, account numbers, or quantities read from user input or an external API are used in calculations without first validating their type, range, sign, and precision. This can cause negative balance injection (transferring a negative amount to add funds), integer overflow in fee calculations, and floating-point rounding exploits — all of which have led to real financial losses and regulatory sanctions in production BFSI systems.
- **Fix:** Validate every financial field before use:

  from decimal import Decimal, InvalidOperation

  def parse_amount(raw: str) -> Decimal:
      try:
          value = Decimal(raw)
      except InvalidOperation:
          raise ValueError("Invalid amount format")
      if value <= 0:
          raise ValueError("Amount must be positive")
      if value > MAX_TRANSFER_LIMIT:
          raise ValueError("Amount exceeds transfer limit")
      # Enforce precision (e.g. max 2 decimal places for INR)
      if value.as_tuple().exponent < -2:
          raise ValueError("Amount has too many decimal places")
      return value

Use Decimal (not float) for all monetary values to avoid floating-point rounding errors. Never accept negative amounts unless the business logic explicitly requires it.

#### `GR-BFSI-004` — Insecure Password Hashing (MD5 / SHA-1)

- **File:** `models.py` line 47
- **Match:** `hashlib.md5(`
- **Compliance:** maps to PCI-DSS v4.0 Req 8.3.1, OWASP A02:2021 Cryptographic Failures, NIST SP 800-131A Rev 2, CWE-916
- **Why:** MD5 and SHA-1 are cryptographically broken hash functions. Pre-computed rainbow tables and GPU-accelerated brute-force tools can reverse an MD5 or SHA-1 password hash in seconds to minutes. PCI-DSS v4.0 explicitly prohibits their use for credential storage. Using them in a BFSI application exposes every customer password if the database is breached, leading to account takeover, regulatory fines, and reputational damage.
- **Fix:** Use a modern, slow, memory-hard password hashing algorithm:

  # Python — bcrypt (recommended)
  import bcrypt
  hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
  bcrypt.checkpw(password.encode(), hashed)

  # Python — argon2-cffi (NIST-recommended post-2023)
  from argon2 import PasswordHasher
  ph = PasswordHasher()
  hashed = ph.hash(password)
  ph.verify(hashed, password)

Never use MD5, SHA-1, or even SHA-256 without a slow KDF (key derivation function) for password storage. For non-password data integrity use SHA-256 or SHA-3 minimum.
