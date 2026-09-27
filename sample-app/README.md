# NovaPay Sample App — GuardRail Live Demo Target

A deliberately vulnerable mini FinTech API written to look like ordinary
production code.  It is used to demo GuardRail catching real BFSI violations.

> **Do NOT deploy this application anywhere.** For local demo purposes only.

---

## Files

| File | Purpose |
|---|---|
| `app.py` | Flask API — `/api/v1/login` and `/api/v1/transfer` endpoints |
| `db.py` | Database access layer — account queries, transaction records |
| `models.py` | SQLite schema bootstrap + seed data |

---

## Embedded violations

| Rule ID | Severity | Location | What it looks like |
|---|---|---|---|
| **GR-BFSI-001** | CRITICAL | `app.py:21` | `DB_PASSWORD = "N0vaPay$DB#Prod"` — hardcoded database password |
| **GR-BFSI-002** | CRITICAL | `db.py:41` | `"SELECT … WHERE holder_name = " + holder_name` — SQL injection via concatenation |
| **GR-BFSI-003** | HIGH | `app.py:166` | `amount = float(request.json.get("amount"))` — no range/sign/precision check |
| **GR-BFSI-004** | HIGH | `app.py:83` | `hashlib.md5(password.encode()).hexdigest()` — MD5 password hashing |
| **GR-BFSI-005** | HIGH | `app.py:121` | `def transfer(...)` — no audit log call; fund movement leaves no trace |
| **GR-BFSI-007** | HIGH | `app.py:73` | `@app.route("/api/v1/login")` — no `@limiter` decorator; open to brute-force |

All violations are written as code a real developer might commit — no comments
flagging the bugs within the source files themselves.

---

## Quick demo

```bash
# 1. Bootstrap the database
cd guardrail-core/sample-app
python models.py

# 2. Scan with GuardRail
cd ..
guardrail scan sample-app/ --format rich

# GuardRail should report 6 findings across app.py and db.py.
```

---

## API endpoints (for manual testing)

```
POST /api/v1/login
    Body: {"username": "alice", "password": "Alice!Pass1"}
    Returns: {"token": "<jwt>", "expires_in": 3600}

GET  /api/v1/account/<id>
    Header: Authorization: Bearer <token>

POST /api/v1/transfer
    Header: Authorization: Bearer <token>
    Body: {"from_account_id": 1, "to_account_id": 2, "amount": 500}
```
