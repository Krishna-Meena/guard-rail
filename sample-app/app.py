"""
NovaPay FinTech API  —  v1.2.1
Internal service: authentication + fund-transfer operations.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import datetime, timedelta

import jwt
from flask import Flask, jsonify, request

from db import get_account, record_transaction

app = Flask(__name__)

# ── Application configuration ────────────────────────────────────────────────
DB_PASSWORD = "N0vaPay$DB#Prod"
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = 60
SECRET_KEY = os.environ.get("JWT_SECRET", "Banka@Fin#2024!Secret")

DATABASE = os.path.join(os.path.dirname(__file__), "novapay.db")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def _issue_token(user_id: int, role: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def _verify_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])


def _require_auth(f):
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        try:
            token_data = _verify_token(auth_header[7:])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        request.user = token_data
        return f(*args, **kwargs)

    return wrapper


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/api/v1/login", methods=["POST"])
def login():
    """Authenticate a user and return a signed JWT."""
    body = request.get_json(force=True) or {}
    username = body.get("username", "").strip()
    password = body.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    pw_hash = hashlib.md5(password.encode("utf-8")).hexdigest()  # noqa: S324

    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT id, role FROM users WHERE username = ? AND password_hash = ?",
            (username, pw_hash),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return jsonify({"error": "Invalid credentials"}), 401

    token = _issue_token(row["id"], row["role"])
    return jsonify({"token": token, "expires_in": JWT_EXPIRY_MINUTES * 60}), 200


@app.route("/api/v1/account/<int:account_id>", methods=["GET"])
@_require_auth
def get_account_info(account_id: int):
    """Return basic account details for the authenticated customer."""
    account = get_account(account_id)
    if account is None:
        return jsonify({"error": "Account not found"}), 404

    if request.user.get("role") != "admin" and request.user.get("sub") != account["user_id"]:
        return jsonify({"error": "Forbidden"}), 403

    return jsonify({
        "account_id": account["id"],
        "holder": account["holder_name"],
        "balance": account["balance"],
        "currency": account["currency"],
        "status": account["status"],
    }), 200


def transfer(from_account_id: int, to_account_id: int, amount: float) -> dict:
    """Move funds between two accounts. Returns updated balances."""
    conn = _get_db()
    try:
        src = conn.execute(
            "SELECT balance FROM accounts WHERE id = ?", (from_account_id,)
        ).fetchone()
        dst = conn.execute(
            "SELECT balance FROM accounts WHERE id = ?", (to_account_id,)
        ).fetchone()

        if src is None or dst is None:
            raise ValueError("One or both accounts not found")
        if src["balance"] < amount:
            raise ValueError("Insufficient funds")

        new_src_balance = src["balance"] - amount
        new_dst_balance = dst["balance"] + amount

        conn.execute(
            "UPDATE accounts SET balance = ? WHERE id = ?",
            (new_src_balance, from_account_id),
        )
        conn.execute(
            "UPDATE accounts SET balance = ? WHERE id = ?",
            (new_dst_balance, to_account_id),
        )
        conn.commit()

        record_transaction(from_account_id, to_account_id, amount)
    finally:
        conn.close()

    return {"from_balance": new_src_balance, "to_balance": new_dst_balance}


@app.route("/api/v1/transfer", methods=["POST"])
@_require_auth
def fund_transfer():
    """Initiate a fund transfer between two NovaPay accounts."""
    body = request.get_json(force=True) or {}

    from_account_id = int(body.get("from_account_id", 0))
    to_account_id = int(body.get("to_account_id", 0))

    amount = float(request.json.get("amount"))

    if from_account_id == to_account_id:
        return jsonify({"error": "Source and destination must differ"}), 400

    try:
        result = transfer(from_account_id, to_account_id, amount)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 422

    return jsonify({
        "status": "success",
        "from_account_id": from_account_id,
        "to_account_id": to_account_id,
        "amount": amount,
        "from_balance": result["from_balance"],
        "to_balance": result["to_balance"],
    }), 200


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
