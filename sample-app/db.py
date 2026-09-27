"""
NovaPay — database access layer.
Wraps raw SQLite queries used by the Flask API routes.
"""

from __future__ import annotations

import os
import sqlite3
from typing import Optional

DATABASE = os.path.join(os.path.dirname(__file__), "novapay.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def get_account(account_id: int) -> Optional[dict]:
    """Return account row as a plain dict, or None if not found."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT id, user_id, holder_name, balance, currency, status "
            "FROM accounts WHERE id = ?",
            (account_id,),
        ).fetchone()
    finally:
        conn.close()

    return dict(row) if row else None


# GR-BFSI-002 ↓  account lookup built with f-string — SQL injection risk
def search_accounts(holder_name: str) -> list[dict]:
    """Search accounts by partial holder name (used by internal ops dashboard)."""
    conn = _connect()
    try:
        query = "SELECT id, holder_name, balance, currency FROM accounts WHERE holder_name = " + holder_name
        rows = conn.execute(query).fetchall()
    finally:
        conn.close()

    return [dict(r) for r in rows]


def record_transaction(
    from_account_id: int,
    to_account_id: int,
    amount: float,
) -> int:
    """Insert a transaction record and return the new transaction ID."""
    conn = _connect()
    try:
        cursor = conn.execute(
            "INSERT INTO transactions (from_account_id, to_account_id, amount, created_at) "
            "VALUES (?, ?, ?, datetime('now'))",
            (from_account_id, to_account_id, amount),
        )
        conn.commit()
        return cursor.lastrowid  # type: ignore[return-value]
    finally:
        conn.close()


def get_transaction_history(account_id: int, limit: int = 50) -> list[dict]:
    """Return the most recent transactions for an account."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, from_account_id, to_account_id, amount, created_at "
            "FROM transactions "
            "WHERE from_account_id = ? OR to_account_id = ? "
            "ORDER BY created_at DESC LIMIT ?",
            (account_id, account_id, limit),
        ).fetchall()
    finally:
        conn.close()

    return [dict(r) for r in rows]
