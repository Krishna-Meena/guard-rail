"""
NovaPay — SQLite schema bootstrap.
Run once to create the development database with seed data.

Usage:
    python models.py
"""

from __future__ import annotations

import hashlib
import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(__file__), "novapay.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'customer',
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    holder_name   TEXT    NOT NULL,
    balance       REAL    NOT NULL DEFAULT 0.0,
    currency      TEXT    NOT NULL DEFAULT 'INR',
    status        TEXT    NOT NULL DEFAULT 'active',
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS transactions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    from_account_id   INTEGER NOT NULL REFERENCES accounts(id),
    to_account_id     INTEGER NOT NULL REFERENCES accounts(id),
    amount            REAL    NOT NULL,
    created_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


def _hash_password(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()  # noqa: S324


def bootstrap(db_path: str = DATABASE) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)

        conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", _hash_password("admin123"), "admin"),
        )
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("alice", _hash_password("Alice!Pass1"), "customer"),
        )
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("bob", _hash_password("Bob!Pass2"), "customer"),
        )
        conn.commit()

        alice_id = conn.execute(
            "SELECT id FROM users WHERE username = 'alice'"
        ).fetchone()[0]
        bob_id = conn.execute(
            "SELECT id FROM users WHERE username = 'bob'"
        ).fetchone()[0]

        conn.execute(
            "INSERT OR IGNORE INTO accounts (user_id, holder_name, balance) VALUES (?, ?, ?)",
            (alice_id, "Alice Sharma", 50000.00),
        )
        conn.execute(
            "INSERT OR IGNORE INTO accounts (user_id, holder_name, balance) VALUES (?, ?, ?)",
            (bob_id, "Bob Mehta", 25000.00),
        )
        conn.commit()
    finally:
        conn.close()

    print(f"Database bootstrapped at: {db_path}")


if __name__ == "__main__":
    bootstrap()
