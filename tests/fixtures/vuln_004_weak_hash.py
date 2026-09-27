# GR-BFSI-004 fixture — Insecure Password Hashing (Python)
"""
Intentionally vulnerable: passwords hashed with MD5 or SHA-1.
DO NOT deploy — sample-app fixture for GuardRail unit tests only.
"""

import hashlib


def hash_password_md5(password: str) -> str:
    # MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()  # noqa: S324


def hash_password_sha1(password: str) -> str:
    # SHA-1 is also broken for password storage
    return hashlib.sha1(password.encode()).hexdigest()  # noqa: S324


def store_user(username: str, password: str) -> dict:
    # Uses MD5 near "password" keyword
    hashed = md5(password)
    return {"username": username, "password_hash": hashed}
