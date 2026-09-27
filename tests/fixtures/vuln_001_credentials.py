# GR-BFSI-001 fixture — Hardcoded Credentials (Python)
# noqa: S106, S105
"""
Intentionally vulnerable: hard-coded credentials in multiple forms.
DO NOT deploy — sample-app fixture for GuardRail unit tests only.
"""

# Plain assignment — most common form
password = "Sup3rS3cret!"  # noqa: S105
api_key = "sk-abcdef1234567890abcdef"  # noqa: S105
secret = "my_very_secret_value"  # noqa: S105

# Connection string with embedded credentials
DATABASE_URL = "postgres://admin:P@ssw0rd123@db.example.com/finance"

# AWS access key pattern
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE1234"

# Bearer token in code
AUTH_HEADER = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefghijklmnop"

def connect():
    # Inline credential — also a hit
    return {"password": "hardcoded_pass_here"}  # noqa: S106
