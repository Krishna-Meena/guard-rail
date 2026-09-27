# GR-BFSI-005 fixture — Missing Audit Log on Sensitive Operations (Python)
"""
Intentionally vulnerable: sensitive financial operations with no audit logging.
DO NOT deploy — sample-app fixture for GuardRail unit tests only.
"""

from decimal import Decimal


def transfer(from_account: str, to_account: str, amount: Decimal) -> None:
    """Transfer funds — no audit log call."""
    _debit(from_account, amount)
    _credit(to_account, amount)


def login(username: str, password: str) -> bool:
    """Authenticate user — no audit log call."""
    return _check_credentials(username, password)


def change_password(user_id: str, new_password: str) -> None:
    """Change user password — no audit log call."""
    _update_password(user_id, new_password)


def get_kyc(customer_id: str) -> dict:
    """Fetch KYC data — no audit log call."""
    return _load_kyc(customer_id)


# Stubs
def _debit(account: str, amount: Decimal) -> None: ...
def _credit(account: str, amount: Decimal) -> None: ...
def _check_credentials(u: str, p: str) -> bool: return False
def _update_password(u: str, p: str) -> None: ...
def _load_kyc(c: str) -> dict: return {}
