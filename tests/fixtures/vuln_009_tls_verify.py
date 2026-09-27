# GR-BFSI-009 fixture — TLS Certificate Verification Disabled (Python)
"""
Intentionally vulnerable: TLS verification disabled in multiple ways.
DO NOT deploy — sample-app fixture for GuardRail unit tests only.
"""

import ssl
import requests


def fetch_balance(account_id: str) -> dict:
    # verify=False disables certificate validation entirely
    response = requests.get(  # noqa: S501
        f"https://api.bank.example.com/accounts/{account_id}",
        verify=False,
    )
    return response.json()


def post_transfer(payload: dict) -> dict:
    # Also dangerous on POST with financial data
    response = requests.post(  # noqa: S501
        "https://api.bank.example.com/transfers",
        json=payload,
        verify=False,
    )
    return response.json()


def create_insecure_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False   # disables hostname verification
    ctx.verify_mode = ssl.CERT_NONE  # disables certificate verification
    return ctx
