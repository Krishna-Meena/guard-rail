# GR-BFSI-006 fixture — Unencrypted PII Storage (Python)
"""
Intentionally vulnerable: PII stored as plain strings without encryption.
DO NOT deploy — sample-app fixture for GuardRail unit tests only.
"""

import json
from django.db import models


class Customer(models.Model):
    # PAN and Aadhaar stored as plain text columns
    pan_number = models.Column(String(20))
    aadhaar = models.Column(String(12))
    ssn = models.Column(String(11))
    phone = models.Column(String(15))
    email = models.Column(String(255))
    date_of_birth = models.Column(String(10))


def export_customer(customer: dict) -> str:
    # PII serialised directly to JSON without encryption
    return json.dumps({"pan": customer["pan"], "aadhaar": customer["aadhaar"], "dob": customer["dob"]})


def save_record(record: dict) -> None:
    # Direct dict write of PII without encryption call
    data = {
        "pan": record["pan_number"],
        "phone_number": record["phone"],
        "email_address": record["email"],
    }
    with open("customers.json", "w") as f:
        json.dump(data, f)
