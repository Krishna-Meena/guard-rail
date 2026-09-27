# GR-BFSI-003 fixture — Missing Input Validation on Financial Fields (Python)
"""
Intentionally vulnerable: financial fields used raw from request without validation.
DO NOT deploy — sample-app fixture for GuardRail unit tests only.
"""

from flask import Flask, request

app = Flask(__name__)


@app.route("/transfer", methods=["POST"])
def transfer():
    # Amount taken from request body and used directly — no validation
    amount = request.form.amount  # noqa: B010
    balance = request.data.balance

    # Direct type cast without try/except or range check
    quantity = int(request.form.get("quantity"))
    price = float(request.json.get("price"))
    fee = Decimal(request.args.get("fee"))

    total = amount + fee
    return {"status": "ok", "total": total}
