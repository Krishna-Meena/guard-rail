# GR-BFSI-007 fixture — Missing Rate-Limiting on Auth Endpoints (Python)
"""
Intentionally vulnerable: auth endpoints with no rate-limit decorator.
DO NOT deploy — sample-app fixture for GuardRail unit tests only.
"""

from flask import Flask, request

app = Flask(__name__)


# Login endpoint — no @limiter.limit() decorator
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    return {"token": "..."}


# OTP verify — no rate limit
@app.route("/auth/otp", methods=["POST"])
def verify_otp():
    otp = request.json.get("otp")
    return {"valid": True}


# Password reset — no rate limit
@app.post("/password/reset")
def reset_password():
    email = request.json.get("email")
    return {"sent": True}


# Token refresh — no rate limit
@app.route("/auth/token", methods=["POST"])
def refresh_token():
    refresh = request.json.get("refresh_token")
    return {"access_token": "..."}
