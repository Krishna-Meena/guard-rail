// GR-BFSI-007 fixture — Missing Rate-Limiting on Auth Endpoints (JavaScript/Express)
// Intentionally vulnerable. DO NOT deploy.

const express = require('express');
const router = express.Router();

// Login endpoint — no rate limiter middleware
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    res.json({ token: '...' });
});

// OTP verify — no rate limit
router.post('/auth/otp', (req, res) => {
    const { otp } = req.body;
    res.json({ valid: true });
});

// Password reset — no rate limit
router.post('/password/reset', (req, res) => {
    const { email } = req.body;
    res.json({ sent: true });
});

// Signin — no rate limit
router.post('/signin', (req, res) => {
    res.json({ token: '...' });
});

module.exports = router;
