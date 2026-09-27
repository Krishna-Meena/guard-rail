// GR-BFSI-003 fixture — Missing Input Validation on Financial Fields (JavaScript)
// Intentionally vulnerable. DO NOT deploy.

const express = require('express');
const router = express.Router();

router.post('/transfer', (req, res) => {
    // Financial fields used directly from request without validation
    const amount = req.body.amount;
    const balance = req.body.balance;
    const transferAmount = req.body.transferAmount;
    const fee = req.params.fee;

    // Arithmetic directly on unvalidated input
    const total = parseFloat(req.body.price) + parseFloat(fee);
    res.json({ status: 'ok', total });
});

module.exports = router;
