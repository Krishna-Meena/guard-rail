// GR-BFSI-006 fixture — Unencrypted PII Storage (JavaScript)
// Intentionally vulnerable. DO NOT deploy.

const fs = require('fs');

function exportCustomer(customer) {
    // PII serialised directly to JSON without encryption
    const data = JSON.stringify({
        pan: customer.pan,
        aadhaar: customer.aadhaar,
        dob: customer.dob,
        phone: customer.phone,
        email: customer.email
    });
    fs.writeFileSync('customers.json', data);
}

// Plain object with PII fields — no encrypt call nearby
const record = {
    "pan": rawPan,
    "phone_number": rawPhone,
    "email_address": rawEmail,
};

module.exports = { exportCustomer };
