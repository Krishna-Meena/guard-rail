// GR-BFSI-009 fixture — TLS Certificate Verification Disabled (JavaScript)
// Intentionally vulnerable. DO NOT deploy.

const https = require('https');
const axios = require('axios');

// rejectUnauthorized=false disables TLS certificate validation
const agent = new https.Agent({ rejectUnauthorized: false });

function fetchBalance(accountId) {
    return axios.get(`https://api.bank.example.com/accounts/${accountId}`, {
        httpsAgent: agent,
        // verify=false is the JS equivalent pattern
        verify: false,
    });
}

// NODE_TLS_REJECT_UNAUTHORIZED set to 0 disables globally
function disableGlobalTls() {
    process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';
}

module.exports = { fetchBalance, disableGlobalTls };
