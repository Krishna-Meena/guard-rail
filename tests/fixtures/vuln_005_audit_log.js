// GR-BFSI-005 fixture — Missing Audit Log on Sensitive Operations (JavaScript)
// Intentionally vulnerable. DO NOT deploy.

// Fund transfer with no audit/log call
function transfer(fromAccount, toAccount, amount) {
    debit(fromAccount, amount);
    credit(toAccount, amount);
}

// Authentication with no audit/log call
function login(username, password) {
    return checkCredentials(username, password);
}

// Password change with no audit/log call
function changePassword(userId, newPassword) {
    updatePassword(userId, newPassword);
}

// Stubs
function debit() {}
function credit() {}
function checkCredentials() { return false; }
function updatePassword() {}

module.exports = { transfer, login, changePassword };
