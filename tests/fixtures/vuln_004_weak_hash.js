// GR-BFSI-004 fixture — Insecure Password Hashing (JavaScript)
// Intentionally vulnerable. DO NOT deploy.

const crypto = require('crypto');

function hashPasswordMd5(password) {
    // MD5 is cryptographically broken for passwords
    return crypto.createHash('md5').update(password).digest('hex');
}

function hashPasswordSha1(password) {
    // SHA-1 is also broken
    return crypto.createHash('sha1').update(password).digest('hex');
}

module.exports = { hashPasswordMd5, hashPasswordSha1 };
