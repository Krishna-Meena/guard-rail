// GR-BFSI-001 fixture — Hardcoded Credentials (JavaScript)
// Intentionally vulnerable. DO NOT deploy.

const password = "Sup3rS3cret!";
const apiKey = "sk-abcdef1234567890abcdef";
const secret = "my_very_secret_value";

// Connection string with embedded credentials
const dbUrl = "postgres://admin:P@ssw0rd123@db.example.com/finance";

// AWS access key pattern
const awsKey = "AKIAIOSFODNN7EXAMPLE5678";

// Bearer token in code
const authHeader = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefghijklmnop";

module.exports = { password, apiKey };
