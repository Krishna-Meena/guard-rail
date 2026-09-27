// GR-BFSI-002 fixture — SQL Injection (JavaScript / Node.js)
// Intentionally vulnerable. DO NOT deploy.

const mysql = require('mysql');

function getAccount(userId) {
    const conn = mysql.createConnection({});
    // Pattern 1: query() with string containing + inside the argument
    // This also triggers pattern 3 via the SELECT ... + variable form
    const sql = "SELECT " + "* FROM accounts WHERE id = " + userId;
    conn.query(sql, (err, rows) => {  // nosec
        return rows;
    });
}

function deleteRecord(table, recordId) {
    const conn = mysql.createConnection({});
    // Pattern: execute/query with literal containing placeholder-like chars
    conn.query("DELETE FROM " + table + " WHERE id = " + recordId, (err) => {});
}

module.exports = { getAccount, deleteRecord };
