# GR-BFSI-002 fixture — SQL Injection (Python)
# noqa: S608
"""
Intentionally vulnerable: user input concatenated directly into SQL.
DO NOT deploy — sample-app fixture for GuardRail unit tests only.
"""

import sqlite3


def get_account(user_id: str) -> list:
    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()
    # Pattern 1: execute() with a string literal containing + or format
    cursor.execute("SELECT * FROM accounts WHERE id = %s" % user_id)  # noqa: S608
    return cursor.fetchall()


def search_transactions(term: str) -> list:
    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()
    # Pattern 2: SELECT with .format()
    query = "SELECT * FROM transactions WHERE description LIKE '%{}'".format(term)  # noqa: S608
    cursor.execute(query)
    return cursor.fetchall()


def delete_record(table: str, record_id: int) -> None:
    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()
    # Pattern 3: raw string concat "SELECT ..." + var
    sql = "DELETE FROM " + table + " WHERE id = " + str(record_id)  # noqa: S608
    cursor.execute(sql)
    conn.commit()
