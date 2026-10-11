# Semgrep test fixture (lint patterns only, not a runnable app).
import sqlite3


def lookups(conn: sqlite3.Connection, name, order_id):
    cur = conn.cursor()
    # ruleid: sqlite-formatted-sql
    cur.execute(f"SELECT * FROM users WHERE username = '{name}'")
    # ruleid: sqlite-formatted-sql
    cur.execute("SELECT * FROM orders WHERE id = %s" % order_id)
    # ruleid: sqlite-formatted-sql
    conn.execute("DELETE FROM orders WHERE id = {}".format(order_id))
    # ruleid: sqlite-formatted-sql
    conn.execute("SELECT * FROM users WHERE username = '" + name + "'")
    query = f"SELECT * FROM orders WHERE note LIKE '%{name}%'"
    # ruleid: sqlite-formatted-sql
    cur.execute(query)

    # ok: sqlite-formatted-sql
    cur.execute("SELECT * FROM users WHERE username = ?", (name,))
    # ok: sqlite-formatted-sql
    conn.execute("UPDATE orders SET status = ? WHERE id = ?", ("shipped", order_id))
    # ok: sqlite-formatted-sql
    conn.execute("SELECT id, product FROM orders ORDER BY id")
