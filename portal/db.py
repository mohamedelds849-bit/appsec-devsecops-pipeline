"""Data access. Every SQL statement uses ? placeholders (CWE-89, ASVS V5.3.4).

Rule for this file: user input is NEVER concatenated or formatted into SQL text.
tests/test_static_checks.py and the custom Semgrep rule rules/sqlite-formatted-sql.yaml
both enforce it. Authorization is also pushed into the query (customer_id = ?) so a
customer can never load another customer's row, even by guessing its id.
"""
import os
import sqlite3

from flask import current_app, g

ALLOWED_STATUSES = ("pending", "shipped", "delivered", "cancelled")


def get_db():
    if "db" not in g:
        path = current_app.config["DATABASE"]
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        g.db = sqlite3.connect(path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    schema = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema, encoding="utf-8") as fh:
        get_db().executescript(fh.read())


def create_user(username, password_hash, role):
    db = get_db()
    cur = db.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, password_hash, role),
    )
    db.commit()
    return cur.lastrowid


def find_user_by_username(username):
    return get_db().execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def find_user_by_id(user_id):
    return get_db().execute(
        "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def create_order(customer_id, product, quantity_kg, total_mad, status="pending", note=""):
    db = get_db()
    cur = db.execute(
        "INSERT INTO orders (customer_id, product, quantity_kg, total_mad, status, note) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (customer_id, product, quantity_kg, total_mad, status, note),
    )
    db.commit()
    return cur.lastrowid


def list_orders_for(user):
    """Staff see every order; a customer sees only their own (object-level authz)."""
    db = get_db()
    if user["role"] == "staff":
        return db.execute(
            "SELECT id, customer_id, product, quantity_kg, total_mad, status, note "
            "FROM orders ORDER BY id"
        ).fetchall()
    return db.execute(
        "SELECT id, customer_id, product, quantity_kg, total_mad, status, note "
        "FROM orders WHERE customer_id = ? ORDER BY id",
        (user["id"],),
    ).fetchall()


def get_order_for(user, order_id):
    """Return the order only if `user` may see it, else None (the route answers 404)."""
    db = get_db()
    if user["role"] == "staff":
        return db.execute(
            "SELECT id, customer_id, product, quantity_kg, total_mad, status, note "
            "FROM orders WHERE id = ?", (order_id,)
        ).fetchone()
    return db.execute(
        "SELECT id, customer_id, product, quantity_kg, total_mad, status, note "
        "FROM orders WHERE id = ? AND customer_id = ?",
        (order_id, user["id"]),
    ).fetchone()


def update_note(order_id, note):
    db = get_db()
    db.execute("UPDATE orders SET note = ? WHERE id = ?", (note, order_id))
    db.commit()


def update_status(order_id, status):
    if status not in ALLOWED_STATUSES:
        raise ValueError("invalid status")
    db = get_db()
    db.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
    db.commit()
