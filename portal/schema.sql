-- AgriSouss order portal (lab). Synthetic data only.
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('customer', 'staff'))
);

CREATE TABLE IF NOT EXISTS orders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL REFERENCES users(id),
    product     TEXT    NOT NULL,
    quantity_kg INTEGER NOT NULL CHECK (quantity_kg > 0),
    total_mad   INTEGER NOT NULL CHECK (total_mad >= 0),
    status      TEXT    NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'shipped', 'delivered', 'cancelled')),
    note        TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_id);
