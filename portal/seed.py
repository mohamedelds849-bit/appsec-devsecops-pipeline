"""Create synthetic demo data. Passwords are generated at random and printed ONCE.

    python -m portal.seed

No password is ever written in this repository (gitleaks runs on every push).
"""
import secrets

from . import create_app, db
from .auth import hash_password

USERS = [("staff.agadir", "staff"), ("client.taroudant", "customer"), ("client.tiznit", "customer")]
ORDERS = {
    "client.taroudant": [("Argan oil 1L", 20, 4200), ("Saffron 50g", 2, 1300)],
    "client.tiznit": [("Amlou 500g", 40, 3600), ("Dates Mejhoul", 100, 6500)],
}


def seed():
    app = create_app()
    with app.app_context():
        if db.find_user_by_username(USERS[0][0]):
            print("Database already seeded; delete instance/portal.db to start again.")
            return
        ids = {}
        for username, role in USERS:
            password = secrets.token_urlsafe(16)
            ids[username] = db.create_user(username, hash_password(password), role)
            print(f"{username:18} {role:9} password: {password}")
        for username, items in ORDERS.items():
            for product, qty, total in items:
                db.create_order(ids[username], product, qty, total)
        print("Seeded. These passwords are shown only now.")


if __name__ == "__main__":
    seed()
