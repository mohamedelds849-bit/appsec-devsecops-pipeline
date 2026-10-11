# Semgrep test fixture (lint patterns only, not a runnable app).
from flask import Blueprint

from portal.auth import login_required, role_required

bp = Blueprint("x", __name__)


# ruleid: flask-route-missing-auth
@bp.route("/admin/export")
def export_everything():
    return "all orders"


# ruleid: flask-route-missing-auth
@bp.route("/orders/<int:order_id>/delete", methods=["POST"])
def delete_order(order_id):
    return "deleted"


# ok: flask-route-missing-auth
@bp.route("/orders")
@login_required
def list_orders():
    return "mine"


# ok: flask-route-missing-auth
@bp.route("/orders/<int:order_id>/status", methods=["POST"])
@role_required("staff")
def change_status(order_id):
    return "ok"


# ok: flask-route-missing-auth
@bp.route("/login", methods=["GET", "POST"])
def login():
    return "public by design"
