"""Order views: list, detail, customer note, staff status change, CSV export."""
import csv
import io

from flask import (Blueprint, Response, abort, current_app, g, redirect, render_template,
                   request, url_for)

from . import db
from .auth import login_required, role_required
from .security import neutralize_csv_cell

bp = Blueprint("orders", __name__)

MAX_NOTE_LEN = 500


def _order_or_404(order_id):
    """Object-level authorization (OWASP A01, ASVS V4.2.1, CWE-639).

    The lookup is scoped to the current user in SQL. "Not yours" and "does not exist"
    both give 404, so ids cannot be enumerated to learn which orders exist.
    """
    order = db.get_order_for(g.user, order_id)
    if order is None:
        current_app.logger.warning("order_not_found_or_denied user=%s order=%s", g.user["id"], order_id)
        abort(404)
    return order


@bp.route("/")
@login_required
def index():
    return redirect(url_for("orders.list_orders"))


@bp.route("/orders")
@login_required
def list_orders():
    return render_template("orders.html", orders=db.list_orders_for(g.user))


@bp.route("/orders/<int:order_id>")
@login_required
def order_detail(order_id):
    return render_template("order_detail.html", order=_order_or_404(order_id),
                           statuses=db.ALLOWED_STATUSES)


@bp.route("/orders/<int:order_id>/note", methods=["POST"])
@login_required
def add_note(order_id):
    order = _order_or_404(order_id)
    if g.user["role"] != "customer":
        abort(403)
    note = request.form.get("note", "").strip()
    if len(note) > MAX_NOTE_LEN:  # server-side validation; the HTML maxlength is only UX
        abort(400)
    db.update_note(order["id"], note)
    return redirect(url_for("orders.order_detail", order_id=order["id"]))


@bp.route("/orders/<int:order_id>/status", methods=["POST"])
@role_required("staff")
def change_status(order_id):
    order = _order_or_404(order_id)
    status = request.form.get("status", "")
    if status not in db.ALLOWED_STATUSES:  # allow-list, not a deny-list
        abort(400)
    db.update_status(order["id"], status)
    current_app.logger.info("status_changed user=%s order=%s status=%s", g.user["id"], order["id"], status)
    return redirect(url_for("orders.order_detail", order_id=order["id"]))


@bp.route("/orders/export.csv")
@login_required
def export_csv():
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "product", "quantity_kg", "total_mad", "status", "note"])
    for o in db.list_orders_for(g.user):  # same authz scope as the list page
        writer.writerow([neutralize_csv_cell(o[k]) for k in
                         ("id", "product", "quantity_kg", "total_mad", "status", "note")])
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=orders.csv"},
    )
