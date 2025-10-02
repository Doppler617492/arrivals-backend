# routes/suppliers.py
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import func

from extensions import db
from models import Supplier


bp = Blueprint("suppliers", __name__, url_prefix="/api/suppliers")


@bp.route("", methods=["GET", "HEAD"], strict_slashes=False)
@bp.route("/", methods=["GET", "HEAD"], strict_slashes=False)
@jwt_required(optional=True)
def list_suppliers():
    """Return suppliers for dropdowns with optional search and limit."""

    if request.method == "HEAD":
        return ("", 204)

    q = (request.args.get("q") or "").strip()
    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, 500))

    query = Supplier.query
    active = request.args.get("active")
    if active in ("1", "true", "yes", "on"):
        query = query.filter(Supplier.is_active.is_(True))
    if q:
        like = f"%{q}%"
        query = query.filter(Supplier.name.ilike(like))

    suppliers = query.order_by(Supplier.name.asc()).limit(limit).all()
    return jsonify([s.to_dict() for s in suppliers])


@bp.route("", methods=["POST", "OPTIONS"], strict_slashes=False)
@bp.route("/", methods=["POST", "OPTIONS"], strict_slashes=False)
@bp.route("/create", methods=["POST", "OPTIONS"], strict_slashes=False)
@jwt_required()
def create_supplier():
    """Minimal supplier creation endpoint (admin downstream can expand)."""

    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "").strip()
    if not name:
        return jsonify({'error': 'name_required', 'message': 'Naziv je obavezan'}), 400

    currency = str(data.get("default_currency") or "EUR").strip().upper()[:8] or "EUR"
    is_active = bool(data.get("is_active", True))

    existing = Supplier.query.filter(func.lower(Supplier.name) == name.lower()).first()
    if existing:
        return jsonify({'error': 'duplicate', 'message': 'Dobavljač već postoji'}), 409

    supplier = Supplier(name=name, default_currency=currency, is_active=is_active)
    db.session.add(supplier)
    db.session.commit()
    return jsonify(supplier.to_dict()), 201
