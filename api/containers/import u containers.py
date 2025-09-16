

# routes/containers_import.py
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from extensions import db
from app import Container, _parse_iso

bp = Blueprint("containers_import", __name__, url_prefix="/api/containers")

@bp.post("/import")
@jwt_required()
def import_containers():
    """
    Bulk import containers from JSON payload.
    Expects: { "containers": [ {code,status,note,eta,arrived_at}, ... ] }
    """
    data = request.get_json(silent=True) or {}
    items = data.get("containers")
    if not isinstance(items, list):
        return jsonify({"error": "containers must be a list"}), 400
    created = []
    for row in items:
        c = Container(
            code=row.get("code"),
            status=row.get("status", "pending"),
            note=row.get("note"),
            eta=row.get("eta"),
            arrived_at=_parse_iso(row.get("arrived_at")),
        )
        db.session.add(c)
        db.session.flush()
        created.append(c.to_dict())
    db.session.commit()
    return jsonify({"ok": True, "imported": created}), 201