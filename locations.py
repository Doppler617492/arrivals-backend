# locations.py
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required  # ako želiš zaštitu, za sad je public
from models import Arrival
from extensions import db

bp = Blueprint("locations", __name__, url_prefix="/api/locations")

@bp.route("", methods=["GET", "HEAD", "OPTIONS"])
def list_locations():
    # Preflight
    if request.method == "OPTIONS":
        return ("", 204)
    # Distinct lokacije iz postojećih Arrival zapisa
    rows = (
        db.session.query(Arrival.location)
        .filter(Arrival.location.isnot(None))
        .filter(Arrival.location != "")
        .distinct()
        .order_by(Arrival.location.asc())
        .all()
    )
    # frontend očekuje niz stringova ili {value,label}; vrati stringove:
    items = [r[0] for r in rows]
    return jsonify(items), 200
