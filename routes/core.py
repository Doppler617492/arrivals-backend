# routes/core.py
from flask import Blueprint, jsonify

bp = Blueprint("core", __name__)

@bp.get("/")
def root():
    # Minimalno: frontend očekuje ok=true na rootu
    return jsonify({"ok": True, "service": "arrivals-backend"}), 200

@bp.get("/health")
def health():
    return jsonify({"status": "healthy"}), 200