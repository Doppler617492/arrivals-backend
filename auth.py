# routes/auth blueprint (incremental extraction from app.py)
# Safe-by-default: will be registered from app.py only when enabled.
from __future__ import annotations

from flask import Blueprint, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash  # generate used for optional admin seed
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
    verify_jwt_in_request,
)
import os
from datetime import timedelta

# Try to use shared singletons
try:
    from extensions import db, jwt  # noqa: F401  # jwt is unused directly but confirms availability
except Exception:  # pragma: no cover
    # Local fallbacks (should not be needed once extensions.py exists)
    from flask_sqlalchemy import SQLAlchemy  # type: ignore
    db = SQLAlchemy()  # type: ignore

# Try to import the canonical User model
User = None  # type: ignore
try:
    from models import User as _User  # type: ignore
    User = _User
except Exception:
    try:
        from app import User as _User  # type: ignore
        User = _User
    except Exception:
        # As a last resort, we will use a raw query path when needed.
        pass

bp = Blueprint("auth", __name__, url_prefix="/auth", strict_slashes=False)

# --- Helpers -----------------------------------------------------------------

def _get_user_by_email(email: str):
    """
    Fetch user by email using the canonical User model if present,
    otherwise fallback to a raw SQL query.
    """
    if User is not None:
        return db.session.query(User).filter_by(email=email).first()
    # Fallback raw SQL (expects a table named 'user' with columns id,email,name,role,password_hash)
    res = db.session.execute(
        db.text("SELECT id, email, name, role, password_hash FROM \"user\" WHERE email = :email LIMIT 1"),
        {"email": email},
    )
    row = res.first()
    if not row:
        return None
    # Lightweight object to mimic attributes
    class _RowObj:
        id = row.id
        email = row.email
        name = row.name
        role = row.role
        password_hash = row.password_hash
    return _RowObj()

def _get_user_by_id(user_id: int):
    if User is not None:
        return db.session.get(User, user_id)
    res = db.session.execute(
        db.text("SELECT id, email, name, role, password_hash FROM \"user\" WHERE id = :id LIMIT 1"),
        {"id": user_id},
    )
    row = res.first()
    if not row:
        return None
    class _RowObj:
        id = row.id
        email = row.email
        name = row.name
        role = row.role
        password_hash = row.password_hash
    return _RowObj()

def _issue_token_for(user):
    minutes = int(os.environ.get("JWT_EXPIRE_MINUTES", "1440"))  # default 24h
    additional_claims = {
        "email": getattr(user, "email", None),
        "role": getattr(user, "role", None),
        "name": getattr(user, "name", None),
    }
    return create_access_token(
        identity=str(getattr(user, "id", "")),
        additional_claims=additional_claims,
        expires_delta=timedelta(minutes=minutes),
    )

# --- Routes ------------------------------------------------------------------

@bp.post("/login")
def login():
    """
    Body: { "email": "...", "password": "..." }
    Response: { "access_token": "...", "user": {...} }
    """
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"ok": False, "error": "Missing credentials"}), 400

    user = _get_user_by_email(email)
    if not user:
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401

    if not getattr(user, "password_hash", None) or not check_password_hash(user.password_hash, password):
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401

    token = _issue_token_for(user)
    user_payload = {
        "id": getattr(user, "id", None),
        "email": getattr(user, "email", None),
        "name": getattr(user, "name", None),
        "role": getattr(user, "role", None),
    }
    return jsonify({"ok": True, "access_token": token, "user": user_payload}), 200

@bp.route("/me", methods=["GET", "HEAD", "OPTIONS"])
def me():
    """
    Return current user info based on JWT.
    Also handles CORS preflight (OPTIONS) without requiring a token.
    """
    # Preflight: browsers don't send Authorization here
    if request.method == "OPTIONS":
        return ("", 204)

    # Enforce JWT for GET/HEAD
    try:
        verify_jwt_in_request(optional=False)
    except Exception:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    ident = get_jwt_identity()
    if ident is None:
        return jsonify({"ok": False, "error": "No identity"}), 401
    try:
        uid = int(ident)
    except Exception:
        uid = int(str(ident)) if str(ident).isdigit() else None
    if uid is None:
        return jsonify({"ok": False, "error": "Invalid identity"}), 401

    user = _get_user_by_id(uid)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404

    return jsonify({
        "ok": True,
        "user": {
            "id": getattr(user, "id", None),
            "email": getattr(user, "email", None),
            "name": getattr(user, "name", None),
            "role": getattr(user, "role", None),
        }
    }), 200

@bp.post("/refresh")
@jwt_required()
def refresh():
    """
    Issue a new access token for the current identity.
    (Note: using access token guard for simplicity. If you use true refresh tokens,
    this can be switched to @jwt_required(refresh=True) and a refresh token store.)
    """
    ident = get_jwt_identity()
    if ident is None:
        return jsonify({"ok": False, "error": "No identity"}), 401
    try:
        uid = int(ident)
    except Exception:
        uid = int(str(ident)) if str(ident).isdigit() else None
    if uid is None:
        return jsonify({"ok": False, "error": "Invalid identity"}), 401

    user = _get_user_by_id(uid)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404

    token = _issue_token_for(user)
    return jsonify({"ok": True, "access_token": token}), 200
