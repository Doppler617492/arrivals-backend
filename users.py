# routes/users.py
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from werkzeug.security import generate_password_hash
from extensions import db
from models import User

bp = Blueprint("users", __name__, url_prefix="/users")

@bp.get("/")
@jwt_required()
def list_users():
    users = User.query.all()
    return jsonify([
        {"id": u.id, "email": u.email, "name": u.name, "role": u.role}
        for u in users
    ]), 200

@bp.post("/")
@jwt_required()
def create_user():
    data = request.get_json(silent=True) or {}
    if not data.get("email") or not data.get("password"):
        return jsonify({"ok": False, "error": "Missing email or password"}), 400
    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"ok": False, "error": "Email already exists"}), 400
    new_user = User(
        email=data["email"].strip().lower(),
        name=data.get("name") or "",
        role=data.get("role") or "viewer",
        password_hash=generate_password_hash(data["password"]),
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"ok": True, "id": new_user.id}), 201

@bp.get("/<int:user_id>")
@jwt_required()
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    return jsonify({
        "ok": True,
        "user": {"id": user.id, "email": user.email, "name": user.name, "role": user.role}
    }), 200

@bp.patch("/<int:user_id>")
@jwt_required()
def update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    data = request.get_json(silent=True) or {}
    if "email" in data:
        user.email = data["email"].strip().lower()
    if "name" in data:
        user.name = data["name"]
    if "role" in data:
        user.role = data["role"]
    if "password" in data and data["password"]:
        user.password_hash = generate_password_hash(data["password"])
    db.session.commit()
    return jsonify({"ok": True}), 200

@bp.delete("/<int:user_id>")
@jwt_required()
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({"ok": True}), 200
