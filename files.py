

# files.py — blueprint for serving uploaded files
from flask import Blueprint, request, send_from_directory, jsonify, current_app
from flask_jwt_extended import jwt_required

bp = Blueprint("files", __name__, url_prefix="/files")

@bp.route("/<path:filename>", methods=["GET", "HEAD", "OPTIONS"])
def get_file(filename: str):
    # Handle preflight explicitly (helps certain browsers/tools)
    if request.method == "OPTIONS":
        return ("", 204)

    try:
        # If you want to protect downloads, uncomment @jwt_required() above
        # and require a token here.
        return send_from_directory(current_app.config["UPLOAD_FOLDER"], filename, as_attachment=False)
    except FileNotFoundError:
        return jsonify({"error": "Not found"}), 404

# Legacy alias: some clients may hit /files/files/<name>
@bp.route("/files/<path:filename>", methods=["GET", "HEAD", "OPTIONS"])
def get_file_compat(filename: str):
    return get_file(filename)
