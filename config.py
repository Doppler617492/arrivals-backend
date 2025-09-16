import os

_DEFAULT_ALLOWED = ["http://localhost:5173", "http://127.0.0.1:5173"]

def allowed_origins():
    raw = (os.environ.get("ALLOWED_ORIGINS") or "").strip()
    if not raw:
        return _DEFAULT_ALLOWED
    return [o.strip() for o in raw.split(",") if o.strip()]

def load_config(app):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL',
        os.environ.get('SQLITE_URL', 'sqlite:///arrivals.db')
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'change-me-dev')
    app.config['JWT_TOKEN_LOCATION'] = ['headers']
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False

    upload_dir_env = os.environ.get('UPLOAD_DIR') or os.environ.get('UPLOAD_FOLDER')
    app.config['UPLOAD_FOLDER'] = upload_dir_env or os.path.join(os.path.dirname(__file__), 'uploads')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_UPLOAD_MB', '16')) * 1024 * 1024