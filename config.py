import os

_DEFAULT_ALLOWED = ["http://localhost:5173", "http://127.0.0.1:5173"]

def allowed_origins():
    raw = (os.environ.get("ALLOWED_ORIGINS") or "").strip()
    if not raw:
        return _DEFAULT_ALLOWED
    return [o.strip() for o in raw.split(",") if o.strip()]

def load_config(app):
    # Enforce Postgres: require DATABASE_URL and do not fall back to SQLite
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        raise RuntimeError(
            "DATABASE_URL is not set. Configure a Postgres DSN, e.g. "
            "postgresql+psycopg://user:pass@host:5432/dbname"
        )
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'change-me-dev')
    # Auth tokens available in headers and (optionally) HttpOnly cookies
    app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
    app.config['JWT_COOKIE_SECURE'] = (os.environ.get('JWT_COOKIE_SECURE', '0').lower() in ('1','true','yes','on'))
    app.config['JWT_COOKIE_SAMESITE'] = os.environ.get('JWT_COOKIE_SAMESITE', 'Lax')
    app.config['JWT_COOKIE_CSRF_PROTECT'] = (os.environ.get('JWT_COOKIE_CSRF_PROTECT', '0').lower() in ('1','true','yes','on'))
    app.config['JWT_ACCESS_COOKIE_NAME'] = os.environ.get('JWT_ACCESS_COOKIE_NAME', 'access_token')
    app.config['JWT_REFRESH_COOKIE_NAME'] = os.environ.get('JWT_REFRESH_COOKIE_NAME', 'refresh_token')

    upload_dir_env = os.environ.get('UPLOAD_DIR') or os.environ.get('UPLOAD_FOLDER')
    app.config['UPLOAD_FOLDER'] = upload_dir_env or os.path.join(os.path.dirname(__file__), 'uploads')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_UPLOAD_MB', '16')) * 1024 * 1024
