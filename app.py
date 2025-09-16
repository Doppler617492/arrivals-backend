from flask import Flask, request, jsonify, send_from_directory, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import relationship
from sqlalchemy import or_, text, func
from functools import wraps
import os
import time
import threading
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Optional/legacy modules (guarded so app can start even if they don't exist)
try:
    from mailer import maybe_notify_paid  # noqa: F401
except Exception:
    pass

try:
    from db import Base, engine, SessionLocal, get_db  # noqa: F401
except Exception:
    pass

load_dotenv()

# --- Modular config/extensions (safe import with fallbacks) ---
try:
    from extensions import db, jwt  # externalized singletons
except Exception:
    # Fallback definitions if extensions.py doesn't exist yet
    from flask_sqlalchemy import SQLAlchemy
    from flask_jwt_extended import JWTManager
    db = SQLAlchemy()
    jwt = JWTManager()

try:
    from config import load_config, allowed_origins
except Exception:
    # Fallback inline config helpers if config.py doesn't exist yet
    import os as _os
    _DEFAULT_ALLOWED = ["http://localhost:5173", "http://127.0.0.1:5173"]

    def allowed_origins():
        raw = (_os.environ.get("ALLOWED_ORIGINS") or "").strip()
        if not raw:
            return _DEFAULT_ALLOWED
        return [o.strip() for o in raw.split(",") if o.strip()]

    def load_config(app):
        app.config['SQLALCHEMY_DATABASE_URI'] = _os.environ.get(
            'DATABASE_URL',
            _os.environ.get('SQLITE_URL', 'sqlite:///arrivals.db')
        )
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        app.config['JWT_SECRET_KEY'] = _os.environ.get('JWT_SECRET_KEY', 'change-me-dev')
        app.config['JWT_TOKEN_LOCATION'] = ['headers']
        app.config['JWT_COOKIE_CSRF_PROTECT'] = False

        upload_dir_env = _os.environ.get('UPLOAD_DIR') or _os.environ.get('UPLOAD_FOLDER')
        app.config['UPLOAD_FOLDER'] = upload_dir_env or _os.path.join(_os.path.dirname(__file__), 'uploads')
        _os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

        # Limit upload size via env (default 16 MB)
        app.config['MAX_CONTENT_LENGTH'] = int(_os.environ.get('MAX_UPLOAD_MB', '16')) * 1024 * 1024

app = Flask(__name__)

# Allowed CORS origins (env override via ALLOWED_ORIGINS)
ALLOWED_ORIGINS = allowed_origins()

# Core blueprint (enabled now that overlapping routes are removed)
from routes.core import bp as core_bp
app.register_blueprint(core_bp, url_prefix="")



CORS(
    app,
    resources={
        r"/api/*": {"origins": ALLOWED_ORIGINS},
        r"/auth/*": {"origins": ALLOWED_ORIGINS},
        r"/files/*": {"origins": ALLOWED_ORIGINS},
        r"/health": {"origins": ALLOWED_ORIGINS},
        r"/": {"origins": ALLOWED_ORIGINS},
    },
    supports_credentials=True,
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
    expose_headers=["Content-Type", "Authorization"],
    max_age=86400,
)

# Catch-all OPTIONS handler for CORS preflight requests
@app.route('/<path:_any>', methods=['OPTIONS'])
def _cors_preflight(_any):
    # Credentials-safe CORS preflight response with allowed headers, methods, and origin
    origin = request.headers.get("Origin")
    headers = {}
    if origin in (ALLOWED_ORIGINS or []):
        headers["Access-Control-Allow-Origin"] = origin
        headers["Vary"] = "Origin"
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key"
        headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD"
    return ("", 204, headers)

# After-request hook to set CORS headers if missing
@app.after_request
def _add_cors_fallback(resp):
    # Force credentials-safe CORS headers (never wildcard when cookies are used)
    origin = request.headers.get("Origin")
    if origin in (ALLOWED_ORIGINS or []):
        resp.headers["Access-Control-Allow-Origin"] = origin  # overwrite any previous value (avoid '*')
        # Merge with existing Vary header if present
        if resp.headers.get("Vary"):
            if "Origin" not in resp.headers.get("Vary"):
                resp.headers["Vary"] = resp.headers.get("Vary") + ", Origin"
        else:
            resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers.setdefault("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
        resp.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD")
    else:
        # If not an allowed origin, drop wildcard if any slipped through
        if resp.headers.get("Access-Control-Allow-Origin") == "*":
            del resp.headers["Access-Control-Allow-Origin"]
    return resp

# --- Config ---
load_config(app)

# Mail / SLA
# Sensible defaults for Gmail (App Password required):
SMTP_HOST = (os.environ.get('SMTP_HOST') or 'smtp.gmail.com').strip()
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = (os.environ.get('SMTP_USER') or '').strip()
SMTP_PASS = (os.environ.get('SMTP_PASS') or '').strip()

# From must match authenticated user for Gmail; fall back to SMTP_USER
MAIL_FROM = (os.environ.get('MAIL_FROM') or SMTP_USER or os.environ.get('ADMIN_EMAIL') or 'noreply@example.com').strip()

# Recipients: env MAIL_DEFAULT_TO (comma separated) or ADMIN_EMAIL
MAIL_DEFAULT_TO = [e.strip() for e in (os.environ.get('MAIL_DEFAULT_TO') or os.environ.get('ADMIN_EMAIL','')).split(',') if e.strip()]
# Always include it@cungu.com during development (remove for prod if undesired)
if 'it@cungu.com' not in MAIL_DEFAULT_TO:
    MAIL_DEFAULT_TO.append('it@cungu.com')

# Mail flags
SMTP_TLS = (os.environ.get('SMTP_TLS', 'true').lower() in ('1','true','yes','on'))
SMTP_SSL = (os.environ.get('SMTP_SSL', 'false').lower() in ('1','true','yes','on'))
MAIL_DEBUG = (os.environ.get('MAIL_DEBUG', 'false').lower() in ('1','true','yes','on'))

NOTIFY_ON_STATUS = os.environ.get('NOTIFY_ON_STATUS', 'true').lower() == 'true'
NOTIFY_ON_SLA = os.environ.get('NOTIFY_ON_SLA', 'true').lower() == 'true'
NOTIFY_ON_PAID = os.environ.get('NOTIFY_ON_PAID', 'true').lower() == 'true'
SLA_CHECK_SECONDS = int(os.environ.get('SLA_CHECK_SECONDS', '3600'))

jwt.init_app(app)

# JWT error/unauthorized handlers
@jwt.unauthorized_loader
def _jwt_unauthorized(err_str):
    return jsonify({"error": "Missing or invalid auth", "detail": err_str}), 401

@jwt.invalid_token_loader
def _jwt_invalid(reason):
    return jsonify({"error": "Invalid token", "detail": reason}), 401

@jwt.expired_token_loader
def _jwt_expired(jwt_header, jwt_payload):
    return jsonify({"error": "Token expired"}), 401

@jwt.needs_fresh_token_loader
def _jwt_needs_fresh(jwt_header, jwt_payload):
    return jsonify({"error": "Fresh token required"}), 401

db.init_app(app)

# API-friendly error handlers
@app.errorhandler(400)
def _bad_request(e):
    return jsonify({"error": "Bad request"}), 400

@app.errorhandler(403)
def _forbidden(e):
    return jsonify({"error": "Forbidden"}), 403

@app.errorhandler(404)
def _not_found(e):
    # If the path looks like API, respond JSON; otherwise fall back to default Flask index
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(405)
def _method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(413)
def _too_large(e):
    return jsonify({"error": "File too large"}), 413

# --- Models (imported from models.py) ---
from models import (
    User as User,
    Arrival as Arrival,
    ArrivalFile as ArrivalFile,
    ArrivalUpdate as ArrivalUpdate,
    Container as Container,
    ContainerFile as ContainerFile,
)

# Create missing tables in development by default to avoid 500s on first run
if os.environ.get('AUTO_CREATE_TABLES', '1').lower() in ('1','true','yes','on'):
    try:
        with app.app_context():
            db.create_all()
            # Optionally seed admin if env provided
            try:
                ensure_admin()
            except Exception:
                pass
    except Exception as e:
        print('[DB INIT] create_all failed:', e)

# --- Role permissions ---
ROLE_FIELDS = {
    'admin': {'supplier','carrier','plate','type','eta','status','note','order_date','production_due',
              'shipped_at','arrived_at','customs_info','freight_cost','customs_cost','currency','assignee_id',
              'driver','pickup_date','goods_cost','responsible','location'},
    'planer': {'supplier','order_date','production_due','status','note','location'},
    'proizvodnja': {'status','note'},
    'transport': {'carrier','plate','eta','status','shipped_at','note','driver','pickup_date','freight_cost','location'},
    'carina': {'status','customs_info','customs_cost','note'},
    'viewer': set(),
}

ALLOWED_STATUSES = {
    'not_shipped','shipped','arrived'
}

def can_edit(role: str, fields: set) -> bool:
    allowed = ROLE_FIELDS.get(role, set())
    return bool(allowed & fields) or role == 'admin'

# --- Helpers ---
def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        expected = os.environ.get('API_KEY')
        provided = request.headers.get('X-API-Key')
        if expected and provided == expected:
            return f(*args, **kwargs)
        return jsonify({'error': 'Unauthorized'}), 401
    return wrapper

def has_valid_api_key():
    expected = os.environ.get('API_KEY')
    provided = request.headers.get('X-API-Key')
    return bool(expected) and (provided == expected)

def check_api_or_jwt(attempted_fields: set):
    """
    Allow either:
    - valid X-API-Key (system integrations), or
    - valid JWT with role-based field editing
    Returns (allowed: bool, role: str|None, uid: int|None, error_response: flask.Response|None)
    """
    # First, accept API key if present
    if has_valid_api_key():
        return True, 'system', None, None

    # Otherwise try JWT (optional verify to allow no token case)
    try:
        verify_jwt_in_request(optional=True)
    except Exception:
        # Invalid token provided
        return False, None, None, (jsonify({'error': 'Invalid token'}), 401)

    claims = get_jwt() if get_jwt else {}
    uid = get_jwt_identity()
    role = (claims or {}).get('role', 'viewer')

    # If no JWT at all, allow anonymous writes in DEV if ALLOW_ANON_WRITE=1 (or true/yes/on)
    if uid is None and not claims:
        if os.environ.get('ALLOW_ANON_WRITE', '').lower() in ('1', 'true', 'yes', 'on'):
            return True, 'system', None, None
        return False, None, None, (jsonify({'error': 'Unauthorized'}), 401)

    # Admin can edit anything
    if role == 'admin':
        return True, role, int(uid) if uid else None, None

    # Field-level permission check
    if attempted_fields and not can_edit(role, attempted_fields):
        return False, role, int(uid) if uid else None, (jsonify({'error': 'Forbidden for your role'}), 403)

    return True, role, int(uid) if uid else None, None

def send_email(subject: str, body: str, to_list=None):
    """
    Sends an email via SMTP.
    Supports:
      - STARTTLS (default, e.g. smtp.gmail.com:587 with app password)
      - SMTPS/SSL (e.g. port 465) if SMTP_SSL=true or SMTP_PORT==465
    Set MAIL_DEBUG=1 to enable SMTP debug prints.
    """
    to_list = (to_list or MAIL_DEFAULT_TO) or []
    if not to_list:
        print(f"[MAIL-DEV] {subject}\n(no recipients configured)\n{body}")
        return

    # Development shortcut: if SMTP_HOST missing, just log
    if not SMTP_HOST:
        print(f"[MAIL-DEV] {subject}\nTo: {', '.join(to_list)}\n{body}")
        return

    try:
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject

        # For Gmail, the envelope-from and header From should be the authenticated user
        from_addr = MAIL_FROM or SMTP_USER or 'noreply@example.com'
        if 'gmail' in (SMTP_HOST or '').lower() and SMTP_USER:
            from_addr = SMTP_USER
        msg['From'] = from_addr
        msg['To'] = ', '.join(to_list)
        if MAIL_FROM and MAIL_FROM != from_addr:
            msg['Reply-To'] = MAIL_FROM

        use_ssl = SMTP_SSL or str(SMTP_PORT) == '465'
        server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20) if use_ssl else smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20)
        if MAIL_DEBUG:
            server.set_debuglevel(1)
        try:
            if not use_ssl and SMTP_TLS:
                server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(from_addr, to_list, msg.as_string())
            print(f"[MAIL-SENT] subject='{subject}' from='{from_addr}' to={to_list}")
        finally:
            try:
                server.quit()
            except Exception:
                pass

    except smtplib.SMTPAuthenticationError as e:
        print("[MAIL-ERROR] AUTH failed – check SMTP_USER / SMTP_PASS (use App Password for Gmail).", e)
        raise
    except smtplib.SMTPSenderRefused as e:
        print("[MAIL-ERROR] SENDER refused – check MAIL_FROM / SMTP_USER alignment.", e)
        raise
    except smtplib.SMTPRecipientsRefused as e:
        print("[MAIL-ERROR] RECIPIENTS refused – check 'to' addresses.", e)
        raise
    except Exception as e:
        print("[MAIL-ERROR]", e)
        raise

def all_user_emails():
    emails = [u.email for u in User.query.all() if u.email]
    return emails or MAIL_DEFAULT_TO

# --- Routes ---

# Fallback list for arrivals (guards against 405/308 edge-cases)
@app.route('/api/arrivals', methods=['GET', 'HEAD', 'OPTIONS'])
def arrivals_list_fallback():
    # Handle CORS preflight explicitly
    if request.method == 'OPTIONS':
        origin = request.headers.get("Origin")
        headers = {}
        if origin in (ALLOWED_ORIGINS or []):
            headers["Access-Control-Allow-Origin"] = origin
            headers["Vary"] = "Origin"
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key"
            headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD"
        return ("", 204, headers)

    try:
        # GET/HEAD: mirror the blueprint's list output (including files_count)
        rows = Arrival.query.order_by(Arrival.created_at.desc()).all()
        counts_map = dict(
            db.session.query(ArrivalFile.arrival_id, func.count(ArrivalFile.id))
            .group_by(ArrivalFile.arrival_id).all()
        )
        payload = []
        for a in rows:
            d = a.to_dict()
            d["files_count"] = int(counts_map.get(a.id, 0))
            payload.append(d)
        return jsonify(payload), 200
    except Exception as e:
        db.session.rollback()
        print("[/api/arrivals ERROR]", e)
        return jsonify({"error": "Server error", "detail": str(e)}), 500

# Fallback list for containers (guards against 405/308 edge-cases)
@app.route('/api/containers', methods=['GET', 'HEAD', 'OPTIONS'], strict_slashes=False)
def containers_list_fallback():
    # Handle CORS preflight explicitly
    if request.method == 'OPTIONS':
        origin = request.headers.get("Origin")
        headers = {}
        if origin in (ALLOWED_ORIGINS or []):
            headers["Access-Control-Allow-Origin"] = origin
            headers["Vary"] = "Origin"
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key"
            headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD"
        return ("", 204, headers)

    try:
        # GET/HEAD: mirror the containers blueprint list (including files_count)
        rows = Container.query.order_by(Container.created_at.desc()).all()
        counts_map = dict(
            db.session.query(ContainerFile.container_id, func.count(ContainerFile.id))
            .group_by(ContainerFile.container_id).all()
        )
        payload = []
        for c in rows:
            d = c.to_dict()
            d["files_count"] = int(counts_map.get(c.id, 0))
            payload.append(d)
        return jsonify(payload), 200
    except Exception as e:
        db.session.rollback()
        print("[/api/containers ERROR]", e)
        return jsonify({"error": "Server error", "detail": str(e)}), 500

# Legacy mirror for containers list (no /api prefix)
@app.route('/containers', methods=['GET', 'HEAD', 'OPTIONS'], strict_slashes=False)
def containers_list_legacy():
    # Reuse the same implementation as the /api prefixed endpoint
    return containers_list_fallback()

 

# Update a single container (fallback so the UI can PATCH even if the blueprint failed)
@app.route('/api/containers/<int:cid>', methods=['PATCH', 'PUT', 'OPTIONS'], strict_slashes=False)
def containers_update_fallback(cid):
    # CORS preflight
    if request.method == 'OPTIONS':
        origin = request.headers.get("Origin")
        headers = {}
        if origin in (ALLOWED_ORIGINS or []):
            headers["Access-Control-Allow-Origin"] = origin
            headers["Vary"] = "Origin"
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key"
            headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD"
        return ("", 204, headers)

    # Permissions: allow API key or JWT role-based
    data = request.get_json(silent=True) or {}
    attempted_fields = set(data.keys())
    allowed, role, uid, error_resp = check_api_or_jwt(attempted_fields)
    if not allowed:
        return error_resp

    try:
        obj = Container.query.get(cid)
        if not obj:
            return jsonify({"error": "Not found"}), 404

        # Allowed fields to patch (keep in sync with model)
        ALLOWED = {
            'supplier','proforma_no','etd','delivery','eta','cargo_qty','cargo','container_no',
            'roba','contain_price','agent','total','deposit','balance','paid','status','note',
            'code'
        }

        # Apply incoming values with light parsing for dates/bools
        for k, v in data.items():
            if k not in ALLOWED:
                continue
            if k in ('etd','delivery','eta'):
                setattr(obj, k, _parse_date_any(v))
            elif k == 'paid':
                pb = _parse_boolish(v)
                setattr(obj, k, bool(pb) if pb is not None else False)
            else:
                # Keep numeric-like values as strings if your columns are VARCHAR
                setattr(obj, k, v)

        # Optional: auto-balance when paid toggled on
        if 'paid' in data and getattr(obj, 'paid', False):
            try:
                total_f = _money_to_number(getattr(obj, 'total')) or 0.0
                deposit_f = _money_to_number(getattr(obj, 'deposit')) or 0.0
                obj.balance = f"{max(total_f - deposit_f, 0.0):.2f}"
            except Exception:
                pass

        db.session.commit()
        return jsonify(obj.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Update failed", "detail": str(e)}), 500

# Legacy mirror for container update (no /api prefix)
@app.route('/containers/<int:cid>', methods=['PATCH', 'PUT', 'OPTIONS'], strict_slashes=False)
def containers_update_legacy(cid):
    # Reuse the same implementation as the /api prefixed endpoint
    return containers_update_fallback(cid)

# Notifications (placeholder to avoid 405s on frontend)
@app.route('/notifications', methods=['GET', 'POST', 'OPTIONS'])
def notifications():
    if request.method == 'OPTIONS':
        origin = request.headers.get("Origin")
        headers = {}
        if origin in (ALLOWED_ORIGINS or []):
            headers["Access-Control-Allow-Origin"] = origin
            headers["Vary"] = "Origin"
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key"
            headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD"
        return ("", 204, headers)
    # GET returns notifications; POST can acknowledge/clear (placeholder)
    return jsonify([])

#
# Explicit preflight for /auth/login (helps some browsers)
@app.route('/auth/login', methods=['OPTIONS'])
def _preflight_auth_login():
    return ("", 204)

# Legacy compatibility: keep old endpoints working by redirecting to blueprint paths
@app.route('/login', methods=['POST', 'OPTIONS'])
def legacy_login_redirect():
    if request.method == 'OPTIONS':
        return ("", 204)
    # 307 preserves method and body for POST
    return redirect('/auth/login', code=307)

@app.route('/me', methods=['GET'])
def legacy_me_redirect():
    # 307 preserves method if this were non-GET; for GET it's a normal redirect
    return redirect('/auth/me', code=307)





# Import containers from Excel/CSV
@app.route('/api/containers/import', methods=['POST', 'OPTIONS'])
def import_containers():
    """Import containers from an uploaded Excel (.xlsx/.xls) or CSV file.
    Expects a multipart/form-data with field name 'file'.
    Returns a JSON summary with counts and any row-level errors.
    """
    # CORS preflight support
    if request.method == 'OPTIONS':
        return ("", 204)

    # Validate file presence
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400
    f = request.files['file']
    if not f or f.filename.strip() == '':
        return jsonify({'error': 'Empty filename'}), 400

    filename = secure_filename(f.filename)
    ext = os.path.splitext(filename)[1].lower()

    # Lazy import so the app boots even if pandas/openpyxl are missing
    try:
        import pandas as pd
    except Exception as e:
        return jsonify({'error': 'pandas not installed on server', 'detail': str(e)}), 500

    # Parse the file into a DataFrame
    try:
        if ext in ('.xlsx', '.xls'):
            df = pd.read_excel(f)
        elif ext == '.csv':
            try:
                df = pd.read_csv(f)
            except UnicodeDecodeError:
                f.stream.seek(0)
                df = pd.read_csv(f, encoding='latin-1')
        else:
            return jsonify({'error': 'Unsupported file type. Use .xlsx, .xls or .csv'}), 415
    except Exception as e:
        return jsonify({'error': 'Failed to read file', 'detail': str(e)}), 400

    # Normalize headers (lowercase, trimmed)
    df.columns = [str(c).strip().lower() for c in df.columns]

    def pick(row, *aliases, default=""):
        for a in aliases:
            if a in row and pd.notna(row[a]):
                return row[a]
        return default

    def to_number(v, default=0.0):
        try:
            s = str(v).strip()
            if not s:
                return default
            # remove currency and spaces, normalize decimal comma
            s = s.replace('€', '').replace('$', '').replace('\u00A0', ' ').replace(' ', '')
            if ',' in s and '.' in s:
                s = s.replace('.', '').replace(',', '.')
            else:
                s = s.replace(',', '.')
            return float(s)
        except Exception:
            return default

    created, updated, errors = 0, 0, []

    for idx, row in df.iterrows():
        try:
            # Read values with common aliases from your sample sheet
            supplier     = pick(df.loc[idx], 'supplier', 'dobavljač', 'dobavljac')
            proforma_no  = pick(df.loc[idx], 'proforma', 'proforma no', 'proforma_no')
            etd_raw      = pick(df.loc[idx], 'etd')
            delivery_raw = pick(df.loc[idx], 'delivery')
            eta_raw      = pick(df.loc[idx], 'eta')
            cargo_qty    = pick(df.loc[idx], 'qty', 'količina', 'kolicina', default="")
            cargo        = pick(df.loc[idx], 'tip', 'cargo', 'type')
            container_no = pick(df.loc[idx], 'kontejner', 'container', 'container no', 'container_no')
            roba         = pick(df.loc[idx], 'roba', 'goods', 'product')
            contain_price= pick(df.loc[idx], 'cijena', 'cena', 'price', 'contain_price')
            agent        = pick(df.loc[idx], 'agent')
            total        = pick(df.loc[idx], 'total', 'ukupno')
            deposit      = pick(df.loc[idx], 'deposit', 'depozit')
            balance      = pick(df.loc[idx], 'balance', 'balans')
            paid_raw     = pick(df.loc[idx], 'paid', 'plaćeno', 'placeno', 'status')

            # Dates – reuse backend helper by feeding ISO where possible
            def to_date_str(v):
                if pd.isna(v) or v is None or str(v).strip() == '':
                    return None
                # pandas may give Timestamp; keep ISO date part
                try:
                    return pd.to_datetime(v).date().isoformat()
                except Exception:
                    return str(v)

            etd_s      = to_date_str(etd_raw)
            delivery_s = to_date_str(delivery_raw)
            eta_s      = to_date_str(eta_raw)

            # Numeric-like
            total_f   = to_number(total, 0.0)
            deposit_f = to_number(deposit, 0.0)
            balance_f = to_number(balance, total_f - deposit_f)

            # Paid flag
            paid = False
            if isinstance(paid_raw, bool):
                paid = paid_raw
            else:
                s = str(paid_raw).strip().lower()
                if s in ('1','true','yes','y','da','paid','plaćeno','placeno'):
                    paid = True

            # If paid, force balance 0.00
            if paid:
                balance_f = 0.0

            # Create and store row
            rec = Container(
                supplier=str(supplier or ''),
                proforma_no=str(proforma_no or ''),
                etd=_parse_date_any(etd_s),
                delivery=_parse_date_any(delivery_s),
                eta=_parse_date_any(eta_s),
                cargo_qty=str(cargo_qty or ''),
                cargo=str(cargo or ''),
                container_no=str(container_no or ''),
                roba=str(roba or ''),
                contain_price=str(pick(df.loc[idx], 'contain_price', 'cijena', 'price') or ''),
                agent=str(agent or ''),
                total=f"{total_f:.2f}",
                deposit=f"{deposit_f:.2f}",
                balance=f"{balance_f:.2f}",
                paid=bool(paid),
            )
            db.session.add(rec)
            created += 1
        except Exception as e:
            errors.append({'row': int(idx) + 2, 'error': str(e)})  # +2 for header + 1-index

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'DB commit failed', 'detail': str(e), 'created': created, 'errors': errors}), 500

    return jsonify({'ok': True, 'created': created, 'updated': updated, 'errors': errors}), 201

# KPI
@app.route('/api/kpi', methods=['GET'])
def kpi():
    counts = {}
    for st in ALLOWED_STATUSES:
        counts[st] = Arrival.query.filter_by(status=st).count()
    total = Arrival.query.count()
    return jsonify({'total': total, 'by_status': counts})
# Options for dropdowns
@app.get('/api/options/responsibles')
def options_responsibles():
    # Allow env-based override: RESPONSIBLES="Ludvig,Gazi,Gezim,Armir"
    from_env = (os.environ.get('RESPONSIBLES') or '').strip()
    if from_env:
        vals = [v.strip() for v in from_env.split(',') if v.strip()]
    else:
        vals = ["Ludvig", "Gazi", "Gezim", "Armir"]
    return jsonify(vals)

def _compute_locations_list():
    """
    1) LOCATIONS iz .env (comma-separated) ako postoji,
    2) default poslovna lista (fiksna),
    3) distinct vrijednosti iz Arrival.location (append + dedupe).
    """
    from_env = (os.environ.get('LOCATIONS') or '').strip()
    if from_env:
        base_list = [v.strip() for v in from_env.split(',') if v.strip()]
    else:
        base_list = [
            "Veleprodajni magaci",
            "Pg Centar",
            "Pg",
            "Bar",
            "Bar Centar",
            "Budva",
            "Kotor Centar",
            "Herceg Novi",
            "Herceg Novi Centar",
            "Niksic",
            "Bijelo polje",
            "Ulcinj Centar",
        ]
    try:
        rows = db.session.query(Arrival.location).filter(Arrival.location.isnot(None)).all()
        extra = [(r[0] or '').strip() for r in rows if (r[0] or '').strip()]
    except Exception:
        extra = []
    seen, result = set(), []
    for v in base_list + extra:
        k = v.strip()
        if k and k not in seen:
            seen.add(k)
            result.append(k)
    return result

@app.route('/api/locations', methods=['GET', 'HEAD', 'OPTIONS'])
def api_locations():
    # CORS preflight
    if request.method == 'OPTIONS':
        return ("", 204)
    return jsonify(_compute_locations_list()), 200

@app.get('/api/options/locations')
def options_locations():
    """
    Returns the list of allowed shop/warehouse locations for dropdowns.
    Reuses the canonical computation used by /api/locations.
    """
    return jsonify(_compute_locations_list())

def _parse_boolish(val):
    """
    Best-effort parser that turns various truthy/falsy representations into bool.
    Accepts: True/False, 1/0, "true"/"false", "yes"/"no", "da"/"ne",
    "paid"/"unpaid", "placeno"/"nije placeno", "plaćeno"/"nije plaćeno".
    Returns True/False or None if undecidable.
    """
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    try:
        # Numbers: 0/1
        if isinstance(val, (int, float)):
            return bool(int(val))
    except Exception:
        pass
    s = str(val).strip().lower()
    if s in ("true", "1", "yes", "y", "da"):
        return True
    if s in ("false", "0", "no", "n", "ne"):
        return False
    if s in ("paid", "plaćeno", "placeno"):
        return True
    if s in ("unpaid", "nije plaćeno", "nije placeno"):
        return False
    return None

# --- Utility parsers ---
def _parse_iso(val):
    if not val:
        return None
    s = str(val).strip()
    if not s:
        return None
    try:
        # Standard ISO: '2025-03-11' or '2025-03-11T12:34:56Z'
        return datetime.fromisoformat(s.replace('Z', '+00:00'))
    except Exception:
        pass
    # Accept European formats: 'dd.mm.yyyy' and 'dd.mm.yyyy HH:MM'
    for fmt in ("%d.%m.%Y", "%d.%m.%Y %H:%M"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    # Accept common fallback: 'dd/mm/yyyy'
    for fmt in ("%d/%m/%Y", "%d/%m/%Y %H:%M"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    return None

def _parse_float(val):
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    # Remove currency symbols and spaces
    for ch in ['€', '$', ' ', '\u00A0']:
        s = s.replace(ch, '')
    # If the string has both '.' and ',', assume '.' is thousands sep and ',' is decimal
    if ',' in s and '.' in s:
        s = s.replace('.', '').replace(',', '.')
    else:
        # Otherwise, just turn comma into decimal point
        s = s.replace(',', '.')
    try:
        return float(s)
    except Exception:
        return None

def _parse_date_any(val):
    """
    Robust date parser for 'YYYY-MM-DD', ISO strings, and Excel serial numbers.
    Returns datetime.date or None.
    """
    if not val:
        return None
    s = str(val).strip()
    if not s:
        return None
    # Already ISO date 'YYYY-MM-DD'
    try:
        if len(s) == 10 and s[4] == "-" and s[7] == "-":
            return datetime.fromisoformat(s).date()
    except Exception:
        pass
    # Excel serial number?
    try:
        n = float(s)
        if n > 10000:  # crude guard for serials
            base = datetime(1899, 12, 30)
            dt = base + timedelta(days=n)
            return dt.date()
    except Exception:
        pass
    # Fallback parse
    try:
        dt = datetime.fromisoformat(s)
        return dt.date()
    except Exception:
        pass
    for fmt in ("%d/%m/%Y", "%m/%d/%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except Exception:
            continue
    return None

def _money_to_number(val):
    if val is None:
        return None
    s = str(val)
    s = "".join(ch for ch in s if ch.isdigit() or ch in ",.-")
    if "," in s and "." not in s:
        s = s.replace(",", ".")
    try:
        return float(s)
    except Exception:
        return None

ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
ADMIN_NAME = os.environ.get('ADMIN_NAME', 'Admin')

def ensure_admin():
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        return
    email = ADMIN_EMAIL.strip().lower()
    existing = User.query.filter_by(email=email).first()
    if existing:
        return
    u = User(email=email, name=ADMIN_NAME, role='admin')
    # podrži obje varijante modela:
    # - hashed preko set_password()
    # - plain polje "password"
    # - legacy hash polje "password_hash"
    if hasattr(u, "set_password") and callable(getattr(u, "set_password")):
        u.set_password(ADMIN_PASSWORD)
    elif hasattr(u, "password"):
        setattr(u, "password", ADMIN_PASSWORD)
    else:
        try:
            u.password_hash = generate_password_hash(ADMIN_PASSWORD)
        except Exception:
            pass
    db.session.add(u)
    db.session.commit()
    print(f"[SEED] Admin user created: {email}")

# --- Soft migrations for SQLite ---
def column_exists(table, column):
    try:
        info = db.session.execute(text(f"PRAGMA table_info('{table}')")).fetchall()
        return any(row[1] == column for row in info)
    except Exception:
        return False

def soft_migrate():
    # Add columns if missing
    cols = {
        'order_date': 'DATETIME',
        'production_due': 'DATETIME',
        'shipped_at': 'DATETIME',
        'arrived_at': 'DATETIME',
        'customs_info': 'TEXT',
        'freight_cost': 'FLOAT',
        'customs_cost': 'FLOAT',
        'currency': "VARCHAR(8) DEFAULT 'EUR'",
        'assignee_id': 'INTEGER',
        'production_overdue_notified': 'BOOLEAN DEFAULT 0',
        'driver': 'VARCHAR(120)',
        'pickup_date': 'DATETIME',
        'goods_cost': 'FLOAT',
        'responsible': 'VARCHAR(120)',
        'location': 'VARCHAR(120)',
    }
    for c, t in cols.items():
        if not column_exists('arrival', c):
            try:
                db.session.execute(text(f"ALTER TABLE arrival ADD COLUMN {c} {t}"))
                db.session.commit()
            except Exception as e:
                print("[MIGRATION]", c, e)

# --- SLA monitor thread ---
def sla_monitor_loop():
    # Simple loop – production overdue alerts
    while True:
        try:
            with app.app_context():
                now = datetime.utcnow()
                # Build base query
                query = Arrival.query.filter(
                    Arrival.production_due.isnot(None),
                    Arrival.production_due < now,
                    Arrival.status.in_(['ordered','in_production'])
                )
                # Guard for deployments where the column doesn't exist
                if hasattr(Arrival, 'production_overdue_notified'):
                    query = query.filter(Arrival.production_overdue_notified.is_(False))
                pending = query.all()
                if pending and NOTIFY_ON_SLA:
                    for a in pending:
                        try:
                            send_email(
                                subject=f"[Arrivals] PRODUCTION OVERDUE for #{a.id}",
                                body=f"Supplier: {a.supplier}\nDue: {a.production_due}\nStatus: {a.status}\nPlease contact manufacturer.",
                                to_list=all_user_emails()
                            )
                            if hasattr(a, 'production_overdue_notified'):
                                a.production_overdue_notified = True
                        except Exception as e:
                            print("[SLA MAIL ERROR]", e)
                    db.session.commit()
        except Exception as e:
            print("[SLA LOOP ERROR]", e)
        time.sleep(SLA_CHECK_SECONDS)

# --- Blueprints (deferred registration after helpers to avoid circular imports) ---

def _register_blueprint(module_candidates, attr_name="bp", fallback_url_prefix=None, label=""):
    """
    Try importing a blueprint object from a list of module paths and register it.
    Example:
      _register_blueprint(["routes.auth", "auth"], label="auth")
    """
    for mod in module_candidates:
        try:
            mod_obj = __import__(mod, fromlist=[attr_name])
            bp_obj = getattr(mod_obj, attr_name, None)
            if bp_obj is None:
                raise AttributeError(f"Module '{mod}' has no attr '{attr_name}'")
            # Optionally override url_prefix if provided
            if fallback_url_prefix:
                app.register_blueprint(bp_obj, url_prefix=fallback_url_prefix)
            else:
                app.register_blueprint(bp_obj)
            print(f"[BOOT] registered blueprint '{label or mod}' from {mod}")
            return True
        except Exception as e:
            print(f"[BOOT] blueprint '{label or mod}' not registered from {mod}: {e}")
            continue
    print(f"[BOOT] blueprint '{label or module_candidates}' could not be registered from any candidate.")
    return False

# Auth blueprint: try new path first (routes.auth), then legacy (auth)
_register_blueprint(["routes.auth", "auth"], label="auth")

# Users blueprint
_register_blueprint(["routes.users", "users"], label="users")

# Arrivals blueprint
_register_blueprint(["routes.arrivals", "arrivals"], label="arrivals")

# Containers blueprint
# The 'containers' blueprint in containers.py already defines url_prefix='/api/containers'.
# Register without forcing an extra prefix to avoid '/api/containers/api/containers'.
_register_blueprint(["routes.containers", "containers"], label="containers")


# Files blueprint
_register_blueprint(["routes.files", "files"], label="files")

# --- Debug: list all routes (helps verify that PATCH endpoints are registered) ---
@app.get('/_debug/routes')
def _debug_routes():
    out = []
    try:
        for r in app.url_map.iter_rules():
            methods = ",".join(sorted(m for m in r.methods if m not in ("HEAD", "OPTIONS")))
            out.append({"rule": str(r), "endpoint": r.endpoint, "methods": methods})
    except Exception as e:
        return jsonify({"error": "route-introspection-failed", "detail": str(e)}), 500
    return jsonify(out), 200

# --- Admin: DB info (alembic revision) ---
@app.route('/admin/db-info', methods=['GET', 'HEAD', 'OPTIONS'], strict_slashes=False)
@jwt_required(optional=True)
def admin_db_info():
    if request.method == 'OPTIONS':
        origin = request.headers.get("Origin")
        headers = {}
        if origin in (ALLOWED_ORIGINS or []):
            headers["Access-Control-Allow-Origin"] = origin
            headers["Vary"] = "Origin"
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key"
            headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD"
        return ("", 204, headers)
    # Allow API key or admin JWT only
    if not has_valid_api_key():
        try:
            verify_jwt_in_request(optional=False)
        except Exception:
            return jsonify({"error": "Unauthorized"}), 401
        claims = get_jwt() or {}
        if claims.get('role') != 'admin':
            return jsonify({"error": "Admin only"}), 403

    info = {"db_revision": None, "repo_heads": [], "is_at_head": None}
    # Read DB's current alembic revision
    try:
        row = db.session.execute(text("SELECT version_num FROM alembic_version"))
        row = row.first()
        if row:
            info["db_revision"] = row[0]
    except Exception as e:
        info["db_error"] = str(e)

    # Read repo heads via alembic config (best effort)
    try:
        from alembic.config import Config as _AConfig
        from alembic.script import ScriptDirectory as _AScript
        cfg_path = os.path.join(os.path.dirname(__file__), 'alembic.ini')
        acfg = _AConfig(cfg_path)
        script = _AScript.from_config(acfg)
        heads = list(script.get_heads())
        info["repo_heads"] = heads
        if info["db_revision"] is not None:
            info["is_at_head"] = info["db_revision"] in heads
    except Exception as e:
        info["repo_error"] = str(e)

    return jsonify(info), 200

# --- Fallback AUTH routes (only if the auth blueprint failed to register) ---
def _has_endpoint(name: str) -> bool:
    try:
        return name in app.view_functions
    except Exception:
        return False

# If nothing registered a handler for /auth/login, provide a minimal working fallback.
if not (_has_endpoint("auth.login") or _has_endpoint("login") or _has_endpoint("auth_login_fallback")):
    @app.route('/auth/login', methods=['POST'])
    def auth_login_fallback():
        try:
            data = request.get_json(force=True, silent=True) or {}
            email = (data.get('email') or '').strip().lower()
            password = (data.get('password') or '')
            if not email or not password:
                return jsonify({'error': 'Email and password required'}), 400

            user = User.query.filter_by(email=email).first()
            if not user:
                return jsonify({'error': 'Invalid credentials'}), 401

            # Support both password_hash/check_password and plain password field
            ok = False
            if hasattr(user, "check_password") and callable(getattr(user, "check_password")):
                ok = user.check_password(password)
            elif hasattr(user, "password_hash"):
                try:
                    ok = check_password_hash(user.password_hash, password)
                except Exception:
                    ok = False
            elif hasattr(user, "password"):
                ok = (getattr(user, "password") == password)

            if not ok:
                return jsonify({'error': 'Invalid credentials'}), 401

            claims = {'role': getattr(user, "role", "viewer"), 'email': user.email}
            token = create_access_token(identity=str(getattr(user, "id", 0)), additional_claims=claims)
            return jsonify({'access_token': token, 'user': {'id': getattr(user, "id", 0), 'email': user.email, 'role': getattr(user, "role", "viewer"), 'name': getattr(user, "name", "")}}), 200
        except Exception as e:
            return jsonify({'error': 'Login failed', 'detail': str(e)}), 500

# If nothing registered a handler for /auth/me, provide a minimal working fallback.
if not (_has_endpoint("auth.me") or _has_endpoint("me") or _has_endpoint("auth_me_fallback")):
    @app.route('/auth/me', methods=['GET'])
    @jwt_required()
    def auth_me_fallback():
        try:
            uid = get_jwt_identity()
            claims = get_jwt() or {}
            email = claims.get('email')
            role = claims.get('role', 'viewer')
            user = None
            if uid:
                try:
                    user = User.query.get(int(uid))
                except Exception:
                    user = None
            return jsonify({
                'id': int(uid) if uid else None,
                'email': email or (user.email if user else None),
                'role': role,
                'name': (user.name if user and hasattr(user, "name") else None),
            }), 200
        except Exception as e:
            return jsonify({'error': 'Auth check failed', 'detail': str(e)}), 401

# --- App bootstrap ---
if os.environ.get("ALEMBIC_SKIP_BOOTSTRAP") != "1":
    with app.app_context():
        # Dev/first-run convenience: ensure tables exist. In production prefer Alembic.
        try:
            db.create_all()
            print("[BOOTSTRAP] db.create_all() completed")
        except Exception as e:
            print("[BOOTSTRAP ERROR] create_all failed:", e)
        # Seed admin if missing
        try:
            ensure_admin()
        except Exception as e:
            print("[BOOTSTRAP ERROR]", e)
        # start SLA thread
        t = threading.Thread(target=sla_monitor_loop, daemon=True)
        t.start()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8081))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host='0.0.0.0', port=port, debug=debug)

    
