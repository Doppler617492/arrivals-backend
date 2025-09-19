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
import json

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
        db_url = _os.environ.get('DATABASE_URL')
        if not db_url:
            raise RuntimeError(
                "DATABASE_URL is not set. Configure Postgres DSN, e.g. postgresql+psycopg://user:pass@host:5432/db"
            )
        app.config['SQLALCHEMY_DATABASE_URI'] = db_url
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

# --- Optional WebSocket support (Flask-Sock) ---
WS_CLIENTS = set()
try:
    from flask_sock import Sock
    sock = Sock(app)

    @sock.route('/ws')
    def _ws(ws):
        try:
            # Basic handshake context: read query params if available
            # Topics (comma separated) and token are optional
            # NOTE: For dev we don't enforce JWT here; use a reverse proxy for auth in prod.
            params = request.args or {}
            topics = (params.get('topics') or '').split(',') if params.get('topics') else []

            # Register this client
            WS_CLIENTS.add(ws)
            # Send a hello/heartbeat so client knows it’s connected
            try:
                ws.send(json.dumps({
                    'type': 'system.welcome',
                    'v': 1,
                    'ts': datetime.utcnow().isoformat() + 'Z',
                    'topics': [t for t in topics if t],
                }))
            except Exception:
                pass

            # Keep the socket open; echo pings, ignore others
            while True:
                try:
                    msg = ws.receive()
                    if msg is None:
                        break
                    try:
                        data = json.loads(msg)
                    except Exception:
                        data = {'type': 'text', 'data': msg}
                    # Respond to pings to keep connection lively
                    if isinstance(data, dict) and data.get('type') in ('ping', 'system.ping'):
                        ws.send(json.dumps({'type': 'system.pong', 'ts': datetime.utcnow().isoformat() + 'Z', 'v': 1}))
                except Exception:
                    break
        finally:
            try:
                WS_CLIENTS.discard(ws)
            except Exception:
                pass
except Exception as _ws_err:
    sock = None
    print('[WS] WebSocket not enabled (install flask-sock + simple-websocket).', _ws_err)

def ws_broadcast(event: dict):
    """Best-effort broadcast to all connected WS clients."""
    if not WS_CLIENTS:
        return
    try:
        payload = json.dumps(event)
    except Exception:
        return
    dead = []
    for client in list(WS_CLIENTS):
        try:
            client.send(payload)
        except Exception:
            dead.append(client)
    for d in dead:
        try:
            WS_CLIENTS.discard(d)
        except Exception:
            pass

def notify(text: str, *, ntype: str = 'info', entity_type: str | None = None, entity_id: int | None = None, user_id: int | None = None, role: str | None = None):
    """Create, persist and broadcast a notification.
    Emits WS event 'notifications.created'. Safe to call anywhere; rolls back on failure.
    """
    try:
        n = Notification(user_id=user_id, role=role, type=ntype, entity_type=entity_type, entity_id=entity_id, text=text, read=False)
        db.session.add(n)
        db.session.commit()
        try:
            ws_broadcast({
                'type': 'notifications.created',
                'resource': 'notifications',
                'action': 'created',
                'id': int(n.id),
                'v': 1,
                'ts': datetime.utcnow().isoformat() + 'Z',
                'data': n.to_dict(),
            })
        except Exception:
            pass
        return n
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return None

# Optional lightweight request logging to diagnose slow requests
if os.environ.get('LOG_HTTP', '').lower() in ('1','true','yes','on'):
    from flask import g
    @app.before_request
    def _http_log_begin():
        try:
            g._t0 = time.time()
            print(f"[HTTP] -> {request.method} {request.path}")
        except Exception:
            pass
    @app.after_request
    def _http_log_end(resp):
        try:
            t0 = getattr(g, '_t0', None)
            if t0:
                dt = (time.time() - t0) * 1000.0
                print(f"[HTTP] <- {request.method} {request.path} {resp.status_code} in {dt:.1f}ms")
        except Exception:
            pass
        return resp

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

# Blocklist check for revoked sessions (best-effort)
try:
    @jwt.token_in_blocklist_loader
    def _is_token_revoked(jwt_header, jwt_payload):  # type: ignore[override]
        try:
            jti = jwt_payload.get('jti')
            sub = jwt_payload.get('sub')
            if not jti or not sub:
                return False
            try:
                uid = int(sub)
            except Exception:
                uid = None
            if uid is None:
                return False
            s = db.session.query(Session).filter_by(user_id=uid, jti=jti).first()
            return bool(s and s.revoked)
        except Exception:
            return False
except Exception:
    pass

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
    Notification as Notification,
    Container as Container,
    ContainerFile as ContainerFile,
    Session as Session,
)

# Create missing tables in development by default to avoid 500s on first run
if os.environ.get('AUTO_CREATE_TABLES', '1').lower() in ('1','true','yes','on'):
    try:
        with app.app_context():
            db.create_all()
            # Optionally seed admin and migrate user passwords
            try:
                from sqlalchemy import inspect
                insp = inspect(db.engine)
                # Ensure users.password_hash exists
                try:
                    cols = [c['name'] for c in insp.get_columns('users')]
                    if 'password_hash' not in cols:
                        db.session.execute(text("ALTER TABLE users ADD COLUMN password_hash VARCHAR(255)"))
                        db.session.commit()
                        print('[BOOTSTRAP] Added users.password_hash')
                except Exception as e:
                    print('[BOOTSTRAP] Inspect/add users.password_hash skipped:', e)
                # Migrate legacy plaintext passwords
                try:
                    from werkzeug.security import generate_password_hash
                    rows = db.session.execute(text("SELECT id, password, password_hash FROM users")).fetchall()
                    for r in rows:
                        uid = r[0]; pwd = r[1]; ph = r[2]
                        if pwd and (not ph or not str(ph).strip()):
                            s = str(pwd)
                            h = s if s.startswith('pbkdf2:') else generate_password_hash(s)
                            db.session.execute(text("UPDATE users SET password_hash = :h, password = NULL WHERE id = :id"), { 'h': h, 'id': uid })
                    db.session.commit()
                    print('[BOOTSTRAP] Migrated users.password -> users.password_hash')
                except Exception as e:
                    print('[BOOTSTRAP] Password migration failed:', e)
                # Ensure admin
                ensure_admin()
            except Exception as e:
                print('[SEED] ensure_admin failed:', e)
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

# Fallback list/create for arrivals (guards against 405/308 edge-cases)
@app.route('/api/arrivals', methods=['GET', 'HEAD', 'OPTIONS', 'POST'], strict_slashes=False)
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

    if request.method == 'POST':
        # Minimal create handler to avoid 405 when blueprint slashes mismatch
        data = request.get_json(silent=True) or {}
        attempted = set((data or {}).keys())
        ok, role, uid, err = check_api_or_jwt(attempted)
        if not ok:
            return err
        try:
            loc = data.get('location') or data.get('lokacija') or data.get('store') or data.get('shop') or data.get('warehouse')
            if isinstance(loc, str):
                loc = loc.strip()
            a = Arrival(
                supplier=data.get('supplier'),
                carrier=data.get('carrier'),
                plate=data.get('plate'),
                driver=data.get('driver'),
                type=data.get('type') or data.get('transport_type') or 'truck',
                pickup_date=_parse_iso(data.get('pickup_date')),
                eta=_parse_iso(data.get('eta')),
                status=(data.get('status') or 'not_shipped'),
                note=data.get('note'),
                order_date=_parse_iso(data.get('order_date')),
                production_due=_parse_iso(data.get('production_due')),
                shipped_at=_parse_iso(data.get('shipped_at')),
                arrived_at=_parse_iso(data.get('arrived_at')),
                customs_info=data.get('customs_info'),
                freight_cost=_parse_float(data.get('freight_cost')),
                goods_cost=_parse_float(data.get('goods_cost')),
                customs_cost=_parse_float(data.get('customs_cost')),
                currency=(data.get('currency') or 'EUR')[:8],
                responsible=data.get('responsible'),
                location=loc,
                assignee_id=data.get('assignee_id'),
            )
            db.session.add(a)
            db.session.commit()
            try:
                ws_broadcast({
                    'type': 'arrivals.created',
                    'resource': 'arrivals',
                    'action': 'created',
                    'id': int(a.id),
                    'v': 1,
                    'ts': datetime.utcnow().isoformat() + 'Z',
                    'data': a.to_dict(),
                })
            except Exception:
                pass
            return jsonify(a.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            print("[/api/arrivals POST ERROR]", e)
            return jsonify({"error": "create_failed", "detail": str(e)}), 500

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

# Fallback: update a single arrival (PATCH/PUT) so status and other edits persist
@app.route('/api/arrivals/<int:aid>', methods=['PATCH', 'PUT', 'OPTIONS'], strict_slashes=False)
def arrivals_update_fallback(aid):
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

    data = request.get_json(silent=True) or {}
    attempted = set(data.keys() or [])
    allowed, role, uid, err = check_api_or_jwt(attempted)
    if not allowed:
        return err
    obj = Arrival.query.get(aid)
    if not obj:
        return jsonify({"error": "Not found"}), 404
    try:
        # Simple field map
        str_fields = [
            'supplier','carrier','plate','driver','type','status','note','currency','responsible','location'
        ]
        for k in str_fields:
            if k in data:
                setattr(obj, k, data.get(k))
        if 'pickup_date' in data:
            obj.pickup_date = _parse_iso(data.get('pickup_date'))
        if 'eta' in data:
            obj.eta = _parse_iso(data.get('eta'))
        if 'order_date' in data:
            obj.order_date = _parse_iso(data.get('order_date'))
        if 'production_due' in data:
            obj.production_due = _parse_iso(data.get('production_due'))
        if 'shipped_at' in data:
            obj.shipped_at = _parse_iso(data.get('shipped_at'))
        if 'arrived_at' in data:
            obj.arrived_at = _parse_iso(data.get('arrived_at'))
        if 'freight_cost' in data:
            obj.freight_cost = _parse_float(data.get('freight_cost'))
        if 'goods_cost' in data:
            obj.goods_cost = _parse_float(data.get('goods_cost'))
        if 'customs_cost' in data:
            obj.customs_cost = _parse_float(data.get('customs_cost'))

        db.session.commit()
        try:
            ws_broadcast({
                'type': 'arrivals.updated',
                'resource': 'arrivals',
                'action': 'updated',
                'id': int(obj.id),
                'v': 1,
                'ts': datetime.utcnow().isoformat() + 'Z',
                'changes': {k: data.get(k) for k in (data.keys() if isinstance(data, dict) else [])},
            })
        except Exception:
            pass
        return jsonify(obj.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "update_failed", "detail": str(e)}), 500

# Fallback: explicit status endpoint (helps clients that can't PATCH reliably)
@app.route('/api/arrivals/<int:aid>/status', methods=['POST', 'OPTIONS'], strict_slashes=False)
def arrivals_status_fallback(aid):
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
    data = request.get_json(silent=True) or {}
    status = (data.get('status') or '').strip()
    if not status:
        return jsonify({'error':'status_required'}), 400
    allowed, role, uid, err = check_api_or_jwt({'status'})
    if not allowed:
        return err
    obj = Arrival.query.get(aid)
    if not obj:
        return jsonify({'error':'Not found'}), 404
    try:
        obj.status = status
        db.session.commit()
        try:
            ws_broadcast({
                'type': 'arrivals.updated', 'resource': 'arrivals', 'action':'updated',
                'id': int(obj.id), 'v':1, 'ts': datetime.utcnow().isoformat()+'Z',
                'changes': {'status': status}
            })
        except Exception:
            pass
        return jsonify(obj.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error':'update_failed','detail':str(e)}), 500
# Fallback: list/upload arrival files when the arrivals blueprint isn't registered
@app.route('/api/arrivals/<int:arrival_id>/files', methods=['GET', 'POST', 'OPTIONS'], strict_slashes=False)
def arrivals_files_fallback(arrival_id):
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

    # Ensure arrival exists
    a = Arrival.query.get(arrival_id)
    if not a:
        return jsonify({"error": "Not found"}), 404

    if request.method == 'GET':
        files = ArrivalFile.query.filter_by(arrival_id=arrival_id).order_by(ArrivalFile.uploaded_at.asc()).all()
        return jsonify([
            {
                "id": f.id,
                "arrival_id": f.arrival_id,
                "filename": f.filename,
                "original_name": getattr(f, 'original_name', None),
                "uploaded_at": (getattr(f, 'uploaded_at', None) or datetime.utcnow()).isoformat(),
                "url": f"/api/arrivals/{arrival_id}/files/{f.id}/download",
            } for f in files
        ])

    # POST – upload one or more files
    try:
        files = []
        if 'files' in request.files:
            files.extend(request.files.getlist('files'))
        if 'file' in request.files:
            files.append(request.files['file'])
        if not files:
            return jsonify({"error": "file or files required"}), 400

        out = []
        for f in files:
            if not f or f.filename == '':
                continue
            safe_name = secure_filename(f.filename)
            uniq = f"{int(time.time()*1000)}_{safe_name}"
            path = os.path.join(app.config['UPLOAD_FOLDER'], uniq)
            f.save(path)
            rec = ArrivalFile(arrival_id=arrival_id, filename=uniq, original_name=safe_name)
            db.session.add(rec)
            db.session.flush()
            out.append({
                "id": rec.id,
                "arrival_id": rec.arrival_id,
                "filename": rec.filename,
                "original_name": rec.original_name,
                "uploaded_at": (rec.uploaded_at or datetime.utcnow()).isoformat(),
                "url": f"/api/arrivals/{arrival_id}/files/{rec.id}/download",
            })
        db.session.commit()
        return jsonify(out), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "upload_failed", "detail": str(e)}), 500

# Fallback: delete a single arrival file
@app.route('/api/arrivals/<int:arrival_id>/files/<int:file_id>', methods=['DELETE', 'OPTIONS'], strict_slashes=False)
def arrivals_file_delete_fallback(arrival_id, file_id):
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
    rec = ArrivalFile.query.filter_by(id=file_id, arrival_id=arrival_id).first()
    if not rec:
        return jsonify({"error": "Not found"}), 404
    try:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], rec.filename))
        except Exception:
            pass
        db.session.delete(rec)
        db.session.commit()
        return jsonify({"ok": True, "deleted_id": file_id})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "delete_failed", "detail": str(e)}), 500
# Direct download for an arrival file (fallback when /files blueprint is not available)
@app.route('/api/arrivals/<int:arrival_id>/files/<int:file_id>/download', methods=['GET'], strict_slashes=False)
def arrival_file_download(arrival_id, file_id):
    try:
        rec = ArrivalFile.query.filter_by(id=file_id, arrival_id=arrival_id).first()
        if not rec:
            return jsonify({'error':'Not found'}), 404
        return send_from_directory(app.config['UPLOAD_FOLDER'], rec.filename, as_attachment=False)
    except Exception as e:
        return jsonify({'error':'download_failed','detail':str(e)}), 500

# Explicit create endpoint to avoid any method shadowing on '/api/arrivals'
@app.route('/api/arrivals/create', methods=['OPTIONS', 'POST'], strict_slashes=False)
def arrivals_create_explicit():
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

    data = request.get_json(silent=True) or {}
    ok, role, uid, err = check_api_or_jwt(set((data or {}).keys()))
    if not ok:
        return err
    try:
        loc = data.get('location') or data.get('lokacija') or data.get('store') or data.get('shop') or data.get('warehouse')
        if isinstance(loc, str):
            loc = loc.strip()
        a = Arrival(
            supplier=data.get('supplier'),
            carrier=data.get('carrier'),
            plate=data.get('plate'),
            driver=data.get('driver'),
            type=data.get('type') or data.get('transport_type') or 'truck',
            pickup_date=_parse_iso(data.get('pickup_date')),
            eta=_parse_iso(data.get('eta')),
            status=(data.get('status') or 'not_shipped'),
            note=data.get('note'),
            order_date=_parse_iso(data.get('order_date')),
            production_due=_parse_iso(data.get('production_due')),
            shipped_at=_parse_iso(data.get('shipped_at')),
            arrived_at=_parse_iso(data.get('arrived_at')),
            customs_info=data.get('customs_info'),
            freight_cost=_parse_float(data.get('freight_cost')),
            goods_cost=_parse_float(data.get('goods_cost')),
            customs_cost=_parse_float(data.get('customs_cost')),
            currency=(data.get('currency') or 'EUR')[:8],
            responsible=data.get('responsible'),
            location=loc,
            assignee_id=data.get('assignee_id'),
        )
        db.session.add(a)
        db.session.commit()
        try:
            ws_broadcast({
                'type': 'arrivals.created',
                'resource': 'arrivals',
                'action': 'created',
                'id': int(a.id),
                'v': 1,
                'ts': datetime.utcnow().isoformat() + 'Z',
                'data': a.to_dict(),
            })
        except Exception:
            pass
        return jsonify(a.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        print("[/api/arrivals/create ERROR]", e)
        return jsonify({"error": "create_failed", "detail": str(e)}), 500

# Fallback list/create for containers (guards against 405/308 edge-cases)
@app.route('/api/containers', methods=['GET', 'HEAD', 'OPTIONS', 'POST'], strict_slashes=False)
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

    # Create (form or JSON)
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        if not data:
            data = {k: v for k, v in (request.form or {}).items()}
        attempted = set((data or {}).keys())
        ok, role, uid, err = check_api_or_jwt(attempted)
        if not ok:
            return err
        try:
            def pick(obj,*aliases,default=""):
                for a in aliases:
                    if a in obj and obj[a] not in (None,""):
                        return obj[a]
                return default
            supplier     = pick(data,'supplier')
            proforma_no  = pick(data,'proforma_no','proforma','proformaNo','proforma_number','pf_no','pfNumber')
            etd          = _parse_date_any(pick(data,'etd'))
            delivery     = _parse_date_any(pick(data,'delivery'))
            eta          = _parse_date_any(pick(data,'eta'))
            cargo_qty    = str(pick(data,'cargo_qty','qty','quantity') or '')
            cargo        = pick(data,'cargo','goods','tip')
            container_no = pick(data,'container_no','container','containerNo','container_number','containerno','containerNum')
            roba         = pick(data,'roba','goods','product')
            contain_price= str(pick(data,'contain_price','container_price','price') or '')
            agent        = pick(data,'agent')
            total        = str(pick(data,'total') or '')
            deposit      = str(pick(data,'deposit') or '')
            balance      = str(pick(data,'balance') or '')
            paid_flag    = pick(data,'paid','placeno','payment_status')
            paid_bool    = None
            try:
                if str(paid_flag).lower() in ('1','true','yes','y','paid','plaćeno','placeno','uplaćeno','uplaceno'):
                    paid_bool = True
                elif str(paid_flag).lower() in ('0','false','no','n','unpaid','nije plaćeno','nije placeno'):
                    paid_bool = False
            except Exception:
                pass
            c = Container(
                supplier=supplier,
                proforma_no=proforma_no,
                etd=etd,
                delivery=delivery,
                eta=eta,
                cargo_qty=cargo_qty,
                cargo=cargo,
                container_no=container_no,
                roba=roba,
                contain_price=contain_price,
                agent=agent,
                total=total,
                deposit=deposit,
                balance=balance,
                paid=bool(paid_bool) if paid_bool is not None else False,
                status=str(pick(data,'status') or ("plaćeno" if paid_bool else "nije plaćeno")),
            )
            db.session.add(c)
            db.session.commit()
            try:
                ws_broadcast({'type':'containers.created','resource':'containers','action':'created','id':int(c.id),'v':1,'ts':datetime.utcnow().isoformat()+'Z','data':c.to_dict()})
            except Exception:
                pass
            return jsonify(c.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            print('[/api/containers POST ERROR]', e)
            return jsonify({'error':'create_failed','detail':str(e)}), 500

    try:
        # Filters
        q = (request.args.get('q') or '').strip().lower()
        status = (request.args.get('status') or '').strip().lower()  # 'paid' | 'unpaid' | ''
        status_text = (request.args.get('status_text') or '').strip()  # textual status e.g. 'pending','shipped','arrived'
        date_from = (request.args.get('from') or '').strip()  # ISO yyyy-mm-dd
        date_to = (request.args.get('to') or '').strip()
        date_field = (request.args.get('date_field') or 'eta').strip().lower()  # eta|etd|delivery
        # Default sort: ETD descending so future dates (e.g., 2026) appear first
        sort_by = (request.args.get('sort_by') or 'etd').strip().lower()
        sort_dir = (request.args.get('sort_dir') or 'desc').strip().lower()

        query = Container.query

        if q:
            like = f"%{q}%"
            query = query.filter(or_(
                Container.supplier.ilike(like),
                Container.proforma_no.ilike(like),
                Container.cargo.ilike(like),
                Container.container_no.ilike(like),
                Container.roba.ilike(like),
                Container.agent.ilike(like),
                Container.code.ilike(like),
                Container.status.ilike(like),
                Container.note.ilike(like),
            ))
        if status == 'paid':
            query = query.filter(Container.paid.is_(True))
        elif status == 'unpaid':
            query = query.filter(Container.paid.is_(False))
        if status_text:
            try:
                query = query.filter(Container.status == status_text)
            except Exception:
                pass
        # Choose date column to filter on
        date_col = Container.eta
        try:
            if date_field == 'etd' and hasattr(Container, 'etd'):
                date_col = getattr(Container, 'etd')
            elif date_field == 'delivery' and hasattr(Container, 'delivery'):
                date_col = getattr(Container, 'delivery')
        except Exception:
            pass
        if date_from:
            query = query.filter(date_col >= date_from)
        if date_to:
            query = query.filter(date_col <= date_to)

        sort_map = {
            'id': Container.id,
            'supplier': Container.supplier,
            'eta': Container.eta,
            'etd': Container.etd if hasattr(Container, 'etd') else Container.created_at,
            'total': Container.total,
            'balance': Container.balance,
            'created_at': Container.created_at,
            'status': Container.status,
        }
        col = sort_map.get(sort_by, Container.created_at)
        # Place NULL ETD/ETA/DELIVERY at the bottom when sorting DESC
        if sort_dir == 'asc':
            order_expr = col.asc()
            if sort_by in ('etd', 'eta', 'delivery'):
                try:
                    order_expr = order_expr.nullsfirst()
                except Exception:
                    pass
        else:
            order_expr = col.desc()
            if sort_by in ('etd', 'eta', 'delivery'):
                try:
                    order_expr = order_expr.nullslast()
                except Exception:
                    pass
        query = query.order_by(order_expr)

        # Server pagination (optional)
        # Paging: support offset/limit or page/per_page
        try:
            offset = int(request.args.get('offset', '')) if request.args.get('offset') is not None else None
            limit = int(request.args.get('limit', '')) if request.args.get('limit') is not None else None
        except Exception:
            offset, limit = None, None
        try:
            page = int(request.args.get('page', '0'))
            per_page = int(request.args.get('per_page', '0'))
        except Exception:
            page, per_page = 0, 0
        total = None
        if limit is not None and limit > 0:
            total = query.count()
            rows = query.limit(limit).offset(int(offset or 0)).all()
        elif page > 0 and per_page > 0:
            total = query.count()
            rows = query.limit(per_page).offset((page - 1) * per_page).all()
        else:
            rows = query.all()
        counts_map = dict(
            db.session.query(ContainerFile.container_id, func.count(ContainerFile.id))
            .group_by(ContainerFile.container_id).all()
        )
        payload = []
        for c in rows:
            d = c.to_dict()
            d["files_count"] = int(counts_map.get(c.id, 0))
            payload.append(d)
        if total is not None:
            resp = {'items': payload, 'total': total}
            # include whichever paging scheme supplied
            if limit is not None and limit > 0:
                resp.update({'offset': int(offset or 0), 'limit': int(limit)})
            else:
                resp.update({'page': page, 'per_page': per_page})
            return jsonify(resp), 200
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

        # Realtime: emit containers.updated (best-effort)
        try:
            ws_broadcast({
                'type': 'containers.updated',
                'resource': 'containers',
                'action': 'updated',
                'id': int(obj.id),
                'v': 1,
                'ts': datetime.utcnow().isoformat() + 'Z',
                'changes': {k: getattr(obj, k, None) for k in (data.keys() if isinstance(data, dict) else [])},
            })
        except Exception:
            pass

        return jsonify(obj.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Update failed", "detail": str(e)}), 500

# Legacy mirror for container update (no /api prefix)
@app.route('/containers/<int:cid>', methods=['PATCH', 'PUT', 'OPTIONS'], strict_slashes=False)
def containers_update_legacy(cid):
    # Reuse the same implementation as the /api prefixed endpoint
    return containers_update_fallback(cid)

# Provide a DELETE fallback so clients can always remove a container even if
# the dedicated blueprint isn't registered in a given deployment.
@app.route('/api/containers/<int:cid>', methods=['DELETE', 'OPTIONS'], strict_slashes=False)
def containers_delete_fallback(cid):
    # CORS preflight
    if request.method == 'OPTIONS':
        return ("", 204)
    # Auth: allow API key or require admin JWT
    if not has_valid_api_key():
        try:
            verify_jwt_in_request(optional=False)
        except Exception:
            return jsonify({'error': 'Unauthorized'}), 401
        claims = get_jwt()
        if (claims or {}).get('role') != 'admin':
            return jsonify({'error': 'Admin only'}), 403
    c = Container.query.get(cid)
    if not c:
        return jsonify({'error': 'Not found'}), 404
    # Best-effort remove files and DB row
    try:
        try:
            for f in list(getattr(c, 'files', []) or []):
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], f.filename))
                except Exception:
                    pass
        except Exception:
            pass
        db.session.delete(c)
        db.session.commit()
        try:
            notify(f"Kontejner obrisan (#{cid})", ntype='warning', entity_type='container', entity_id=cid)
            ws_broadcast({
                'type': 'containers.deleted', 'resource': 'containers', 'action': 'deleted',
                'id': int(cid), 'v': 1, 'ts': datetime.utcnow().isoformat() + 'Z',
            })
        except Exception:
            pass
        return jsonify({'ok': True, 'deleted_id': cid}), 200
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        return jsonify({'error': 'delete_failed', 'detail': str(e)}), 500

# Also provide POST-based deletion endpoints for environments where DELETE is blocked.
@app.route('/api/containers/delete', methods=['POST', 'OPTIONS'], strict_slashes=False)
def containers_delete_via_post():
    # CORS preflight
    if request.method == 'OPTIONS':
        return ("", 204)
    data = request.get_json(silent=True) or {}
    try:
        cid = int(data.get('id') or 0)
    except Exception:
        cid = 0
    if not cid:
        return jsonify({'error': 'id_required'}), 400
    # Delegate to the fallback implementation (auth + delete logic)
    return containers_delete_fallback(cid)

@app.route('/api/containers/bulk-delete', methods=['POST', 'OPTIONS'], strict_slashes=False)
def containers_bulk_delete_via_post():
    if request.method == 'OPTIONS':
        return ("", 204)
    data = request.get_json(silent=True) or {}
    ids = data.get('ids') or []
    if not isinstance(ids, list) or not ids:
        return jsonify({'error': 'ids_required'}), 400
    deleted = []
    failed = []
    for cid in ids:
        try:
            resp = containers_delete_fallback(int(cid))
            # containers_delete_fallback returns a Flask Response; check status_code
            if isinstance(resp, tuple):
                body, status = resp[0], resp[1]
            else:
                body, status = resp, getattr(resp, 'status_code', 200)
            if status == 200:
                deleted.append(int(cid))
            else:
                failed.append(int(cid))
        except Exception:
            failed.append(int(cid))
    return jsonify({'ok': True, 'deleted_ids': deleted, 'failed_ids': failed})

# (compat redirect no longer needed; POST handled above)

## Notifications: legacy synthesized endpoints removed in favor of blueprint at /api/notifications

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
        notify('Greška pri importu: pandas nije instaliran', ntype='error', entity_type='container_import')
        return jsonify({'error': 'pandas not installed on server', 'detail': str(e)}), 500

    # Parse the file into a DataFrame (with smart header detection)
    def _read_with_smart_header_excel(file_like):
        # First try default
        try:
            df1 = pd.read_excel(file_like)
            return df1
        except Exception:
            pass
        # Fallback: detect header row by scanning first 12 rows
        try:
            try:
                file_like.stream.seek(0)
            except Exception:
                pass
            df0 = pd.read_excel(file_like, header=None)
            header_idx = None
            tokens = ('total', 'ukupno', 'deposit', 'depozit', 'balance', 'balans', 'cijena', 'price')
            for i in range(min(12, len(df0.index))):
                row = [str(x).strip().lower() for x in (df0.iloc[i] or []).tolist()]
                if any(any(t in cell for t in tokens) for cell in row):
                    header_idx = i
                    break
            if header_idx is not None:
                try:
                    file_like.stream.seek(0)
                except Exception:
                    pass
                return pd.read_excel(file_like, header=header_idx)
        except Exception:
            pass
        # Last resort
        try:
            file_like.stream.seek(0)
        except Exception:
            pass
        return pd.read_excel(file_like)

    def _read_with_smart_header_csv(file_like):
        # Default read
        try:
            return pd.read_csv(file_like)
        except Exception:
            pass
        # Fallback latin-1
        try:
            try:
                file_like.stream.seek(0)
            except Exception:
                pass
            return pd.read_csv(file_like, encoding='latin-1')
        except Exception:
            pass
        # Header auto-detect
        try:
            try:
                file_like.stream.seek(0)
            except Exception:
                pass
            df0 = pd.read_csv(file_like, header=None)
            header_idx = None
            tokens = ('total', 'ukupno', 'deposit', 'depozit', 'balance', 'balans', 'cijena', 'price')
            for i in range(min(12, len(df0.index))):
                row = [str(x).strip().lower() for x in (df0.iloc[i] or []).tolist()]
                if any(any(t in cell for t in tokens) for cell in row):
                    header_idx = i
                    break
            if header_idx is not None:
                try:
                    file_like.stream.seek(0)
                except Exception:
                    pass
                return pd.read_csv(file_like, header=header_idx)
        except Exception:
            pass
        # give up
        try:
            file_like.stream.seek(0)
        except Exception:
            pass
        return pd.read_csv(file_like, errors='ignore')

    try:
        if ext in ('.xlsx', '.xls'):
            df = _read_with_smart_header_excel(f)
        elif ext == '.csv':
            df = _read_with_smart_header_csv(f)
        else:
            return jsonify({'error': 'Unsupported file type. Use .xlsx, .xls or .csv'}), 415
        # Validate that header row contains expected tokens; otherwise re-read with detection
        def _has_tokens(columns):
            cols_l = [str(c).strip().lower() for c in columns]
            tokens = ('total', 'ukupno', 'deposit', 'depozit', 'balance', 'balans', 'cijena', 'price')
            return any(any(t in c for t in tokens) for c in cols_l)
        if not _has_tokens(df.columns):
            try:
                # Try again with explicit detection (Excel)
                if ext in ('.xlsx', '.xls'):
                    try:
                        f.stream.seek(0)
                    except Exception:
                        pass
                    df = _read_with_smart_header_excel(f)
                elif ext == '.csv':
                    try:
                        f.stream.seek(0)
                    except Exception:
                        pass
                    df = _read_with_smart_header_csv(f)
            except Exception:
                pass
    except Exception as e:
        notify(f"Greška pri importu: {str(e)}", ntype='error', entity_type='container_import')
        return jsonify({'error': 'Failed to read file', 'detail': str(e)}), 400

    # If inspect requested, return detected columns and first rows
    if (request.args.get('inspect') or '').strip() == '1':
        cols = [str(c).strip() for c in df.columns]
        try:
            preview = df.head(5).astype(str).to_dict(orient='records')
        except Exception:
            preview = []
        return jsonify({'ok': True, 'columns': cols, 'preview': preview}), 200

    # Normalize headers (lowercase, trimmed)
    df.columns = [str(c).strip().lower() for c in df.columns]

    def pick(row, *aliases, default=""):
        # exact match first
        for a in aliases:
            if a in row and pd.notna(row[a]):
                return row[a]
        # fuzzy: normalize tokens and column names (remove spaces, nbsp, punctuation)
        try:
            import re
            cols = list(row.index)
            def norm(s: str) -> str:
                s = (s or '').lower().replace('\u00a0',' ').replace('(eur)','')
                s = re.sub(r'[^a-z0-9]+', '', s)
                return s
            norm_aliases = [norm(str(a)) for a in aliases]
            for c in cols:
                cc = norm(str(c))
                for ta in norm_aliases:
                    if ta and (ta in cc or cc in ta):
                        val = row[c]
                        if pd.notna(val):
                            return val
        except Exception:
            pass
        return default

    def to_number(v, default=0.0):
        try:
            s = str(v).strip()
            if not s:
                return default
            # remove currency and keep only digits and separators
            allowed = set('0123456789.,- ')
            s = ''.join(ch for ch in s if ch in allowed)
            s = s.replace('\u00A0', ' ')
            # If both separators exist, decide decimal by the right‑most separator
            if ',' in s and '.' in s:
                if s.rfind('.') > s.rfind(','):
                    # US style: comma thousands, dot decimal
                    s = s.replace(',', '')
                else:
                    # EU style: dot thousands, comma decimal
                    s = s.replace('.', '').replace(',', '.')
            else:
                # Single separator present – if comma, treat as decimal comma
                if ',' in s:
                    s = s.replace(',', '.')
                else:
                    s = s  # dot or none → already fine
            s = s.replace(' ', '')
            return float(s)
        except Exception:
            return default

    created, updated, errors = 0, 0, []

    # Iterate from bottom to top so that the first row in the file
    # (typically the highest 'redni broj') is created last and receives
    # the highest auto-increment ID. With default sort id DESC, the list
    # will display in the same order as the file (highest → lowest).
    for idx in reversed(df.index):
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
            contain_price= pick(df.loc[idx], 'cijena (eur)', 'cijena', 'cena', 'price', 'contain_price')
            agent        = pick(df.loc[idx], 'agent')
            total        = pick(df.loc[idx], 'total (eur)', 'total', 'ukupno')
            deposit      = pick(df.loc[idx], 'depozit (eur)', 'deposit', 'depozit')
            balance      = pick(df.loc[idx], 'balans (eur)', 'balance', 'balans')
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
            # Cijena (EUR) rule: if empty -> '0,00', else keep original value
            _cijena_raw = str(pick(df.loc[idx], 'contain_price', 'cijena', 'price') or '')
            _cijena_val = '0,00' if _cijena_raw.strip() == '' else _cijena_raw

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
                contain_price=_cijena_val,
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
        notify(f"Greška pri importu (DB): {str(e)}", ntype='error', entity_type='container_import')
        return jsonify({'error': 'DB commit failed', 'detail': str(e), 'created': created, 'errors': errors}), 500

    # Success summary
    try:
        if errors:
            notify(f"Import završen: {created} kreirano, {updated} ažurirano, {len(errors)} grešaka", ntype='warning', entity_type='container_import')
        else:
            notify(f"Import završen: {created} kreirano, {updated} ažurirano", ntype='success', entity_type='container_import')
    except Exception:
        pass

    return jsonify({'ok': True, 'created': created, 'updated': updated, 'errors': errors}), 201

# Import containers from an existing file on the server (UPLOAD_FOLDER)
@app.post('/api/containers/admin/import-local')
def import_containers_local():
    # Auth guard: admin or API key
    ok, role, uid, err = check_api_or_jwt({'import'})
    if not ok:
        return err
    if role != 'admin' and not has_valid_api_key():
        return jsonify({'error': 'Admin only'}), 403

    name = (request.args.get('name') or request.json.get('name') if request.is_json else None) or ''
    name = (name or '').strip()
    if not name:
        return jsonify({'error':'name_required','hint':'?name=filename.xlsx'}), 400
    path = os.path.join(app.config['UPLOAD_FOLDER'], name)
    if not os.path.exists(path):
        return jsonify({'error':'not_found','path': name}), 404

    try:
        import pandas as pd
    except Exception as e:
        return jsonify({'error':'pandas_missing','detail':str(e)}), 500

    try:
        ext = os.path.splitext(path)[1].lower()
        if ext in ('.xlsx', '.xls'):
            # smart header detect from file path
            try:
                df = pd.read_excel(path)
            except Exception:
                df0 = pd.read_excel(path, header=None)
                header_idx = None
                tokens = ('total', 'ukupno', 'deposit', 'depozit', 'balance', 'balans', 'cijena', 'price')
                for i in range(min(12, len(df0.index))):
                    row = [str(x).strip().lower() for x in (df0.iloc[i] or []).tolist()]
                    if any(any(t in cell for t in tokens) for cell in row):
                        header_idx = i
                        break
                if header_idx is not None:
                    df = pd.read_excel(path, header=header_idx)
                else:
                    df = pd.read_excel(path)
        elif ext == '.csv':
            try:
                df = pd.read_csv(path)
            except UnicodeDecodeError:
                df = pd.read_csv(path, encoding='latin-1')
            except Exception:
                df0 = pd.read_csv(path, header=None)
                header_idx = None
                tokens = ('total', 'ukupno', 'deposit', 'depozit', 'balance', 'balans', 'cijena', 'price')
                for i in range(min(12, len(df0.index))):
                    row = [str(x).strip().lower() for x in (df0.iloc[i] or []).tolist()]
                    if any(any(t in cell for t in tokens) for cell in row):
                        header_idx = i
                        break
                if header_idx is not None:
                    df = pd.read_csv(path, header=header_idx)
        else:
            return jsonify({'error':'unsupported','detail':'Use .xlsx/.xls/.csv'}), 415
    except Exception as e:
        return jsonify({'error':'read_failed','detail': str(e)}), 400

    # Optional inspect mode: return detected columns and first rows (strings)
    if (request.args.get('inspect') or '').strip() == '1':
        cols = [str(c).strip() for c in df.columns]
        try:
            head = df.head(5).astype(str).to_dict(orient='records')
        except Exception:
            head = []
        return jsonify({'ok': True, 'columns': cols, 'preview': head}), 200

    # Reuse the same normalization helpers from import_containers
    df.columns = [str(c).strip().lower() for c in df.columns]

    def pick(row, *aliases, default=""):
        import pandas as pd, re
        # exact
        for a in aliases:
            if a in row and pd.notna(row[a]):
                return row[a]
        # fuzzy normalized
        try:
            cols = list(row.index)
            def norm(s: str) -> str:
                s = (s or '').lower().replace('\u00a0',' ').replace('(eur)','')
                s = re.sub(r'[^a-z0-9]+', '', s)
                return s
            norm_aliases = [norm(str(a)) for a in aliases]
            for c in cols:
                cc = norm(str(c))
                for ta in norm_aliases:
                    if ta and (ta in cc or cc in ta):
                        val = row[c]
                        if pd.notna(val):
                            return val
        except Exception:
            pass
        return default

    created, updated, errors = 0, 0, []
    # Create from bottom to top so highest row in file ends up with highest DB id
    for idx in reversed(df.index):
        try:
            supplier     = pick(df.loc[idx], 'supplier', 'dobavljač', 'dobavljac')
            proforma_no  = pick(df.loc[idx], 'proforma', 'proforma no', 'proforma_no')
            etd_s        = pick(df.loc[idx], 'etd')
            delivery_s   = pick(df.loc[idx], 'delivery')
            eta_s        = pick(df.loc[idx], 'eta')
            cargo_qty    = pick(df.loc[idx], 'qty', 'količina', 'kolicina', default="")
            cargo        = pick(df.loc[idx], 'tip', 'cargo', 'type')
            container_no = pick(df.loc[idx], 'kontejner', 'container', 'container no', 'container_no')
            roba         = pick(df.loc[idx], 'roba', 'goods', 'product')
            contain_price= pick(df.loc[idx], 'contain_price', 'cijena', 'price')
            agent        = pick(df.loc[idx], 'agent')
            total        = pick(df.loc[idx], 'total', 'total (eur)', 'ukupno')
            deposit      = pick(df.loc[idx], 'deposit', 'depozit')
            balance      = pick(df.loc[idx], 'balance', 'balans')
            paid_raw     = pick(df.loc[idx], 'paid', 'plaćeno', 'placeno', 'status', 'placeno', 'placenje')

            def to_number_local(v):
                return to_number(v, 0.0)
            total_f   = to_number_local(total)
            deposit_f = to_number_local(deposit)
            balance_f = to_number_local(balance) if str(balance).strip() != '' else (total_f - deposit_f)

            paid = False
            if isinstance(paid_raw, bool):
                paid = paid_raw
            else:
                s = str(paid_raw).strip().lower()
                paid = s in ('1','true','yes','y','da','paid','plaćeno','placeno')
            if paid:
                balance_f = 0.0

            # Cijena (EUR) rule: if empty -> '0,00', else keep original value
            _cijena_raw = str(contain_price or '')
            _cijena_val = '0,00' if _cijena_raw.strip() == '' else _cijena_raw

            rec = Container(
                supplier=str(supplier or ''),
                proforma_no=str(proforma_no or ''),
                etd=_parse_date_any(str(etd_s) if etd_s is not None else None),
                delivery=_parse_date_any(str(delivery_s) if delivery_s is not None else None),
                eta=_parse_date_any(str(eta_s) if eta_s is not None else None),
                cargo_qty=str(cargo_qty or ''),
                cargo=str(cargo or ''),
                container_no=str(container_no or ''),
                roba=str(roba or ''),
                contain_price=_cijena_val,
                agent=str(agent or ''),
                total=f"{total_f:.2f}",
                deposit=f"{deposit_f:.2f}",
                balance=f"{balance_f:.2f}",
                paid=bool(paid),
            )
            db.session.add(rec)
            created += 1
        except Exception as e:
            errors.append({'row': int(idx) + 2, 'error': str(e)})

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
    try:
        u.password_hash = generate_password_hash(ADMIN_PASSWORD)
        if hasattr(u, 'password'):
            u.password = None
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
                # Late arrivals based on ETA (string field): ETA < today and not arrived
                try:
                    today = datetime.utcnow().date()
                    # Fetch recent arrivals to limit work
                    recent_arrivals = db.session.query(Arrival).order_by(Arrival.created_at.desc()).limit(200).all()
                    for a in recent_arrivals:
                        try:
                            if getattr(a, 'status', None) == 'arrived':
                                continue
                            eta_s = getattr(a, 'eta', None)
                            if not eta_s:
                                continue
                            eta_date = _parse_date_any(eta_s)
                            if not eta_date:
                                continue
                            if eta_date < today:
                                # Prevent spamming: skip if we already have a warning for this arrival
                                existing = (
                                    db.session.query(Notification)
                                    .filter(
                                        Notification.entity_type == 'arrival',
                                        Notification.entity_id == a.id,
                                        Notification.type == 'warning'
                                    )
                                    .first()
                                )
                                if not existing:
                                    notify(f"Dolazak kasni (#{a.id})", ntype='warning', entity_type='arrival', entity_id=a.id)
                        except Exception:
                            continue
                except Exception as _late_err:
                    print('[SLA LOOP] late-arrivals scan error:', _late_err)
                # Late containers based on ETA (date field): ETA < today and not arrived/delivered
                try:
                    today = datetime.utcnow().date()
                    recent_containers = db.session.query(Container).order_by(Container.created_at.desc()).limit(200).all()
                    for c in recent_containers:
                        try:
                            # arrived if arrived_at set or explicit status
                            status = (getattr(c, 'status', '') or '').lower()
                            if status in ('arrived','delivered','received') or getattr(c, 'arrived_at', None):
                                continue
                            eta = getattr(c, 'eta', None)
                            if not eta:
                                continue
                            # c.eta is a date already
                            if eta < today:
                                existing = (
                                    db.session.query(Notification)
                                    .filter(
                                        Notification.entity_type == 'container',
                                        Notification.entity_id == c.id,
                                        Notification.type == 'warning'
                                    )
                                    .first()
                                )
                                if not existing:
                                    notify(f"Kontejner kasni (#{c.id})", ntype='warning', entity_type='container', entity_id=c.id)
                        except Exception:
                            continue
                except Exception as _late2_err:
                    print('[SLA LOOP] late-containers scan error:', _late2_err)
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

# Enterprise users API (RBAC, sessions, audit)
_register_blueprint(["routes.users_enterprise", "routes.enterprise_users"], label="enterprise_users")

# Arrivals blueprint
_register_blueprint(["routes.arrivals", "arrivals"], label="arrivals")

# Containers blueprint
# The 'containers' blueprint in containers.py already defines url_prefix='/api/containers'.
# Register without forcing an extra prefix to avoid '/api/containers/api/containers'.
_register_blueprint(["routes.containers", "containers"], label="containers")


# Files blueprint
_register_blueprint(["routes.files", "files"], label="files")

# Notifications blueprint
_register_blueprint(["routes.notifications", "notifications"], label="notifications")

# Analytics blueprint (new). Try module paths, then add safe fallbacks for key routes.
_register_blueprint(["routes.analytics", "analytics", "analytics"], label="analytics")
def _has_get_for(path: str) -> bool:
    try:
        for r in app.url_map.iter_rules():
            if str(r) == path and ('GET' in (r.methods or set())):
                return True
    except Exception:
        pass
    return False

try:
    from analytics import (
        arrivals_kpi as _an_kpi,
        arrivals_trend_costs as _an_trend,
        arrivals_cost_structure as _an_struct,
        arrivals_list_filtered as _an_list,
        arrivals_top_suppliers as _an_top,
        arrivals_on_time as _an_ontime,
        arrivals_lead_time as _an_lead,
        arrivals_lookups as _an_lookups,
        containers_kpi as _c_kpi,
        containers_trend_amounts as _c_trend,
        containers_cost_structure as _c_struct,
        containers_top_suppliers as _c_top,
        containers_lookups as _c_lookups,
        costs_series as _costs_series,
        arrivals_trend_status as _arr_trend_status,
    )
    # Add minimal wrappers if GET not present
    if not _has_get_for('/api/analytics/arrivals/kpi'):
        @app.get('/api/analytics/arrivals/kpi')
        def _an_kpi_fallback():
            return _an_kpi()
    if not _has_get_for('/api/analytics/arrivals/trend-costs'):
        @app.get('/api/analytics/arrivals/trend-costs')
        def _an_trend_fallback():
            return _an_trend()
    if not _has_get_for('/api/analytics/arrivals/cost-structure'):
        @app.get('/api/analytics/arrivals/cost-structure')
        def _an_struct_fallback():
            return _an_struct()
    if not _has_get_for('/api/analytics/arrivals/list'):
        @app.get('/api/analytics/arrivals/list')
        def _an_list_fallback():
            return _an_list()
    if not _has_get_for('/api/analytics/arrivals/top-suppliers'):
        @app.get('/api/analytics/arrivals/top-suppliers')
        def _an_top_fallback():
            return _an_top()
    if not _has_get_for('/api/analytics/arrivals/on-time'):
        @app.get('/api/analytics/arrivals/on-time')
        def _an_ontime_fallback():
            return _an_ontime()
    if not _has_get_for('/api/analytics/arrivals/lead-time'):
        @app.get('/api/analytics/arrivals/lead-time')
        def _an_lead_fallback():
            return _an_lead()
    if not _has_get_for('/api/analytics/arrivals/lookups'):
        @app.get('/api/analytics/arrivals/lookups')
        def _an_lookups_fallback():
            return _an_lookups()
    if not _has_get_for('/api/analytics/costs/series'):
        @app.get('/api/analytics/costs/series')
        def _costs_series_fallback():
            return _costs_series()
    if not _has_get_for('/api/analytics/arrivals/trend'):
        @app.get('/api/analytics/arrivals/trend')
        def _arr_trend_status_fallback():
            return _arr_trend_status()
    # Containers fallbacks
    if not any(str(r) == '/api/analytics/containers/kpi' for r in app.url_map.iter_rules()):
        @app.get('/api/analytics/containers/kpi')
        def _c_kpi_fallback():
            return _c_kpi()
    if not any(str(r) == '/api/analytics/containers/trend-amounts' for r in app.url_map.iter_rules()):
        @app.get('/api/analytics/containers/trend-amounts')
        def _c_trend_fallback():
            return _c_trend()
    if not any(str(r) == '/api/analytics/containers/cost-structure' for r in app.url_map.iter_rules()):
        @app.get('/api/analytics/containers/cost-structure')
        def _c_struct_fallback():
            return _c_struct()
    if not any(str(r) == '/api/analytics/containers/top-suppliers' for r in app.url_map.iter_rules()):
        @app.get('/api/analytics/containers/top-suppliers')
        def _c_top_fallback():
            return _c_top()
    if not any(str(r) == '/api/analytics/containers/lookups' for r in app.url_map.iter_rules()):
        @app.get('/api/analytics/containers/lookups')
        def _c_lookups_fallback():
            return _c_lookups()
except Exception as _an_err:
    print('[BOOT] analytics fallbacks not installed:', _an_err)

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

@app.get('/_debug/arrivals-methods')
def _debug_arrivals_methods():
    """Inspect and return the methods bound to /api/arrivals and related paths.
    Useful to verify POST availability after deploy.
    """
    try:
        targets = [
            '/api/arrivals',
            '/api/arrivals/',
            '/api/arrivals/create',
        ]
        found = []
        for r in app.url_map.iter_rules():
            rule = str(r)
            if rule in targets:
                methods = sorted(m for m in r.methods if m not in ("HEAD", "OPTIONS"))
                found.append({
                    'rule': rule,
                    'endpoint': r.endpoint,
                    'methods': methods,
                })
        # Also include a quick WS availability hint
        ws_ok = any(str(r) == '/ws' for r in app.url_map.iter_rules())
        return jsonify({'arrivals_endpoints': found, 'ws_enabled': ws_ok}), 200
    except Exception as e:
        return jsonify({'error': 'introspect_failed', 'detail': str(e)}), 500

# --- Health ---
@app.route('/health', methods=['GET', 'HEAD', 'OPTIONS'], strict_slashes=False)
def health():
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

    result = {
        'ok': False,
        'db_ok': False,
        'db_revision': None,
        'repo_heads': [],
        'is_at_head': None,
    }
    status = 200
    # DB connectivity check
    try:
        db.session.execute(text('SELECT 1'))
        result['db_ok'] = True
    except Exception as e:
        result['db_error'] = str(e)
        status = 500

    # DB alembic revision
    try:
        row = db.session.execute(text('SELECT version_num FROM alembic_version'))
        row = row.first()
        if row:
            result['db_revision'] = row[0]
    except Exception as e:
        result['db_revision_error'] = str(e)

    # Repo heads (best-effort)
    try:
        from alembic.config import Config as _AConfig
        from alembic.script import ScriptDirectory as _AScript
        cfg_path = os.path.join(os.path.dirname(__file__), 'alembic.ini')
        acfg = _AConfig(cfg_path)
        script = _AScript.from_config(acfg)
        heads = list(script.get_heads())
        result['repo_heads'] = heads
        if result['db_revision'] is not None:
            result['is_at_head'] = (result['db_revision'] in heads)
    except Exception as e:
        result['repo_error'] = str(e)

    # Overall ok if DB is reachable
    result['ok'] = bool(result['db_ok'])
    if not result['ok']:
        status = 500
    return jsonify(result), status

# --- SSO stubs ---
@app.get('/auth/sso/google')
def sso_google():
    # Placeholder: redirect back to login with a hint
    return redirect('/login?provider=google', code=307)

@app.get('/auth/sso/microsoft')
def sso_ms():
    return redirect('/login?provider=microsoft', code=307)

# --- MFA stubs ---
@app.post('/auth/mfa/challenge')
def mfa_challenge():
    # In a real impl, you would send an OTP (email/app) and return a challenge_id
    return jsonify({'ok': True, 'challenge_id': 'demo'}), 200

@app.post('/auth/mfa/verify')
def mfa_verify():
    data = request.get_json(silent=True) or {}
    code = str(data.get('code', '')).strip()
    # Demo accept any 6+ length numeric-ish code
    if not code or len(code) < 4:
      return jsonify({'error': 'invalid_code'}), 401
    # Issue a short-lived token
    token = create_access_token(identity=1, additional_claims={'role': 'admin', 'email': 'demo@arrivals.local'})
    return jsonify({'access_token': token, 'user': {'id': 1, 'email': 'demo@arrivals.local', 'name': 'Demo Admin', 'role': 'admin'}})

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
        # Ensure Notification.role column exists (soft migration for existing DBs)
        try:
            from sqlalchemy import inspect as _inspect
            insp = _inspect(db.engine)
            cols = [c['name'] for c in insp.get_columns('notifications')]
            if 'role' not in cols:
                try:
                    db.session.execute(text("ALTER TABLE notifications ADD COLUMN role VARCHAR(64)"))
                    db.session.commit()
                    print('[BOOTSTRAP] Added notifications.role column')
                except Exception as e2:
                    print('[BOOTSTRAP] Could not add notifications.role:', e2)
        except Exception as e:
            print('[BOOTSTRAP] Inspector error for notifications:', e)
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

    
# Fallback admin endpoints for containers maintenance (wipe/export) if blueprint didn't register them
try:
    if not any(str(r) == '/api/containers/admin/wipe' and ('POST' in (r.methods or set())) for r in app.url_map.iter_rules()):
        @app.post('/api/containers/admin/wipe')
        def _containers_admin_wipe_fallback():
            ok, role, uid, err = check_api_or_jwt({'wipe'})
            if not ok:
                return err
            if role != 'admin':
                return jsonify({'error':'Forbidden'}), 403
            confirm = (request.args.get('confirm') or '').lower() in ('yes','y','true','1')
            if not confirm:
                return jsonify({'error':'confirm_required','hint':'POST /api/containers/admin/wipe?confirm=yes'}), 400
            try:
                db.session.execute(text('TRUNCATE TABLE container_files, containers RESTART IDENTITY CASCADE'))
                db.session.commit()
                return jsonify({'ok': True, 'message': 'All containers deleted and IDs reset'}), 200
            except Exception as e:
                db.session.rollback()
                try:
                    ContainerFile.query.delete(); Container.query.delete(); db.session.commit()
                    return jsonify({'ok': True, 'message': 'All containers deleted (fallback).'}), 200
                except Exception as e2:
                    db.session.rollback(); return jsonify({'error':'wipe_failed','detail':str(e2)}), 500
    if not any(str(r) == '/api/containers/admin/export' and ('GET' in (r.methods or set())) for r in app.url_map.iter_rules()):
        @app.get('/api/containers/admin/export')
        def _containers_admin_export_fallback():
            ok, role, uid, err = check_api_or_jwt({'export'})
            if not ok:
                return err
            if role != 'admin':
                return jsonify({'error':'Forbidden'}), 403
            rows = Container.query.order_by(Container.id.asc()).all()
            return jsonify({'count': len(rows), 'items': [c.to_dict() for c in rows]})
    if not any(str(r) == '/api/containers/admin/duplicates' and ('GET' in (r.methods or set())) for r in app.url_map.iter_rules()):
        @app.get('/api/containers/admin/duplicates')
        def _containers_admin_duplicates_fallback():
            ok, role, uid, err = check_api_or_jwt({'duplicates'})
            if not ok:
                return err
            if role != 'admin':
                return jsonify({'error':'Forbidden'}), 403
            try:
                year = int(request.args.get('year') or 0)
            except Exception:
                year = 0
            if not year:
                return jsonify({'error':'year_required'}), 400
            field = (request.args.get('date_field') or 'etd').strip().lower()
            keys_raw = (request.args.get('keys') or 'container_no,supplier').strip()
            key_names = [k.strip() for k in keys_raw.split(',') if k.strip()]
            # pick date column
            # build in-Python filter to avoid type mismatch issues
            y_from = f"{year}-01-01"; y_to = f"{year}-12-31"
            cols = []
            for k in key_names:
                if hasattr(Container, k):
                    cols.append(getattr(Container, k))
            if not cols:
                return jsonify({'error':'invalid_keys'}), 400
            # Do aggregation in Python to handle types robustly
            rows = db.session.query(Container).all()
            groups = {}
            def _m2n(v):
                try:
                    s = ''.join(ch for ch in str(v) if ch.isdigit() or ch in ',.-')
                    if ',' in s and '.' not in s:
                        s = s.replace(',', '.')
                    return float(s or 0)
                except Exception:
                    return 0.0
            def _date_in_year(c):
                try:
                    if field == 'etd' and getattr(c,'etd',None):
                        s = str(c.etd); return s[:4] == str(year)
                    if field == 'eta' and getattr(c,'eta',None):
                        s = str(c.eta); return s[:4] == str(year)
                    if field == 'delivery' and getattr(c,'delivery',None):
                        s = str(c.delivery); return s[:4] == str(year)
                    s = str(getattr(c, 'created_at', '') or '')
                    return s[:4] == str(year)
                except Exception:
                    return False
            for c in rows:
                if not _date_in_year(c):
                    continue
                key = tuple((getattr(c, k) if hasattr(c,k) else None) for k in key_names)
                g = groups.setdefault(key, {'count': 0, 'total_sum': 0.0})
                g['count'] += 1
                g['total_sum'] += _m2n(getattr(c, 'total', 0))
            out = []
            for key, g in groups.items():
                if g['count'] > 1:
                    rec = {'count': g['count'], 'total_sum': g['total_sum']}
                    for i, k in enumerate(key_names):
                        rec[k] = key[i]
                    out.append(rec)
            return jsonify({'year': year, 'date_field': field, 'keys': key_names, 'groups': out, 'groups_count': len(out)})
except Exception as _adm_err:
    print('[BOOT] containers admin fallbacks not installed:', _adm_err)
