from flask import Flask, request, jsonify, send_from_directory
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

from mailer import maybe_notify_paid

load_dotenv()

app = Flask(__name__)

ALLOWED_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]

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
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///arrivals.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'change-me-dev')
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

upload_dir_env = os.environ.get('UPLOAD_DIR') or os.environ.get('UPLOAD_FOLDER')
app.config['UPLOAD_FOLDER'] = upload_dir_env or os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Limit upload size via env (default 16 MB)
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_UPLOAD_MB', '16')) * 1024 * 1024

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

jwt = JWTManager(app)

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

db = SQLAlchemy(app)

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

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(120))
    role = db.Column(db.String(32), default='viewer')  # admin, planer, proizvodnja, transport, carina, viewer
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password_hash, raw)

class ArrivalUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    arrival_id = db.Column(db.Integer, db.ForeignKey('arrival.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ArrivalFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    arrival_id = db.Column(db.Integer, db.ForeignKey('arrival.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- ContainerFile model ---
class ContainerFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    container_id = db.Column(db.Integer, db.ForeignKey('containers.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Arrival(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    supplier = db.Column(db.String(120), nullable=False)
    carrier = db.Column(db.String(120))
    plate = db.Column(db.String(32))
    driver = db.Column(db.String(120))            # name of the driver (Šofer)
    pickup_date = db.Column(db.DateTime)          # datum za podizanje robe
    type = db.Column(db.String(32), default="truck")
    eta = db.Column(db.String(32))
    status = db.Column(db.String(32), default="announced")
    note = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Workflow/plan fields
    order_date = db.Column(db.DateTime)             # datum narudžbe
    production_due = db.Column(db.DateTime)         # rok završetka proizvodnje
    shipped_at = db.Column(db.DateTime)             # datum kad je poslano
    arrived_at = db.Column(db.DateTime)             # datum kad je stiglo

    # Finansije / carina
    customs_info = db.Column(db.Text)
    freight_cost = db.Column(db.Float)
    goods_cost = db.Column(db.Float)              # cijena robe
    customs_cost = db.Column(db.Float)
    currency = db.Column(db.String(8), default='EUR')
    # Odgovorna osoba i lokacija
    responsible = db.Column(db.String(120))
    location = db.Column(db.String(120))

    # Asignacija i notifikacija
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    production_overdue_notified = db.Column(db.Boolean, default=False)

    updates = relationship('ArrivalUpdate', backref='arrival', cascade='all, delete-orphan')
    files = relationship('ArrivalFile', backref='arrival', cascade='all, delete-orphan')

    def progress_and_overdue(self):
        """
        Progres od order_date do production_due.
        """
        if not self.order_date or not self.production_due:
            return 0, None, False
        now = datetime.now(timezone.utc)
        # Pohranili smo kao naive? Pokušaj tretirati kao naive u UTC
        start = self.order_date.replace(tzinfo=timezone.utc) if self.order_date.tzinfo is None else self.order_date
        end = self.production_due.replace(tzinfo=timezone.utc) if self.production_due.tzinfo is None else self.production_due
        total = (end - start).total_seconds()
        done = (now - start).total_seconds()
        pct = 0 if total <= 0 else max(0, min(100, int((done / total) * 100)))
        days_left = int((end - now).total_seconds() // 86400)
        overdue = now > end
        return pct, days_left, overdue

    def to_dict(self):
        pct, days_left, overdue = self.progress_and_overdue()
        return {
            'id': self.id,
            'supplier': self.supplier,
            'carrier': self.carrier,
            'plate': self.plate,
            'driver': self.driver,
            'pickup_date': self.pickup_date.isoformat() if self.pickup_date else None,
            'type': self.type,
            'eta': self.eta,
            'status': self.status,
            'note': self.note,
            'created_at': self.created_at.isoformat(),
            'order_date': self.order_date.isoformat() if self.order_date else None,
            'production_due': self.production_due.isoformat() if self.production_due else None,
            'shipped_at': self.shipped_at.isoformat() if self.shipped_at else None,
            'arrived_at': self.arrived_at.isoformat() if self.arrived_at else None,
            'customs_info': self.customs_info,
            'freight_cost': self.freight_cost,
            'goods_cost': self.goods_cost,
            'customs_cost': self.customs_cost,
            'currency': self.currency,
            'responsible': (self.responsible or ''),
            'location': (self.location or ''),
            'assignee_id': self.assignee_id,
            'progress': pct,
            'days_left': days_left,
            'overdue': overdue,
            'files_count': (len(self.files) if getattr(self, 'files', None) is not None else 0),
        }

# --- Container model ---
class Container(db.Model):
    __tablename__ = "containers"
    id = db.Column(db.Integer, primary_key=True)

    supplier = db.Column(db.String(255), default="")
    proforma_no = db.Column(db.String(255), default="")

    etd = db.Column(db.Date, nullable=True)
    delivery = db.Column(db.Date, nullable=True)
    eta = db.Column(db.Date, nullable=True)

    cargo_qty = db.Column(db.String(64), default="")
    cargo = db.Column(db.String(255), default="")
    container_no = db.Column(db.String(128), default="")
    roba = db.Column(db.String(255), default="")
    contain_price = db.Column(db.String(64), default="")
    agent = db.Column(db.String(128), default="")

    total = db.Column(db.String(64), default="")
    deposit = db.Column(db.String(64), default="")
    balance = db.Column(db.String(64), default="")
    paid = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    files = relationship('ContainerFile', backref='container', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            "id": self.id,
            "supplier": self.supplier or "",
            "proformaNo": self.proforma_no or "",
            "etd": self.etd.isoformat() if self.etd else "",
            "delivery": self.delivery.isoformat() if self.delivery else "",
            "eta": self.eta.isoformat() if self.eta else "",
            "cargoQty": self.cargo_qty or "",
            "cargo": self.cargo or "",
            "containerNo": self.container_no or "",
            "roba": self.roba or "",
            "containPrice": self.contain_price or "",
            "agent": self.agent or "",
            "total": self.total or "",
            "deposit": self.deposit or "",
            "balance": self.balance or "",
            "placeno": bool(self.paid),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

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
@app.route('/', methods=['GET'])
def health():
    return jsonify({"ok": True, "routes": ["/api/arrivals","/api/containers","/auth/login"]})

# Simple health endpoint for CLI checks and uptime probes
@app.route('/health', methods=['GET', 'HEAD', 'OPTIONS'])
def health_route():
    if request.method == 'OPTIONS':
        return ("", 204)
    return jsonify({"ok": True})

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


# --- Auth ---
@app.route('/auth/login', methods=['POST'])
def auth_login():
    data = request.json or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401

    identity = str(user.id)  # must be string
    claims = {'email': user.email, 'name': user.name, 'role': user.role}
    token = create_access_token(identity=identity, additional_claims=claims)
    return jsonify({'access_token': token, 'user': {'id': user.id, 'email': user.email, 'name': user.name, 'role': user.role}})

# --- Legacy compatibility routes (old frontend paths) ---
# Some older clients may POST to /login instead of /auth/login.
# This forwards those requests to the same handler to avoid 405 errors.
@app.route('/login', methods=['POST', 'OPTIONS'])
def legacy_login():
    if request.method == 'OPTIONS':
        # Preflight handled here explicitly, though global handler also covers it
        return ("", 204)
    return auth_login()

# Some older clients may call GET /me; forward to /auth/me
@app.route('/me', methods=['GET'])
@jwt_required()
def legacy_me():
    return auth_me()

# Refresh endpoint for JWT
@app.route('/auth/refresh', methods=['POST'])
@jwt_required()
def auth_refresh():
    claims = get_jwt() or {}
    uid = get_jwt_identity()
    if uid is None:
        return jsonify({"error": "Unauthorized"}), 401
    new_token = create_access_token(identity=str(uid), additional_claims={
        "email": claims.get("email"),
        "name": claims.get("name"),
        "role": claims.get("role", "viewer"),
    })
    return jsonify({"access_token": new_token})

@app.route('/auth/me', methods=['GET'])
@jwt_required()
def auth_me():
    claims = get_jwt()
    uid = get_jwt_identity()
    user = User.query.get(int(uid))
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'user': {'id': user.id, 'email': claims.get('email', user.email), 'name': claims.get('name', user.name), 'role': claims.get('role', user.role)}})

# Users (admin only)
@app.route('/users', methods=['GET'])
@jwt_required()
def list_users():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    users = User.query.order_by(User.id.asc()).all()
    return jsonify([{'id': u.id, 'email': u.email, 'name': u.name, 'role': u.role} for u in users])

@app.route('/users', methods=['POST'])
@jwt_required()
def create_user():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json or {}
    email = (data.get('email') or '').strip().lower()
    if not email or not data.get('password'):
        return jsonify({'error': 'email and password required'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'email already exists'}), 400
    user = User(email=email, name=data.get('name'), role=data.get('role', 'viewer'))
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'id': user.id, 'email': user.email, 'name': user.name, 'role': user.role}), 201

@app.route('/users/<int:uid>', methods=['DELETE'])
@jwt_required()
def delete_user(uid):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    if int(get_jwt_identity()) == uid:
        return jsonify({'error': "Can't delete yourself"}), 400
    u = User.query.get(uid)
    if not u:
        return jsonify({'error': 'Not found'}), 404
    db.session.delete(u)
    db.session.commit()
    return jsonify({'ok': True})

# Admin: get single user
@app.route('/users/<int:uid>', methods=['GET'])
@jwt_required()
def get_user(uid):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    u = User.query.get(uid)
    if not u:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'id': u.id, 'email': u.email, 'name': u.name, 'role': u.role})

# Admin: update single user
@app.route('/users/<int:uid>', methods=['PATCH'])
@jwt_required()
def update_user(uid):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    u = User.query.get(uid)
    if not u:
        return jsonify({'error': 'Not found'}), 404
    data = request.json or {}
    if 'email' in data and data['email']:
        new_email = data['email'].strip().lower()
        if new_email != u.email and User.query.filter_by(email=new_email).first():
            return jsonify({'error': 'email already exists'}), 400
        u.email = new_email
    if 'name' in data:
        u.name = data['name']
    if 'role' in data:
        u.role = data['role']
    if 'password' in data and data['password']:
        u.set_password(data['password'])
    db.session.commit()
    return jsonify({'id': u.id, 'email': u.email, 'name': u.name, 'role': u.role})

# Arrivals
@app.route('/api/arrivals', methods=['GET'])
def list_arrivals():
    arrivals = Arrival.query.order_by(Arrival.created_at.desc()).all()
    # Precompute file counts for all arrivals in one query (robust & fast)
    counts_map = dict(
        db.session.query(ArrivalFile.arrival_id, func.count(ArrivalFile.id))
        .group_by(ArrivalFile.arrival_id)
        .all()
    )
    results = []
    for a in arrivals:
        d = a.to_dict()
        d["files_count"] = int(counts_map.get(a.id, 0))
        results.append(d)
    return jsonify(results)

@app.route('/api/arrivals/<int:id>', methods=['GET'])
def get_arrival(id):
    a = Arrival.query.get_or_404(id)
    d = a.to_dict()
    d["files_count"] = db.session.query(func.count(ArrivalFile.id)).filter(ArrivalFile.arrival_id == a.id).scalar() or 0
    return jsonify(d)

@app.route('/api/arrivals/search', methods=['GET'])
def search_arrivals():
    try:
        page = int(request.args.get('page', 1))
        # accept both per_page and page_size (frontend sends per_page)
        per_page_raw = request.args.get('per_page', request.args.get('page_size', 20))
        per_page = int(per_page_raw)
        page = max(1, page)
        per_page = min(max(1, per_page), 100)
    except ValueError:
        return jsonify({'error': 'page/per_page must be integers'}), 400

    status = request.args.get('status')
    supplier = request.args.get('supplier')
    q = request.args.get('q')
    from_str = request.args.get('from')
    to_str = request.args.get('to')
    sort = request.args.get('sort', 'created_at')
    order = request.args.get('order', 'desc').lower()

    sort_field_map = {'created_at': Arrival.created_at, 'supplier': Arrival.supplier, 'status': Arrival.status}
    sort_col = sort_field_map.get(sort, Arrival.created_at)
    sort_expr = sort_col.desc() if order != 'asc' else sort_col.asc()
    query = Arrival.query
    if status:
        query = query.filter(Arrival.status == status)
    if supplier:
        query = query.filter(Arrival.supplier.ilike(f"%{supplier}%"))
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Arrival.plate.ilike(like), Arrival.carrier.ilike(like)))

    def parse_dt(val):
        if not val:
            return None
        try:
            return datetime.fromisoformat(val)
        except Exception:
            return None

    from_dt = parse_dt(from_str)
    to_dt = parse_dt(to_str)
    if from_str and not from_dt:
        return jsonify({'error': "Invalid 'from' ISO datetime"}), 400
    if to_str and not to_dt:
        return jsonify({'error': "Invalid 'to' ISO datetime"}), 400
    if from_dt:
        query = query.filter(Arrival.created_at >= from_dt)
    if to_dt:
        query = query.filter(Arrival.created_at <= to_dt)

    total = query.count()
    items = query.order_by(sort_expr).offset((page - 1) * per_page).limit(per_page).all()
    item_ids = [a.id for a in items]
    counts_map = {}
    if item_ids:
        counts_map = dict(
            db.session.query(ArrivalFile.arrival_id, func.count(ArrivalFile.id))
            .filter(ArrivalFile.arrival_id.in_(item_ids))
            .group_by(ArrivalFile.arrival_id)
            .all()
        )
    items_payload = []
    for a in items:
        d = a.to_dict()
        d["files_count"] = int(counts_map.get(a.id, 0))
        items_payload.append(d)
    return jsonify({'page': page, 'per_page': per_page, 'total': total, 'items': items_payload})

@app.route('/api/arrivals', methods=['POST'])
def create_arrival():
    data = request.json or {}
    # --- Normalize aliases for location (frontend may send different keys) ---
    loc = data.get('location')
    if not loc:
        for alias in ('lokacija', 'store', 'shop', 'warehouse'):
            if alias in data and data.get(alias):
                loc = data.get(alias)
                break
    if isinstance(loc, str):
        loc = loc.strip()
    attempted_fields = set(data.keys() or [])
    ok, role, uid, err = check_api_or_jwt(attempted_fields)
    if not ok:
        return err
    a = Arrival(
        supplier=data.get('supplier'),
        carrier=data.get('carrier'),
        plate=data.get('plate'),
        driver=data.get('driver'),
        pickup_date=_parse_iso(data.get('pickup_date')),
        type=data.get('type','truck'),
        eta=data.get('eta'),
        status=data.get('status','not_shipped'),
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
        assignee_id=data.get('assignee_id')
    )
    db.session.add(a); db.session.commit()
    return jsonify(a.to_dict()), 201

@app.route('/api/arrivals/<int:id>', methods=['PATCH'])
def update_arrival(id):
    a = Arrival.query.get_or_404(id)
    data = request.json or {}

    attempted_fields = set(data.keys() or [])
    ok, role, uid, err = check_api_or_jwt(attempted_fields)
    if not ok:
        return err

    # --- Normalize aliases for location and write back into data ---
    if 'location' not in data or (isinstance(data.get('location'), str) and not data.get('location').strip()):
        loc = None
        for alias in ('lokacija', 'store', 'shop', 'warehouse'):
            if alias in data and data.get(alias):
                loc = data.get(alias)
                break
        if isinstance(loc, str):
            loc = loc.strip()
        if loc is not None:
            data['location'] = loc

    # If JWT (non-admin), restrict to editable fields for their role
    editable = ROLE_FIELDS.get(role, set()) if role and role != 'system' else None
    def can_set(field):
        if role == 'admin' or role == 'system':
            return True
        return field in (editable or set())

    # --- Field alias normalization (accept common frontend variants) ---
    # transport_type -> type
    if 'transport_type' in data and 'type' not in data and can_set('type'):
        data['type'] = data.get('transport_type')
    # assignee / assignee_name -> responsible (fallback if responsible not explicitly provided)
    if 'responsible' not in data:
        if 'assignee_name' in data and can_set('responsible'):
            data['responsible'] = data.get('assignee_name')
        elif 'assignee' in data and can_set('responsible'):
            data['responsible'] = data.get('assignee')
    # normalize empty strings for simple text fields so they persist consistently
    for _k in ('responsible', 'location'):
        if _k in data and isinstance(data[_k], str):
            data[_k] = data[_k].strip()

    for field in ['supplier','carrier','plate','driver','type','eta','status','note','customs_info','currency','assignee_id','responsible','location']:
        if field in data and can_set(field):
            setattr(a, field, data[field])
    if 'order_date' in data and can_set('order_date'): a.order_date = _parse_iso(data.get('order_date'))
    if 'production_due' in data and can_set('production_due'): a.production_due = _parse_iso(data.get('production_due'))
    if 'shipped_at' in data and can_set('shipped_at'): a.shipped_at = _parse_iso(data.get('shipped_at'))
    if 'arrived_at' in data and can_set('arrived_at'): a.arrived_at = _parse_iso(data.get('arrived_at'))
    if 'freight_cost' in data and can_set('freight_cost'): a.freight_cost = _parse_float(data.get('freight_cost'))
    if 'customs_cost' in data and can_set('customs_cost'): a.customs_cost = _parse_float(data.get('customs_cost'))
    if 'pickup_date' in data and can_set('pickup_date'): a.pickup_date = _parse_iso(data.get('pickup_date'))
    if 'goods_cost' in data and can_set('goods_cost'): a.goods_cost = _parse_float(data.get('goods_cost'))
    db.session.commit()
    return jsonify(a.to_dict())

# Role/JWT update (frontend koristi ovo)
@app.route('/api/arrivals/<int:id>/status', methods=['PATCH'])
@jwt_required()
def update_arrival_status(id):
    a = Arrival.query.get_or_404(id)
    claims = get_jwt()
    uid = get_jwt_identity()
    role = claims.get('role','viewer')
    user_id = int(uid) if uid is not None else None
    data = request.json or {}

    attempted_fields = set(data.keys())
    if 'status' in data and data['status'] not in ALLOWED_STATUSES:
        return jsonify({'error': 'Invalid status'}), 400
    if not can_edit(role, attempted_fields):
        return jsonify({'error': 'Forbidden for your role'}), 403

    editable = ROLE_FIELDS.get(role, set()) | (ROLE_FIELDS.get('admin') if role == 'admin' else set())
    for field in attempted_fields & editable:
        if field in {'order_date','production_due','shipped_at','arrived_at'}:
            setattr(a, field, _parse_iso(data[field]))
        elif field in {'freight_cost','customs_cost'}:
            setattr(a, field, _parse_float(data[field]))
        else:
            setattr(a, field, data[field])

    # activity
    if 'status' in data:
        msg = f"Status changed to '{data['status']}'"
        db.session.add(ArrivalUpdate(arrival_id=a.id, user_id=user_id, message=msg))
        if NOTIFY_ON_STATUS:
            try:
                send_email(
                    subject=f"[Arrivals] #{a.id} status → {data['status']}",
                    body=f"Supplier: {a.supplier}\nPlate: {a.plate or '-'}\nNew status: {data['status']}\nBy: {claims.get('email')}"
                    , to_list=all_user_emails()
                )
            except Exception as e:
                print("[STATUS MAIL ERROR]", e)

    db.session.commit()
    return jsonify(a.to_dict())

@app.route('/api/arrivals/<int:id>', methods=['DELETE'])
@jwt_required(optional=True)
def delete_arrival(id):
    # Allow admin via JWT or system via X-API-Key
    if not (has_valid_api_key()):
        try:
            verify_jwt_in_request(optional=False)
        except Exception:
            return jsonify({'error': 'Unauthorized'}), 401
        claims = get_jwt()
        if (claims or {}).get('role') != 'admin':
            return jsonify({'error': 'Admin only'}), 403

    a = Arrival.query.get(id)
    if not a:
        return jsonify({'error': 'Not found'}), 404
    # Remove all files from disk for this arrival
    try:
        for f in list(getattr(a, "files", []) or []):
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], f.filename))
            except Exception:
                # ignore per-file deletion errors
                pass
    except Exception:
        pass
    db.session.delete(a)
    db.session.commit()
    return jsonify({'ok': True, 'deleted_id': id}), 200

# Bulk delete arrivals endpoint
@app.route('/api/arrivals/bulk_delete', methods=['DELETE'])
@jwt_required(optional=True)
def bulk_delete_arrivals():
    payload = request.json or {}
    ids = payload.get('ids') or []
    if not isinstance(ids, list) or not all(isinstance(i, int) for i in ids):
        return jsonify({'error': 'ids must be an array of integers'}), 400

    # Allow admin via JWT or system via API key
    if not (has_valid_api_key()):
        try:
            verify_jwt_in_request(optional=False)
        except Exception:
            return jsonify({'error': 'Unauthorized'}), 401
        claims = get_jwt()
        if (claims or {}).get('role') != 'admin':
            return jsonify({'error': 'Admin only'}), 403

    if not ids:
        return jsonify({'ok': True, 'deleted': []})

    # Remove all related files from disk for these arrivals
    try:
        file_rows = db.session.query(ArrivalFile.filename).filter(ArrivalFile.arrival_id.in_(ids)).all()
        for (fname,) in file_rows:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], fname))
            except Exception:
                # ignore per-file deletion errors
                pass
    except Exception:
        pass

    db.session.query(Arrival).filter(Arrival.id.in_(ids)).delete(synchronize_session=False)
    db.session.commit()
    return jsonify({'ok': True, 'deleted': ids}), 200

# Alternate bulk delete via querystring: DELETE /api/arrivals?ids=1,2,3
@app.route('/api/arrivals', methods=['DELETE'])
@jwt_required(optional=True)
def delete_arrivals_querystring():
    # Get ids from querystring or JSON body
    qs_ids = request.args.get('ids')
    body = request.get_json(silent=True) or {}
    body_ids = body.get('ids') if isinstance(body, dict) else []

    ids = []
    if qs_ids:
        try:
            ids.extend([int(x) for x in qs_ids.split(',') if x.strip()])
        except Exception:
            return jsonify({'error': 'ids in querystring must be comma-separated integers'}), 400
    if isinstance(body_ids, list):
        try:
            ids.extend([int(x) for x in body_ids])
        except Exception:
            return jsonify({'error': 'ids in JSON must be integers'}), 400

    # De-duplicate
    ids = list(sorted(set(ids)))

    # Authorization: allow admin via JWT or system via X-API-Key
    if not (has_valid_api_key()):
        try:
            verify_jwt_in_request(optional=False)
        except Exception:
            return jsonify({'error': 'Unauthorized'}), 401
        claims = get_jwt()
        if (claims or {}).get('role') != 'admin':
            return jsonify({'error': 'Admin only'}), 403

    if not ids:
        return jsonify({'ok': True, 'deleted': []})

    # Remove all related files from disk for these arrivals
    try:
        file_rows = db.session.query(ArrivalFile.filename).filter(ArrivalFile.arrival_id.in_(ids)).all()
        for (fname,) in file_rows:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], fname))
            except Exception:
                pass
    except Exception:
        pass

    db.session.query(Arrival).filter(Arrival.id.in_(ids)).delete(synchronize_session=False)
    db.session.commit()
    return jsonify({'ok': True, 'deleted': ids}), 200

# Updates
@app.route('/api/arrivals/<int:arrival_id>/updates', methods=['GET'])
@jwt_required(optional=True)
def list_updates(arrival_id):
    updates = ArrivalUpdate.query.filter_by(arrival_id=arrival_id).order_by(ArrivalUpdate.created_at.asc()).all()
    return jsonify([{'id': u.id, 'arrival_id': u.arrival_id, 'user_id': u.user_id, 'message': u.message, 'created_at': u.created_at.isoformat()} for u in updates])

@app.route('/api/arrivals/<int:arrival_id>/updates', methods=['POST'])
@jwt_required()
def create_update(arrival_id):
    Arrival.query.get_or_404(arrival_id)
    uid = get_jwt_identity()
    msg = (request.json or {}).get('message','').strip()
    if not msg: return jsonify({'error': 'message required'}), 400
    upd = ArrivalUpdate(arrival_id=arrival_id, user_id=int(uid) if uid else None, message=msg)
    db.session.add(upd); db.session.commit()
    return jsonify({'id': upd.id, 'arrival_id': upd.arrival_id, 'user_id': upd.user_id, 'message': upd.message, 'created_at': upd.created_at.isoformat()}), 201

# Files
@app.route('/api/arrivals/<int:arrival_id>/files', methods=['POST'])
@jwt_required()
def upload_file(arrival_id):
    Arrival.query.get_or_404(arrival_id)

    # Collect files from both 'files' (multiple) and 'file' (single)
    files = []
    if 'files' in request.files:
        files.extend(request.files.getlist('files'))
    if 'file' in request.files:
        files.append(request.files['file'])

    if not files:
        return jsonify({'error': 'file/files missing'}), 400

    recs = []
    for f in files:
        if not f or f.filename == '':
            continue
        safe_name = secure_filename(f.filename)
        unique_name = f"{int(time.time()*1000)}_{safe_name}"
        path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
        f.save(path)
        rec = ArrivalFile(arrival_id=arrival_id, filename=unique_name, original_name=safe_name)
        db.session.add(rec)
        db.session.flush()  # get IDs without full commit
        recs.append({
            'id': rec.id,
            'arrival_id': rec.arrival_id,
            'filename': rec.filename,
            'original_name': rec.original_name,
            'uploaded_at': (rec.uploaded_at or datetime.utcnow()).isoformat(),
            'url': f"/files/{rec.filename}",
        })
    db.session.commit()
    return jsonify(recs), 201

# List files for an arrival
@app.route('/api/arrivals/<int:arrival_id>/files', methods=['GET'])
@jwt_required(optional=True)
def list_files(arrival_id):
    Arrival.query.get_or_404(arrival_id)
    files = ArrivalFile.query.filter_by(arrival_id=arrival_id).order_by(ArrivalFile.uploaded_at.asc()).all()
    return jsonify([
        {
            'id': f.id,
            'arrival_id': f.arrival_id,
            'filename': f.filename,
            'original_name': f.original_name,
            'uploaded_at': f.uploaded_at.isoformat(),
            'url': f"/files/{f.filename}",
        } for f in files
    ])


# Delete a file (admin or API key)
@app.route('/api/arrivals/<int:arrival_id>/files/<int:file_id>', methods=['DELETE'])
@jwt_required(optional=True)
def delete_file(arrival_id, file_id):
    # Admin via JWT or system via API key
    if not (has_valid_api_key()):
        try:
            verify_jwt_in_request(optional=False)
        except Exception:
            return jsonify({'error': 'Unauthorized'}), 401
        claims = get_jwt()
        if (claims or {}).get('role') != 'admin':
            return jsonify({'error': 'Admin only'}), 403
    rec = ArrivalFile.query.filter_by(id=file_id, arrival_id=arrival_id).first()
    if not rec:
        return jsonify({'error': 'Not found'}), 404
    # Try delete file from disk
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], rec.filename))
    except Exception:
        pass
    db.session.delete(rec)
    db.session.commit()
    return jsonify({'ok': True, 'deleted_id': file_id})

# Container Files
@app.route('/api/containers/<int:cid>/files', methods=['POST'])
@jwt_required()
def upload_container_file(cid):
    # Ensure container exists
    Container.query.get_or_404(cid)

    # Collect files from both 'files' (multiple) and 'file' (single)
    files = []
    if 'files' in request.files:
        files.extend(request.files.getlist('files'))
    if 'file' in request.files:
        files.append(request.files['file'])

    if not files:
        return jsonify({'error': 'file/files missing'}), 400

    recs = []
    for f in files:
        if not f or f.filename == '':
            continue
        safe_name = secure_filename(f.filename)
        unique_name = f"{int(time.time()*1000)}_{safe_name}"
        path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
        f.save(path)
        rec = ContainerFile(container_id=cid, filename=unique_name, original_name=safe_name)
        db.session.add(rec)
        db.session.flush()
        recs.append({
            'id': rec.id,
            'container_id': rec.container_id,
            'filename': rec.filename,
            'original_name': rec.original_name,
            'uploaded_at': (rec.uploaded_at or datetime.utcnow()).isoformat(),
            'url': f"/files/{rec.filename}",
        })
    db.session.commit()
    return jsonify(recs), 201

@app.route('/api/containers/<int:cid>/files', methods=['GET'])
@jwt_required(optional=True)
def list_container_files(cid):
    Container.query.get_or_404(cid)
    files = ContainerFile.query.filter_by(container_id=cid).order_by(ContainerFile.uploaded_at.asc()).all()
    return jsonify([
        {
            'id': f.id,
            'container_id': f.container_id,
            'filename': f.filename,
            'original_name': f.original_name,
            'uploaded_at': f.uploaded_at.isoformat(),
            'url': f"/files/{f.filename}",
        } for f in files
    ])

@app.route('/api/containers/<int:cid>/files/<int:file_id>', methods=['DELETE'])
@jwt_required(optional=True)
def delete_container_file(cid, file_id):
    # Admin via JWT or system via API key
    if not (has_valid_api_key()):
        try:
            verify_jwt_in_request(optional=False)
        except Exception:
            return jsonify({'error': 'Unauthorized'}), 401
        claims = get_jwt()
        if (claims or {}).get('role') != 'admin':
            return jsonify({'error': 'Admin only'}), 403

    rec = ContainerFile.query.filter_by(id=file_id, container_id=cid).first()
    if not rec:
        return jsonify({'error': 'Not found'}), 404

    # Try delete file from disk
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], rec.filename))
    except Exception:
        pass

    db.session.delete(rec)
    db.session.commit()
    return jsonify({'ok': True, 'deleted_id': file_id})

@app.route('/files/<path:filename>', methods=['GET', 'HEAD', 'OPTIONS'])
def get_file(filename):
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

    # Support both `?download=1` and `?inline=1` toggles
    download_q = (request.args.get('download') or '').strip().lower()
    inline_q = (request.args.get('inline') or '').strip().lower()
    # Default to inline preview; allow `?download=1` to force download
    as_att = download_q in ('1', 'true', 'yes', 'on') and not (inline_q in ('1','true','yes','on'))

    try:
        resp = send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=as_att)
        # Ensure credentials-safe CORS headers (avoid wildcard when cookies are used)
        origin = request.headers.get("Origin")
        if origin in (ALLOWED_ORIGINS or []):
            resp.headers["Access-Control-Allow-Origin"] = origin
            # Merge with existing Vary header if present
            if resp.headers.get("Vary"):
                if "Origin" not in resp.headers.get("Vary"):
                    resp.headers["Vary"] = resp.headers.get("Vary") + ", Origin"
            else:
                resp.headers["Vary"] = "Origin"
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers.setdefault("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
            resp.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD")
        return resp
    except FileNotFoundError:
        return jsonify({'error': 'Not found'}), 404


# Legacy/compatibility route for accidental double /files/files/ URLs
@app.route('/files/files/<path:filename>', methods=['GET', 'HEAD', 'OPTIONS'])
def get_file_compat(filename):
    # Delegate to the canonical handler
    return get_file(filename)

# Containers CRUD + search
@app.get('/api/containers')
@jwt_required(optional=True)
def containers_list():
    q = (request.args.get('q') or '').strip().lower()
    status = (request.args.get('status') or 'all').lower()  # all | paid | unpaid

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
        ))

    if status == 'paid':
        query = query.filter(Container.paid.is_(True))
    elif status == 'unpaid':
        query = query.filter(Container.paid.is_(False))

    rows = query.order_by(Container.created_at.desc()).all()
    return jsonify([r.to_dict() for r in rows])


@app.post('/api/containers')
@jwt_required()
def containers_create():
    data = request.get_json(force=True) or {}
    r = Container(
        supplier=data.get('supplier', ''),
        proforma_no=data.get('proformaNo', ''),
        etd=_parse_date_any(data.get('etd')),
        delivery=_parse_date_any(data.get('delivery')),
        eta=_parse_date_any(data.get('eta')),
        cargo_qty=data.get('cargoQty', ''),
        cargo=data.get('cargo', ''),
        container_no=data.get('containerNo', ''),
        roba=data.get('roba', ''),
        contain_price=data.get('containPrice', ''),
        agent=data.get('agent', ''),
        total=data.get('total', ''),
        deposit=data.get('deposit', ''),
        balance=data.get('balance', ''),
        paid=bool(data.get('placeno', False) if _parse_boolish(data.get('placeno', False)) is not None else _parse_boolish(
            data.get('paid')
            or data.get('is_paid')
            or data.get('payment_status')
            or data.get('status')
        ) or False),
    )

    # server-side BALANCE recompute
    T = _money_to_number(r.total)
    D = _money_to_number(r.deposit)
    paid_flag = bool(r.paid)
    if paid_flag:
        # If paid on creation, force balance to 0.00
        r.balance = "0.00"
    elif T is not None and D is not None:
        bal = round(T - D, 2)
        r.balance = f"{bal:.2f}"
    # NOTE: do NOT auto-set r.paid based purely on balance; user controls it via 'placeno/paid'.

    db.session.add(r)
    db.session.commit()

    # notify if newly created row is paid (e.g., total == deposit or manual)
    try:
        if NOTIFY_ON_PAID:
            new_row = r.to_dict()
            # Simulate previous state as unpaid to trigger transition
            old_row = dict(new_row)
            old_row["placeno"] = False
            maybe_notify_paid(old_row, new_row, recipients=(MAIL_DEFAULT_TO or all_user_emails()))
    except Exception as _notify_err:
        print("[MAIL notify_paid (create) ERROR]", _notify_err)

    return jsonify(r.to_dict()), 201


@app.patch('/api/containers/<int:cid>')
@jwt_required()
def containers_update(cid):
    r = Container.query.get_or_404(cid)
    data = request.get_json(force=True) or {}
    # snapshot prije izmjena (za detekciju prelaza neplaćeno -> plaćeno)
    try:
        old_row = r.to_dict()
    except Exception:
        old_row = None

    # basic fields
    mapping = {
        "supplier": "supplier",
        "proformaNo": "proforma_no",
        "cargoQty": "cargo_qty",
        "cargo": "cargo",
        "containerNo": "container_no",
        "roba": "roba",
        "containPrice": "contain_price",
        "agent": "agent",
        "total": "total",
        "deposit": "deposit",
        "balance": "balance",
    }
    for k, attr in mapping.items():
        if k in data:
            setattr(r, attr, data.get(k) or "")

    # dates
    if "etd" in data:
        r.etd = _parse_date_any(data.get("etd"))
    if "delivery" in data:
        r.delivery = _parse_date_any(data.get("delivery"))
    if "eta" in data:
        r.eta = _parse_date_any(data.get("eta"))

    # manual paid toggle (alias-aware)
    paid_in = None
    if "placeno" in data:
        paid_in = _parse_boolish(data.get("placeno"))
    else:
        for k in ("paid", "is_paid", "payment_status", "status"):
            if k in data:
                paid_in = _parse_boolish(data.get(k))
                break
    if paid_in is not None:
        r.paid = bool(paid_in)

    # server-side recompute balance with paid awareness
    T = _money_to_number(r.total)
    D = _money_to_number(r.deposit)
    if bool(r.paid):
        # When paid, keep balance at 0.00 regardless of T/D
        r.balance = "0.00"
    else:
        if T is not None and D is not None:
            bal = round(T - D, 2)
            r.balance = f"{bal:.2f}"
        # if we can't compute (missing numbers), leave as-is string
    # NOTE: do NOT auto-set r.paid based on balance; user controls "placeno/paid" manually.

    db.session.commit()
    # nakon upisa – provjeri da li je došlo do prelaza na plaćeno i pošalji mail
    if NOTIFY_ON_PAID:
        try:
            new_row = r.to_dict()
            if old_row is not None:
                maybe_notify_paid(old_row, new_row, recipients=(MAIL_DEFAULT_TO or all_user_emails()))
        except Exception as _notify_err:
            # ne ruši request ako mail ne prođe
            print("[MAIL notify_paid (update) ERROR]", _notify_err)
    return jsonify(r.to_dict())



@app.delete('/api/containers/<int:cid>')
@jwt_required()
def containers_delete(cid):
    r = Container.query.get_or_404(cid)
    db.session.delete(r)
    db.session.commit()
    return jsonify({"ok": True, "deleted_id": cid})


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

@app.get('/api/options/locations')
def options_locations():
    """
    Returns the list of allowed shop/warehouse locations for dropdowns.
    Priority:
      1) LOCATIONS env var (comma-separated) if present.
      2) Fixed list provided by the business.
      3) Any additional distinct, non-empty locations already present in DB (appended).
    """
    # 1) Environment override
    from_env = (os.environ.get('LOCATIONS') or '').strip()
    if from_env:
        base_list = [v.strip() for v in from_env.split(',') if v.strip()]
    else:
        # 2) Fixed list from the user (trimmed, order preserved)
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

    # 3) Union with distinct locations already stored in the DB
    try:
        rows = db.session.query(Arrival.location).filter(Arrival.location.isnot(None)).all()
        extra = [(r[0] or '').strip() for r in rows if (r[0] or '').strip()]
    except Exception:
        extra = []

    # Deduplicate while preserving order: base_list first, then extras not already present
    seen = set()
    result = []
    for v in base_list + extra:
        k = v.strip()
        if k and k not in seen:
            seen.add(k)
            result.append(k)

    return jsonify(result)

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

# --- Admin seed ---
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
ADMIN_NAME = os.environ.get('ADMIN_NAME', 'Admin')

def ensure_admin():
    if not ADMIN_EMAIL or not ADMIN_PASSWORD: return
    email = ADMIN_EMAIL.strip().lower()
    if not User.query.filter_by(email=email).first():
        u = User(email=email, name=ADMIN_NAME, role='admin')
        u.set_password(ADMIN_PASSWORD)
        db.session.add(u); db.session.commit()

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
                pending = Arrival.query.filter(
                    Arrival.production_due.isnot(None),
                    Arrival.production_due < now,
                    Arrival.status.in_(['ordered','in_production']),
                    (Arrival.production_overdue_notified.is_(False))
                ).all()
                if pending and NOTIFY_ON_SLA:
                    for a in pending:
                        try:
                            send_email(
                                subject=f"[Arrivals] PRODUCTION OVERDUE for #{a.id}",
                                body=f"Supplier: {a.supplier}\nDue: {a.production_due}\nStatus: {a.status}\nPlease contact manufacturer.",
                                to_list=all_user_emails()
                            )
                            a.production_overdue_notified = True
                        except Exception as e:
                            print("[SLA MAIL ERROR]", e)
                    db.session.commit()
        except Exception as e:
            print("[SLA LOOP ERROR]", e)
        time.sleep(SLA_CHECK_SECONDS)

# --- App bootstrap ---
with app.app_context():
    db.create_all()
    soft_migrate()
    ensure_admin()
    # start SLA thread (avoid double-run in reloader; debug is off anyway)
    t = threading.Thread(target=sla_monitor_loop, daemon=True)
    t.start()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8081))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host='0.0.0.0', port=port, debug=debug)