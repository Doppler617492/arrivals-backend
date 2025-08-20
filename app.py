from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
from sqlalchemy.orm import relationship
from sqlalchemy import or_, text
from functools import wraps
import os
import time
import threading
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True, methods=['GET','POST','PATCH','DELETE','OPTIONS'])

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
SMTP_HOST = os.environ.get('SMTP_HOST')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASS = os.environ.get('SMTP_PASS')
MAIL_FROM = os.environ.get('MAIL_FROM', os.environ.get('ADMIN_EMAIL', 'noreply@example.com'))
MAIL_DEFAULT_TO = [e.strip() for e in (os.environ.get('MAIL_DEFAULT_TO') or os.environ.get('ADMIN_EMAIL','')).split(',') if e.strip()]
NOTIFY_ON_STATUS = os.environ.get('NOTIFY_ON_STATUS', 'true').lower() == 'true'
NOTIFY_ON_SLA = os.environ.get('NOTIFY_ON_SLA', 'true').lower() == 'true'
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

class Arrival(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    supplier = db.Column(db.String(120), nullable=False)
    carrier = db.Column(db.String(120))
    plate = db.Column(db.String(32))
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
    customs_cost = db.Column(db.Float)
    currency = db.Column(db.String(8), default='EUR')

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
            'customs_cost': self.customs_cost,
            'currency': self.currency,
            'assignee_id': self.assignee_id,
            'progress': pct,
            'days_left': days_left,
            'overdue': overdue,
        }

# --- Role permissions ---
ROLE_FIELDS = {
    'admin': {'supplier','carrier','plate','type','eta','status','note','order_date','production_due',
              'shipped_at','arrived_at','customs_info','freight_cost','customs_cost','currency','assignee_id'},
    'planer': {'supplier','order_date','production_due','status','note'},
    'proizvodnja': {'status','note'},
    'transport': {'carrier','plate','eta','status','shipped_at','note'},
    'carina': {'status','customs_info','customs_cost','note'},
    'viewer': set(),
}

ALLOWED_STATUSES = {
    'announced','ordered','in_production','ready_for_pickup',
    'picked_up','shipped','at_customs','cleared_customs',
    'arriving','arrived','warehoused','delayed','cancelled'
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

    # If no JWT at all, unauthorized
    if uid is None and not claims:
        return False, None, None, (jsonify({'error': 'Unauthorized'}), 401)

    # Admin can edit anything
    if role == 'admin':
        return True, role, int(uid) if uid else None, None

    # Field-level permission check
    if attempted_fields and not can_edit(role, attempted_fields):
        return False, role, int(uid) if uid else None, (jsonify({'error': 'Forbidden for your role'}), 403)

    return True, role, int(uid) if uid else None, None

def send_email(subject: str, body: str, to_list=None):
    to_list = to_list or MAIL_DEFAULT_TO
    if not to_list:
        print(f"[MAIL-DEV] {subject}\n{body}\n(no recipients configured)")
        return
    if not SMTP_HOST:
        print(f"[MAIL-DEV] {subject}\nTo: {', '.join(to_list)}\n{body}")
        return
    try:
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = MAIL_FROM
        msg['To'] = ', '.join(to_list)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.starttls()
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASS or '')
            s.sendmail(MAIL_FROM, to_list, msg.as_string())
    except Exception as e:
        print("[MAIL-ERROR]", e)

def all_user_emails():
    emails = [u.email for u in User.query.all() if u.email]
    return emails or MAIL_DEFAULT_TO

# --- Routes ---
@app.route('/', methods=['GET'])
def health():
    return jsonify({"ok": True, "routes": ["/api/arrivals","/auth/login"]})

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
    return jsonify([a.to_dict() for a in arrivals])

@app.route('/api/arrivals/<int:id>', methods=['GET'])
def get_arrival(id):
    a = Arrival.query.get_or_404(id)
    return jsonify(a.to_dict())

@app.route('/api/arrivals/search', methods=['GET'])
def search_arrivals():
    try:
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', 20))
        page = max(1, page); page_size = min(max(1, page_size), 100)
    except ValueError:
        return jsonify({'error': 'page/page_size must be integers'}), 400

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
    if status: query = query.filter(Arrival.status == status)
    if supplier: query = query.filter(Arrival.supplier.ilike(f"%{supplier}%"))
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Arrival.plate.ilike(like), Arrival.carrier.ilike(like)))

    def parse_dt(val):
        if not val: return None
        try: return datetime.fromisoformat(val)
        except Exception: return None
    from_dt = parse_dt(from_str); to_dt = parse_dt(to_str)
    if from_str and not from_dt: return jsonify({'error': "Invalid 'from' ISO datetime"}), 400
    if to_str and not to_dt: return jsonify({'error': "Invalid 'to' ISO datetime"}), 400
    if from_dt: query = query.filter(Arrival.created_at >= from_dt)
    if to_dt: query = query.filter(Arrival.created_at <= to_dt)

    total = query.count()
    items = query.order_by(sort_expr).offset((page-1)*page_size).limit(page_size).all()
    return jsonify({'page': page, 'page_size': page_size, 'total': total, 'items': [a.to_dict() for a in items]})

@app.route('/api/arrivals', methods=['POST'])
def create_arrival():
    data = request.json or {}
    attempted_fields = set(data.keys() or [])
    ok, role, uid, err = check_api_or_jwt(attempted_fields)
    if not ok:
        return err
    a = Arrival(
        supplier=data.get('supplier'),
        carrier=data.get('carrier'),
        plate=data.get('plate'),
        type=data.get('type','truck'),
        eta=data.get('eta'),
        status=data.get('status','announced'),
        note=data.get('note'),
        order_date=_parse_iso(data.get('order_date')),
        production_due=_parse_iso(data.get('production_due')),
        shipped_at=_parse_iso(data.get('shipped_at')),
        arrived_at=_parse_iso(data.get('arrived_at')),
        customs_info=data.get('customs_info'),
        freight_cost=_parse_float(data.get('freight_cost')),
        customs_cost=_parse_float(data.get('customs_cost')),
        currency=(data.get('currency') or 'EUR')[:8],
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

    # If JWT (non-admin), restrict to editable fields for their role
    editable = ROLE_FIELDS.get(role, set()) if role and role != 'system' else None
    def can_set(field):
        if role == 'admin' or role == 'system':
            return True
        return field in (editable or set())

    for field in ['supplier','carrier','plate','type','eta','status','note','customs_info','currency','assignee_id']:
        if field in data and can_set(field):
            setattr(a, field, data[field])
    if 'order_date' in data and can_set('order_date'): a.order_date = _parse_iso(data.get('order_date'))
    if 'production_due' in data and can_set('production_due'): a.production_due = _parse_iso(data.get('production_due'))
    if 'shipped_at' in data and can_set('shipped_at'): a.shipped_at = _parse_iso(data.get('shipped_at'))
    if 'arrived_at' in data and can_set('arrived_at'): a.arrived_at = _parse_iso(data.get('arrived_at'))
    if 'freight_cost' in data and can_set('freight_cost'): a.freight_cost = _parse_float(data.get('freight_cost'))
    if 'customs_cost' in data and can_set('customs_cost'): a.customs_cost = _parse_float(data.get('customs_cost'))
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
    if 'file' not in request.files: return jsonify({'error': 'file missing'}), 400
    f = request.files['file']
    if f.filename == '': return jsonify({'error': 'empty filename'}), 400
    safe_name = secure_filename(f.filename)
    unique_name = f"{int(time.time()*1000)}_{safe_name}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
    f.save(path)
    rec = ArrivalFile(arrival_id=arrival_id, filename=unique_name, original_name=safe_name)
    db.session.add(rec); db.session.commit()
    return jsonify({'id': rec.id, 'arrival_id': rec.arrival_id, 'filename': rec.filename, 'original_name': rec.original_name, 'uploaded_at': rec.uploaded_at.isoformat()}), 201

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

@app.route('/files/<path:filename>', methods=['GET'])
def get_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# KPI
@app.route('/api/kpi', methods=['GET'])
def kpi():
    counts = {}
    for st in ALLOWED_STATUSES:
        counts[st] = Arrival.query.filter_by(status=st).count()
    total = Arrival.query.count()
    return jsonify({'total': total, 'by_status': counts})

# --- Utility parsers ---
def _parse_iso(val):
    if not val: return None
    try:
        return datetime.fromisoformat(val.replace('Z','+00:00'))
    except Exception:
        return None

def _parse_float(val):
    if val is None: return None
    try: return float(val)
    except Exception: return None

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
                            body=f"Supplier: {a.supplier}\nDue: {a.production_due}\nStatus: {a.status}\nPlease contact manufacturer."
                            , to_list=all_user_emails()
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
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host='0.0.0.0', port=port, debug=debug)