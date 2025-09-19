# models.py
from datetime import datetime
from extensions import db

# --- Users ---
class User(db.Model):
    __tablename__ = "users"
    id          = db.Column(db.Integer, primary_key=True)
    email       = db.Column(db.String(255), unique=True, nullable=False, index=True)
    # Keep legacy plain password column for backward compatibility (will be nulled during migration)
    password    = db.Column(db.String(255), nullable=True)
    # New: hashed password storage (pbkdf2:sha256)
    password_hash = db.Column(db.String(255), nullable=True)
    name        = db.Column(db.String(255), default="")
    role        = db.Column(db.String(32),  default="viewer")
    is_active   = db.Column(db.Boolean, default=True)

    # Enterprise additions (backward compatible, nullable defaults)
    username    = db.Column(db.String(255), unique=False, index=True)
    phone       = db.Column(db.String(64))
    status      = db.Column(db.String(32), default="active", index=True)  # active|invited|suspended|locked
    type        = db.Column(db.String(32), default="internal")            # internal|external
    last_activity_at = db.Column(db.DateTime, index=True)
    last_login_at = db.Column(db.DateTime, index=True)
    failed_logins = db.Column(db.Integer, default=0)
    must_change_password = db.Column(db.Boolean, default=False)
    require_password_change = db.Column(db.Boolean, default=False)
    note        = db.Column(db.Text)
    deleted_at  = db.Column(db.DateTime, index=True)

    created_at  = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username or "",
            "name": self.name or "",
            "role": self.role or "viewer",
            "is_active": bool(self.is_active),
            "phone": self.phone or "",
            "status": (self.status or "active"),
            "type": (self.type or "internal"),
            "last_activity_at": (self.last_activity_at or self.updated_at or datetime.utcnow()).isoformat(),
            "last_login_at": (self.last_login_at or None).isoformat() if self.last_login_at else None,
            "failed_logins": int(self.failed_logins or 0),
            "require_password_change": bool(self.require_password_change or self.must_change_password or False),
            "created_at": (self.created_at or datetime.utcnow()).isoformat(),
            "updated_at": (self.updated_at or datetime.utcnow()).isoformat(),
        }

class ArrivalFile(db.Model):
    __tablename__ = "arrival_files"
    id            = db.Column(db.Integer, primary_key=True)
    arrival_id    = db.Column(db.Integer, db.ForeignKey("arrivals.id", ondelete="CASCADE"), index=True, nullable=False)
    filename      = db.Column(db.String(512), nullable=False)
    original_name = db.Column(db.String(512))
    uploaded_at   = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class ArrivalUpdate(db.Model):
    __tablename__ = "arrival_updates"
    id          = db.Column(db.Integer, primary_key=True)
    arrival_id  = db.Column(db.Integer, db.ForeignKey("arrivals.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id     = db.Column(db.Integer, index=True)
    message     = db.Column(db.Text, nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow, index=True)

# --- Notifications ---
class Notification(db.Model):
    __tablename__ = "notifications"
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, index=True, nullable=True)  # null = global
    role        = db.Column(db.String(64), nullable=True, index=True)  # null = all roles; otherwise visible to role
    type        = db.Column(db.String(64), default="info")         # info|warning|error|success
    entity_type = db.Column(db.String(64), nullable=True)           # arrival|container|...
    entity_id   = db.Column(db.Integer, nullable=True)
    text        = db.Column(db.Text, nullable=False)
    read        = db.Column(db.Boolean, default=False, index=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'role': self.role,
            'type': self.type,
            'entity_type': self.entity_type,
            'entity_id': self.entity_id,
            'text': self.text,
            'read': bool(self.read),
            'created_at': (self.created_at or datetime.utcnow()).isoformat(),
        }

# --- Arrivals ---
class Arrival(db.Model):
    __tablename__ = "arrivals"
    id             = db.Column(db.Integer, primary_key=True)

    supplier       = db.Column(db.String(255))
    carrier        = db.Column(db.String(255))
    plate          = db.Column(db.String(64))
    driver         = db.Column(db.String(255))
    type           = db.Column(db.String(32), default="truck")
    eta            = db.Column(db.String(64))  # keep string as in existing API
    status         = db.Column(db.String(64), default="not_shipped", index=True)
    note           = db.Column(db.Text)

    order_date     = db.Column(db.DateTime)
    production_due = db.Column(db.DateTime)
    pickup_date    = db.Column(db.DateTime)
    shipped_at     = db.Column(db.DateTime)
    arrived_at     = db.Column(db.DateTime)

    customs_info   = db.Column(db.Text)
    freight_cost   = db.Column(db.Float)
    goods_cost     = db.Column(db.Float)
    customs_cost   = db.Column(db.Float)
    currency       = db.Column(db.String(8), default="EUR")

    responsible    = db.Column(db.String(255))
    location       = db.Column(db.String(255))
    assignee_id    = db.Column(db.Integer)

    created_at     = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at     = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    files          = db.relationship(ArrivalFile, backref="arrival", cascade="all, delete-orphan", lazy="select")
    updates        = db.relationship(ArrivalUpdate, backref="arrival", cascade="all, delete-orphan", lazy="select")

    def to_dict(self):
        return {
            "id": self.id,
            "supplier": self.supplier or "",
            "carrier": self.carrier or "",
            "plate": self.plate or "",
            "driver": self.driver or "",
            "type": self.type or "truck",
            "eta": self.eta or "",
            "status": self.status or "not_shipped",
            "note": self.note or "",
            "order_date": self.order_date.isoformat() if self.order_date else None,
            "production_due": self.production_due.isoformat() if self.production_due else None,
            "pickup_date": self.pickup_date.isoformat() if self.pickup_date else None,
            "shipped_at": self.shipped_at.isoformat() if self.shipped_at else None,
            "arrived_at": self.arrived_at.isoformat() if self.arrived_at else None,
            "customs_info": self.customs_info or "",
            "freight_cost": self.freight_cost,
            "goods_cost": self.goods_cost,
            "customs_cost": self.customs_cost,
            "currency": self.currency or "EUR",
            "responsible": self.responsible or "",
            "location": self.location or "",
            "assignee_id": self.assignee_id,
            "created_at": (self.created_at or datetime.utcnow()).isoformat(),
            "updated_at": (self.updated_at or datetime.utcnow()).isoformat(),
        }

# --- Containers ---
class ContainerFile(db.Model):
    __tablename__ = "container_files"
    id            = db.Column(db.Integer, primary_key=True)
    container_id  = db.Column(db.Integer, db.ForeignKey("containers.id", ondelete="CASCADE"), index=True, nullable=False)
    filename      = db.Column(db.String(512), nullable=False)
    original_name = db.Column(db.String(512))
    uploaded_at   = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class Container(db.Model):
    __tablename__ = "containers"
    id           = db.Column(db.Integer, primary_key=True)

    # Business fields (match frontend and import expectations)
    supplier     = db.Column(db.String(255))
    proforma_no  = db.Column(db.String(255))
    etd          = db.Column(db.Date)
    delivery     = db.Column(db.Date)
    cargo_qty    = db.Column(db.String(64))
    cargo        = db.Column(db.String(255))
    container_no = db.Column(db.String(64))
    roba         = db.Column(db.String(255))
    contain_price= db.Column(db.String(64))
    agent        = db.Column(db.String(255))
    total        = db.Column(db.String(64))
    deposit      = db.Column(db.String(64))
    balance      = db.Column(db.String(64))
    paid         = db.Column(db.Boolean, default=False)

    code         = db.Column(db.String(255))        # e.g. booking/container code
    status       = db.Column(db.String(64), default="pending", index=True)
    note         = db.Column(db.Text)
    # In some deployed DBs this column is DATE; align model to Date for compatibility.
    eta          = db.Column(db.Date)               # store as date
    arrived_at   = db.Column(db.DateTime)

    created_at   = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at   = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    files        = db.relationship(ContainerFile, backref="container", cascade="all, delete-orphan", lazy="select")

    def to_dict(self):
        return {
            "id": self.id,
            "supplier": self.supplier or "",
            "proforma_no": self.proforma_no or "",
            "etd": (self.etd.isoformat() if self.etd else ""),
            "delivery": (self.delivery.isoformat() if self.delivery else ""),
            "cargo_qty": self.cargo_qty or "",
            "cargo": self.cargo or "",
            "container_no": self.container_no or "",
            "roba": self.roba or "",
            "contain_price": self.contain_price or "",
            "agent": self.agent or "",
            "total": self.total or "",
            "deposit": self.deposit or "",
            "balance": self.balance or "",
            "paid": bool(self.paid),
            "code": self.code or "",
            "status": self.status or "pending",
            "note": self.note or "",
            "eta": (self.eta.isoformat() if self.eta else ""),
            "arrived_at": self.arrived_at.isoformat() if self.arrived_at else None,
            "created_at": (self.created_at or datetime.utcnow()).isoformat(),
            "updated_at": (self.updated_at or datetime.utcnow()).isoformat(),
        }

# --- RBAC ---
class Role(db.Model):
    __tablename__ = "roles"
    id   = db.Column(db.Integer, primary_key=True)
    key  = db.Column(db.String(64), unique=True, index=True)  # e.g. admin, manager, worker
    name = db.Column(db.String(255))

class UserRole(db.Model):
    __tablename__ = "user_roles"
    id       = db.Column(db.Integer, primary_key=True)
    user_id  = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    role_id  = db.Column(db.Integer, db.ForeignKey("roles.id", ondelete="CASCADE"), index=True, nullable=False)
    # JSON string of location codes for scope (simple, portable)
    scope_location_ids = db.Column(db.Text)  # comma-separated list of codes e.g. "PG,NK,BAR"

class UserLocation(db.Model):
    __tablename__ = "user_locations"
    id       = db.Column(db.Integer, primary_key=True)
    user_id  = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    location = db.Column(db.String(255), index=True)

# --- Sessions (basic, JWT tracking) ---
class Session(db.Model):
    __tablename__ = "sessions"
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    ip           = db.Column(db.String(64))
    ua           = db.Column(db.Text)
    os           = db.Column(db.String(128))
    jti          = db.Column(db.String(128), index=True)  # JWT ID to support revocation
    trusted      = db.Column(db.Boolean, default=False)
    revoked      = db.Column(db.Boolean, default=False)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow, index=True)

# --- Notification preferences ---
class NotificationPref(db.Model):
    __tablename__ = "notification_prefs"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    channel    = db.Column(db.String(32))     # email|slack|teams
    event_key  = db.Column(db.String(64))     # arrivals.assigned, arrivals.due_today, container.late, ...
    enabled    = db.Column(db.Boolean, default=True)
    frequency  = db.Column(db.String(32), default="instant")  # instant|daily|weekly

# --- Audit ---
class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id            = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(db.Integer, index=True)
    event         = db.Column(db.String(128))       # e.g. users.bulk_export, users.reset_password
    target_type   = db.Column(db.String(64))        # user|session|export
    target_id     = db.Column(db.Integer, nullable=True)
    meta          = db.Column(db.Text)              # JSON (string)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow, index=True)

# --- User notes/files ---
class UserNote(db.Model):
    __tablename__ = "user_notes"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    author_id  = db.Column(db.Integer, index=True)
    text       = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class UserFile(db.Model):
    __tablename__ = "user_files"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    file_path  = db.Column(db.String(512), nullable=False)
    label      = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
