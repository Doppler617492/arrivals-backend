# models.py
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

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

    def to_dict(self):
        d = {
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
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
        return d