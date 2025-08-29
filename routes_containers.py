# routes_containers.py
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from sqlalchemy import or_
from datetime import date, datetime
from models import db, Container

bp = Blueprint("containers", __name__)

def parse_date_any(val):
    if not val:
        return None
    s = str(val).strip()
    # ISO (YYYY-MM-DD) iz fronta
    try:
        if len(s) == 10 and s[4] == "-" and s[7] == "-":
            return date.fromisoformat(s)
    except:
        pass
    # Excel serial broj?
    try:
        n = float(s)
        if n > 10000:
            base = datetime(1899, 12, 30)
            dt = base + timedelta(days=n)
            return dt.date()
    except:
        pass
    # fallback parse
    try:
        dt = datetime.fromisoformat(s)
        return dt.date()
    except:
        pass
    try:
        dt = datetime.strptime(s, "%d/%m/%Y")
        return dt.date()
    except:
        pass
    try:
        dt = datetime.strptime(s, "%m/%d/%Y")
        return dt.date()
    except:
        pass
    return None

def money_to_number(val):
    if val is None:
        return None
    s = str(val)
    s = "".join(ch for ch in s if ch.isdigit() or ch in ",.-")
    if "," in s and "." not in s:
        s = s.replace(",", ".")
    try:
        return float(s)
    except:
        return None

@bp.get("/containers")
@jwt_required(optional=True)
def list_containers():
    q = (request.args.get("q") or "").strip().lower()
    status = request.args.get("status")  # all/paid/unpaid

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
    if status == "paid":
        query = query.filter(Container.paid.is_(True))
    elif status == "unpaid":
        query = query.filter(Container.paid.is_(False))

    query = query.order_by(Container.created_at.desc())
    rows = query.all()
    return jsonify([r.to_dict() for r in rows])

@bp.post("/containers")
@jwt_required()
def create_container():
    data = request.get_json(force=True) or {}
    r = Container(
        supplier=data.get("supplier",""),
        proforma_no=data.get("proformaNo",""),
        etd=parse_date_any(data.get("etd")),
        delivery=parse_date_any(data.get("delivery")),
        eta=parse_date_any(data.get("eta")),
        cargo_qty=data.get("cargoQty",""),
        cargo=data.get("cargo",""),
        container_no=data.get("containerNo",""),
        roba=data.get("roba",""),
        contain_price=data.get("containPrice",""),
        agent=data.get("agent",""),
        total=data.get("total",""),
        deposit=data.get("deposit",""),
        balance=data.get("balance",""),
        paid=bool(data.get("placeno", False)),
    )

    # server-side izračun balansa i auto-plaćanje (ako zatreba)
    T = money_to_number(r.total)
    D = money_to_number(r.deposit)
    if T is not None and D is not None:
        bal = round(T - D, 2)
        r.balance = f"{bal:.2f}"
        if abs(bal) < 0.005:
            r.paid = True

    db.session.add(r)
    db.session.commit()
    return jsonify(r.to_dict()), 201

@bp.patch("/containers/<int:cid>")
@jwt_required()
def update_container(cid):
    r = Container.query.get_or_404(cid)
    data = request.get_json(force=True) or {}

    for k, v in {
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
    }.items():
        if k in data:
            setattr(r, v, data[k] or "")

    if "placeno" in data:
        r.paid = bool(data["placeno"])

    # datumi
    for k, v in {"etd": "etd", "delivery": "delivery", "eta": "eta"}.items():
        if k in data:
            setattr(r, v, parse_date_any(data[k]))

    # server-side obračun balansa + auto-plaćeno ako == 0.00
    T = money_to_number(r.total)
    D = money_to_number(r.deposit)
    if T is not None and D is not None:
        bal = round(T - D, 2)
        r.balance = f"{bal:.2f}"
        if abs(bal) < 0.005:
            r.paid = True

    db.session.commit()
    return jsonify(r.to_dict())

@bp.delete("/containers/<int:cid>")
@jwt_required()
def delete_container(cid):
    r = Container.query.get_or_404(cid)
    db.session.delete(r)
    db.session.commit()
    return jsonify({"ok": True})