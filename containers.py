

# routes/containers.py
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request
from werkzeug.utils import secure_filename
from sqlalchemy import func, or_
from datetime import datetime
import os, time

from extensions import db
from models import Container, ContainerFile
from app import _parse_iso, _parse_float, _parse_date_any, check_api_or_jwt, has_valid_api_key, ROLE_FIELDS, can_edit

bp = Blueprint("containers", __name__, url_prefix="/api/containers")

@bp.route("", methods=["GET", "HEAD", "OPTIONS"])
@bp.route("/", methods=["GET", "HEAD", "OPTIONS"])
def list_containers():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        containers = Container.query.order_by(Container.created_at.desc()).all()
        counts_map = dict(
            db.session.query(ContainerFile.container_id, func.count(ContainerFile.id))
            .group_by(ContainerFile.container_id).all()
        )
        results = []
        for c in containers:
            d = c.to_dict()
            d["files_count"] = int(counts_map.get(c.id, 0))
            results.append(d)
        return jsonify(results)
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Server error", "detail": str(e)}), 500

@bp.get("/<int:id>")
def get_container(id):
    c = Container.query.get_or_404(id)
    d = c.to_dict()
    d["files_count"] = db.session.query(func.count(ContainerFile.id)).filter(ContainerFile.container_id == c.id).scalar() or 0
    return jsonify(d)

@bp.route("", methods=["POST"], strict_slashes=False)
@bp.route("/", methods=["POST"], strict_slashes=False)
def create_container():
    # Accept JSON or form-urlencoded
    data = request.get_json(silent=True) or {}
    if not data:
        data = {k: v for k, v in (request.form or {}).items()}

    def pick(obj, *aliases, default=""):
        for k in aliases:
            if k in obj and (obj[k] or str(obj[k]).strip() != ""):
                return obj[k]
        return default
    ok, role, uid, err = check_api_or_jwt(set(data.keys()))
    if not ok:
        return err
    try:
        # Map incoming payload (support multiple common aliases)
        supplier     = pick(data, 'supplier')
        proforma_no  = pick(data, 'proforma_no','proforma','proformaNo','proforma_number','pf_no','pfNumber')
        etd          = _parse_date_any(pick(data, 'etd'))
        delivery     = _parse_date_any(pick(data, 'delivery'))
        eta          = _parse_date_any(pick(data, 'eta'))
        cargo_qty    = str(pick(data, 'cargo_qty','qty','quantity','cargoQty','cargo_quantity') or '')
        cargo        = pick(data, 'cargo','goods','tip')
        container_no = pick(data, 'container_no','container','containerNo','container_number','containerno','containerNum')
        roba         = pick(data, 'roba','goods','product')
        contain_price= str(pick(data, 'contain_price','container_price','price') or '')
        agent        = pick(data, 'agent')
        total_s      = str(pick(data, 'total') or '')
        deposit_s    = str(pick(data, 'deposit') or '')
        # Compute balance if both total/deposit are numeric-like
        t = _parse_float(total_s)
        d = _parse_float(deposit_s)
        balance_s = f"{(t - d):.2f}" if (t is not None and d is not None) else str(pick(data, 'balance') or '')
        paid_flag   = pick(data, 'paid','placeno')
        paid        = False
        if isinstance(paid_flag, bool):
            paid = paid_flag
        else:
            s = str(paid_flag).strip().lower()
            paid = s in ('1','true','yes','y','da','paid','plaćeno','placeno')

        c = Container(
            supplier=supplier or None,
            proforma_no=proforma_no or None,
            etd=etd,
            delivery=delivery,
            cargo_qty=cargo_qty or None,
            cargo=cargo or None,
            container_no=container_no or None,
            roba=roba or None,
            contain_price=contain_price or None,
            agent=agent or None,
            total=total_s or None,
            deposit=deposit_s or None,
            balance=balance_s or None,
            paid=bool(paid),
            code=data.get("code"),
            status=data.get("status", "pending"),
            note=data.get("note"),
            eta=eta,
            arrived_at=_parse_iso(data.get("arrived_at")),
        )
        db.session.add(c)
        db.session.commit()
        return jsonify(c.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "create_failed", "detail": str(e)}), 500

@bp.route("/<int:id>", methods=["OPTIONS"])  # CORS preflight for PATCH/DELETE/etc.
def _options_container_id(id):
    return ("", 204)

@bp.patch("/<int:id>")
def update_container(id):
    c = Container.query.get_or_404(id)
    data = request.get_json(silent=True) or {}
    ok, role, uid, err = check_api_or_jwt(set(data.keys()))
    if not ok:
        return err
    editable = ROLE_FIELDS.get(role, set()) if role and role != "system" else None
    def can_set(field): return True if role in ("admin","system") else field in (editable or set())
    for field in ["code","status","note"]:
        if field in data and can_set(field):
            setattr(c, field, data[field])
    if "eta" in data and can_set("eta"):
        c.eta = _parse_date_any(data.get("eta"))
    # Mapped fields
    if "supplier" in data and can_set("supplier"): c.supplier = data.get("supplier")
    if any(k in data for k in ("proforma_no","proforma","proformaNo","proforma_number","pf_no","pfNumber")) and can_set("proforma_no"):
        c.proforma_no = data.get("proforma_no") or data.get("proforma") or data.get("proformaNo") or data.get("proforma_number") or data.get("pf_no") or data.get("pfNumber")
    if "etd" in data and can_set("etd"): c.etd = _parse_date_any(data.get("etd"))
    if "delivery" in data and can_set("delivery"): c.delivery = _parse_date_any(data.get("delivery"))
    if any(k in data for k in ("cargo_qty","qty","quantity","cargoQty","cargo_quantity")) and can_set("cargo_qty"):
        c.cargo_qty = str(data.get("cargo_qty") or data.get("qty") or data.get("quantity") or data.get("cargoQty") or data.get("cargo_quantity") or '')
    if any(k in data for k in ("cargo","goods","tip")) and can_set("cargo"):
        c.cargo = data.get("cargo") or data.get("goods") or data.get("tip")
    if any(k in data for k in ("container_no","container","containerNo","container_number","containerno","containerNum")) and can_set("container_no"):
        c.container_no = data.get("container_no") or data.get("container") or data.get("containerNo") or data.get("container_number") or data.get("containerno") or data.get("containerNum")
    if any(k in data for k in ("roba","goods","product")) and can_set("roba"):
        c.roba = data.get("roba") or data.get("goods") or data.get("product")
    if any(k in data for k in ("contain_price","container_price","price")) and can_set("contain_price"):
        c.contain_price = str(data.get("contain_price") or data.get("container_price") or data.get("price") or '')
    if "agent" in data and can_set("agent"): c.agent = data.get("agent")
    if "total" in data and can_set("total"): c.total = str(data.get("total") or '')
    if "deposit" in data and can_set("deposit"): c.deposit = str(data.get("deposit") or '')
    # Recompute balance if total/deposit provided
    t = _parse_float(c.total)
    d = _parse_float(c.deposit)
    if t is not None and d is not None:
        c.balance = f"{(t - d):.2f}"
        if abs(t - d) < 0.005:
            c.paid = True
    if "balance" in data and can_set("balance") and not (t is not None and d is not None):
        c.balance = str(data.get("balance") or '')
    if "paid" in data and can_set("paid"):
        pv = data.get("paid")
        if isinstance(pv, bool):
            c.paid = pv
        else:
            s = str(pv).strip().lower()
            c.paid = s in ('1','true','yes','y','da','paid','plaćeno','placeno')
    if "arrived_at" in data and can_set("arrived_at"):
        c.arrived_at = _parse_iso(data.get("arrived_at"))
    try:
        db.session.commit()
        return jsonify(c.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "update_failed", "detail": str(e)}), 500

@bp.delete("/<int:id>")
@jwt_required(optional=True)
def delete_container(id):
    if not (has_valid_api_key()):
        try: verify_jwt_in_request(optional=False)
        except Exception: return jsonify({"error":"Unauthorized"}),401
        claims = get_jwt()
        if (claims or {}).get("role") != "admin":
            return jsonify({"error":"Admin only"}),403
    c = Container.query.get(id)
    if not c:
        return jsonify({"error":"Not found"}),404
    try:
        for f in list(getattr(c,"files",[]) or []):
            try: os.remove(os.path.join(current_app.config["UPLOAD_FOLDER"], f.filename))
            except Exception: pass
    except Exception: pass
    db.session.delete(c)
    db.session.commit()
    return jsonify({"ok":True,"deleted_id":id}),200

# Toggle paid via status mapping (no dedicated 'paid' column)
@bp.post("/<int:id>/paid")
def set_paid(id):
    c = Container.query.get_or_404(id)
    data = request.get_json(silent=True) or {}
    paid = data.get("paid")
    # Interpret truthy/falsy
    val = str(paid).strip().lower()
    is_paid = paid is True or val in ("1","true","yes","y","da","paid")
    c.status = "paid" if is_paid else "unpaid"
    # Also persist boolean/derived values so refresh reflects change
    try:
        c.paid = bool(is_paid)
    except Exception:
        pass
    # If marking as paid, zero the balance; otherwise recompute from total - deposit if possible
    try:
        if is_paid:
            c.balance = "0.00"
        else:
            t = _parse_float(getattr(c, 'total', None)) or 0.0
            d = _parse_float(getattr(c, 'deposit', None)) or 0.0
            c.balance = f"{(t - d):.2f}"
    except Exception:
        pass
    try:
        db.session.commit()
        d = c.to_dict()
        return jsonify(d)
    except Exception as e:
        db.session.rollback()
        return jsonify({"error":"update_failed","detail":str(e)}),500

# Generic status setter (maps directly to c.status)
@bp.post("/<int:id>/status")
def set_status(id):
    c = Container.query.get_or_404(id)
    data = request.get_json(silent=True) or {}
    status = (data.get("status") or "").strip()
    if not status:
        return jsonify({"error":"status_required"}),400
    c.status = status
    try:
        db.session.commit()
        return jsonify(c.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({"error":"update_failed","detail":str(e)}),500

@bp.route("/<int:cid>/files", methods=["OPTIONS"])  # CORS preflight for file uploads
def _options_container_files(cid):
    return ("", 204)

@bp.post("/<int:cid>/files")
@jwt_required()
def upload_file(cid):
    Container.query.get_or_404(cid)
    files=[]
    if "files" in request.files: files.extend(request.files.getlist("files"))
    if "file" in request.files: files.append(request.files["file"])
    if not files: return jsonify({"error":"file/files missing"}),400
    recs=[]
    for f in files:
        if not f or f.filename=="": continue
        safe_name = secure_filename(f.filename)
        unique_name = f"{int(time.time()*1000)}_{safe_name}"
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name)
        f.save(path)
        rec = ContainerFile(container_id=cid, filename=unique_name, original_name=safe_name)
        db.session.add(rec)
        db.session.flush()
        recs.append({
            "id": rec.id,
            "container_id": rec.container_id,
            "filename": rec.filename,
            "original_name": rec.original_name,
            "uploaded_at": (rec.uploaded_at or datetime.utcnow()).isoformat(),
            "url": f"/files/{rec.filename}",
        })
    db.session.commit()
    return jsonify(recs),201

@bp.get("/<int:cid>/files")
@jwt_required(optional=True)
def list_files(cid):
    Container.query.get_or_404(cid)
    files = ContainerFile.query.filter_by(container_id=cid).order_by(ContainerFile.uploaded_at.asc()).all()
    return jsonify([
        {
            "id": f.id,
            "container_id": f.container_id,
            "filename": f.filename,
            "original_name": f.original_name,
            "uploaded_at": f.uploaded_at.isoformat(),
            "url": f"/files/{f.filename}",
        }
        for f in files
    ])

@bp.route("/<int:cid>/files/<int:file_id>", methods=["OPTIONS"])  # CORS preflight for delete
def _options_container_file_id(cid, file_id):
    return ("", 204)

@bp.delete("/<int:cid>/files/<int:file_id>")
@jwt_required(optional=True)
def delete_file(cid, file_id):
    if not (has_valid_api_key()):
        try: verify_jwt_in_request(optional=False)
        except Exception: return jsonify({"error":"Unauthorized"}),401
        claims=get_jwt()
        if (claims or {}).get("role")!="admin":
            return jsonify({"error":"Admin only"}),403
    rec = ContainerFile.query.filter_by(id=file_id, container_id=cid).first()
    if not rec: return jsonify({"error":"Not found"}),404
    try: os.remove(os.path.join(current_app.config["UPLOAD_FOLDER"], rec.filename))
    except Exception: pass
    db.session.delete(rec)
    db.session.commit()
    return jsonify({"ok":True,"deleted_id":file_id})
