

# routes/arrivals.py
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request
from werkzeug.utils import secure_filename
from sqlalchemy import func, or_
from sqlalchemy.orm import selectinload
from datetime import datetime
import os, time

from extensions import db
from models import Arrival, ArrivalFile, ArrivalUpdate, ArrivalSupplier, Supplier, ArrivalCountry
from countries import EUROPEAN_COUNTRY_CODES
try:
    from services.mailer import send_email, all_user_emails  # if available
except Exception:
    send_email = None  # type: ignore
    all_user_emails = None  # type: ignore
"""Lazy app imports are used inside functions to avoid circular imports."""

bp = Blueprint("arrivals", __name__)


ALLOWED_SUPPLIER_CURRENCIES = {"EUR"}
DEFAULT_SUPPLIER_CURRENCY = "EUR"


class SupplierPayloadError(ValueError):
    def __init__(self, message: str, code: str = "invalid_suppliers") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class CountryPayloadError(ValueError):
    def __init__(self, message: str, code: str = "invalid_country") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


def _normalize_country_code(raw: str | None) -> str | None:
    """Return an uppercased ISO-2 code or ``None`` if empty.

    Raises ``ValueError`` if the code is not part of the European list.
    """

    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError("invalid_country")
    code = raw.strip().upper()
    if not code:
        return None
    if code not in EUROPEAN_COUNTRY_CODES:
        raise ValueError("invalid_country")
    return code


def _normalize_country_list(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        items = raw
    else:
        items = [raw]
    codes: list[str] = []
    for item in items:
        if item is None:
            continue
        if isinstance(item, str) and not item.strip():
            continue
        try:
            code = _normalize_country_code(item)
        except ValueError:
            raise CountryPayloadError("neispravan kod države", "invalid_country")
        if not code:
            continue
        if code in codes:
            raise CountryPayloadError("Zemlja je već dodata", "duplicate_country")
        codes.append(code)
    return codes


def _prepare_suppliers_payload(raw_items, parse_float):
    """Validate and normalize the incoming supplier payload."""

    if raw_items is None:
        return []
    if not isinstance(raw_items, list):
        raise SupplierPayloadError("Lista dobavljača mora biti niz objekata", "invalid_suppliers")

    prepared = []
    seen_ids = set()
    for idx, item in enumerate(raw_items):
        if not isinstance(item, dict):
            raise SupplierPayloadError(f"Stavka #{idx + 1} mora biti objekat", "invalid_suppliers")

        supplier_id = item.get("supplier_id")
        if supplier_id is None:
            supplier_id = item.get("id")
        try:
            supplier_id_int = int(supplier_id)
        except (TypeError, ValueError):
            raise SupplierPayloadError(f"Neispravan supplier_id u stavci #{idx + 1}", "invalid_supplier_id")

        if supplier_id_int in seen_ids:
            raise SupplierPayloadError("Dobavljač je naveden više puta", "duplicate_supplier")
        seen_ids.add(supplier_id_int)

        supplier_obj = db.session.get(Supplier, supplier_id_int)
        if not supplier_obj:
            raise SupplierPayloadError(f"Dobavljač #{supplier_id_int} ne postoji", "supplier_not_found")

        raw_value = item.get("value")
        if raw_value is None:
            raw_value = item.get("goods_value")
        value = parse_float(raw_value)

        currency_raw = item.get("currency") or supplier_obj.default_currency or DEFAULT_SUPPLIER_CURRENCY
        currency = str(currency_raw).strip().upper() if currency_raw else DEFAULT_SUPPLIER_CURRENCY
        if currency not in ALLOWED_SUPPLIER_CURRENCIES:
            raise SupplierPayloadError(f"Valuta '{currency}' trenutno nije podržana", "invalid_currency")

        note_raw = item.get("note")
        note = note_raw.strip() if isinstance(note_raw, str) and note_raw.strip() else None

        prepared.append({
            "supplier": supplier_obj,
            "supplier_id": supplier_id_int,
            "value": value,
            "currency": currency,
            "note": note,
        })

    return prepared


def _dedup_join_supplier_names(links):
    names = []
    for link in links or []:
        supplier = getattr(link, "supplier", None)
        if supplier and supplier.name:
            names.append(supplier.name)
    if not names:
        return ""
    deduped = list(dict.fromkeys(names))
    return ", ".join(deduped)


def _recalculate_arrival_supplier_totals(a: Arrival) -> float:
    links = list(getattr(a, "suppliers", []) or [])
    total = 0.0
    for link in links:
        try:
            value = float(link.goods_value or 0.0)
        except (TypeError, ValueError):
            value = 0.0
        total += value
    if links:
        a.goods_cost = total
    return total


def delete_arrival_record(arrival_id: int):
    """Remove an arrival row (and related files) and broadcast the change."""
    a = Arrival.query.get(arrival_id)
    if not a:
        return jsonify({'error': 'Not found'}), 404

    # optional best-effort file cleanup (keep if present)
    try:
        import os
        from flask import current_app

        for f in list(getattr(a, 'files', []) or []):
            try:
                upload_folder = (current_app.config.get('UPLOAD_FOLDER') or '')
                if getattr(f, 'filename', None):
                    os.remove(os.path.join(upload_folder, f.filename))
            except Exception:
                pass
    except Exception:
        pass

    try:
        db.session.delete(a)
        db.session.commit()
    except Exception as err:
        try:
            db.session.rollback()
        except Exception:
            pass
        return jsonify({'error': 'delete_failed', 'detail': str(err)}), 500

    from datetime import datetime
    try:
        from app import notify

        title = (a.supplier or a.plate or '').strip()
        notify(
            f"Dolazak obrisan (#{arrival_id}{' – ' + title if title else ''})",
            ntype='warning',
            event='DELETED',
            entity_type='arrival',
            entity_id=arrival_id,
        )
    except Exception:
        pass
    try:
        from app import ws_broadcast  # type: ignore

        ws_broadcast({
            'type': 'arrivals.deleted',
            'resource': 'arrivals',
            'id': int(arrival_id),
            'v': 1,
            'ts': datetime.utcnow().isoformat() + 'Z',
        })
    except Exception:
        pass

    return jsonify({'ok': True, 'id': int(arrival_id)}), 200


def _parse_when(value: str | None):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except Exception:
        try:
            return datetime.fromisoformat(str(value).replace('Z', ''))
        except Exception:
            try:
                return datetime.strptime(str(value)[:10], '%Y-%m-%d')
            except Exception:
                return None


def _maybe_notify_arrival_overdue(a: Arrival):
    try:
        eta = _parse_when(a.eta)
        if not eta:
            return
        if str(a.status or '').lower() == 'arrived':
            return
        if eta.date() <= datetime.utcnow().date():
            from app import notify

            notify(
                f"Rok dolaska probijen (#{a.id})",
                ntype='warning',
                event='DEADLINE_BREACHED',
                entity_type='arrival',
                entity_id=a.id,
            )
    except Exception:
        pass

@bp.route("", methods=["GET", "HEAD", "OPTIONS"])
@bp.route("/", methods=["GET", "HEAD", "OPTIONS"])
def list_arrivals():
    if request.method == "OPTIONS":
        return ("", 204)
    arrivals = (
        Arrival.query.options(
            selectinload(Arrival.suppliers).selectinload(ArrivalSupplier.supplier)
        )
        .order_by(Arrival.created_at.desc())
        .all()
    )
    counts_map = dict(
        db.session.query(ArrivalFile.arrival_id, func.count(ArrivalFile.id))
        .group_by(ArrivalFile.arrival_id).all()
    )
    results = []
    for a in arrivals:
        d = a.to_dict()
        d["files_count"] = int(counts_map.get(a.id, 0))
        results.append(d)
    return jsonify(results)

@bp.get("/<int:id>")
def get_arrival(id):
    a = (
        Arrival.query.options(
            selectinload(Arrival.suppliers).selectinload(ArrivalSupplier.supplier)
        ).get_or_404(id)
    )
    d = a.to_dict()
    d["files_count"] = db.session.query(func.count(ArrivalFile.id)).filter(ArrivalFile.arrival_id == a.id).scalar() or 0
    return jsonify(d)

@bp.get("/search")
def search_arrivals():
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', request.args.get('page_size', 20)))
        page = max(1, page); per_page = min(max(1, per_page), 100)
    except ValueError:
        return jsonify({'error': 'page/per_page must be integers'}), 400

    status = request.args.get('status'); supplier = request.args.get('supplier'); q = request.args.get('q')
    from_str = request.args.get('from'); to_str = request.args.get('to')
    sort = request.args.get('sort', 'created_at'); order = request.args.get('order', 'desc').lower()

    sort_field_map = {'created_at': Arrival.created_at, 'supplier': Arrival.supplier, 'status': Arrival.status}
    sort_col = sort_field_map.get(sort, Arrival.created_at)
    sort_expr = sort_col.desc() if order != 'asc' else sort_col.asc()
    query = Arrival.query.options(
        selectinload(Arrival.suppliers).selectinload(ArrivalSupplier.supplier)
    )
    if status: query = query.filter(Arrival.status == status)
    if supplier: query = query.filter(Arrival.supplier.ilike(f"%{supplier}%"))
    if q: query = query.filter(or_(Arrival.plate.ilike(f"%{q}%"), Arrival.carrier.ilike(f"%{q}%")))

    def parse_dt(val): 
        try: return datetime.fromisoformat(val) if val else None
        except Exception: return None
    from_dt, to_dt = parse_dt(from_str), parse_dt(to_str)
    if from_str and not from_dt: return jsonify({'error': "Invalid 'from' ISO datetime"}), 400
    if to_str and not to_dt: return jsonify({'error': "Invalid 'to' ISO datetime"}), 400
    if from_dt: query = query.filter(Arrival.created_at >= from_dt)
    if to_dt: query = query.filter(Arrival.created_at <= to_dt)

    total = query.count()
    items = query.order_by(sort_expr).offset((page-1)*per_page).limit(per_page).all()
    counts_map = {}
    if items:
        counts_map = dict(
            db.session.query(ArrivalFile.arrival_id, func.count(ArrivalFile.id))
            .filter(ArrivalFile.arrival_id.in_([a.id for a in items]))
            .group_by(ArrivalFile.arrival_id).all()
        )
    items_payload = []
    for a in items:
        d = a.to_dict(); d["files_count"] = int(counts_map.get(a.id, 0)); items_payload.append(d)
    return jsonify({'page': page, 'per_page': per_page, 'total': total, 'items': items_payload})

@bp.post("/")
@bp.post("")
def create_arrival():
    from app import _parse_iso, _parse_float, check_api_or_jwt, NOTIFY_ON_STATUS
    data = request.json or {}
    loc = data.get('location')
    if not loc:
        for alias in ('lokacija','store','shop','warehouse'):
            if alias in data and data.get(alias): loc = data.get(alias); break
    if isinstance(loc,str): loc = loc.strip()
    attempted_fields = set(data.keys() or [])
    ok, role, uid, err = check_api_or_jwt(attempted_fields)
    if not ok: return err
    try:
        countries_payload = _normalize_country_list(data.get('countries'))
        if not countries_payload and data.get('country') is not None:
            countries_payload = _normalize_country_list(data.get('country'))
    except CountryPayloadError as exc:
        return jsonify({'error': exc.code, 'message': exc.message}), 400
    try:
        suppliers_payload = _prepare_suppliers_payload(data.get('suppliers'), _parse_float)
    except SupplierPayloadError as exc:
        return jsonify({'error': exc.code, 'message': exc.message}), 400
    primary_country = countries_payload[0] if countries_payload else None
    a = Arrival(
        supplier=data.get('supplier'), carrier=data.get('carrier'), plate=data.get('plate'),
        driver=data.get('driver'), pickup_date=_parse_iso(data.get('pickup_date')), type=data.get('type','truck'),
        category=(data.get('category') or None),
        eta=data.get('eta'), status=data.get('status','not_shipped'), note=data.get('note'),
        order_date=_parse_iso(data.get('order_date')), production_due=_parse_iso(data.get('production_due')),
        shipped_at=_parse_iso(data.get('shipped_at')), arrived_at=_parse_iso(data.get('arrived_at')),
        customs_info=data.get('customs_info'), freight_cost=_parse_float(data.get('freight_cost')),
        goods_cost=_parse_float(data.get('goods_cost')), customs_cost=_parse_float(data.get('customs_cost')),
        currency=(data.get('currency') or 'EUR')[:8], responsible=data.get('responsible'),
        location=loc, assignee_id=data.get('assignee_id'),
        country=primary_country,
    )
    try:
        db.session.add(a)
        for entry in suppliers_payload:
            link = ArrivalSupplier(
                supplier_id=entry['supplier_id'],
                supplier=entry['supplier'],
                goods_value=entry['value'],
                currency=entry['currency'],
                note=entry['note'],
            )
            a.suppliers.append(link)
        if suppliers_payload:
            a.supplier = _dedup_join_supplier_names(a.suppliers)
        if countries_payload:
            for code in countries_payload:
                a.countries.append(ArrivalCountry(code=code))
            a.country = countries_payload[0]
        supplier_total = _recalculate_arrival_supplier_totals(a)
        if not suppliers_payload:
            try:
                a.goods_cost = _parse_float(data.get('goods_cost'))
            except Exception:
                pass
        db.session.commit()
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        return jsonify({'error': 'create_failed', 'detail': str(e)}), 500
    try:
        # CREATED notification with dedup key
        from app import notify
        notify(
            f"Novi dolazak (#{a.id}{' – ' + (a.supplier or '').strip() if (a.supplier or '').strip() else ''})",
            ntype='info', event='CREATED', dedup_key=f"arrival:{a.id}:created", entity_type='arrival', entity_id=a.id
        )
        _maybe_notify_arrival_overdue(a)
    except Exception:
        pass
    try:
        from app import ws_broadcast
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

@bp.patch("/<int:id>")
def update_arrival(id):
    a = Arrival.query.get_or_404(id)
    data = request.json or {}
    from app import _parse_iso, _parse_float, check_api_or_jwt, ROLE_FIELDS, can_edit
    attempted_fields = set(data.keys() or [])
    ok, role, uid, err = check_api_or_jwt(attempted_fields)
    if not ok: return err
    if 'location' not in data or (isinstance(data.get('location'),str) and not data.get('location').strip()):
        loc=None
        for alias in ('lokacija','store','shop','warehouse'):
            if alias in data and data.get(alias): loc=data.get(alias); break
        if isinstance(loc,str): loc=loc.strip()
        if loc is not None: data['location']=loc
    editable = ROLE_FIELDS.get(role,set()) if role and role!='system' else None
    def can_set(field): return True if role in ('admin','system') else field in (editable or set())
    if 'transport_type' in data and 'type' not in data and can_set('type'): data['type']=data.get('transport_type')
    if 'responsible' not in data:
        if 'assignee_name' in data and can_set('responsible'): data['responsible']=data.get('assignee_name')
        elif 'assignee' in data and can_set('responsible'): data['responsible']=data.get('assignee')
    for _k in ('responsible','location'):
        if _k in data and isinstance(data[_k],str): data[_k]=data[_k].strip()
    suppliers_payload = None
    if 'suppliers' in data and can_set('suppliers'):
        try:
            suppliers_payload = _prepare_suppliers_payload(data.get('suppliers'), _parse_float)
        except SupplierPayloadError as exc:
            return jsonify({'error': exc.code, 'message': exc.message}), 400
    countries_payload = None
    if ('countries' in data or 'country' in data) and can_set('country'):
        raw_countries = data.get('countries')
        if raw_countries is None and 'country' in data:
            raw_countries = data.get('country')
        try:
            countries_payload = _normalize_country_list(raw_countries)
        except CountryPayloadError as exc:
            return jsonify({'error': exc.code, 'message': exc.message}), 400
    for field in ['supplier','carrier','plate','driver','type','eta','status','note','customs_info','currency','assignee_id','responsible','location','category']:
        if field in data and can_set(field): setattr(a,field,data[field])
    if 'order_date' in data and can_set('order_date'): a.order_date=_parse_iso(data.get('order_date'))
    if 'production_due' in data and can_set('production_due'): a.production_due=_parse_iso(data.get('production_due'))
    if 'shipped_at' in data and can_set('shipped_at'): a.shipped_at=_parse_iso(data.get('shipped_at'))
    if 'arrived_at' in data and can_set('arrived_at'): a.arrived_at=_parse_iso(data.get('arrived_at'))
    if 'freight_cost' in data and can_set('freight_cost'): a.freight_cost=_parse_float(data.get('freight_cost'))
    if 'customs_cost' in data and can_set('customs_cost'): a.customs_cost=_parse_float(data.get('customs_cost'))
    if 'pickup_date' in data and can_set('pickup_date'): a.pickup_date=_parse_iso(data.get('pickup_date'))
    if 'country' in data and can_set('country'):
        try:
            a.country = _normalize_country_code(data.get('country'))
        except ValueError:
            return jsonify({'error': 'invalid_country', 'message': 'neispravan kod države'}), 400
    if suppliers_payload is not None:
        existing_by_supplier = {link.supplier_id: link for link in list(a.suppliers)}
        keep_supplier_ids = set()
        for entry in suppliers_payload:
            sid = entry['supplier_id']
            keep_supplier_ids.add(sid)
            link = existing_by_supplier.get(sid)
            if link:
                link.supplier_id = entry['supplier_id']
                link.goods_value = entry['value']
                link.currency = entry['currency']
                link.note = entry['note']
                if entry['supplier']:
                    link.supplier = entry['supplier']
            else:
                a.suppliers.append(ArrivalSupplier(
                    supplier_id=entry['supplier_id'],
                    supplier=entry['supplier'],
                    goods_value=entry['value'],
                    currency=entry['currency'],
                    note=entry['note'],
                ))
        for link in list(a.suppliers):
            if link.supplier_id not in keep_supplier_ids:
                db.session.delete(link)
        a.supplier = _dedup_join_supplier_names(a.suppliers)
        supplier_total = _recalculate_arrival_supplier_totals(a)
        if not list(a.suppliers or []):
            if 'goods_cost' in data and can_set('goods_cost'):
                a.goods_cost = _parse_float(data.get('goods_cost'))
        elif not supplier_total and 'goods_cost' in data and can_set('goods_cost'):
            a.goods_cost = _parse_float(data.get('goods_cost'))
    else:
        # No supplier payload provided; allow explicit goods_cost update for legacy flows
        if 'goods_cost' in data and can_set('goods_cost'):
            a.goods_cost=_parse_float(data.get('goods_cost'))
    if countries_payload is not None and can_set('country'):
        existing_codes = {(link.code or "").upper(): link for link in list(a.countries)}
        keep_codes = set()
        for code in countries_payload:
            keep_codes.add(code)
            if code not in existing_codes:
                a.countries.append(ArrivalCountry(code=code))
        for link in list(a.countries):
            if (link.code or "").upper() not in keep_codes:
                db.session.delete(link)
        a.country = countries_payload[0] if countries_payload else None
    elif 'country' in data and can_set('country'):
        try:
            normalized_single = _normalize_country_code(data.get('country'))
        except ValueError:
            return jsonify({'error': 'invalid_country', 'message': 'neispravan kod države'}), 400
        a.country = normalized_single
        if normalized_single:
            existing_codes = {(link.code or "").upper() for link in list(a.countries)}
            if normalized_single not in existing_codes:
                a.countries.append(ArrivalCountry(code=normalized_single))
    db.session.commit()
    # Notify meaningful changes (eta/location/note)
    try:
        from app import notify
        if 'eta' in data:
            notify(f"Promjena ETA (#{a.id})", ntype='info', entity_type='arrival', entity_id=a.id)
        if 'location' in data:
            notify(f"Promjena lokacije (#{a.id})", ntype='info', entity_type='arrival', entity_id=a.id)
        if 'note' in data:
            notify(f"Ažurirana napomena (#{a.id})", ntype='info', entity_type='arrival', entity_id=a.id)
    except Exception:
        pass
    try:
        from app import ws_broadcast
        ws_broadcast({
            'type': 'arrivals.updated',
            'resource': 'arrivals',
            'action': 'updated',
            'id': int(a.id),
            'v': 1,
            'ts': datetime.utcnow().isoformat() + 'Z',
            'changes': {k: data.get(k) for k in (data.keys() if isinstance(data, dict) else [])},
        })
    except Exception:
        pass
    _maybe_notify_arrival_overdue(a)
    return jsonify(a.to_dict())

@bp.patch("/<int:id>/status")
@jwt_required()
def update_arrival_status(id):
    from app import ALLOWED_STATUSES, NOTIFY_ON_STATUS, can_edit, ROLE_FIELDS, _parse_iso, _parse_float
    a = Arrival.query.get_or_404(id); claims=get_jwt(); uid=get_jwt_identity()
    role = claims.get('role','viewer'); user_id = int(uid) if uid is not None else None
    data=request.json or {}; attempted_fields=set(data.keys())
    if 'status' in data and data['status'] not in ALLOWED_STATUSES: return jsonify({'error':'Invalid status'}),400
    if not can_edit(role,attempted_fields): return jsonify({'error':'Forbidden for your role'}),403
    editable = ROLE_FIELDS.get(role,set()) | (ROLE_FIELDS.get('admin') if role=='admin' else set())
    for field in attempted_fields & editable:
        if field in {'order_date','production_due','shipped_at','arrived_at'}: setattr(a,field,_parse_iso(data[field]))
        elif field in {'freight_cost','customs_cost'}: setattr(a,field,_parse_float(data[field]))
        else: setattr(a,field,data[field])
    if 'status' in data:
        msg=f"Status changed to '{data['status']}'"
        db.session.add(ArrivalUpdate(arrival_id=a.id,user_id=user_id,message=msg))
        try:
            from app import notify
            today = datetime.utcnow().strftime('%Y%m%d')
            notify(
                f"Promjena statusa dolaska (#{a.id}) → {data['status']}",
                ntype='info', event='STATUS_CHANGED', dedup_key=f"arrival:{a.id}:status:{data['status']}:{today}", entity_type='arrival', entity_id=a.id
            )
        except Exception:
            pass
        if NOTIFY_ON_STATUS:
            try:
                send_email(
                    subject=f"[Arrivals] #{a.id} status → {data['status']}",
                    body=f"Supplier: {a.supplier}\\nPlate: {a.plate or '-'}\\nNew status: {data['status']}\\nBy: {claims.get('email')}",
                    to_list=all_user_emails()
                )
            except Exception as e: print("[STATUS MAIL ERROR]",e)
            # Also persist a UI notification for key transitions
            try:
                status_l = str(data['status']).lower()
                if status_l in ('shipped', 'u transportu', 'transport'):
                    notify(f"Promjena statusa na U transportu (#{a.id})", ntype='info', entity_type='arrival', entity_id=a.id)
                elif status_l in ('arrived', 'stiglo'):
                    notify(f"Stiglo (#{a.id})", ntype='success', entity_type='arrival', entity_id=a.id)
            except Exception:
                pass
    db.session.commit()
    try:
        from app import ws_broadcast
        ws_broadcast({
            'type': 'arrivals.updated',
            'resource': 'arrivals',
            'action': 'updated',
            'id': int(a.id),
            'v': 1,
            'ts': datetime.utcnow().isoformat() + 'Z',
            'changes': {k: data.get(k) for k in (data.keys() if isinstance(data, dict) else [])},
        })
    except Exception:
        pass
    _maybe_notify_arrival_overdue(a)
    return jsonify(a.to_dict())


@bp.route("/<int:id>", methods=["DELETE", "OPTIONS"], strict_slashes=False)
def delete_arrival(id: int):
    if request.method == 'OPTIONS':
        return ("", 204)
    from flask_jwt_extended import verify_jwt_in_request
    try:
        verify_jwt_in_request(optional=False)
    except Exception:
        from flask import jsonify
        return jsonify({'error': 'Unauthorized'}), 401
    return delete_arrival_record(id)

@bp.delete("/")
@jwt_required(optional=True)
def delete_arrivals_querystring():
    from app import has_valid_api_key
    qs_ids=request.args.get('ids'); body=request.get_json(silent=True) or {}; body_ids=body.get('ids') if isinstance(body,dict) else []
    ids=[]
    if qs_ids:
        try: ids.extend([int(x) for x in qs_ids.split(',') if x.strip()])
        except Exception: return jsonify({'error':'ids in querystring must be comma-separated integers'}),400
    if isinstance(body_ids,list):
        try: ids.extend([int(x) for x in body_ids])
        except Exception: return jsonify({'error':'ids in JSON must be integers'}),400
    ids=list(sorted(set(ids)))
    if not (has_valid_api_key()):
        try: verify_jwt_in_request(optional=False)
        except Exception: return jsonify({'error':'Unauthorized'}),401
        claims=get_jwt()
        if (claims or {}).get('role')!='admin': return jsonify({'error':'Admin only'}),403
    if not ids: return jsonify({'ok':True,'deleted':[]})
    try:
        file_rows=db.session.query(ArrivalFile.filename).filter(ArrivalFile.arrival_id.in_(ids)).all()
        for (fname,) in file_rows:
            try: os.remove(os.path.join(current_app.config['UPLOAD_FOLDER'],fname))
            except Exception: pass
    except Exception: pass
    db.session.query(Arrival).filter(Arrival.id.in_(ids)).delete(synchronize_session=False)
    db.session.commit()
    try:
        from app import ws_broadcast
        ws_broadcast({
            'type': 'system.bulk',
            'v': 1,
            'ts': datetime.utcnow().isoformat() + 'Z',
            'events': [
                {'type':'arrivals.deleted','resource':'arrivals','action':'deleted','id': int(x), 'v':1, 'ts': datetime.utcnow().isoformat() + 'Z'}
                for x in ids
            ],
        })
    except Exception:
        pass
    return jsonify({'ok':True,'deleted':ids}),200

@bp.get("/<int:arrival_id>/updates")
@jwt_required(optional=True)
def list_updates(arrival_id):
    updates=ArrivalUpdate.query.filter_by(arrival_id=arrival_id).order_by(ArrivalUpdate.created_at.asc()).all()
    return jsonify([{'id':u.id,'arrival_id':u.arrival_id,'user_id':u.user_id,'message':u.message,'created_at':u.created_at.isoformat()} for u in updates])

@bp.post("/<int:arrival_id>/updates")
@jwt_required()
def create_update(arrival_id):
    Arrival.query.get_or_404(arrival_id); uid=get_jwt_identity(); msg=(request.json or {}).get('message','').strip()
    if not msg: return jsonify({'error':'message required'}),400
    upd=ArrivalUpdate(arrival_id=arrival_id,user_id=int(uid) if uid else None,message=msg)
    db.session.add(upd); db.session.commit()
    return jsonify({'id':upd.id,'arrival_id':upd.arrival_id,'user_id':upd.user_id,'message':upd.message,'created_at':upd.created_at.isoformat()}),201

@bp.post("/<int:arrival_id>/files")
@jwt_required()
def upload_file(arrival_id):
    Arrival.query.get_or_404(arrival_id)
    files=[]; 
    if 'files' in request.files: files.extend(request.files.getlist('files'))
    if 'file' in request.files: files.append(request.files['file'])
    if not files: return jsonify({'error':'file/files missing'}),400
    recs=[]
    for f in files:
        if not f or f.filename=='': continue
        safe_name=secure_filename(f.filename); unique_name=f"{int(time.time()*1000)}_{safe_name}"
        path=os.path.join(current_app.config['UPLOAD_FOLDER'],unique_name); f.save(path)
        rec=ArrivalFile(arrival_id=arrival_id,filename=unique_name,original_name=safe_name)
        db.session.add(rec); db.session.flush()
        recs.append({'id':rec.id,'arrival_id':rec.arrival_id,'filename':rec.filename,'original_name':rec.original_name,'uploaded_at':(rec.uploaded_at or datetime.utcnow()).isoformat(),'url':f"/files/{rec.filename}"})
    db.session.commit();
    try:
        from app import notify
        notify(f"Dodati fajlovi (#{arrival_id})", ntype='info', entity_type='arrival', entity_id=arrival_id)
    except Exception:
        pass
    return jsonify(recs),201

@bp.get("/<int:arrival_id>/files")
@jwt_required(optional=True)
def list_files(arrival_id):
    Arrival.query.get_or_404(arrival_id)
    files=ArrivalFile.query.filter_by(arrival_id=arrival_id).order_by(ArrivalFile.uploaded_at.asc()).all()
    return jsonify([{'id':f.id,'arrival_id':f.arrival_id,'filename':f.filename,'original_name':f.original_name,'uploaded_at':f.uploaded_at.isoformat(),'url':f"/files/{f.filename}"} for f in files])

@bp.delete("/<int:arrival_id>/files/<int:file_id>")
@jwt_required(optional=True)
def delete_file(arrival_id,file_id):
    from app import has_valid_api_key
    if not (has_valid_api_key()):
        try: verify_jwt_in_request(optional=False)
        except Exception: return jsonify({'error':'Unauthorized'}),401
        claims=get_jwt()
        if (claims or {}).get('role')!='admin': return jsonify({'error':'Admin only'}),403
    rec=ArrivalFile.query.filter_by(id=file_id,arrival_id=arrival_id).first()
    if not rec: return jsonify({'error':'Not found'}),404
    try: os.remove(os.path.join(current_app.config['UPLOAD_FOLDER'],rec.filename))
    except Exception: pass
    db.session.delete(rec); db.session.commit()
    try:
        from app import notify
        notify(f"Obrisan fajl (#{arrival_id})", ntype='warning', entity_type='arrival', entity_id=arrival_id)
    except Exception:
        pass
    return jsonify({'ok':True,'deleted_id':file_id})
