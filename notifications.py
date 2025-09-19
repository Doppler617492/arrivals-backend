from flask import Blueprint, request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from datetime import datetime

from extensions import db
from models import Notification
from app import ws_broadcast

bp = Blueprint("notifications", __name__, url_prefix="/api/notifications")


def _current_user():
    try:
        verify_jwt_in_request(optional=True)
    except Exception:
        return None, {}
    uid = get_jwt_identity()
    claims = get_jwt() or {}
    try:
        return (int(uid) if uid is not None else None), claims
    except Exception:
        return None, claims


@bp.route("", methods=["GET"], strict_slashes=False)
@bp.route("/", methods=["GET"], strict_slashes=False)
def list_notifications():
    # Global visibility: return latest notifications regardless of role/user
    unread = (str(request.args.get("unread", "")).lower() in ("1","true","yes","on"))
    limit = request.args.get("limit")
    try:
        limit = int(limit) if limit else 50
    except Exception:
        limit = 50
    limit = max(1, min(limit, 200))

    q = Notification.query
    if unread:
        q = q.filter(Notification.read.is_(False))

    # Optional type/entity filters
    t = request.args.get("type")
    if t:
        q = q.filter(Notification.type == t)
    et = request.args.get("entity_type")
    if et:
        q = q.filter(Notification.entity_type == et)
    eid = request.args.get("entity_id")
    if eid:
        try:
            q = q.filter(Notification.entity_id == int(eid))
        except Exception:
            pass

    items = q.order_by(Notification.created_at.desc()).limit(limit).all()

    # Augment with a navigate_url convention for the UI
    out = []
    for n in items:
        d = n.to_dict()
        if n.entity_type == 'arrival' and n.entity_id:
            d['navigate_url'] = f"/arrivals#{n.entity_id}"
        elif n.entity_type == 'container' and n.entity_id:
            d['navigate_url'] = f"/containers#{n.entity_id}"
        out.append(d)
    return jsonify(out)


@bp.get("/count")
def count_notifications():
    # Global count (no role/user filter)
    unread = (str(request.args.get("unread", "")).lower() in ("1","true","yes","on"))
    q = Notification.query
    if unread:
        q = q.filter(Notification.read.is_(False))
    try:
        n = q.count()
    except Exception:
        n = 0
    return jsonify({'count': n, 'unread': bool(unread)})


@bp.post("")
@bp.post("/")
def create_notification():
    uid, claims = _current_user()
    # Only admin/system can create arbitrary notifications
    role = (claims or {}).get('role')
    if role not in ('admin',):
        return jsonify({'error': 'Forbidden'}), 403
    payload = request.get_json(silent=True) or {}
    text = (payload.get('text') or '').strip()
    if not text:
        return jsonify({'error': 'text required'}), 400
    n = Notification(
        user_id=payload.get('user_id'),
        role=payload.get('role'),
        type=payload.get('type') or 'info',
        entity_type=payload.get('entity_type'),
        entity_id=payload.get('entity_id'),
        text=text,
        read=bool(payload.get('read') or False),
    )
    db.session.add(n)
    db.session.commit()
    try:
        ws_broadcast({'type':'notifications.created','resource':'notifications','action':'created','id':int(n.id),'v':1,'ts':datetime.utcnow().isoformat()+'Z','data':n.to_dict()})
    except Exception:
        pass
    return jsonify(n.to_dict()), 201


@bp.patch("/<int:nid>")
def update_notification(nid: int):
    uid, claims = _current_user()
    n = Notification.query.get_or_404(nid)
    if n.user_id is not None and uid != n.user_id and (claims or {}).get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    payload = request.get_json(silent=True) or {}
    if 'read' in payload:
        n.read = bool(payload.get('read'))
    db.session.commit()
    try:
        ws_broadcast({'type':'notifications.updated','resource':'notifications','action':'updated','id':int(n.id),'v':1,'ts':datetime.utcnow().isoformat()+'Z','data':n.to_dict()})
    except Exception:
        pass
    return jsonify(n.to_dict())


@bp.delete("/<int:nid>")
def delete_notification(nid: int):
    uid, claims = _current_user()
    n = Notification.query.get_or_404(nid)
    # Allow delete if: owner; or admin; or matches user's role when role-targeted
    user_role = (claims or {}).get('role')
    if n.user_id is not None and uid != n.user_id and (claims or {}).get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    if n.user_id is None and n.role is not None and user_role != n.role and (claims or {}).get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    db.session.delete(n)
    db.session.commit()
    try:
        ws_broadcast({'type':'notifications.deleted','resource':'notifications','action':'deleted','id':int(nid),'v':1,'ts':datetime.utcnow().isoformat()+'Z'})
    except Exception:
        pass
    return jsonify({'ok': True, 'deleted_id': nid})


@bp.post("/ack")
def ack_notifications():
    uid, claims = _current_user()
    payload = request.get_json(silent=True) or {}
    ids = payload.get('ids') or []
    mark_read = bool(payload.get('read', True))
    if not isinstance(ids, list):
        return jsonify({'error': 'ids must be an array'}), 400
    rows = Notification.query.filter(Notification.id.in_(ids)).all() if ids else []
    changed = []
    for n in rows:
        # Only allow ack on own or role-targeted; admin can ack all
        user_role = (claims or {}).get('role')
        if n.user_id is not None and uid != n.user_id and (claims or {}).get('role') != 'admin':
            continue
        if n.user_id is None and n.role is not None and user_role != n.role and (claims or {}).get('role') != 'admin':
            continue
        n.read = mark_read
        changed.append(int(n.id))
    if changed:
        db.session.commit()
        try:
            ws_broadcast({'type':'notifications.bulk','resource':'notifications','action':'ack','ids':changed,'v':1,'ts':datetime.utcnow().isoformat()+'Z'})
        except Exception:
            pass
    return jsonify({'ok': True, 'acknowledged': changed})


@bp.post("/<int:nid>/open")
def open_notification(nid: int):
    uid, claims = _current_user()
    n = Notification.query.get_or_404(nid)
    if n.user_id is not None and uid != n.user_id and (claims or {}).get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    # Emit a UI-focused event so the client can focus the linked entity
    try:
        evt = {
            'type': 'ui.focus',
            'resource': n.entity_type,
            'action': 'focus',
            'id': n.entity_id,
            'notification_id': n.id,
            'v': 1,
            'ts': datetime.utcnow().isoformat() + 'Z',
        }
        ws_broadcast(evt)
        # Emit a legacy/specific event name to simplify frontend wiring
        if n.entity_type == 'arrival' and n.entity_id:
            ws_broadcast({'type': 'focus-arrival', 'id': n.entity_id, 'notification_id': n.id, 'v': 1, 'ts': evt['ts']})
    except Exception:
        pass
    # Mark as read by default when opened
    n.read = True
    db.session.commit()
    return jsonify({'ok': True})


@bp.post("/bulk_delete")
def bulk_delete_notifications():
    uid, claims = _current_user()
    payload = request.get_json(silent=True) or {}
    all_flag = bool(payload.get('all'))
    unread_only = bool(payload.get('unread'))
    user_role = (claims or {}).get('role')
    deleted: list[int] = []

    if all_flag:
        q = Notification.query
        if unread_only:
            q = q.filter(Notification.read.is_(False))
        # Scope by permissions
        if user_role == 'admin':
            # Admin clears everything (respecting unread filter if set)
            ids = [int(r.id) for r in q.with_entities(Notification.id).all()]
            if ids:
                Notification.query.filter(Notification.id.in_(ids)).delete(synchronize_session=False)
                deleted.extend(ids)
        else:
            # Non-admin: only own or role-targeted
            own_q = q.filter(Notification.user_id == uid)
            role_q = q.filter(Notification.user_id.is_(None), Notification.role == user_role)
            ids = [int(r.id) for r in own_q.with_entities(Notification.id).all()]
            ids += [int(r.id) for r in role_q.with_entities(Notification.id).all()]
            if ids:
                Notification.query.filter(Notification.id.in_(ids)).delete(synchronize_session=False)
                deleted.extend(ids)
    else:
        ids = payload.get('ids') or []
        if not isinstance(ids, list):
            return jsonify({'error': 'ids must be an array'}), 400
        if not ids:
            return jsonify({'ok': True, 'deleted': []})
        rows = Notification.query.filter(Notification.id.in_(ids)).all()
        for n in rows:
            # Admin can delete anything
            if user_role == 'admin':
                db.session.delete(n); deleted.append(int(n.id)); continue
            # Owner can delete own
            if n.user_id is not None and uid == n.user_id:
                db.session.delete(n); deleted.append(int(n.id)); continue
            # Role-targeted can be deleted by same-role users
            if n.user_id is None and n.role is not None and user_role == n.role:
                db.session.delete(n); deleted.append(int(n.id)); continue
    if deleted:
        db.session.commit()
        try:
            ws_broadcast({'type':'notifications.bulk','resource':'notifications','action':'deleted','ids':deleted,'v':1,'ts':datetime.utcnow().isoformat()+'Z'})
        except Exception:
            pass
    return jsonify({'ok': True, 'deleted': deleted})
