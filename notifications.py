from flask import Blueprint, request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from datetime import datetime
from sqlalchemy import or_, and_

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

    since_id = request.args.get("since_id")
    if since_id:
        try:
            since_id = int(since_id)
            q = q.filter(Notification.id > since_id)
        except Exception:
            since_id = None
    items = q.order_by(Notification.id.asc() if since_id else Notification.created_at.desc()).limit(limit).all()

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


@bp.get("/stream")
def stream_notifications_sse():
    from flask import Response
    import time

    def gen():
        try:
            since_id = request.args.get('since_id')
            try:
                since = int(since_id) if since_id else 0
            except Exception:
                since = 0
            # First batch: send any pending since_id
            initial = Notification.query.filter(Notification.id > since).order_by(Notification.id.asc()).limit(200).all()
            for n in initial:
                payload = n.to_dict()
                yield f"event: notifications.created\nid: {n.id}\ndata: {json.dumps(payload)}\n\n"
                since = int(n.id)
            # Polling loop (lightweight)
            while True:
                time.sleep(2)
                newer = Notification.query.filter(Notification.id > since).order_by(Notification.id.asc()).limit(200).all()
                for n in newer:
                    payload = n.to_dict()
                    yield f"event: notifications.created\nid: {n.id}\ndata: {json.dumps(payload)}\n\n"
                    since = int(n.id)
        except GeneratorExit:
            return
        except Exception:
            return

    headers = {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no',
    }
    return Response(gen(), headers=headers)


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


@bp.post("/bulk_delete")
def bulk_delete_notifications():
    """Delete notifications in bulk.
    Body: { unread: boolean } — when true, deletes only unread; otherwise deletes all accessible notifications.
    Returns: { ok: true, deleted_count: number }
    """
    try:
        verify_jwt_in_request(optional=True)
    except Exception:
        return jsonify({'error': 'Unauthorized'}), 401

    uid, claims = _current_user()
    claims = claims or {}
    user_role = claims.get('role')
    if uid is None and user_role is None:
        # An authenticated principal must be identifiable either by id or role.
        return jsonify({'error': 'Forbidden'}), 403

    payload = (request.get_json(silent=True) or {})
    unread_only = str(payload.get('unread', '')).lower() in ('1','true','yes','on')

    try:
        q = Notification.query
        if unread_only:
            q = q.filter(Notification.read.is_(False))

        if user_role != 'admin':
            allowed_filters = []
            if uid is not None:
                allowed_filters.append(Notification.user_id == uid)
            if user_role:
                allowed_filters.append(and_(Notification.user_id.is_(None), Notification.role == user_role))
            # Global notifications without explicit ownership stay deletable, matching single-delete behaviour.
            allowed_filters.append(and_(Notification.user_id.is_(None), Notification.role.is_(None)))
            q = q.filter(or_(*allowed_filters))

        deleted_count = q.delete(synchronize_session=False)
        db.session.commit()
        try:
            ws_broadcast({'type':'notifications.bulk','resource':'notifications','action':'deleted','count':int(deleted_count),'v':1,'ts':datetime.utcnow().isoformat()+'Z'})
        except Exception:
            pass
        return jsonify({'ok': True, 'deleted_count': int(deleted_count)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error':'delete_failed','detail':str(e)}), 500


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
