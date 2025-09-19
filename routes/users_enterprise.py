from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone, date
from typing import Any, Dict, List, Optional

from flask import Blueprint, request, jsonify, Response, current_app, send_from_directory
from flask_jwt_extended import jwt_required, get_jwt_identity

from extensions import db
from models import (
    User, Role, UserRole, Session as UserSession,
    NotificationPref, AuditLog, ArrivalUpdate, Arrival, UserNote, UserFile
)
from sqlalchemy import func
import os
from werkzeug.utils import secure_filename

bp = Blueprint("enterprise_users", __name__, url_prefix="/api/users")


# --- helpers -----------------------------------------------------------------

def _now_utc():
    try:
        return datetime.now(timezone.utc)
    except Exception:
        return datetime.utcnow()


def _actor_id() -> Optional[int]:
    ident = get_jwt_identity()
    try:
        return int(ident) if ident is not None else None
    except Exception:
        return None


def _audit(event: str, target_type: str, target_id: Optional[int] = None, meta: Optional[dict] = None) -> None:
    try:
        rec = AuditLog(
            actor_user_id=_actor_id(),
            event=event,
            target_type=target_type,
            target_id=target_id,
            meta=json.dumps(meta or {})[:4000],
        )
        db.session.add(rec)
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass


def _parse_since(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip().lower()
    if s.endswith("d") and s[:-1].isdigit():
        days = int(s[:-1])
        return _now_utc() - timedelta(days=days)
    if s in ("24h", "1d"):
        return _now_utc() - timedelta(days=1)
    if s == "7d":
        return _now_utc() - timedelta(days=7)
    if s == "30d":
        return _now_utc() - timedelta(days=30)
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _productivity_for_user(uid: int, since: datetime, days: int = 7) -> Dict[str, Any]:
    # Processed: arrivals assigned to user and arrived within range
    start = since
    end = _now_utc()
    arrivals_q = db.session.query(Arrival).filter(Arrival.assignee_id == uid)
    if start:
        arrivals_q = arrivals_q.filter(Arrival.arrived_at.isnot(None)).filter(Arrival.arrived_at >= start)
    arrivals = arrivals_q.all()

    processed = len(arrivals)

    # Avg duration: order_date -> arrived_at for processed
    durations = []
    on_time = 0
    for a in arrivals:
        try:
            if a.order_date and a.arrived_at:
                dt = (a.arrived_at - a.order_date).total_seconds() / 60.0
                durations.append(dt)
        except Exception:
            pass
        # On-time: arrived_at date <= ETA date if ETA parseable; fallback to production_due
        try:
            eta_date = None
            if a.eta:
                # Arrival.eta is string in this schema; try parse YYYY-MM-DD first
                try:
                    eta_date = datetime.fromisoformat(str(a.eta)).date()
                except Exception:
                    # try generic date tokens
                    from app import _parse_date_any  # type: ignore
                    eta_date = _parse_date_any(a.eta)
            pdue_date = a.production_due.date() if getattr(a, 'production_due', None) else None
            ref_date = eta_date or pdue_date
            if ref_date and a.arrived_at and a.arrived_at.date() <= ref_date:
                on_time += 1
        except Exception:
            pass

    avg_duration = (sum(durations)/len(durations)) if durations else None
    on_time_pct = round(100.0 * on_time / processed, 1) if processed else None

    # Series by day (last N days): count of processed arrivals per calendar day
    series_map: Dict[str, int] = {}
    for a in arrivals:
        try:
            d = a.arrived_at.date().isoformat()
            series_map[d] = series_map.get(d, 0) + 1
        except Exception:
            continue
    series_day = []
    for i in range(days):
        d = (end.date() - timedelta(days=days-1-i)).isoformat()
        series_day.append({"date": d, "count": int(series_map.get(d, 0))})

    # Heatmap: buckets by weekday (0-6) x hour (0-23) of ArrivalUpdate activity
    upd_q = db.session.query(ArrivalUpdate).filter(ArrivalUpdate.user_id == uid)
    if start:
        upd_q = upd_q.filter(ArrivalUpdate.created_at >= start)
    heat = [[0 for _ in range(24)] for __ in range(7)]
    for u in upd_q.all():
        try:
            ts = u.created_at or _now_utc()
            w = int(ts.weekday())
            h = int(ts.hour)
            heat[w][h] += 1
        except Exception:
            continue

    return {
        "processed": int(processed),
        "avg_duration_minutes": round(avg_duration, 1) if avg_duration is not None else None,
        "on_time_pct": on_time_pct,
        "series_day": series_day,
        "heatmap": heat,  # 7x24 matrix
    }


def _compute_last_activity(user: User) -> datetime:
    if user.last_activity_at:
        return user.last_activity_at
    # fallback to latest update
    upd = db.session.query(ArrivalUpdate).filter(ArrivalUpdate.user_id == user.id).order_by(ArrivalUpdate.created_at.desc()).first()
    if upd:
        return upd.created_at
    return user.updated_at or user.created_at or _now_utc()


# --- routes ------------------------------------------------------------------

@bp.get("")
@jwt_required()
def list_users():
    role = (request.args.get("role") or "").strip().lower()
    status = (request.args.get("status") or "").strip().lower()
    since_s = request.args.get("since") or ""
    since = _parse_since(since_s) or (_now_utc() - timedelta(days=7))

    q = db.session.query(User)
    if role:
        q = q.filter(User.role == role)
    if status:
        q = q.filter(User.status == status)

    rows = q.order_by(User.created_at.desc()).all()
    out = []
    for u in rows:
    days = 7 if since_s in ("", "7d") else (1 if since_s == "24h" else 30)
    prod = _productivity_for_user(u.id, since, days)
    # tasks_today: arrivals assigned to user with due today and not arrived
    tasks_today = 0
    try:
        today = _now_utc().date()
        tasks_today = db.session.query(Arrival).filter(
            Arrival.assignee_id == u.id,
            Arrival.arrived_at.is_(None),
            (
                (Arrival.production_due.isnot(None) & (func.date(Arrival.production_due) == today)) |
                (Arrival.eta.isnot(None))
            )
        ).count()
    except Exception:
        tasks_today = 0
        out.append({
            **u.to_dict(),
            "tasks_today": int(tasks_today),
            "kpi_7d": prod,
            "last_activity_at": (_compute_last_activity(u) or _now_utc()).isoformat(),
        })
    return jsonify(out), 200


@bp.post("/invite")
@jwt_required()
def invite_user():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    name = (data.get("name") or "").strip()
    role = (data.get("role") or "viewer").strip().lower()
    if not email:
        return jsonify({"error": "email_required"}), 400
    if db.session.query(User).filter_by(email=email).first():
        return jsonify({"error": "email_exists"}), 400
    u = User(email=email, name=name, role=role, status="invited", is_active=True)
    db.session.add(u)
    db.session.flush()
    # lightweight invite token – single-use link (server does not enforce yet)
    token = f"invite-{u.id}-{int(_now_utc().timestamp())}"
    link = f"{request.host_url.rstrip('/')}#/register?token={token}"
    _audit("users.invite", target_type="user", target_id=int(u.id), meta={"email": email})
    db.session.commit()
    return jsonify({"ok": True, "user_id": int(u.id), "invite_link": link, "token": token}), 201


@bp.patch("/<int:uid>")
@jwt_required()
def update_profile(uid: int):
    u = db.session.get(User, uid)
    if not u:
        return jsonify({"error": "not_found"}), 404
    data = request.get_json(silent=True) or {}
    for k in ["name", "phone", "type", "status", "username", "role", "is_active"]:
        if k in data:
            setattr(u, k, data.get(k))
    db.session.commit()
    _audit("users.update", target_type="user", target_id=uid, meta={"fields": list(data.keys())})
    return jsonify(u.to_dict()), 200


@bp.post("/<int:uid>/roles")
@jwt_required()
def set_roles(uid: int):
    data = request.get_json(silent=True) or {}
    role_keys: List[str] = list(data.get("roles") or [])
    scope: List[str] = list(data.get("scope") or [])
    u = db.session.get(User, uid)
    if not u:
        return jsonify({"error": "not_found"}), 404
    # sync primary role to first if provided for compatibility
    if role_keys:
        u.role = role_keys[0]
    # ensure roles exist
    existing = {r.key: r for r in db.session.query(Role).filter(Role.key.in_(role_keys or [""])).all()}
    ids = []
    for key in role_keys:
        if key not in existing:
            r = Role(key=key, name=key.title())
            db.session.add(r)
            db.session.flush()
            existing[key] = r
        ids.append(existing[key].id)
    # replace assignments
    db.session.query(UserRole).filter_by(user_id=uid).delete()
    for rid in ids:
        db.session.add(UserRole(user_id=uid, role_id=rid, scope_location_ids=",".join(scope)))
    db.session.commit()
    _audit("users.roles.set", target_type="user", target_id=uid, meta={"roles": role_keys, "scope": scope})
    return jsonify({"ok": True}), 200


@bp.get("/<int:uid>/sessions")
@jwt_required()
def list_sessions(uid: int):
    sess = db.session.query(UserSession).filter_by(user_id=uid).order_by(UserSession.created_at.desc()).all()
    return jsonify([
        {
            "id": s.id,
            "ip": s.ip,
            "ua": s.ua,
            "os": s.os,
            "trusted": bool(s.trusted),
            "revoked": bool(s.revoked),
            "last_seen_at": (s.last_seen_at or _now_utc()).isoformat(),
            "created_at": (s.created_at or _now_utc()).isoformat(),
        } for s in sess
    ])


@bp.delete("/<int:uid>/sessions/<int:sid>")
@jwt_required()
def revoke_session(uid: int, sid: int):
    s = db.session.get(UserSession, sid)
    if not s or s.user_id != uid:
        return jsonify({"error": "not_found"}), 404
    s.revoked = True
    db.session.commit()
    _audit("users.sessions.revoke", target_type="session", target_id=sid, meta={"user_id": uid})
    return jsonify({"ok": True})


@bp.delete("/<int:uid>/sessions")
@jwt_required()
def revoke_all_sessions(uid: int):
    q = db.session.query(UserSession).filter_by(user_id=uid, revoked=False)
    n = 0
    for s in q.all():
        s.revoked = True
        n += 1
    db.session.commit()
    _audit("users.sessions.revoke_all", target_type="user", target_id=uid, meta={"count": n})
    return jsonify({"ok": True, "revoked": n})


@bp.post("/<int:uid>/password/reset")
@jwt_required()
def reset_password(uid: int):
    u = db.session.get(User, uid)
    if not u:
        return jsonify({"error": "not_found"}), 404
    data = request.get_json(silent=True) or {}
    generate_temp = bool(data.get("generate_temp", True))
    temp = None
    if generate_temp:
        import secrets, string
        alphabet = string.ascii_letters + string.digits
        temp = ''.join(secrets.choice(alphabet) for _ in range(10))
        # store in legacy plain for compatibility and set flag to change on first login
        u.password = temp
        u.must_change_password = True
    db.session.commit()
    _audit("users.password.reset", target_type="user", target_id=uid, meta={"generate_temp": generate_temp})
    return jsonify({"ok": True, "temp_password": temp})


@bp.get("/<int:uid>/audit")
@jwt_required()
def user_audit(uid: int):
    module = (request.args.get("module") or "").strip().lower()
    since = _parse_since(request.args.get("since"))
    q = db.session.query(AuditLog).filter(AuditLog.target_type.in_(["user", "session", "export"]))
    q = q.filter(AuditLog.target_id == uid)
    if since:
        q = q.filter(AuditLog.created_at >= since)
    if module:
        q = q.filter(AuditLog.event.like(f"{module}.%"))
    q = q.order_by(AuditLog.created_at.desc()).limit(200)
    rows = q.all()
    return jsonify([
        {
            "id": r.id,
            "event": r.event,
            "created_at": (r.created_at or _now_utc()).isoformat(),
            "meta": r.meta,
        } for r in rows
    ])


@bp.get("/<int:uid>/productivity")
@jwt_required()
def productivity(uid: int):
    rng = (request.args.get("range") or "7d").lower()
    since = _parse_since(rng) or (_now_utc() - timedelta(days=7))
    days = 7 if rng in ("", "7d") else (1 if rng == "24h" else 30)
    data = _productivity_for_user(uid, since, days)
    return jsonify({"range": rng, **data})


@bp.post("/<int:uid>/notifications")
@jwt_required()
def set_notifications(uid: int):
    data = request.get_json(silent=True) or {}
    prefs = list(data.get("prefs") or [])
    # replace all
    db.session.query(NotificationPref).filter_by(user_id=uid).delete()
    for p in prefs:
        db.session.add(NotificationPref(
            user_id=uid,
            channel=str(p.get("channel") or "email"),
            event_key=str(p.get("event_key") or ""),
            enabled=bool(p.get("enabled", True)),
            frequency=str(p.get("frequency") or "instant"),
        ))
    db.session.commit()
    _audit("users.notifications.set", target_type="user", target_id=uid, meta={"count": len(prefs)})
    return jsonify({"ok": True})


@bp.post("/export")
@jwt_required()
def export_users():
    # reuse filters from list
    role = (request.args.get("role") or "").strip().lower()
    status = (request.args.get("status") or "").strip().lower()
    q = db.session.query(User)
    if role:
        q = q.filter(User.role == role)
    if status:
        q = q.filter(User.status == status)
    rows = q.order_by(User.created_at.desc()).all()
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["id", "email", "username", "name", "role", "status", "type", "created_at", "last_activity_at"]) 
    for u in rows:
        w.writerow([
            u.id, u.email, u.username or "", u.name or "", u.role or "", u.status or "", u.type or "",
            (u.created_at or _now_utc()).isoformat(), (u.last_activity_at or _compute_last_activity(u)).isoformat(),
        ])
    payload = output.getvalue()
    _audit("users.export", target_type="export", target_id=None, meta={"count": len(rows)})
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return Response(
        payload,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=users_{ts}.csv"
        },
    )


# --- notes & files -----------------------------------------------------------

@bp.get("/<int:uid>/notes")
@jwt_required()
def get_notes(uid: int):
    rows = db.session.query(UserNote).filter_by(user_id=uid).order_by(UserNote.created_at.desc()).all()
    return jsonify([{
        "id": n.id,
        "user_id": n.user_id,
        "author_id": n.author_id,
        "text": n.text,
        "created_at": (n.created_at or _now_utc()).isoformat(),
    } for n in rows])


@bp.post("/<int:uid>/notes")
@jwt_required()
def add_note(uid: int):
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "text_required"}), 400
    n = UserNote(user_id=uid, author_id=_actor_id(), text=text)
    db.session.add(n)
    db.session.commit()
    _audit("users.notes.add", target_type="user", target_id=uid, meta={"note_id": n.id})
    return jsonify({"id": n.id, "created_at": (n.created_at or _now_utc()).isoformat()}), 201


@bp.delete("/<int:uid>/notes/<int:nid>")
@jwt_required()
def delete_note(uid: int, nid: int):
    n = db.session.get(UserNote, nid)
    if not n or n.user_id != uid:
        return jsonify({"error": "not_found"}), 404
    db.session.delete(n)
    db.session.commit()
    _audit("users.notes.delete", target_type="user", target_id=uid, meta={"note_id": nid})
    return jsonify({"ok": True})


@bp.get("/<int:uid>/files")
@jwt_required()
def get_files(uid: int):
    rows = db.session.query(UserFile).filter_by(user_id=uid).order_by(UserFile.created_at.desc()).all()
    return jsonify([{
        "id": f.id,
        "user_id": f.user_id,
        "file_path": f.file_path,
        "label": f.label,
        "created_at": (f.created_at or _now_utc()).isoformat(),
        "url": f"/api/users/{uid}/files/{f.id}/download",
    } for f in rows])


@bp.post("/<int:uid>/files")
@jwt_required()
def upload_file(uid: int):
    if 'file' not in request.files:
        return jsonify({"error": "file_required"}), 400
    f = request.files['file']
    if not f or not f.filename:
        return jsonify({"error": "empty_filename"}), 400
    label = request.form.get('label') or None
    safe_name = secure_filename(f.filename)
    uniq = f"{int(_now_utc().timestamp()*1000)}_{safe_name}"
    upload_dir = current_app.config.get('UPLOAD_FOLDER')
    os.makedirs(upload_dir, exist_ok=True)
    path = os.path.join(upload_dir, uniq)
    f.save(path)
    rec = UserFile(user_id=uid, file_path=uniq, label=label)
    db.session.add(rec)
    db.session.commit()
    _audit("users.files.upload", target_type="user", target_id=uid, meta={"file_id": rec.id, "name": safe_name})
    return jsonify({"id": rec.id, "url": f"/api/users/{uid}/files/{rec.id}/download"}), 201


@bp.delete("/<int:uid>/files/<int:fid>")
@jwt_required()
def delete_file(uid: int, fid: int):
    rec = db.session.get(UserFile, fid)
    if not rec or rec.user_id != uid:
        return jsonify({"error": "not_found"}), 404
    try:
        upload_dir = current_app.config.get('UPLOAD_FOLDER')
        os.remove(os.path.join(upload_dir, rec.file_path))
    except Exception:
        pass
    db.session.delete(rec)
    db.session.commit()
    _audit("users.files.delete", target_type="user", target_id=uid, meta={"file_id": fid})
    return jsonify({"ok": True})


@bp.get("/<int:uid>/files/<int:fid>/download")
@jwt_required()
def download_file(uid: int, fid: int):
    rec = db.session.get(UserFile, fid)
    if not rec or rec.user_id != uid:
        return jsonify({"error": "not_found"}), 404
    upload_dir = current_app.config.get('UPLOAD_FOLDER')
    return send_from_directory(upload_dir, rec.file_path, as_attachment=True)


# --- bulk actions ------------------------------------------------------------

@bp.post("/bulk/status")
@jwt_required()
def bulk_status():
    data = request.get_json(silent=True) or {}
    ids = list(data.get("ids") or [])
    status = (data.get("status") or "").strip().lower()
    n = 0
    for uid in ids:
        u = db.session.get(User, int(uid))
        if not u:
            continue
        u.status = status
        u.is_active = (status == "active")
        n += 1
    db.session.commit()
    _audit("users.bulk.status", target_type="user", target_id=None, meta={"count": n, "status": status})
    return jsonify({"ok": True, "updated": n})


@bp.post("/bulk/roles")
@jwt_required()
def bulk_roles():
    data = request.get_json(silent=True) or {}
    ids = list(data.get("ids") or [])
    roles = list(data.get("roles") or [])
    scope = list(data.get("scope") or [])
    n = 0
    existing = {r.key: r for r in db.session.query(Role).filter(Role.key.in_(roles or [""])).all()}
    for key in roles:
        if key not in existing:
            r = Role(key=key, name=key.title())
            db.session.add(r)
            db.session.flush()
            existing[key] = r
    for uid in ids:
        uid = int(uid)
        db.session.query(UserRole).filter_by(user_id=uid).delete()
        for key in roles:
            db.session.add(UserRole(user_id=uid, role_id=existing[key].id, scope_location_ids=",".join(scope)))
        # sync primary string role as first for compatibility
        u = db.session.get(User, uid)
        if u and roles:
            u.role = roles[0]
        n += 1
    db.session.commit()
    _audit("users.bulk.roles", target_type="user", target_id=None, meta={"count": n, "roles": roles, "scope": scope})
    return jsonify({"ok": True, "updated": n})


@bp.post("/bulk/reset_password")
@jwt_required()
def bulk_reset_password():
    data = request.get_json(silent=True) or {}
    ids = list(data.get("ids") or [])
    out: Dict[int, str] = {}
    for uid in ids:
        uid = int(uid)
        # reuse single reset but inline to avoid many audits
        import secrets, string
        u = db.session.get(User, uid)
        if not u:
            continue
        temp = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
        u.password = temp
        u.must_change_password = True
        out[uid] = temp
    db.session.commit()
    _audit("users.bulk.reset_password", target_type="user", target_id=None, meta={"count": len(out)})
    return jsonify({"ok": True, "temp_passwords": out})
