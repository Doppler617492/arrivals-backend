from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_, text

try:
    from extensions import db
except Exception:
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy()

from models import Arrival, Container

bp = Blueprint("analytics", __name__, url_prefix="/api/analytics")


def _parse_iso_date(s: str | None):
    if not s:
        return None
    try:
        # Accept YYYY-MM-DD or ISO strings
        if len(s) == 10:
            return datetime.fromisoformat(s)
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def _date_range_args():
    qs_from = request.args.get("from")
    qs_to = request.args.get("to")
    dfrom = _parse_iso_date(qs_from)
    dto = _parse_iso_date(qs_to)
    if not dfrom or not dto:
        # default: last 90 days window
        dto = datetime.utcnow()
        dfrom = dto - timedelta(days=90)
    return dfrom, dto


def _apply_common_filters(query):
    supplier = (request.args.get("supplier") or "").strip()
    agent = (request.args.get("agent") or "").strip()
    status = (request.args.get("status") or "").strip()
    location = (request.args.get("location") or "").strip()
    if supplier:
        query = query.filter(Arrival.supplier.ilike(f"%{supplier}%"))
    if agent and hasattr(Arrival, "agent"):
        query = query.filter(getattr(Arrival, "agent").ilike(f"%{agent}%"))
    if status:
        query = query.filter(Arrival.status == status)
    if location:
        query = query.filter(Arrival.location.ilike(f"%{location}%"))
    return query

# --- Date helpers for Arrival/Container ---
def _arrival_date_col():
    """Prefer arrived_at (timestamp), else cast ETA string 'YYYY-MM-DD' to DATE."""
    try:
        return func.coalesce(Arrival.arrived_at, func.to_date(Arrival.eta, 'YYYY-MM-DD'))
    except Exception:
        # Fallback: use arrived_at only
        return Arrival.arrived_at


def _arrival_cost(row: Arrival) -> float:
    try:
        return float((row.goods_cost or 0) + (row.freight_cost or 0) + (row.customs_cost or 0))
    except Exception:
        return 0.0


def _coerce_eta(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return _parse_iso_date(value)
    try:
        # Some deployments store ETA as date objects
        if hasattr(value, 'isoformat'):
            return datetime.fromisoformat(value.isoformat())
    except Exception:
        pass
    return None


def _arrival_delay_days(row: Arrival) -> float | None:
    try:
        eta_dt = _coerce_eta(getattr(row, 'eta', None))
        arrived_at = getattr(row, 'arrived_at', None)
        if not eta_dt or not arrived_at:
            return None
        return (arrived_at - eta_dt).total_seconds() / 86400.0
    except Exception:
        return None


def _fetch_arrivals_scope():
    dfrom, dto = _date_range_args()
    date_col = _arrival_date_col()
    q = db.session.query(Arrival).filter(date_col.between(dfrom, dto))
    q = _apply_common_filters(q)
    rows = q.all()
    return rows, dfrom, dto


def _aggregate_arrivals(rows: list[Arrival], attr: str, fallback_label: str):
    fallback = fallback_label or 'Neodređeno'
    bucket = {}
    for row in rows:
        raw = getattr(row, attr, None) if hasattr(row, attr) else None
        label = raw.strip() if isinstance(raw, str) else raw
        if not label:
            label = fallback
        label = str(label)
        data = bucket.setdefault(label, {
            'label': label,
            'count': 0,
            'total_value': 0.0,
            'late_samples': [],
            'scheduled_samples': 0,
            'on_time_or_early': 0,
        })
        data['count'] += 1
        data['total_value'] += _arrival_cost(row)
        delay_days = _arrival_delay_days(row)
        if delay_days is not None:
            data['scheduled_samples'] += 1
            if delay_days <= 0:
                data['on_time_or_early'] += 1
            else:
                data['late_samples'].append(delay_days)

    items = []
    for entry in bucket.values():
        late_samples = entry['late_samples']
        scheduled = entry['scheduled_samples'] or 0
        on_time = entry['on_time_or_early'] or 0
        avg_delay = (sum(late_samples) / len(late_samples)) if late_samples else 0.0
        on_time_rate = (on_time / scheduled) if scheduled else 0.0
        items.append({
            'label': entry['label'],
            'count': int(entry['count']),
            'total_value': float(entry['total_value']),
            'avg_delay_days': float(avg_delay),
            'on_time_rate': float(on_time_rate),
            'scheduled_samples': int(scheduled),
        })

    items.sort(key=lambda x: (x['total_value'], x['count']), reverse=True)
    return items


def _arrivals_breakdown_response(attr: str, fallback_label: str, error_key: str):
    try:
        rows, dfrom, dto = _fetch_arrivals_scope()
        items = _aggregate_arrivals(rows, attr, fallback_label)
        return jsonify({
            'items': items,
            'window': {'from': dfrom.isoformat(), 'to': dto.isoformat()},
        })
    except Exception as exc:
        return jsonify({'error': error_key, 'detail': str(exc)}), 500

# --- Containers helpers ---
def _money_to_number(val):
    if val is None:
        return 0.0
    try:
        s = str(val)
        s = "".join(ch for ch in s if ch.isdigit() or ch in ",.-")
        if "," in s and "." not in s:
            s = s.replace(",", ".")
        return float(s or 0)
    except Exception:
        return 0.0

def _apply_container_filters(query):
    supplier = (request.args.get("supplier") or "").strip()
    agent = (request.args.get("agent") or "").strip()
    status = (request.args.get("status") or "").strip()
    if supplier:
        query = query.filter(Container.supplier.ilike(f"%{supplier}%"))
    if agent and hasattr(Container, "agent"):
        query = query.filter(getattr(Container, "agent").ilike(f"%{agent}%"))
    if status:
        query = query.filter(Container.status == status)
    return query

def _container_date_col_from_param():
    """Pick date column based on ?date_field=etd|eta|delivery|created_at (default: etd when provided, else eta).
    Falls back safely to created_at as DATE.
    """
    field = (request.args.get('date_field') or request.args.get('dateField') or '').strip().lower()
    try:
        if field == 'etd' and hasattr(Container, 'etd'):
            return getattr(Container, 'etd')
        if field == 'delivery' and hasattr(Container, 'delivery'):
            return getattr(Container, 'delivery')
        if field == 'created_at':
            return func.date(Container.created_at)
        # Default preference: ETD if exists, else ETA, else created_at
        if hasattr(Container, 'etd'):
            return getattr(Container, 'etd')
        if hasattr(Container, 'eta'):
            return getattr(Container, 'eta')
        return func.date(Container.created_at)
    except Exception:
        return func.date(Container.created_at)

def _is_paid_flag(row_paid, row_status: str | None) -> bool:
    try:
        if row_paid is True:
            return True
        s = (row_status or '').strip().lower()
        return s in ('plaćeno','placeno','paid','uplaćeno','uplaceno')
    except Exception:
        return False


@bp.get("/arrivals/kpi")
def arrivals_kpi():
    try:
        dfrom, dto = _date_range_args()
        dcol = _arrival_date_col()
        base = db.session.query(Arrival).filter(or_(Arrival.arrived_at.isnot(None), Arrival.eta.isnot(None)))
        base = _apply_common_filters(base)
        base = base.filter(dcol.between(dfrom, dto))

        # Counts
        today = datetime.utcnow().date()
        today_cnt = base.filter(func.date(Arrival.eta) == today).count()
        in_transit = base.filter(Arrival.status == 'shipped').count()
        arrived = base.filter(Arrival.status == 'arrived').count()

        # Total cost in current month (or within window)
        month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        cost_q = _apply_common_filters(db.session.query(
            func.coalesce(func.sum(func.coalesce(Arrival.goods_cost,0) + func.coalesce(Arrival.freight_cost,0) + func.coalesce(Arrival.customs_cost,0)), 0)
        ))
        cost_q = cost_q.filter(_arrival_date_col() >= month_start)
        total_cost_month = float(cost_q.scalar() or 0.0)

        # Total/avg cost in window (YTD when called with from/to as current year)
        win_cost_q = _apply_common_filters(db.session.query(
            func.coalesce(func.sum(func.coalesce(Arrival.goods_cost,0) + func.coalesce(Arrival.freight_cost,0) + func.coalesce(Arrival.customs_cost,0)), 0)
        ))
        win_cost_q = win_cost_q.filter(_arrival_date_col().between(dfrom, dto))
        total_cost_window = float(win_cost_q.scalar() or 0.0)
        count_window = base.count()
        avg_cost_window = (total_cost_window / count_window) if count_window else 0.0

        return jsonify({
            'today_count': today_cnt,
            'in_transit': in_transit,
            'arrived': arrived,
            'total_cost_month': total_cost_month,
            'total_cost_window': total_cost_window,
            'avg_cost_window': avg_cost_window,
            'count_window': count_window,
            'window': {'from': dfrom.isoformat(), 'to': dto.isoformat()},
        })
    except Exception as e:
        return jsonify({'error':'analytics_kpi_failed','detail':str(e)}), 500


@bp.get("/arrivals/trend-costs")
def arrivals_trend_costs():
    try:
        dfrom, dto = _date_range_args()
        gran = (request.args.get('granularity') or 'month').lower()
        if gran not in ('month','week','day'):
            gran = 'month'
        # Choose date to bucket: arrived_at or cast(eta)
        date_col = _arrival_date_col()
        if gran == 'day':
            bucket = func.date(date_col)
        elif gran == 'week':
            bucket = func.date_trunc('week', date_col)
        else:
            bucket = func.date_trunc('month', date_col)

        q = db.session.query(
            bucket.label('period'),
            func.coalesce(func.sum(func.coalesce(Arrival.goods_cost,0) + func.coalesce(Arrival.freight_cost,0) + func.coalesce(Arrival.customs_cost,0)), 0).label('total')
        )
        q = q.filter(date_col.between(dfrom, dto))
        q = _apply_common_filters(q)
        q = q.group_by(bucket).order_by(bucket)
        rows = q.all()
        data = [{ 'period': (r.period.date().isoformat() if hasattr(r.period,'date') else str(r.period)), 'total': float(r.total) } for r in rows]
        return jsonify({'items': data})
    except Exception as e:
        return jsonify({'error':'analytics_trend_failed','detail':str(e)}), 500


@bp.get("/arrivals/cost-structure")
def arrivals_cost_structure():
    try:
        dfrom, dto = _date_range_args()
        q = db.session.query(
            func.coalesce(func.sum(Arrival.goods_cost), 0).label('goods'),
            func.coalesce(func.sum(Arrival.freight_cost), 0).label('freight'),
            func.coalesce(func.sum(Arrival.customs_cost), 0).label('customs')
        )
        q = _apply_common_filters(q)
        q = q.filter(_arrival_date_col().between(dfrom, dto))
        row = q.first()
        goods = float(row.goods or 0.0)
        freight = float(row.freight or 0.0)
        customs = float(row.customs or 0.0)
        total = goods + freight + customs
        return jsonify({
            'goods': goods,
            'freight': freight,
            'customs': customs,
            'total': total,
            'share': {
                'goods': (goods/total if total else 0.0),
                'freight': (freight/total if total else 0.0),
                'customs': (customs/total if total else 0.0),
            }
        })
    except Exception as e:
        return jsonify({'error':'analytics_structure_failed','detail':str(e)}), 500


@bp.get("/arrivals/list")
def arrivals_list_filtered():
    """Return a list of arrivals with common analytics filters applied.
    Useful for drill‑down modals (period/supplier/status/etc.).
    """
    try:
        dfrom, dto = _date_range_args()
        # Optional override for period via exact month (YYYY-MM)
        month = (request.args.get('month') or '').strip()
        if month and len(month) == 7:  # YYYY-MM
            try:
                y, m = month.split('-')
                y, m = int(y), int(m)
                dfrom = datetime(y, m, 1)
                if m == 12:
                    dto = datetime(y+1, 1, 1) - timedelta(seconds=1)
                else:
                    dto = datetime(y, m+1, 1) - timedelta(seconds=1)
            except Exception:
                pass

        date_col = _arrival_date_col()
        q = db.session.query(Arrival).filter(date_col.between(dfrom, dto))
        q = _apply_common_filters(q)
        rows = q.order_by(date_col.desc()).limit(1000).all()
        items = []
        for a in rows:
            items.append({
                'id': a.id,
                'supplier': a.supplier,
                'status': a.status,
                'eta': a.eta.isoformat() if getattr(a, 'eta', None) else None,
                'arrived_at': a.arrived_at.isoformat() if getattr(a, 'arrived_at', None) else None,
                'shipped_at': a.shipped_at.isoformat() if getattr(a, 'shipped_at', None) else None,
                'goods_cost': float(getattr(a, 'goods_cost', 0) or 0),
                'freight_cost': float(getattr(a, 'freight_cost', 0) or 0),
                'customs_cost': float(getattr(a, 'customs_cost', 0) or 0),
                'location': getattr(a, 'location', None),
                'agent': getattr(a, 'agent', None) if hasattr(a, 'agent') else None,
            })
        return jsonify({'items': items})
    except Exception as e:
        return jsonify({'error':'analytics_list_failed','detail':str(e)}), 500


@bp.get("/arrivals/top-suppliers")
def arrivals_top_suppliers():
    try:
        dfrom, dto = _date_range_args()
        limit = int((request.args.get('limit') or 10))
        date_col = func.coalesce(Arrival.arrived_at, Arrival.eta)
        total_cost = (func.coalesce(Arrival.goods_cost,0) + func.coalesce(Arrival.freight_cost,0) + func.coalesce(Arrival.customs_cost,0))
        q = db.session.query(
            (Arrival.supplier).label('supplier'),
            func.count(Arrival.id).label('count'),
            func.coalesce(func.sum(total_cost),0).label('total'),
            func.coalesce(func.avg(func.greatest(func.extract('epoch', Arrival.arrived_at - Arrival.eta)/3600.0, 0)), 0).label('avg_delay_h')
        )
        q = q.filter(date_col.between(dfrom, dto))
        q = _apply_common_filters(q)
        q = q.group_by(Arrival.supplier).order_by(text('total DESC NULLS LAST')).limit(limit)
        rows = q.all()
        data = [{ 'supplier': (r.supplier or '—'), 'count': int(r.count or 0), 'total': float(r.total or 0), 'avg_delay_h': float(r.avg_delay_h or 0)} for r in rows]
        return jsonify({'items': data, 'limit': limit})
    except Exception as e:
        return jsonify({'error':'analytics_top_suppliers_failed','detail':str(e)}), 500


@bp.get("/arrivals/by-category")
def arrivals_by_category():
    return _arrivals_breakdown_response('category', 'Bez kategorije', 'analytics_arrivals_by_category_failed')


@bp.get("/arrivals/by-responsible")
def arrivals_by_responsible():
    return _arrivals_breakdown_response('responsible', 'Bez odgovorne osobe', 'analytics_arrivals_by_responsible_failed')


@bp.get("/arrivals/by-location")
def arrivals_by_location():
    return _arrivals_breakdown_response('location', 'Bez lokacije', 'analytics_arrivals_by_location_failed')


@bp.get("/arrivals/by-carrier")
def arrivals_by_carrier():
    return _arrivals_breakdown_response('carrier', 'Bez prevoznika', 'analytics_arrivals_by_carrier_failed')


@bp.get("/arrivals/by-agent")
def arrivals_by_agent():
    return _arrivals_breakdown_response('agent', 'Bez agenta', 'analytics_arrivals_by_agent_failed')


@bp.get("/costs/series")
def costs_series():
    """Return monthly cost series: goods, freight, customs and avg_freight.
    Period is 'YYYY-MM'. Applies same common filters.
    """
    try:
        dfrom, dto = _date_range_args()
        # Bucket by month using coalesce(arrived_at, eta)
        date_col = _arrival_date_col()
        bucket = func.date_trunc('month', date_col)
        q = db.session.query(
            bucket.label('period'),
            func.coalesce(func.sum(func.coalesce(Arrival.goods_cost,0)), 0).label('goods'),
            func.coalesce(func.sum(func.coalesce(Arrival.freight_cost,0)), 0).label('freight'),
            func.coalesce(func.sum(func.coalesce(Arrival.customs_cost,0)), 0).label('customs'),
            func.coalesce(func.avg(func.coalesce(Arrival.freight_cost,0)), 0).label('avg_freight')
        ).filter(date_col.between(dfrom, dto))
        q = _apply_common_filters(q)
        q = q.group_by(bucket).order_by(bucket)
        rows = q.all()
        items = [{
            'period': (r.period.date().isoformat() if hasattr(r.period,'date') else str(r.period))[:7],
            'goods': float(r.goods or 0),
            'freight': float(r.freight or 0),
            'customs': float(r.customs or 0),
            'avg_freight': float(r.avg_freight or 0),
        } for r in rows]
        return jsonify({'items': items})
    except Exception as e:
        return jsonify({'error':'costs_series_failed','detail':str(e)}), 500


@bp.get("/arrivals/trend")
def arrivals_trend_status():
    """Status breakdown per month for arrivals: counts of not_shipped, shipped, arrived."""
    try:
        dfrom, dto = _date_range_args()
        date_col = _arrival_date_col()
        bucket = func.date_trunc('month', date_col)
        base = db.session.query(bucket.label('period'), Arrival.status, func.count(Arrival.id).label('cnt'))
        base = base.filter(date_col.between(dfrom, dto))
        base = _apply_common_filters(base)
        base = base.group_by(bucket, Arrival.status).order_by(bucket)
        rows = base.all()
        # Aggregate into dict by period
        agg = {}
        for period, status, cnt in rows:
            key = (period.date().isoformat() if hasattr(period,'date') else str(period))[:7]
            rec = agg.setdefault(key, {'period': key, 'not_shipped': 0, 'shipped': 0, 'arrived': 0})
            st = (status or '').lower()
            if st in ('not_shipped','not shipped','najavljeno'):
                rec['not_shipped'] += int(cnt or 0)
            elif st in ('shipped','u transportu','transport'):
                rec['shipped'] += int(cnt or 0)
            elif st in ('arrived','stiglo'):
                rec['arrived'] += int(cnt or 0)
        items = [agg[k] for k in sorted(agg.keys())]
        return jsonify({'items': items})
    except Exception as e:
        return jsonify({'error':'arrivals_trend_failed','detail':str(e)}), 500


# -------------------------- Containers Analytics --------------------------

@bp.get("/containers/kpi")
def containers_kpi():
    try:
        # Optional date filter: if from/to not provided, include all
        qs_from = request.args.get('from'); qs_to = request.args.get('to')
        dfrom = _parse_iso_date(qs_from) if qs_from else None
        dto = _parse_iso_date(qs_to) if qs_to else None
        date_col = _container_date_col_from_param()
        base = db.session.query(Container)
        if dfrom and dto:
            dfrom_d = dfrom.date() if hasattr(dfrom, 'date') else dfrom
            dto_d = dto.date() if hasattr(dto, 'date') else dto
            base = base.filter(date_col.between(dfrom_d, dto_d))
        base = _apply_container_filters(base)
        rows = base.with_entities(Container.total, Container.deposit, Container.balance, Container.paid, Container.status, Container.eta, Container.created_at).all()
        total = len(rows)
        paid_cnt = 0
        unpaid_cnt = 0
        total_sum = 0.0
        deposit_sum = 0.0
        balance_sum = 0.0
        paid_total_sum = 0.0
        unpaid_total_sum = 0.0
        deposit_paid_sum = 0.0
        deposit_unpaid_sum = 0.0
        balance_paid_sum = 0.0
        balance_unpaid_sum = 0.0
        for r in rows:
            t = _money_to_number(r[0])
            d = _money_to_number(r[1])
            b = _money_to_number(r[2])
            total_sum += t
            deposit_sum += d
            balance_sum += b
            if _is_paid_flag(r[3], r[4]):
                paid_cnt += 1
                paid_total_sum += t
                deposit_paid_sum += d
                balance_paid_sum += b
            else:
                unpaid_cnt += 1
                unpaid_total_sum += t
                deposit_unpaid_sum += d
                balance_unpaid_sum += b
        return jsonify({
            'count': total,
            'paid_count': paid_cnt,
            'unpaid_count': unpaid_cnt,
            'total_sum': total_sum,
            'deposit_sum': deposit_sum,
            'balance_sum': balance_sum,
            'paid_total_sum': paid_total_sum,
            'unpaid_total_sum': unpaid_total_sum,
            'deposit_paid_sum': deposit_paid_sum,
            'deposit_unpaid_sum': deposit_unpaid_sum,
            'balance_paid_sum': balance_paid_sum,
            'balance_unpaid_sum': balance_unpaid_sum,
            'window': ({'from': dfrom.isoformat(), 'to': dto.isoformat()} if (dfrom and dto) else None),
        })
    except Exception as e:
        return jsonify({'error':'containers_kpi_failed','detail':str(e)}), 500


@bp.get("/containers/trend-amounts")
def containers_trend_amounts():
    try:
        qs_from = request.args.get('from'); qs_to = request.args.get('to')
        dfrom = _parse_iso_date(qs_from) if qs_from else None
        dto = _parse_iso_date(qs_to) if qs_to else None
        date_col = _container_date_col_from_param()
        q = db.session.query(Container)
        if dfrom and dto:
            dfrom_d = dfrom.date() if hasattr(dfrom, 'date') else dfrom
            dto_d = dto.date() if hasattr(dto, 'date') else dto
            q = q.filter(date_col.between(dfrom_d, dto_d))
        q = _apply_container_filters(q)
        rows = q.with_entities(Container.total, Container.paid, Container.status, Container.eta, Container.created_at).all()
        buckets = {}
        for c in rows:
            # month key from eta or created_at
            dt = c[3] or c[4]
            key = (dt.isoformat()[:7] if dt else 'unknown')
            b = buckets.setdefault(key, {'month': key, 'paid': 0.0, 'unpaid': 0.0, 'total': 0.0})
            amt = _money_to_number(c[0])
            if _is_paid_flag(c[1], c[2]):
                b['paid'] += amt
            else:
                b['unpaid'] += amt
            b['total'] += amt
        items = [buckets[k] for k in sorted(buckets.keys())]
        return jsonify({'items': items})
    except Exception as e:
        return jsonify({'error':'containers_trend_failed','detail':str(e)}), 500


@bp.get("/containers/cost-structure")
def containers_cost_structure():
    try:
        qs_from = request.args.get('from'); qs_to = request.args.get('to')
        dfrom = _parse_iso_date(qs_from) if qs_from else None
        dto = _parse_iso_date(qs_to) if qs_to else None
        date_col = _container_date_col_from_param()
        q = db.session.query(Container)
        if dfrom and dto:
            dfrom_d = dfrom.date() if hasattr(dfrom, 'date') else dfrom
            dto_d = dto.date() if hasattr(dto, 'date') else dto
            q = q.filter(date_col.between(dfrom_d, dto_d))
        q = _apply_container_filters(q)
        rows = q.with_entities(Container.total, Container.deposit, Container.balance, Container.paid, Container.status).all()
        total_sum = 0.0
        deposit_sum = 0.0
        balance_sum = 0.0
        paid_total_sum = 0.0
        unpaid_total_sum = 0.0
        for r in rows:
            t = _money_to_number(r[0]); d = _money_to_number(r[1]); b = _money_to_number(r[2])
            total_sum += t; deposit_sum += d; balance_sum += b
            if _is_paid_flag(r[3], r[4]):
                paid_total_sum += t
            else:
                unpaid_total_sum += t
        total = total_sum or 1.0
        return jsonify({
            'total_sum': total_sum,
            'deposit_sum': deposit_sum,
            'balance_sum': balance_sum,
            'paid_total_sum': paid_total_sum,
            'unpaid_total_sum': unpaid_total_sum,
            'share': {
                'paid': paid_total_sum/total,
                'unpaid': unpaid_total_sum/total,
                'balance': balance_sum/total,
                'deposit': deposit_sum/total,
            }
        })
    except Exception as e:
        return jsonify({'error':'containers_structure_failed','detail':str(e)}), 500


@bp.get("/containers/top-suppliers")
def containers_top_suppliers():
    try:
        qs_from = request.args.get('from'); qs_to = request.args.get('to')
        dfrom = _parse_iso_date(qs_from) if qs_from else None
        dto = _parse_iso_date(qs_to) if qs_to else None
        date_col = _container_date_col_from_param()
        q = db.session.query(Container)
        if dfrom and dto:
            dfrom_d = dfrom.date() if hasattr(dfrom, 'date') else dfrom
            dto_d = dto.date() if hasattr(dto, 'date') else dto
            q = q.filter(date_col.between(dfrom_d, dto_d))
        q = _apply_container_filters(q)
        rows = q.with_entities(Container.supplier, Container.total).all()
        agg = {}
        for supplier, total in rows:
            key = supplier or '—'
            d = agg.setdefault(key, {'supplier': key, 'count': 0, 'total': 0.0})
            d['count'] += 1
            d['total'] += _money_to_number(total)
        data = sorted(agg.values(), key=lambda r: r['total'], reverse=True)[:10]
        return jsonify({'items': data})
    except Exception as e:
        return jsonify({'error':'containers_top_suppliers_failed','detail':str(e)}), 500


@bp.get("/containers/summary")
def containers_summary():
    """Return totals for a given group (all|paid|unpaid) in the optional period and filters.
    Response: { count, total_sum, deposit_sum, balance_sum }
    """
    try:
        qs_from = request.args.get('from'); qs_to = request.args.get('to')
        dfrom = _parse_iso_date(qs_from) if qs_from else None
        dto = _parse_iso_date(qs_to) if qs_to else None
        group = (request.args.get('group') or 'all').strip().lower()
        date_col = _container_date_col_from_param()
        q = db.session.query(Container)
        if dfrom and dto:
            dfrom_d = dfrom.date() if hasattr(dfrom,'date') else dfrom
            dto_d = dto.date() if hasattr(dto,'date') else dto
            q = q.filter(date_col.between(dfrom_d, dto_d))
        q = _apply_container_filters(q)
        rows = q.with_entities(Container.total, Container.deposit, Container.balance, Container.paid, Container.status).all()
        def _match(paid, status):
            if group == 'all': return True
            f = _is_paid_flag(paid, status)
            return f if group=='paid' else (not f)
        cnt = 0; ts=0.0; ds=0.0; bs=0.0
        for t,d,b,p,s in rows:
            if not _match(p,s):
                continue
            cnt += 1
            ts += _money_to_number(t)
            ds += _money_to_number(d)
            bs += _money_to_number(b)
        return jsonify({'count': cnt, 'total_sum': ts, 'deposit_sum': ds, 'balance_sum': bs, 'group': group, 'window': ({'from': dfrom.isoformat(), 'to': dto.isoformat()} if (dfrom and dto) else None)})
    except Exception as e:
        return jsonify({'error':'containers_summary_failed','detail':str(e)}), 500


@bp.get("/containers/lookups")
def containers_lookups():
    try:
        q_sup = (request.args.get('q_supp') or '').strip().lower()
        q_agent = (request.args.get('q_agent') or '').strip().lower()
        limit = int((request.args.get('limit') or 200))
        def _fetch_distinct(col, q_like: str):
            if not hasattr(Container, col):
                return []
            c = getattr(Container, col)
            q = db.session.query(c).filter(c.isnot(None))
            if q_like:
                q = q.filter(c.ilike(f"%{q_like}%"))
            vals = [r[0] for r in q.distinct().order_by(c.asc()).limit(limit).all() if r[0]]
            seen, out = set(), []
            for v in vals:
                if v not in seen:
                    seen.add(v); out.append(v)
            return out
        suppliers = _fetch_distinct('supplier', q_sup)
        agents = _fetch_distinct('agent', q_agent)
        return jsonify({'suppliers': suppliers, 'agents': agents, 'limit': limit})
    except Exception as e:
        return jsonify({'error':'containers_lookups_failed','detail':str(e)}), 500


@bp.get("/arrivals/on-time")
def arrivals_on_time():
    try:
        dfrom, dto = _date_range_args()
        date_col = func.coalesce(Arrival.arrived_at, Arrival.eta)
        q = db.session.query(Arrival).filter(date_col.between(dfrom, dto))
        q = _apply_common_filters(q)
        rows = q.all()
        total = len(rows)
        on_time = 0
        early = 0
        late = 0
        for a in rows:
            if not a.eta or not a.arrived_at:
                continue
            diff = (a.arrived_at - a.eta).total_seconds()
            if diff < 0:
                early += 1
            elif diff == 0:
                on_time += 1
            else:
                late += 1
        rate = (on_time + early) / total if total else 0.0  # early smatramo "na vrijeme ili prije roka"
        return jsonify({'total': total, 'on_time_or_early_rate': rate, 'buckets': {'early': early, 'on_time': on_time, 'late': late}})
    except Exception as e:
        return jsonify({'error':'analytics_on_time_failed','detail':str(e)}), 500


@bp.get("/arrivals/lead-time")
def arrivals_lead_time():
    try:
        dfrom, dto = _date_range_args()
        date_col = func.coalesce(Arrival.arrived_at, Arrival.eta)
        q = db.session.query(Arrival).filter(date_col.between(dfrom, dto))
        q = _apply_common_filters(q)
        rows = q.all()
        values = []
        for a in rows:
            if a.shipped_at and (a.arrived_at or a.eta):
                stop = a.arrived_at or a.eta
                values.append((stop - a.shipped_at).total_seconds() / 86400.0)
        avg_days = sum(values)/len(values) if values else 0.0
        p95 = sorted(values)[int(0.95*len(values))] if values else 0.0
        return jsonify({'count': len(values), 'avg_days': avg_days, 'p95_days': p95})
    except Exception as e:
        return jsonify({'error':'analytics_lead_time_failed','detail':str(e)}), 500


@bp.get("/arrivals/lookups")
def arrivals_lookups():
    """Return distinct suppliers/agents/locations for autocomplete filter selects.
    Supports optional q_supp, q_agent, q_loc for narrowing results.
    """
    try:
        q_sup = (request.args.get('q_supp') or '').strip().lower()
        q_agent = (request.args.get('q_agent') or '').strip().lower()
        q_loc = (request.args.get('q_loc') or '').strip().lower()
        limit = int((request.args.get('limit') or 200))

        def _fetch_distinct(col, q_like: str):
            if not hasattr(Arrival, col):
                return []
            c = getattr(Arrival, col)
            q = db.session.query(c).filter(c.isnot(None))
            if q_like:
                q = q.filter(c.ilike(f"%{q_like}%"))
            vals = [r[0] for r in q.distinct().order_by(c.asc()).limit(limit).all() if r[0]]
            # unique while preserving order
            seen, out = set(), []
            for v in vals:
                if v not in seen:
                    seen.add(v); out.append(v)
            return out

        suppliers = _fetch_distinct('supplier', q_sup)
        agents = _fetch_distinct('agent', q_agent)
        locations = _fetch_distinct('location', q_loc)
        return jsonify({'suppliers': suppliers, 'agents': agents, 'locations': locations, 'limit': limit}), 200
    except Exception as e:
        return jsonify({'error':'analytics_lookups_failed','detail':str(e)}), 500
