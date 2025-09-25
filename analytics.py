from collections import defaultdict
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify
from sqlalchemy import func

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


def _coerce_datetime(value):
    """Attempt to coerce various date/time representations to naive datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        try:
            if len(v) == 10:
                # YYYY-MM-DD
                return datetime.fromisoformat(v)
            return datetime.fromisoformat(v.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            # Try common fallback formats
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d", "%d.%m.%Y"):
                try:
                    return datetime.strptime(v, fmt)
                except Exception:
                    continue
    try:
        if hasattr(value, "isoformat"):
            return datetime.fromisoformat(value.isoformat()).replace(tzinfo=None)
    except Exception:
        pass
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
    return _coerce_datetime(value)


def _arrival_delay_days(row: Arrival) -> float | None:
    try:
        eta_dt = _coerce_eta(getattr(row, 'eta', None))
        arrived_at = _coerce_datetime(getattr(row, 'arrived_at', None))
        if not eta_dt or not arrived_at:
            return None
        return (arrived_at - eta_dt).total_seconds() / 86400.0
    except Exception:
        return None


def _arrival_reference_datetime(row: Arrival):
    """Use arrived_at if present, otherwise ETA."""
    dt = _coerce_datetime(getattr(row, "arrived_at", None))
    if dt:
        return dt
    return _coerce_eta(getattr(row, "eta", None))


def _fetch_arrivals_scope():
    dfrom, dto = _date_range_args()
    rows = _fetch_arrivals_scope_custom(dfrom, dto)
    return rows, dfrom, dto


def _fetch_arrivals_scope_custom(dfrom: datetime, dto: datetime):
    base = _apply_common_filters(db.session.query(Arrival))
    rows = []
    for row in base.all():
        ref_dt = _arrival_reference_datetime(row)
        if not ref_dt:
            continue
        if dfrom <= ref_dt <= dto:
            rows.append(row)
    return rows


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
        rows, dfrom, dto = _fetch_arrivals_scope()
        today = datetime.utcnow().date()
        month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        today_cnt = 0
        in_transit = 0
        arrived = 0
        total_cost_window = 0.0
        total_cost_month = 0.0

        for row in rows:
            status = (row.status or '').lower()
            if status == 'shipped':
                in_transit += 1
            if status == 'arrived':
                arrived += 1

            eta_dt = _coerce_eta(getattr(row, 'eta', None))
            if eta_dt and eta_dt.date() == today:
                today_cnt += 1

            ref_dt = _arrival_reference_datetime(row)
            cost = _arrival_cost(row)
            total_cost_window += cost
            if ref_dt and ref_dt >= month_start:
                total_cost_month += cost

        count_window = len(rows)
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
        rows, _, _ = _fetch_arrivals_scope()
        gran = (request.args.get('granularity') or 'month').lower()
        if gran not in ('month', 'week', 'day'):
            gran = 'month'

        buckets: dict[datetime, float] = defaultdict(float)

        for row in rows:
            ref = _arrival_reference_datetime(row)
            if not ref:
                continue
            if gran == 'day':
                key = datetime(ref.year, ref.month, ref.day)
            elif gran == 'week':
                monday = ref - timedelta(days=ref.weekday())
                key = datetime(monday.year, monday.month, monday.day)
            else:
                key = datetime(ref.year, ref.month, 1)
            buckets[key] += _arrival_cost(row)

        items = []
        for key in sorted(buckets.keys()):
            if gran == 'month':
                label = key.strftime('%Y-%m')
            else:
                label = key.strftime('%Y-%m-%d')
            items.append({'period': label, 'total': float(buckets[key])})
        return jsonify({'items': items})
    except Exception as e:
        return jsonify({'error':'analytics_trend_failed','detail':str(e)}), 500


@bp.get("/arrivals/cost-structure")
def arrivals_cost_structure():
    try:
        rows, _, _ = _fetch_arrivals_scope()
        goods = 0.0
        freight = 0.0
        customs = 0.0
        for row in rows:
            goods += float(getattr(row, 'goods_cost', 0) or 0)
            freight += float(getattr(row, 'freight_cost', 0) or 0)
            customs += float(getattr(row, 'customs_cost', 0) or 0)
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
        month = (request.args.get('month') or '').strip()
        if month and len(month) == 7:
            try:
                y, m = map(int, month.split('-'))
                dfrom = datetime(y, m, 1)
                if m == 12:
                    dto = datetime(y + 1, 1, 1) - timedelta(seconds=1)
                else:
                    dto = datetime(y, m + 1, 1) - timedelta(seconds=1)
            except Exception:
                pass

        rows = _fetch_arrivals_scope_custom(dfrom, dto)
        rows = sorted(rows, key=lambda r: (_arrival_reference_datetime(r) or dfrom), reverse=True)[:1000]
        items = []
        for a in rows:
            eta_dt = _coerce_eta(getattr(a, 'eta', None))
            arrived_dt = _coerce_datetime(getattr(a, 'arrived_at', None))
            shipped_dt = _coerce_datetime(getattr(a, 'shipped_at', None))
            items.append({
                'id': a.id,
                'supplier': a.supplier,
                'status': a.status,
                'eta': eta_dt.isoformat() if eta_dt else (a.eta if isinstance(getattr(a, 'eta', None), str) else None),
                'arrived_at': arrived_dt.isoformat() if arrived_dt else None,
                'shipped_at': shipped_dt.isoformat() if shipped_dt else None,
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
        rows, _, _ = _fetch_arrivals_scope()
        limit = int((request.args.get('limit') or 10))
        agg = {}
        for row in rows:
            supplier = row.supplier or '—'
            stats = agg.setdefault(supplier, {
                'supplier': supplier,
                'count': 0,
                'total': 0.0,
                'delay_samples': [],
            })
            stats['count'] += 1
            stats['total'] += _arrival_cost(row)
            delay_days = _arrival_delay_days(row)
            if delay_days and delay_days > 0:
                stats['delay_samples'].append(delay_days * 24.0)

        data = []
        for stats in agg.values():
            delays = stats['delay_samples']
            avg_delay_h = sum(delays) / len(delays) if delays else 0.0
            data.append({
                'supplier': stats['supplier'],
                'count': int(stats['count']),
                'total': float(stats['total']),
                'avg_delay_h': float(avg_delay_h),
            })
        data.sort(key=lambda x: x['total'], reverse=True)
        data = data[:limit]
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
        rows, _, _ = _fetch_arrivals_scope()
        buckets: dict[datetime, dict[str, float]] = {}

        for row in rows:
            ref = _arrival_reference_datetime(row)
            if not ref:
                continue
            key = datetime(ref.year, ref.month, 1)
            stats = buckets.setdefault(key, {
                'goods': 0.0,
                'freight': 0.0,
                'customs': 0.0,
                'freight_samples': [],
            })
            goods = float(getattr(row, 'goods_cost', 0) or 0)
            freight = float(getattr(row, 'freight_cost', 0) or 0)
            customs = float(getattr(row, 'customs_cost', 0) or 0)
            stats['goods'] += goods
            stats['freight'] += freight
            stats['customs'] += customs
            if freight:
                stats['freight_samples'].append(freight)

        items = []
        for key in sorted(buckets.keys()):
            stats = buckets[key]
            samples = stats['freight_samples']
            avg_freight = (sum(samples) / len(samples)) if samples else 0.0
            items.append({
                'period': key.strftime('%Y-%m'),
                'goods': float(stats['goods']),
                'freight': float(stats['freight']),
                'customs': float(stats['customs']),
                'avg_freight': float(avg_freight),
            })
        return jsonify({'items': items})
    except Exception as e:
        return jsonify({'error':'costs_series_failed','detail':str(e)}), 500


@bp.get("/arrivals/trend")
def arrivals_trend_status():
    """Status breakdown per month for arrivals: counts of not_shipped, shipped, arrived."""
    try:
        rows, _, _ = _fetch_arrivals_scope()
        agg: dict[str, dict[str, int]] = {}
        for row in rows:
            ref = _arrival_reference_datetime(row)
            if not ref:
                continue
            key = ref.strftime('%Y-%m')
            rec = agg.setdefault(key, {'period': key, 'not_shipped': 0, 'shipped': 0, 'arrived': 0})
            st = (row.status or '').lower()
            if st in ('not_shipped', 'not shipped', 'najavljeno'):
                rec['not_shipped'] += 1
            elif st in ('shipped', 'u transportu', 'transport'):
                rec['shipped'] += 1
            elif st in ('arrived', 'stiglo'):
                rec['arrived'] += 1
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
        rows, _, _ = _fetch_arrivals_scope()
        total = len(rows)
        on_time = 0
        early = 0
        late = 0
        for a in rows:
            eta_dt = _coerce_eta(getattr(a, 'eta', None))
            arrived_dt = _coerce_datetime(getattr(a, 'arrived_at', None))
            if not eta_dt or not arrived_dt:
                continue
            diff = (arrived_dt - eta_dt).total_seconds()
            if diff < 0:
                early += 1
            elif diff == 0:
                on_time += 1
            else:
                late += 1
        considered = on_time + early + late
        rate = ((on_time + early) / considered) if considered else 0.0
        return jsonify({'total': total, 'on_time_or_early_rate': rate, 'buckets': {'early': early, 'on_time': on_time, 'late': late}})
    except Exception as e:
        return jsonify({'error':'analytics_on_time_failed','detail':str(e)}), 500


@bp.get("/arrivals/lead-time")
def arrivals_lead_time():
    try:
        rows, _, _ = _fetch_arrivals_scope()
        values = []
        for a in rows:
            shipped = _coerce_datetime(getattr(a, 'shipped_at', None))
            stop = _coerce_datetime(getattr(a, 'arrived_at', None)) or _coerce_eta(getattr(a, 'eta', None))
            if shipped and stop:
                values.append((stop - shipped).total_seconds() / 86400.0)
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
