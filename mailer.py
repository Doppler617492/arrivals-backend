"""Mailer utilities for Arrivals backend.
This module exposes send_email, notify_paid, maybe_notify_paid.
No Flask app or routes live here to avoid circular imports.
"""
import os
import smtplib
import ssl
import threading
from email.message import EmailMessage
from datetime import datetime

# Load environment variables from .env if present (non-fatal if missing)
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

# --- SMTP config ------------------------------------------------------------
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_FROM = os.getenv("SMTP_FROM") or SMTP_USER or "no-reply@example.com"
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() in ("1", "true", "yes")
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() in ("1", "true", "yes")
MAIL_DEV    = os.getenv("MAIL_DEV", "false").lower() in ("1", "true", "yes")

NOTIFY_PAID_TO = os.getenv("NOTIFY_PAID_TO", os.getenv("SMTP_TO", "it@cungu.com"))
DEFAULT_RECIPIENTS = [x.strip() for x in NOTIFY_PAID_TO.split(",") if x.strip()]

# --- helpers ----------------------------------------------------------------
def _recipients_or_default(recipients):
    if not recipients:
        return DEFAULT_RECIPIENTS
    if isinstance(recipients, str):
        return [recipients]
    if isinstance(recipients, (list, tuple, set)):
        return list(recipients)
    return [recipients]

def _send_now(msg: EmailMessage) -> None:
    """Send the given EmailMessage respecting env config.
    In dev mode (MAIL_DEV=1) it just prints to console.
    """
    if MAIL_DEV:
        print(f"[MAIL-DEV] {msg['Subject']}\nTo: {msg['To']}\n" + (msg.get_content() or ""))
        return

    try:
        if SMTP_USE_SSL:
            context = ssl.create_default_context()
            port = int(os.getenv("SMTP_PORT", "465"))
            with smtplib.SMTP_SSL(SMTP_HOST, port, context=context) as s:
                if SMTP_USER and SMTP_PASS:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                if SMTP_USE_TLS:
                    s.starttls(context=ssl.create_default_context())
                if SMTP_USER and SMTP_PASS:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
    except smtplib.SMTPAuthenticationError as e:
        print(f"[MAIL-ERROR] AUTH failed – check SMTP_USER / SMTP_PASS (use App Password for Gmail). {e}")
        return
    except Exception as e:
        print(f"[MAIL-ERROR] {e}")
        return


def send_email(subject: str, html: str, recipients=None, *, async_: bool = True) -> bool:
    """Send an HTML email. `recipients` can be str or list[str]."""
    to_list = _recipients_or_default(recipients)

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join([str(x) for x in to_list])
    msg.set_content("Ovo je HTML poruka. Ako vidite ovaj tekst, vaš klijent ne prikazuje HTML.")
    msg.add_alternative(html, subtype="html")

    if async_:
        threading.Thread(target=_send_now, args=(msg,), daemon=True).start()
        return True
    _send_now(msg)
    return True


# --- domain-specific notifications -----------------------------------------
def _eur(x) -> str:
    try:
        v = float(x)
    except Exception:
        return str(x)
    # 4.300,20 € format
    return f"{v:,.2f} €".replace(",", "X").replace(".", ",").replace("X", ".")


def render_paid_html(data: dict) -> str:
    # Expected keys: supplier, proformaNo, containerNo, etd, eta, total, deposit, balance
    def row(label, key, fmt=None):
        val = data.get(key, "-")
        val = fmt(val) if fmt else val
        return f"<tr><td style='padding:6px 10px;border:1px solid #eee;font-weight:600'>{label}</td><td style='padding:6px 10px;border:1px solid #eee'>{val}</td></tr>"

    table_rows = "".join([
        row("Supplier", "supplier"),
        row("Proforma No", "proformaNo"),
        row("Container No", "containerNo"),
        row("ETD", "etd"),
        row("ETA", "eta"),
        row("Total", "total", _eur),
        row("Deposit", "deposit", _eur),
        row("Balance", "balance", _eur),
    ])

    sent_ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    return f"""
    <div style="font-family: system-ui, -apple-system, Segoe UI, Arial, sans-serif">
      <h2 style="margin:0 0 8px">✅ Plaćeno — kontejner</h2>
      <p style="margin:0 0 12px">Stanje je prešlo na <b>plaćeno</b> (BALANCE = 0,00).</p>
      <table style="border-collapse:collapse">{table_rows}</table>
      <p style="color:#777;margin-top:12px;font-size:12px">Poslato {sent_ts}</p>
    </div>
    """


def notify_paid(data: dict, *, recipients=None, async_: bool = True) -> bool:
    # Normalize numeric fields to pretty EUR if they are numbers
    recipients = _recipients_or_default(recipients)
    normalized = dict(data)
    for k in ("total", "deposit", "balance"):
        if k in normalized and not isinstance(normalized[k], str):
            normalized[k] = _eur(normalized[k])
    html = render_paid_html(normalized)
    return send_email("[Arrivals] Plaćeno", html, recipients, async_=async_)


def _to_num(val):
    if val is None:
        return None
    if isinstance(val, (int, float)):
        return float(val)
    s = str(val).replace("€", "").replace(" ", "").strip()
    if "," in s and "." in s:
        s = s.replace(".", "").replace(",", ".")
    elif "," in s:
        s = s.replace(",", ".")
    try:
        return float(s)
    except Exception:
        return None


def maybe_notify_paid(old: dict=None, new: dict=None, *, recipients=None, async_: bool = True, **kwargs) -> bool:
    """Send paid email only if transitioned to paid/balance==0.
    Works both for explicit status flip (placeno/paid) and for balance becoming zero.
    """
    if old is None and "old_row" in kwargs:
        old = kwargs.get("old_row")
    if new is None and "new_row" in kwargs:
        new = kwargs.get("new_row")
    if old is None or new is None:
        return False

    old_bal = _to_num(old.get("balance"))
    new_bal = _to_num(new.get("balance"))
    old_paid = bool(old.get("placeno") or old.get("paid"))
    new_paid = bool(new.get("placeno") or new.get("paid"))

    became_paid = (
        (not old_paid and new_paid) or
        (old_bal not in (0, 0.0) and new_bal is not None and abs(new_bal) < 0.005)
    )

    if not became_paid:
        return False

    if recipients is None:
        recipients = DEFAULT_RECIPIENTS

    payload = {
        "supplier": new.get("supplier") or "-",
        "proformaNo": new.get("proformaNo") or new.get("proforma_no") or "-",
        "containerNo": new.get("containerNo") or new.get("container_no") or "-",
        "etd": new.get("etd") or "-",
        "eta": new.get("eta") or "-",
        "total": new.get("total"),
        "deposit": new.get("deposit"),
        "balance": new.get("balance"),
    }
    return notify_paid(payload, recipients=recipients, async_=async_)


__all__ = ["send_email", "notify_paid", "maybe_notify_paid"]
