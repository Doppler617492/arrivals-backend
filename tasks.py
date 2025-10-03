from __future__ import annotations

import time
from typing import Iterable

from celery import states

from celery_app import celery_app


@celery_app.task(bind=True, name="tasks.send_bulk_email")
def send_bulk_email_task(self, recipients: Iterable[str], subject: str, body: str) -> dict:
    """Demo bulk email task.

    A real implementation would integrate with the mailer module. For now we
    simulate work and return a structured result that the API can use.
    """

    recipients = list(recipients or [])
    processed = []
    for index, email in enumerate(recipients, start=1):
        time.sleep(0.1)  # simulate latency per-recipient
        self.update_state(state=states.STARTED, meta={"progress": index, "total": len(recipients)})
        processed.append(email)
    return {"processed": processed, "subject": subject}


@celery_app.task(bind=True, name="tasks.generate_report")
def generate_report_task(self, payload: dict | None = None) -> dict:
    """Placeholder task for heavy PDF/CSV generation."""

    time.sleep(1)
    return {"report": "ok", "request": payload or {}}
