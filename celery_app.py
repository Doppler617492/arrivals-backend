from __future__ import annotations

from celery import Celery
from flask import Flask

celery_app = Celery("arrivals")


def init_celery(app: Flask) -> None:
    """Bind Celery to the Flask application context."""

    celery_app.conf.update(
        broker_url=app.config["CELERY_BROKER_URL"],
        result_backend=app.config["CELERY_RESULT_BACKEND"],
        task_track_started=True,
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        include=["tasks"],
    )

    class ContextTask(celery_app.Task):
        abstract = True

        def __call__(self, *args, **kwargs):  # type: ignore[override]
            with app.app_context():
                return super().__call__(*args, **kwargs)

    celery_app.Task = ContextTask


__all__ = ["celery_app", "init_celery"]
