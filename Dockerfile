# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # Gunicorn logs straight to stdout/stderr
    GUNICORN_CMD_ARGS="--access-logfile - --error-logfile -" 

WORKDIR /app

# System deps (if you use SQLite only, this is enough)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# If you have a requirements.txt, copy & install first to leverage Docker layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt

# Copy app source
COPY . /app

# (Optional) set Flask env vars if your app reads them
ENV FLASK_APP=app.py

# Provide an entrypoint that runs migrations before the server boots
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 8081

# Use the entrypoint to apply migrations, then start Gunicorn (WebSocket-capable worker)
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["gunicorn", "-k", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", "-w", "2", "--timeout", "90", "-b", "0.0.0.0:8081", "app:app"]
