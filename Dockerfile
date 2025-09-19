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

EXPOSE 8081

# Start with Gunicorn in production
# If your Flask instance is named "app" inside app.py, this works:
# Use a WebSocket-capable worker so Flask-Sock /ws works
# Requires gevent + gevent-websocket (added to requirements.txt)
CMD ["gunicorn", "-k", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", "-w", "2", "--timeout", "90", "-b", "0.0.0.0:8081", "app:app"]
