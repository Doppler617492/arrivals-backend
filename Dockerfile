FROM python:3.11-slim

WORKDIR /app

# Instaliraj zavisnosti
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Kopiraj aplikaciju
COPY . /app

ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000

EXPOSE 5000

CMD ["flask", "run"]
