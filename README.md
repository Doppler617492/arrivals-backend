# Arrivals Backend (Flask + SQLite + Docker)

## Setup

API:
- `GET /api/arrivals` – lista dolazaka  
- `POST /api/arrivals` – kreiranje novog dolaska (JSON body)  
- `PATCH /api/arrivals/{id}` – ažuriranje postojećeg (npr. promjena statusa)

## Primjeri

```bash
curl http://localhost:8080/api/arrivals

curl -X POST http://localhost:8080/api/arrivals \
  -H "Content-Type: application/json" \
  -d '{"supplier":"Podravka","plate":"XYZ-001"}'
