from app import app


def test_health_route():
    client = app.test_client()
    rv = client.get("/health")
    assert rv.status_code == 200
    data = rv.get_json() or {}
    assert isinstance(data, dict)

