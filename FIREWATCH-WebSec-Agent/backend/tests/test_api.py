import os

os.environ["DATABASE_URL"] = "sqlite:///./test_firewatch.db"
os.environ["ALLOW_PRIVATE_TARGETS"] = "true"

from fastapi.testclient import TestClient
from app.db import init_db
from app.main import app


def test_health():
    init_db()
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
