import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_get_stats_unauthorized():
    response = client.get("/api/files/stats")
    assert response.status_code == 403 or response.status_code == 401

def test_file_upload_no_token():
    response = client.post("/api/files/upload", files={"file": ("test.txt", b"test content")})
    assert response.status_code == 403 or response.status_code == 401
