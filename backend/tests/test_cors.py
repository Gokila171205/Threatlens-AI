import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_cors_preflight_localhost():
    headers = {
        "Origin": "http://localhost:5173",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authorization, Content-Type",
    }
    response = client.options("/api/v1/auth/login", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert response.headers.get("access-control-allow-credentials") == "true"

def test_cors_preflight_production_vercel():
    headers = {
        "Origin": "https://threatlens-ai.vercel.app",
        "Access-Control-Request-Method": "GET",
    }
    response = client.options("/api/v1/monitoring/health", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "https://threatlens-ai.vercel.app"
    assert response.headers.get("access-control-allow-credentials") == "true"

def test_cors_preflight_vercel_preview():
    headers = {
        "Origin": "https://threatlens-ai-branch-preview.vercel.app",
        "Access-Control-Request-Method": "GET",
    }
    response = client.options("/api/v1/monitoring/health", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "https://threatlens-ai-branch-preview.vercel.app"

def test_cors_disallowed_origin():
    headers = {
        "Origin": "https://malicious-website.com",
        "Access-Control-Request-Method": "GET",
    }
    response = client.options("/api/v1/monitoring/health", headers=headers)
    # Disallowed origin does not get Access-Control-Allow-Origin header
    assert response.headers.get("access-control-allow-origin") is None
