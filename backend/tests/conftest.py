"""
ThreatLens AI - Pytest Configuration and Fixtures
Provides authenticated test client fixtures, JWT token generators,
and mongomock test database isolation to ensure fast, reliable test execution.
"""

import pytest
import mongomock
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.core.security import create_access_token
import app.services.db as db_module

# Shared hermetic in-memory mock database for tests
_mock_mongo_client = mongomock.MongoClient()
_mock_db = _mock_mongo_client["threatlens"]


@pytest.fixture(autouse=True, scope="session")
def isolate_test_database():
    """Points database operations to in-memory mongomock for test isolation."""
    db_module._mongo_db = _mock_db
    db_module._mongo_client = _mock_mongo_client
    with patch("app.services.db.get_mongo_db", return_value=_mock_db), \
         patch("app.services.db.get_mongo_client", return_value=_mock_mongo_client), \
         patch("app.services.db.is_mongo_active", return_value=True):
        from app.services.user_service import seed_admin_if_empty
        seed_admin_if_empty()
        yield


@pytest.fixture(scope="session")
def analyst_token():
    """Generates a valid JWT for Security Analyst role."""
    return create_access_token({
        "sub": "analyst@threatlens.ai",
        "id": "test-analyst-id",
        "email": "analyst@threatlens.ai",
        "role": "Security Analyst",
        "name": "Security Analyst",
    })


@pytest.fixture(scope="session")
def admin_token():
    """Generates a valid JWT for Administrator role."""
    return create_access_token({
        "sub": "admin@threatlens.ai",
        "id": "test-admin-id",
        "email": "admin@threatlens.ai",
        "role": "Administrator",
        "name": "Platform Administrator",
    })


@pytest.fixture(scope="session")
def soc_token():
    """Generates a valid JWT for SOC Team Member role."""
    return create_access_token({
        "sub": "soc@threatlens.ai",
        "id": "test-soc-id",
        "email": "soc@threatlens.ai",
        "role": "SOC Team Member",
        "name": "SOC Member",
    })


@pytest.fixture(scope="session")
def researcher_token():
    """Generates a valid JWT for Researcher role."""
    return create_access_token({
        "sub": "researcher@threatlens.ai",
        "id": "test-researcher-id",
        "email": "researcher@threatlens.ai",
        "role": "Researcher",
        "name": "Threat Researcher",
    })


@pytest.fixture
def auth_headers(analyst_token):
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def soc_headers(soc_token):
    return {"Authorization": f"Bearer {soc_token}"}


@pytest.fixture
def researcher_headers(researcher_token):
    return {"Authorization": f"Bearer {researcher_token}"}


@pytest.fixture(autouse=True)
def apply_default_analyst_auth(analyst_token):
    """
    Default autouse fixture that sets default analyst Authorization header
    on the global TestClient instances in existing legacy test files,
    allowing existing tests to pass without modifying their core test logic.
    """
    from tests.test_malware_analysis import client as m_client
    from tests.test_behavioral_analysis import client as b_client
    from tests.test_threat_prediction import client as t_client

    for c in (m_client, b_client, t_client):
        c.headers["Authorization"] = f"Bearer {analyst_token}"
    yield
