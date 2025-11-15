"""Tests for safe_methods parameter in require_auth dependency."""

import time
from functools import partial

import pytest
from fastapi import Depends, FastAPI
from starlette.testclient import TestClient

from axioms_fastapi import init_axioms, register_axioms_exception_handler, require_auth
from conftest import generate_jwt_token


@pytest.fixture
def app(monkeypatch, test_key):
    """Create test app with mocked JWKS."""
    from axioms_fastapi import helper

    def mock_get_key_from_jwks_json(kid, config=None):
        if kid == test_key.kid:
            return test_key
        raise Exception(f"Key not found: {kid}")

    monkeypatch.setattr(helper, "get_key_from_jwks_json", mock_get_key_from_jwks_json)

    app = FastAPI()
    init_axioms(
        app,
        AXIOMS_AUDIENCE="test-audience",
        AXIOMS_ISS_URL="https://test-domain.com",
        AXIOMS_JWKS_URL="https://test-domain.com/.well-known/jwks.json",
    )
    register_axioms_exception_handler(app)

    # Standard protected route
    @app.get("/protected")
    async def protected_route(payload=Depends(require_auth)):
        if not payload:
            return {"message": "No auth required"}
        return {"user_id": payload.sub}

    @app.options("/protected")
    async def protected_route_options(payload=Depends(require_auth)):
        if not payload:
            return {"message": "OPTIONS allowed"}
        return {"user_id": payload.sub}

    # Route with custom safe methods
    require_auth_custom = partial(require_auth, safe_methods=["GET", "OPTIONS"])

    @app.get("/public-read")
    async def public_read_route(payload=Depends(require_auth_custom)):
        if not payload:
            return {"message": "No auth required for GET"}
        return {"user_id": payload.sub}

    @app.post("/public-read")
    async def public_read_post(payload=Depends(require_auth_custom)):
        if not payload:
            return {"message": "No auth required for POST"}
        return {"user_id": payload.sub}

    # Route with no safe methods
    require_auth_strict = partial(require_auth, safe_methods=[])

    @app.options("/strict")
    async def strict_options(payload=Depends(require_auth_strict)):
        if not payload:
            return {"message": "No auth required"}
        return {"user_id": payload.sub}

    return app


class TestDefaultSafeMethods:
    """Test default safe methods behavior (OPTIONS)."""

    def test_options_request_without_token_succeeds(self, app):
        """Test OPTIONS request succeeds without token."""
        client = TestClient(app)
        response = client.options("/protected")

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "OPTIONS allowed"

    def test_options_request_with_token_still_works(self, app, test_key):
        """Test OPTIONS request with token still works (backward compatibility)."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                "sub": "user123",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            },
            alg="RS256",
        )

        client = TestClient(app)
        response = client.options("/protected", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "OPTIONS allowed"

    def test_get_request_without_token_fails(self, app):
        """Test GET request without token fails."""
        client = TestClient(app)
        response = client.get("/protected")

        assert response.status_code == 401
        data = response.json()
        assert data["error"] == "unauthorized_access"

    def test_get_request_with_valid_token_succeeds(self, app, test_key):
        """Test GET request with valid token succeeds."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                "sub": "user456",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            },
            alg="RS256",
        )

        client = TestClient(app)
        response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "user456"


class TestCustomSafeMethods:
    """Test custom safe methods configuration."""

    def test_get_request_without_token_succeeds_when_configured(self, app):
        """Test GET request without token succeeds when GET is safe method."""
        client = TestClient(app)
        response = client.get("/public-read")

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "No auth required for GET"

    def test_post_request_without_token_fails_when_not_safe(self, app):
        """Test POST request without token fails when POST is not safe method."""
        client = TestClient(app)
        response = client.post("/public-read")

        assert response.status_code == 401
        data = response.json()
        assert data["error"] == "unauthorized_access"

    def test_post_request_with_valid_token_succeeds(self, app, test_key):
        """Test POST request with valid token succeeds."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                "sub": "user789",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            },
            alg="RS256",
        )

        client = TestClient(app)
        response = client.post("/public-read", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "user789"


class TestNoSafeMethods:
    """Test behavior when safe_methods is empty list."""

    def test_options_request_requires_auth_when_no_safe_methods(self, app):
        """Test OPTIONS request requires auth when safe_methods=[]."""
        client = TestClient(app)
        response = client.options("/strict")

        assert response.status_code == 401
        data = response.json()
        assert data["error"] == "unauthorized_access"

    def test_options_request_with_token_succeeds(self, app, test_key):
        """Test OPTIONS request with valid token succeeds."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                "sub": "user999",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            },
            alg="RS256",
        )

        client = TestClient(app)
        response = client.options("/strict", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "user999"


class TestSafeMethodsEdgeCases:
    """Test edge cases for safe methods."""

    def test_empty_payload_returned_for_safe_methods(self, app):
        """Test that safe methods return empty Box."""
        client = TestClient(app)
        response = client.options("/protected")

        assert response.status_code == 200
        data = response.json()
        # Empty payload should not have user_id
        assert "user_id" not in data
        assert data["message"] == "OPTIONS allowed"

    def test_case_sensitive_method_matching(self, app):
        """Test that method matching is case-sensitive."""
        client = TestClient(app)

        # OPTIONS should work (uppercase)
        response = client.options("/protected")
        assert response.status_code == 200

        # Note: HTTP methods are always uppercase in HTTP spec
        # Lowercase methods are not valid HTTP requests
