"""Tests for AccessTokenMiddleware.

This module tests the middleware's configuration validation, token parsing,
and error handling capabilities.
"""

import json
import time

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.testclient import TestClient

from axioms_fastapi import init_axioms
from axioms_fastapi.middleware import AccessTokenMiddleware
from conftest import generate_jwt_token


@pytest.fixture
def base_app():
    """Create a basic FastAPI app without middleware."""
    app = FastAPI()

    @app.get("/test")
    async def test_endpoint(request: Request):
        """Test endpoint that returns request state."""
        return {
            "auth_jwt": getattr(request.state, "auth_jwt", "NOT_SET"),
            "missing_auth_header": getattr(request.state, "missing_auth_header", "NOT_SET"),
            "invalid_bearer_token": getattr(request.state, "invalid_bearer_token", "NOT_SET"),
        }

    return app


@pytest.fixture
def configured_app(base_app):
    """Create app with Axioms configured."""
    init_axioms(
        base_app,
        AXIOMS_AUDIENCE="test-audience",
        AXIOMS_ISS_URL="https://test-domain.com",
        AXIOMS_JWKS_URL="https://test-domain.com/.well-known/jwks.json",
    )
    return base_app


@pytest.fixture
def app_with_middleware(configured_app, monkeypatch, test_key):
    """Create app with middleware and mocked JWKS."""
    from axioms_fastapi import helper

    def mock_get_key_from_jwks_json(kid, config=None):
        if kid == test_key.kid:
            return test_key
        raise Exception(f"Key not found: {kid}")

    monkeypatch.setattr(helper, "get_key_from_jwks_json", mock_get_key_from_jwks_json)

    configured_app.add_middleware(AccessTokenMiddleware)
    return configured_app


class TestMiddlewareConfigurationValidation:
    """Test middleware configuration validation."""

    def test_missing_audience_raises_exception(self, base_app, monkeypatch):
        """Test that missing AXIOMS_AUDIENCE raises exception."""
        from axioms_fastapi import config

        # Clear any existing configuration
        monkeypatch.setattr(config, "_config", None)

        # Don't initialize Axioms, just add middleware
        base_app.add_middleware(AccessTokenMiddleware)
        client = TestClient(base_app)

        with pytest.raises(Exception, match="Axioms configuration error"):
            client.get("/test")

    def test_empty_audience_raises_exception(self, base_app):
        """Test that empty AXIOMS_AUDIENCE raises exception."""
        init_axioms(
            base_app,
            AXIOMS_AUDIENCE="",  # Empty audience
            AXIOMS_ISS_URL="https://test-domain.com",
        )
        base_app.add_middleware(AccessTokenMiddleware)
        client = TestClient(base_app)

        with pytest.raises(Exception, match="AXIOMS_AUDIENCE is required"):
            client.get("/test")

    def test_missing_all_jwks_sources_raises_exception(self, base_app):
        """Test that missing all JWKS sources raises exception."""
        init_axioms(
            base_app,
            AXIOMS_AUDIENCE="test-audience",
            # Don't set any JWKS sources
        )
        base_app.add_middleware(AccessTokenMiddleware)
        client = TestClient(base_app)

        with pytest.raises(Exception, match="JWKS URL configuration required"):
            client.get("/test")

    def test_valid_with_jwks_url_only(self, base_app):
        """Test that middleware works with only AXIOMS_JWKS_URL configured."""
        init_axioms(
            base_app,
            AXIOMS_AUDIENCE="test-audience",
            AXIOMS_JWKS_URL="https://test-domain.com/.well-known/jwks.json",
        )
        base_app.add_middleware(AccessTokenMiddleware)
        client = TestClient(base_app)

        response = client.get("/test")
        assert response.status_code == 200
        data = response.json()
        # Should initialize request state attributes
        assert "auth_jwt" in data
        assert "missing_auth_header" in data
        assert "invalid_bearer_token" in data

    def test_valid_with_iss_url_only(self, base_app):
        """Test that middleware works with only AXIOMS_ISS_URL configured."""
        init_axioms(
            base_app,
            AXIOMS_AUDIENCE="test-audience",
            AXIOMS_ISS_URL="https://test-domain.com",
        )
        base_app.add_middleware(AccessTokenMiddleware)
        client = TestClient(base_app)

        response = client.get("/test")
        assert response.status_code == 200
        data = response.json()
        assert "auth_jwt" in data

    def test_valid_with_domain_only(self, base_app):
        """Test that middleware works with only AXIOMS_DOMAIN configured."""
        init_axioms(
            base_app,
            AXIOMS_AUDIENCE="test-audience",
            AXIOMS_DOMAIN="test-domain.com",
        )
        base_app.add_middleware(AccessTokenMiddleware)
        client = TestClient(base_app)

        response = client.get("/test")
        assert response.status_code == 200
        data = response.json()
        assert "auth_jwt" in data


class TestMiddlewareTokenParsing:
    """Test middleware token parsing logic."""

    def test_missing_authorization_header_sets_flag(self, app_with_middleware):
        """Test that missing Authorization header sets missing_auth_header flag."""
        client = TestClient(app_with_middleware)
        response = client.get("/test")

        assert response.status_code == 200
        data = response.json()
        assert data["missing_auth_header"] is True
        assert data["auth_jwt"] is None
        assert data["invalid_bearer_token"] is False

    def test_invalid_bearer_format_sets_flag(self, app_with_middleware):
        """Test that invalid Bearer format sets invalid_bearer_token flag."""
        client = TestClient(app_with_middleware)
        response = client.get("/test", headers={"Authorization": "InvalidBearer token"})

        assert response.status_code == 200
        data = response.json()
        assert data["invalid_bearer_token"] is True
        assert data["auth_jwt"] is None
        assert data["missing_auth_header"] is False

    def test_bearer_without_token_sets_flag(self, app_with_middleware):
        """Test that 'Bearer' without token sets invalid_bearer_token flag."""
        client = TestClient(app_with_middleware)
        response = client.get("/test", headers={"Authorization": "Bearer"})

        assert response.status_code == 200
        data = response.json()
        assert data["invalid_bearer_token"] is True
        assert data["auth_jwt"] is None

    def test_bearer_with_only_spaces_sets_flag(self, app_with_middleware):
        """Test that 'Bearer' with only spaces sets invalid_bearer_token flag."""
        client = TestClient(app_with_middleware)
        response = client.get("/test", headers={"Authorization": "Bearer   "})

        assert response.status_code == 200
        data = response.json()
        assert data["invalid_bearer_token"] is True
        assert data["auth_jwt"] is None

    def test_valid_bearer_token_sets_auth_jwt(self, app_with_middleware, test_key):
        """Test that valid Bearer token sets auth_jwt attribute."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                "sub": "user123",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "scope": "openid profile",
                "exp": now + 3600,
                "iat": now,
            },
            alg="RS256",
        )

        client = TestClient(app_with_middleware)
        response = client.get("/test", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        data = response.json()
        # auth_jwt will be serialized to dict by FastAPI
        assert data["auth_jwt"] is not None
        assert data["auth_jwt"] is not False
        assert data["auth_jwt"]["sub"] == "user123"
        assert data["missing_auth_header"] is False
        assert data["invalid_bearer_token"] is False

    def test_bearer_token_with_multiple_spaces_handled_correctly(
        self, app_with_middleware, test_key
    ):
        """Test that Bearer token with multiple spaces is handled correctly."""
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

        client = TestClient(app_with_middleware)
        # Multiple spaces between Bearer and token
        response = client.get("/test", headers={"Authorization": f"Bearer   {token}"})

        assert response.status_code == 200
        data = response.json()
        # Should still work because of token.strip()
        assert data["auth_jwt"] is not None
        assert data["auth_jwt"] is not False
        assert data["auth_jwt"]["sub"] == "user456"

    def test_bearer_case_insensitive(self, app_with_middleware, test_key):
        """Test that 'bearer' (lowercase) is accepted."""
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

        client = TestClient(app_with_middleware)
        response = client.get("/test", headers={"Authorization": f"bearer {token}"})

        assert response.status_code == 200
        data = response.json()
        assert data["auth_jwt"] is not None
        assert data["auth_jwt"]["sub"] == "user789"

    def test_invalid_token_sets_auth_jwt_to_false(self, app_with_middleware):
        """Test that invalid token sets auth_jwt to False."""
        client = TestClient(app_with_middleware)
        response = client.get("/test", headers={"Authorization": "Bearer invalid.token.here"})

        assert response.status_code == 200
        data = response.json()
        assert data["auth_jwt"] is False
        assert data["missing_auth_header"] is False
        assert data["invalid_bearer_token"] is False

    def test_expired_token_sets_auth_jwt_to_false(self, app_with_middleware, test_key):
        """Test that expired token sets auth_jwt to False."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                "sub": "user999",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": now - 3600,  # Expired 1 hour ago
                "iat": now - 7200,
            },
            alg="RS256",
        )

        client = TestClient(app_with_middleware)
        response = client.get("/test", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        data = response.json()
        assert data["auth_jwt"] is False

    def test_wrong_audience_sets_auth_jwt_to_false(self, app_with_middleware, test_key):
        """Test that wrong audience sets auth_jwt to False."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                "sub": "user111",
                "aud": "wrong-audience",  # Wrong audience
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            },
            alg="RS256",
        )

        client = TestClient(app_with_middleware)
        response = client.get("/test", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        data = response.json()
        assert data["auth_jwt"] is False


class TestMiddlewareErrorHandling:
    """Test middleware error handling."""

    def test_jwks_fetch_failure_sets_auth_jwt_to_false(
        self, configured_app, monkeypatch, test_key
    ):
        """Test that JWKS fetch failure sets auth_jwt to False."""
        from axioms_fastapi import helper

        # Mock to raise exception
        def mock_get_key_from_jwks_json(kid, config=None):
            raise Exception("Network error")

        monkeypatch.setattr(helper, "get_key_from_jwks_json", mock_get_key_from_jwks_json)

        configured_app.add_middleware(AccessTokenMiddleware)

        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                "sub": "user222",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            },
            alg="RS256",
        )

        client = TestClient(configured_app)
        response = client.get("/test", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        data = response.json()
        # JWKS fetch failure should set auth_jwt to False
        assert data["auth_jwt"] is False

    def test_wrong_issuer_sets_auth_jwt_to_false(self, app_with_middleware, test_key):
        """Test that wrong issuer sets auth_jwt to False."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                "sub": "user555",
                "aud": "test-audience",
                "iss": "https://wrong-issuer.com",  # Wrong issuer
                "exp": now + 3600,
                "iat": now,
            },
            alg="RS256",
        )

        client = TestClient(app_with_middleware)
        response = client.get("/test", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        data = response.json()
        assert data["auth_jwt"] is False

    def test_token_without_kid_sets_auth_jwt_to_false(self, app_with_middleware, test_key):
        """Test that token without kid in header sets auth_jwt to False."""
        from jwcrypto import jwt as jwcrypto_jwt

        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user666",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            }
        )

        # Create token without kid in header
        token = jwcrypto_jwt.JWT(header={"alg": "RS256"}, claims=claims)  # No kid
        token.make_signed_token(test_key)
        token_str = token.serialize()

        client = TestClient(app_with_middleware)
        response = client.get("/test", headers={"Authorization": f"Bearer {token_str}"})

        assert response.status_code == 200
        data = response.json()
        # Token without kid should set auth_jwt to False
        assert data["auth_jwt"] is False


class TestMiddlewareRequestState:
    """Test that middleware sets correct request state attributes."""

    def test_request_state_initialized(self, app_with_middleware):
        """Test that all request state attributes are initialized."""
        client = TestClient(app_with_middleware)
        response = client.get("/test")

        assert response.status_code == 200
        data = response.json()
        # Check all attributes exist
        assert "auth_jwt" in data
        assert "missing_auth_header" in data
        assert "invalid_bearer_token" in data
        assert data["auth_jwt"] != "NOT_SET"
        assert data["missing_auth_header"] != "NOT_SET"
        assert data["invalid_bearer_token"] != "NOT_SET"

    def test_request_state_default_values(self, app_with_middleware):
        """Test default values when no Authorization header."""
        client = TestClient(app_with_middleware)
        response = client.get("/test")

        assert response.status_code == 200
        data = response.json()
        # Check default values
        assert data["auth_jwt"] is None
        assert data["missing_auth_header"] is True
        assert data["invalid_bearer_token"] is False

    def test_request_state_with_valid_token(self, app_with_middleware, test_key):
        """Test state values with valid token."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                "sub": "user777",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "scope": "openid",
                "roles": ["admin"],
                "permissions": ["read:all"],
                "exp": now + 3600,
                "iat": now,
            },
            alg="RS256",
        )

        client = TestClient(app_with_middleware)
        response = client.get("/test", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        data = response.json()
        # Check attributes with valid token
        assert data["auth_jwt"] is not None
        assert data["auth_jwt"] is not False
        assert data["auth_jwt"]["sub"] == "user777"
        assert data["auth_jwt"]["scope"] == "openid"
        # Frozen Box converts lists to tuples for immutability
        assert data["auth_jwt"]["roles"] == ["admin"]
        assert data["auth_jwt"]["permissions"] == ["read:all"]
        assert data["missing_auth_header"] is False
        assert data["invalid_bearer_token"] is False


class TestMiddlewareIntegration:
    """Test middleware integration with FastAPI routes."""

    def test_middleware_accessible_in_route_handler(self, app_with_middleware, test_key):
        """Test that middleware state is accessible in route handlers."""

        @app_with_middleware.get("/protected")
        async def protected_route(request: Request):
            if request.state.auth_jwt:
                return {"user": request.state.auth_jwt.sub}
            return {"error": "Unauthorized"}

        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                "sub": "user888",
                "aud": "test-audience",
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            },
            alg="RS256",
        )

        client = TestClient(app_with_middleware)
        response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        data = response.json()
        assert data["user"] == "user888"

    def test_middleware_with_invalid_token_in_route(self, app_with_middleware):
        """Test route handler behavior with invalid token."""

        @app_with_middleware.get("/check-auth")
        async def check_auth(request: Request):
            if request.state.auth_jwt is False:
                return {"status": "invalid_token"}
            elif request.state.auth_jwt is None:
                return {"status": "no_token"}
            else:
                return {"status": "valid_token", "user": request.state.auth_jwt.sub}

        client = TestClient(app_with_middleware)

        # Test with invalid token
        response = client.get("/check-auth", headers={"Authorization": "Bearer invalid.token"})
        assert response.json()["status"] == "invalid_token"

        # Test with no token
        response = client.get("/check-auth")
        assert response.json()["status"] == "no_token"
