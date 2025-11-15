"""End-to-end tests for JWT issuer claim validation.

Tests the issuer validation feature that validates the 'iss' claim in JWT tokens
to ensure cryptographic keys belong to the expected issuer, preventing token
substitution attacks.
"""

import json
import time
import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from axioms_fastapi import (
    init_axioms,
    require_auth,
    require_scopes,
    AxiomsHTTPException,
)
from axioms_fastapi.config import AxiomsConfig
from conftest import generate_jwt_token


# Create test FastAPI application
@pytest.fixture
def app():
    """Create FastAPI test application with protected routes."""
    fastapi_app = FastAPI()

    # Initialize Axioms configuration
    init_axioms(
        fastapi_app,
        AXIOMS_AUDIENCE='test-audience',
        AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json',
        AXIOMS_DOMAIN='test-domain.com'
    )

    # Exception handler
    @fastapi_app.exception_handler(AxiomsHTTPException)
    async def axioms_exception_handler(request, exc: AxiomsHTTPException):
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.detail,
            headers=exc.headers if exc.headers else {},
        )

    # Create test endpoints
    @fastapi_app.get('/private')
    async def api_private(
        payload=Depends(require_auth),
        _=Depends(require_scopes(['openid', 'profile']))
    ):
        return {'message': 'Private endpoint'}

    return fastapi_app


# Test classes
class TestIssuerValidation:
    """Test issuer claim validation for token security."""

    def test_valid_token_with_matching_issuer(self, client, test_key, app):
        """Test that token with matching issuer is accepted."""
        # Update config with issuer URL
        app.state.axioms_config.AXIOMS_ISS_URL = 'https://test-domain.com'

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert data['message'] == 'Private endpoint'

    def test_token_with_wrong_issuer(self, client, test_key, app):
        """Test that token with wrong issuer is rejected."""
        app.state.axioms_config.AXIOMS_ISS_URL = 'https://test-domain.com'

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://malicious-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = response.json()
        assert data['error'] == 'unauthorized_access'
        # Generic error message for security (doesn't leak implementation details)
        assert data['error_description'] == 'Invalid access token'

    def test_token_without_issuer_claim_when_validation_enabled(self, client, test_key, app):
        """Test that token without issuer is rejected when validation is enabled."""
        app.state.axioms_config.AXIOMS_ISS_URL = 'https://test-domain.com'

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = response.json()
        assert data['error'] == 'unauthorized_access'
        # Generic error message for security (doesn't leak implementation details)
        assert data['error_description'] == 'Invalid access token'

    def test_issuer_derived_from_domain(self, client, test_key, app):
        """Test that issuer is correctly derived from AXIOMS_DOMAIN."""
        # Set domain and let it construct issuer URL
        app.state.axioms_config.AXIOMS_DOMAIN = 'test-domain.com'
        app.state.axioms_config.AXIOMS_ISS_URL = None  # Will be derived from domain

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_backward_compatibility_no_issuer_validation(self, client, test_key, app):
        """Test backward compatibility: tokens without issuer work when validation not configured."""
        # Only set AXIOMS_JWKS_URL, no AXIOMS_ISS_URL or AXIOMS_DOMAIN
        app.state.axioms_config.AXIOMS_JWKS_URL = 'https://test-domain.com/.well-known/jwks.json'
        app.state.axioms_config.AXIOMS_ISS_URL = None
        app.state.axioms_config.AXIOMS_DOMAIN = None

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert data['message'] == 'Private endpoint'

    def test_issuer_with_path(self, client, test_key, app):
        """Test that issuer URL with path is correctly validated."""
        app.state.axioms_config.AXIOMS_ISS_URL = 'https://auth.example.com/oauth2'

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://auth.example.com/oauth2',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_issuer_mismatch_with_path(self, client, test_key, app):
        """Test that issuer path must match exactly."""
        app.state.axioms_config.AXIOMS_ISS_URL = 'https://auth.example.com/oauth2'

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://auth.example.com/different',  # Different path
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = response.json()
        assert data['error'] == 'unauthorized_access'
        # Generic error message for security (doesn't leak implementation details)
        assert data['error_description'] == 'Invalid access token'
