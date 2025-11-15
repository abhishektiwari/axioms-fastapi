"""End-to-end tests for JWT algorithm validation.

Tests algorithm validation to prevent algorithm confusion attacks and ensure
only secure asymmetric algorithms are accepted.
"""

import json
import time
import pytest
import base64
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from axioms_fastapi import (
    init_axioms,
    require_auth,
    require_scopes,
    AxiomsHTTPException,
)
from conftest import generate_jwt_token


# Create malformed token with unsupported algorithm
def create_token_with_none_alg(claims):
    """Create a token with 'none' algorithm (security vulnerability)."""
    header = {"alg": "none", "typ": "JWT", "kid": "test-key-id"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    # 'none' algorithm has empty signature
    return f"{header_b64}.{payload_b64}."


# Create test FastAPI application
@pytest.fixture
def app():
    """Create FastAPI test application with protected routes."""
    fastapi_app = FastAPI()

    # Initialize Axioms configuration
    init_axioms(
        fastapi_app,
        AXIOMS_AUDIENCE='test-audience',
        AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json'
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
class TestAlgorithmValidation:
    """Test JWT algorithm validation for security."""

    def test_valid_rs256_algorithm(self, client, test_key):
        """Test that RS256 algorithm is accepted."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims, alg='RS256')
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_reject_none_algorithm(self, client):
        """Test that 'none' algorithm is rejected (critical security test)."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        }

        token = create_token_with_none_alg(claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = response.json()
        assert data['error'] == 'unauthorized_access'
        assert 'algorithm' in data['error_description'].lower()

    def test_reject_hs256_symmetric_algorithm(self, client, test_key):
        """Test that symmetric algorithms like HS256 are rejected."""
        # Try to create a token with HS256 (symmetric algorithm)
        # This should fail during token generation or be rejected during validation
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        }

        # Create a token with manipulated header claiming HS256
        header = {"alg": "HS256", "typ": "JWT", "kid": "test-key-id"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
        # Add fake signature
        signature_b64 = base64.urlsafe_b64encode(b'fake_signature').decode().rstrip('=')
        token = f"{header_b64}.{payload_b64}.{signature_b64}"

        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = response.json()
        assert data['error'] == 'unauthorized_access'
        assert 'algorithm' in data['error_description'].lower()

    def test_reject_missing_algorithm(self, client):
        """Test that tokens without algorithm are rejected."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        }

        # Create token without 'alg' header
        header = {"typ": "JWT", "kid": "test-key-id"}  # Missing 'alg'
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
        signature_b64 = base64.urlsafe_b64encode(b'fake_signature').decode().rstrip('=')
        token = f"{header_b64}.{payload_b64}.{signature_b64}"

        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = response.json()
        assert data['error'] == 'unauthorized_access'

    def test_reject_missing_kid(self, client, test_key):
        """Test that tokens without key ID are rejected."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        # Create token without kid in header
        token = generate_jwt_token(test_key, json.loads(claims), include_kid=False)

        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = response.json()
        assert data['error'] == 'unauthorized_access'
        assert 'key id' in data['error_description'].lower() or 'kid' in data['error_description'].lower()

    def test_allowed_algorithms_coverage(self, client, test_key):
        """Test that all allowed asymmetric algorithms are accepted."""
        # Note: RS256 is tested separately, this tests the pattern
        # In practice, we'd need different keys for different algorithms

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        # Test RS256 (our test key is RSA)
        token = generate_jwt_token(test_key, claims, alg='RS256')
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

        # Note: To test other algorithms (RS384, RS512, ES256, etc.) we would need
        # to generate appropriate keys and update JWKS. The validation logic
        # supports them via ALLOWED_ALGORITHMS constant.

    def test_invalid_jwt_format(self, client):
        """Test that malformed JWT tokens are rejected."""
        # Token with invalid format (missing parts)
        token = "invalid.token"

        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = response.json()
        assert data['error'] == 'unauthorized_access'
