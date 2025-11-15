"""End-to-end tests for custom claim name configuration.

Tests support for different authorization servers (AWS Cognito, Auth0, Okta, etc.)
that use non-standard claim names.
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
    require_roles,
    require_permissions,
    AxiomsHTTPException,
)
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

    @fastapi_app.get('/role')
    async def sample_role(
        payload=Depends(require_auth),
        _=Depends(require_roles(['admin', 'editor']))
    ):
        return {'message': 'Sample read.'}

    @fastapi_app.get('/permission/read')
    async def sample_read(
        payload=Depends(require_auth),
        _=Depends(require_permissions(['sample:read']))
    ):
        return {'message': 'Sample read.'}

    return fastapi_app


# Test classes
class TestCognitoClaimNames:
    """Test AWS Cognito claim name configuration."""

    def test_cognito_groups_claim(self, client, test_key, app):
        """Test role authorization with Cognito-style cognito:groups claim."""
        app.state.axioms_config.AXIOMS_ROLES_CLAIMS = ['cognito:groups', 'roles']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'cognito:groups': ['admin', 'users'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert data['message'] == 'Sample read.'

    def test_cognito_roles_claim(self, client, test_key, app):
        """Test permission authorization with Cognito-style cognito:roles claim."""
        app.state.axioms_config.AXIOMS_PERMISSIONS_CLAIMS = ['cognito:roles', 'permissions']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'cognito:roles': ['sample:read', 'sample:write'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/permission/read', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert data['message'] == 'Sample read.'


class TestOktaClaimNames:
    """Test Okta claim name configuration."""

    def test_okta_groups_claim(self, client, test_key, app):
        """Test role authorization with Okta-style groups claim."""
        app.state.axioms_config.AXIOMS_ROLES_CLAIMS = ['groups', 'roles']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'groups': ['admin', 'developers'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200


class TestAlternateScopeClaimNames:
    """Test alternate scope claim names."""

    def test_scp_scope_claim(self, client, test_key, app):
        """Test scope authorization with alternate 'scp' claim name."""
        app.state.axioms_config.AXIOMS_SCOPE_CLAIMS = ['scp', 'scope']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scp': 'openid profile email',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200


class TestClaimPriority:
    """Test claim priority and fallback behavior."""

    def test_priority_order_first_claim_wins(self, client, test_key, app):
        """Test that claims are checked in priority order, first non-None wins."""
        app.state.axioms_config.AXIOMS_ROLES_CLAIMS = ['custom:roles', 'roles', 'groups']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'custom:roles': ['admin'],  # This should be found first
            'roles': ['viewer'],  # This should be ignored
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_fallback_to_second_claim(self, client, test_key, app):
        """Test fallback when first claim is not present."""
        app.state.axioms_config.AXIOMS_ROLES_CLAIMS = ['custom:roles', 'roles']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['admin'],  # custom:roles not present, should use this
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_no_matching_claims_fails(self, client, test_key, app):
        """Test that request fails when none of the configured claims are present."""
        app.state.axioms_config.AXIOMS_ROLES_CLAIMS = ['custom:roles', 'special:roles']

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['admin'],  # Configured claims not present
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
