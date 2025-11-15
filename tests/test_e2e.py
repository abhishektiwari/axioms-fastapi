"""End-to-end tests for axioms-fastapi dependencies.

This module creates a FastAPI test application with protected routes
and verifies that authentication and authorization work correctly.
"""

import json
import time
import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from axioms_fastapi import (
    require_auth,
    require_scopes,
    require_roles,
    require_permissions,
    register_axioms_exception_handler,
)
from axioms_fastapi.config import init_axioms
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

    # Register exception handler for Axioms errors
    register_axioms_exception_handler(fastapi_app)

    # Public endpoint
    @fastapi_app.get('/public')
    async def api_public():
        return {'message': 'Public endpoint - no authentication required'}

    # Private endpoint with scopes
    @fastapi_app.get('/private')
    async def api_private(
        payload=Depends(require_auth),
        _=Depends(require_scopes(['openid', 'profile']))
    ):
        return {'message': 'Private endpoint - authenticated'}

    # Role-based endpoint (multiple methods)
    @fastapi_app.get('/role')
    async def sample_role_get(
        payload=Depends(require_auth),
        _=Depends(require_roles(['admin', 'editor']))
    ):
        return {'message': 'Sample read.'}

    @fastapi_app.post('/role')
    async def sample_role_post(
        payload=Depends(require_auth),
        _=Depends(require_roles(['admin', 'editor']))
    ):
        return {'message': 'Sample created.'}

    @fastapi_app.patch('/role')
    async def sample_role_patch(
        payload=Depends(require_auth),
        _=Depends(require_roles(['admin', 'editor']))
    ):
        return {'message': 'Sample updated.'}

    @fastapi_app.delete('/role')
    async def sample_role_delete(
        payload=Depends(require_auth),
        _=Depends(require_roles(['admin', 'editor']))
    ):
        return {'message': 'Sample deleted.'}

    # Permission-based endpoints
    @fastapi_app.post('/permission/create')
    async def sample_create(
        payload=Depends(require_auth),
        _=Depends(require_permissions(['sample:create']))
    ):
        return {'message': 'Sample created.'}

    @fastapi_app.patch('/permission/update')
    async def sample_update(
        payload=Depends(require_auth),
        _=Depends(require_permissions(['sample:update']))
    ):
        return {'message': 'Sample updated.'}

    @fastapi_app.get('/permission/read')
    async def sample_read(
        payload=Depends(require_auth),
        _=Depends(require_permissions(['sample:read']))
    ):
        return {'message': 'Sample read.'}

    @fastapi_app.delete('/permission/delete')
    async def sample_delete(
        payload=Depends(require_auth),
        _=Depends(require_permissions(['sample:delete']))
    ):
        return {'message': 'Sample deleted.'}

    # Chaining endpoints (AND logic tests)
    @fastapi_app.get('/chaining/scopes')
    async def chaining_scopes(
        payload=Depends(require_auth),
        _=Depends(require_scopes(['read:resource'])),
        __=Depends(require_scopes(['write:resource']))
    ):
        return {'message': 'Requires both read and write scopes'}

    @fastapi_app.get('/chaining/roles')
    async def chaining_roles(
        payload=Depends(require_auth),
        _=Depends(require_roles(['admin'])),
        __=Depends(require_roles(['superuser']))
    ):
        return {'message': 'Requires both admin and superuser roles'}

    @fastapi_app.get('/chaining/permissions')
    async def chaining_permissions(
        payload=Depends(require_auth),
        _=Depends(require_permissions(['sample:create'])),
        __=Depends(require_permissions(['sample:delete']))
    ):
        return {'message': 'Requires both create and delete permissions'}

    @fastapi_app.get('/chaining/mixed')
    async def chaining_mixed(
        payload=Depends(require_auth),
        _=Depends(require_scopes(['openid'])),
        __=Depends(require_roles(['editor'])),
        ___=Depends(require_permissions(['sample:read']))
    ):
        return {'message': 'Requires scope AND role AND permission'}

    return fastapi_app


# Test cases
class TestPublicEndpoints:
    """Test public endpoints that don't require authentication."""

    def test_public_endpoint_no_auth(self, client):
        """Test that public endpoint is accessible without authentication."""
        response = client.get('/public')
        assert response.status_code == 200
        data = response.json()
        assert 'message' in data
        assert data['message'] == 'Public endpoint - no authentication required'


class TestAuthentication:
    """Test authentication with valid and invalid tokens."""

    def test_private_endpoint_no_token(self, client):
        """Test that private endpoint rejects requests without token."""
        response = client.get('/private')
        assert response.status_code == 401
        data = response.json()
        assert data['error'] == 'unauthorized_access'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header

    def test_private_endpoint_invalid_bearer(self, client):
        """Test that private endpoint rejects invalid bearer format."""
        response = client.get('/private', headers={'Authorization': 'InvalidBearer token'})
        assert response.status_code == 401
        data = response.json()
        assert data['error'] == 'unauthorized_access'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header

    def test_private_endpoint_with_valid_token(self, client, test_key):
        """Test that private endpoint accepts valid token with required scopes."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile email',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert data['message'] == 'Private endpoint - authenticated'

    def test_private_endpoint_expired_token(self, client, test_key):
        """Test that private endpoint rejects expired tokens."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile email',
            'exp': now - 3600,  # Expired 1 hour ago
            'iat': now - 7200
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = response.json()
        assert data['error'] == 'unauthorized_access'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header

    def test_private_endpoint_wrong_audience(self, client, test_key):
        """Test that private endpoint rejects token with wrong audience."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['wrong-audience'],
            'scope': 'openid profile email',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = response.json()
        assert data['error'] == 'unauthorized_access'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header


class TestScopeAuthorization:
    """Test scope-based authorization."""

    def test_scope_with_required_scope(self, client, test_key):
        """Test that endpoint accepts token with required scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile email',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_scope_without_required_scope(self, client, test_key):
        """Test that endpoint rejects token without required scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'email',  # Missing 'openid' and 'profile'
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/private', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = response.json()
        assert data['error'] == 'insufficient_permission'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header


class TestRoleAuthorization:
    """Test role-based authorization."""

    def test_role_with_required_role(self, client, test_key):
        """Test that endpoint accepts token with required role."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'roles': ['admin', 'viewer'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert data['message'] == 'Sample read.'

    def test_role_without_required_role(self, client, test_key):
        """Test that endpoint rejects token without required role."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'roles': ['viewer'],  # Missing 'admin' or 'editor'
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = response.json()
        assert data['error'] == 'insufficient_permission'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header

    def test_role_with_namespaced_claims(self, client, test_key, app):
        """Test role checking with namespaced claims."""
        # Re-initialize with custom claim names
        init_axioms(
            app,
            AXIOMS_AUDIENCE='test-audience',
            AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json',
            AXIOMS_DOMAIN='test-domain.com',
            AXIOMS_ROLES_CLAIMS=['roles', 'https://test-domain.com/claims/roles']
        )

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'https://test-domain.com/claims/roles': ['admin'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_role_with_expired_token(self, client, test_key):
        """Test that role endpoint rejects expired token even with valid role."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'roles': ['admin'],  # Has required role but token is expired
            'exp': now - 3600,  # Expired 1 hour ago
            'iat': now - 7200
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = response.json()
        assert data['error'] == 'unauthorized_access'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header


class TestPermissionAuthorization:
    """Test permission-based authorization."""

    def test_permission_create_with_valid_permission(self, client, test_key):
        """Test create endpoint with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'permissions': ['sample:create', 'sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.post('/permission/create', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert data['message'] == 'Sample created.'

    def test_permission_create_without_permission(self, client, test_key):
        """Test create endpoint without required permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'permissions': ['sample:read'],  # Missing 'sample:create'
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.post('/permission/create', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = response.json()
        assert data['error'] == 'insufficient_permission'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header

    def test_permission_update_with_valid_permission(self, client, test_key):
        """Test update endpoint with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'permissions': ['sample:update'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.patch('/permission/update', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert data['message'] == 'Sample updated.'

    def test_permission_read_with_valid_permission(self, client, test_key):
        """Test read endpoint with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'permissions': ['sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/permission/read', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert data['message'] == 'Sample read.'

    def test_permission_delete_with_valid_permission(self, client, test_key):
        """Test delete endpoint with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'permissions': ['sample:delete'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.delete('/permission/delete', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert data['message'] == 'Sample deleted.'

    def test_permission_with_namespaced_claims(self, client, test_key, app):
        """Test permission checking with namespaced claims."""
        # Re-initialize with custom claim names
        init_axioms(
            app,
            AXIOMS_AUDIENCE='test-audience',
            AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json',
            AXIOMS_DOMAIN='test-domain.com',
            AXIOMS_PERMISSIONS_CLAIMS=['permissions', 'https://test-domain.com/claims/permissions']
        )

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'https://test-domain.com/claims/permissions': ['sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/permission/read', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_permission_with_expired_token(self, client, test_key):
        """Test that permission endpoint rejects expired token even with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'permissions': ['sample:read'],  # Has required permission but token is expired
            'exp': now - 3600,  # Expired 1 hour ago
            'iat': now - 7200
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/permission/read', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
        data = response.json()
        assert data['error'] == 'unauthorized_access'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header


class TestMultipleMethodsEndpoint:
    """Test endpoint that handles multiple HTTP methods with role authorization."""

    def test_role_endpoint_get(self, client, test_key):
        """Test GET method on role-protected endpoint."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'roles': ['editor'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/role', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert 'message' in data


class TestChainingDependencies:
    """Test chaining dependencies for AND logic."""

    def test_chaining_scopes_with_both_scopes(self, client, test_key):
        """Test chaining scopes succeeds when token has both required scopes."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'read:resource write:resource other:scope',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/scopes', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert data['message'] == 'Requires both read and write scopes'

    def test_chaining_scopes_with_only_one_scope(self, client, test_key):
        """Test chaining scopes fails when token has only one of the required scopes."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'read:resource other:scope',  # Missing write:resource
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/scopes', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = response.json()
        assert data['error'] == 'insufficient_permission'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header

    def test_chaining_scopes_with_no_scopes(self, client, test_key):
        """Test chaining scopes fails when token has neither required scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'other:scope',  # Missing both read:resource and write:resource
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/scopes', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = response.json()
        assert data['error'] == 'insufficient_permission'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header

    def test_chaining_roles_with_both_roles(self, client, test_key):
        """Test chaining roles succeeds when token has both required roles."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'roles': ['admin', 'superuser', 'viewer'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/roles', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert data['message'] == 'Requires both admin and superuser roles'

    def test_chaining_roles_with_only_one_role(self, client, test_key):
        """Test chaining roles fails when token has only one of the required roles."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'roles': ['admin', 'viewer'],  # Missing superuser
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/roles', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = response.json()
        assert data['error'] == 'insufficient_permission'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header

    def test_chaining_permissions_with_both_permissions(self, client, test_key):
        """Test chaining permissions succeeds when token has both required permissions."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'permissions': ['sample:create', 'sample:delete', 'sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/permissions', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert data['message'] == 'Requires both create and delete permissions'

    def test_chaining_permissions_with_only_one_permission(self, client, test_key):
        """Test chaining permissions fails when token has only one of the required permissions."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'permissions': ['sample:create', 'sample:read'],  # Missing sample:delete
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/permissions', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = response.json()
        assert data['error'] == 'insufficient_permission'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header

    def test_chaining_mixed_with_all_claims(self, client, test_key):
        """Test mixed chaining succeeds when token has all required claims."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile email',
            'roles': ['editor', 'viewer'],
            'permissions': ['sample:read', 'sample:write'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/mixed', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
        data = response.json()
        assert data['message'] == 'Requires scope AND role AND permission'

    def test_chaining_mixed_missing_scope(self, client, test_key):
        """Test mixed chaining fails when scope is missing."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'profile email',  # Missing openid
            'roles': ['editor'],
            'permissions': ['sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/mixed', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = response.json()
        assert data['error'] == 'insufficient_permission'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header

    def test_chaining_mixed_missing_role(self, client, test_key):
        """Test mixed chaining fails when role is missing."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'roles': ['viewer'],  # Missing editor
            'permissions': ['sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/mixed', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = response.json()
        assert data['error'] == 'insufficient_permission'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header

    def test_chaining_mixed_missing_permission(self, client, test_key):
        """Test mixed chaining fails when permission is missing."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'roles': ['editor'],
            'permissions': ['sample:write'],  # Missing sample:read
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        response = client.get('/chaining/mixed', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 403
        data = response.json()
        assert data['error'] == 'insufficient_permission'

        # Verify WWW-Authenticate header
        assert 'WWW-Authenticate' in response.headers
        auth_header = response.headers['WWW-Authenticate']
        assert auth_header.startswith('Bearer realm=')
        assert 'error=' in auth_header
        assert 'error_description=' in auth_header
