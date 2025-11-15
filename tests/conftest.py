"""Pytest configuration and shared fixtures for axioms-fastapi tests."""

import json
import uuid
import pytest
import jwt
from jwcrypto import jwk


@pytest.fixture
def test_key():
    """Generate test RSA key for JWT signing."""
    key = jwk.JWK.generate(kty='RSA', size=2048, kid='test-key-id')
    return key


@pytest.fixture
def mock_jwks_data(test_key):
    """Generate mock JWKS data."""
    public_key = test_key.export_public(as_dict=True)
    jwks = {'keys': [public_key]}
    return json.dumps(jwks).encode('utf-8')


@pytest.fixture(autouse=True)
def mock_jwks_fetch(monkeypatch, mock_jwks_data):
    """Mock JWKS fetch to return test keys."""
    from axioms_fastapi import helper

    class MockCacheFetcher:
        def fetch(self, url, max_age=300):
            return mock_jwks_data

    monkeypatch.setattr(helper, 'CacheFetcher', MockCacheFetcher)


@pytest.fixture
def client(app):
    """Create FastAPI test client."""
    from fastapi.testclient import TestClient
    return TestClient(app)


def generate_jwt_token(key, claims, alg='RS256', include_kid=True, include_jti=True, custom_header=None):
    """Generate a JWT token with specified claims and algorithm using PyJWT.

    Args:
        key: JWK key for signing.
        claims: Dictionary or JSON string of claims.
        alg: Algorithm to use (default: RS256).
        include_kid: Whether to include kid in header (default: True).
        include_jti: Whether to add jti (JWT ID) claim (default: True).
        custom_header: Custom header dict to override defaults.

    Returns:
        str: Serialized JWT token.
    """
    # Convert claims to dict if it's a JSON string
    if isinstance(claims, str):
        claims_dict = json.loads(claims)
    else:
        claims_dict = claims.copy()

    # Add jti (JWT ID) if not present and requested
    if include_jti and 'jti' not in claims_dict:
        claims_dict['jti'] = str(uuid.uuid4())

    # Build headers
    if custom_header:
        headers = custom_header
    else:
        headers = {}
        if include_kid:
            headers['kid'] = key.kid

    # Convert JWK to PyJWT-compatible key
    key_json = key.export_private() if hasattr(key, 'export_private') else key.export_public()
    algorithm = jwt.algorithms.get_default_algorithms()[alg]
    pyjwt_key = algorithm.from_jwk(key_json)

    # Generate token using PyJWT
    token = jwt.encode(
        payload=claims_dict,
        key=pyjwt_key,
        algorithm=alg,
        headers=headers
    )

    return token
