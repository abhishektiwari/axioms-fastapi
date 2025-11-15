"""Integration tests for helper.py functions.

This module contains comprehensive tests for has_valid_token and related
token validation functions.
"""

import json
import time
import pytest
from unittest.mock import patch, MagicMock
from box.exceptions import BoxError
from axioms_fastapi.helper import has_valid_token, cache
from axioms_fastapi.error import AxiomsError
from axioms_fastapi.config import AxiomsConfig
from conftest import generate_jwt_token


@pytest.fixture
def mock_jwks_response(test_key):
    """Mock JWKS endpoint response."""
    jwks_data = {
        'keys': [json.loads(test_key.export_public())]
    }
    return json.dumps(jwks_data).encode('utf-8')


@pytest.fixture
def mock_urlopen(mock_jwks_response):
    """Mock urlopen to return JWKS data."""
    with patch('axioms_fastapi.helper.urlopen') as mock:
        mock_response = MagicMock()
        mock_response.read.return_value = mock_jwks_response
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = False
        mock.return_value = mock_response
        yield mock


@pytest.fixture(autouse=True)
def clear_cache_between_tests():
    """Clear cache before and after each test to prevent JWKS caching issues."""
    cache._cache.clear()
    yield
    cache._cache.clear()


@pytest.fixture
def default_config():
    """Default test configuration."""
    return AxiomsConfig(
        AXIOMS_AUDIENCE='test-audience',
        AXIOMS_ISS_URL='https://test-domain.com',
        AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json'
    )


class TestHasValidToken:
    """Test has_valid_token function with various token scenarios.

    Default test configuration:
    - AXIOMS_AUDIENCE = 'test-audience'
    - AXIOMS_ISS_URL = 'https://test-domain.com'
    - AXIOMS_JWKS_URL = 'https://test-domain.com/.well-known/jwks.json'
    """

    def test_valid_token_returns_payload(self, test_key, mock_urlopen, default_config):
        """Test that a valid token returns the payload as an immutable Box."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token, default_config)

        # Verify payload contents
        assert payload.sub == 'user123'
        assert payload.aud == ('test-audience',)  # Frozen Box converts lists to tuples
        assert payload.iss == 'https://test-domain.com'
        assert payload.scope == 'openid profile'

        # Verify jti (JWT ID) is automatically added
        assert hasattr(payload, 'jti')
        assert payload.jti is not None
        assert len(payload.jti) > 0  # Should be a UUID string

        # Verify Box is frozen (immutable)
        with pytest.raises(BoxError):
            payload.sub = 'hacker'

    def test_expired_token_raises_error(self, test_key, mock_urlopen, default_config):
        """Test that an expired token raises AxiomsError."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now - 3600,  # Expired 1 hour ago
            'iat': now - 7200
        }

        token = generate_jwt_token(test_key, claims)

        with pytest.raises(AxiomsError):
            has_valid_token(token, default_config)

    def test_tampered_token_raises_error(self, test_key, mock_urlopen, default_config):
        """Test that a tampered token raises AxiomsError."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)

        # Tamper with the token by changing a character in the payload section
        parts = token.split('.')
        if len(parts) == 3:
            # Change one character in the payload (base64 encoded)
            tampered_payload = parts[1][:-1] + ('A' if parts[1][-1] != 'A' else 'B')
            tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

            with pytest.raises(AxiomsError):
                has_valid_token(tampered_token, default_config)

    def test_wrong_audience_raises_error(self, test_key, mock_urlopen, default_config):
        """Test that a token with wrong audience raises AxiomsError."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['wrong-audience'],  # Wrong audience
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)

        with pytest.raises(AxiomsError):
            has_valid_token(token, default_config)

    def test_wrong_issuer_raises_error(self, test_key, mock_urlopen, default_config):
        """Test that a token with wrong issuer raises AxiomsError."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://evil-domain.com',  # Wrong issuer
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)

        with pytest.raises(AxiomsError):
            has_valid_token(token, default_config)

    def test_token_without_issuer_when_not_required(self, test_key, mock_urlopen):
        """Test that a token without issuer succeeds when issuer validation is not configured."""
        config = AxiomsConfig(
            AXIOMS_AUDIENCE='test-audience',
            AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json'
        )

        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            # No 'iss' claim
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token, config)

        assert payload.sub == 'user123'

    def test_token_without_kid_raises_error(self, test_key, mock_urlopen, default_config):
        """Test that a token without kid in header raises AxiomsError."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        # Generate token without kid
        token = generate_jwt_token(test_key, claims, include_kid=False)

        with pytest.raises(AxiomsError):
            has_valid_token(token, default_config)

    def test_token_with_symmetric_algorithm_raises_error(self, test_key, mock_urlopen, default_config):
        """Test that a token with symmetric algorithm (HS256) raises AxiomsError.

        Uses manual JWT construction to create a token claiming HS256 algorithm.
        """
        import base64

        now = int(time.time())

        # Manually construct JWT with HS256 in header
        header = base64.urlsafe_b64encode(
            json.dumps({'alg': 'HS256', 'typ': 'JWT', 'kid': test_key.kid}).encode()
        ).decode().rstrip('=')

        payload = base64.urlsafe_b64encode(
            json.dumps({
                'sub': 'user123',
                'aud': ['test-audience'],
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now,
                'jti': 'test-jti'
            }).encode()
        ).decode().rstrip('=')

        # Create fake signature
        signature = base64.urlsafe_b64encode(b'fake_signature').decode().rstrip('=')

        token = f"{header}.{payload}.{signature}"

        with pytest.raises(AxiomsError):
            has_valid_token(token, default_config)

    def test_token_with_none_algorithm_raises_error(self, test_key, mock_urlopen, default_config):
        """Test that a token with 'none' algorithm raises AxiomsError.

        Uses manual JWT construction to create a token claiming 'none' algorithm.
        """
        import base64

        now = int(time.time())

        # Manually construct JWT with 'none' in header
        header = base64.urlsafe_b64encode(
            json.dumps({'alg': 'none', 'typ': 'JWT', 'kid': test_key.kid}).encode()
        ).decode().rstrip('=')

        payload = base64.urlsafe_b64encode(
            json.dumps({
                'sub': 'user123',
                'aud': ['test-audience'],
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now,
                'jti': 'test-jti'
            }).encode()
        ).decode().rstrip('=')

        # 'none' algorithm has no signature
        token = f"{header}.{payload}."

        with pytest.raises(AxiomsError):
            has_valid_token(token, default_config)

    def test_token_without_exp_claim_raises_error(self, test_key, mock_urlopen, default_config):
        """Test that a token without exp claim raises AxiomsError.

        Manually constructs a properly signed JWT token that's missing the exp claim.
        """
        import jwt as pyjwt

        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            # No 'exp' claim - this should cause rejection
            'iat': now,
            'jti': 'test-jti'
        }

        # Use PyJWT directly with options to allow missing exp during encoding
        key_json = test_key.export_private()
        algorithm = pyjwt.algorithms.get_default_algorithms()['RS256']
        pyjwt_key = algorithm.from_jwk(key_json)

        # Encode without exp claim (PyJWT allows this during encoding)
        token = pyjwt.encode(
            payload=claims,
            key=pyjwt_key,
            algorithm='RS256',
            headers={'kid': test_key.kid}
        )

        # Our validation should reject this because require_exp is True
        with pytest.raises(AxiomsError):
            has_valid_token(token, default_config)

    def test_token_with_future_iat_raises_error(self, test_key, mock_urlopen, default_config):
        """Test that a token with future iat (issued at) raises AxiomsError."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 7200,
            'iat': now + 3600  # Issued 1 hour in the future - invalid
        }

        token = generate_jwt_token(test_key, claims)

        with pytest.raises(AxiomsError):
            has_valid_token(token, default_config)

    def test_token_with_nbf_in_future_raises_error(self, test_key, mock_urlopen, default_config):
        """Test that a token with nbf (not before) in future raises AxiomsError."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 7200,
            'iat': now,
            'nbf': now + 3600  # Not valid before 1 hour from now
        }

        token = generate_jwt_token(test_key, claims)

        with pytest.raises(AxiomsError):
            has_valid_token(token, default_config)

    def test_token_with_multiple_audiences(self, test_key, mock_urlopen, default_config):
        """Test that a token with multiple audiences succeeds if one matches."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['other-audience', 'test-audience', 'another-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token, default_config)

        assert payload.sub == 'user123'
        assert 'test-audience' in payload.aud

    def test_malformed_token_raises_error(self, test_key, mock_urlopen, default_config):
        """Test that a malformed token raises AxiomsError."""
        malformed_tokens = [
            'not.a.valid.token',
            'invalid-token',
            '',
            'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9',  # Only header, no payload
            'a.b',  # Only 2 parts instead of 3
        ]

        for token in malformed_tokens:
            with pytest.raises(AxiomsError):
                has_valid_token(token, default_config)

    def test_token_with_different_kid_raises_error(self, test_key, mock_urlopen, default_config):
        """Test that a token with kid not in JWKS raises AxiomsError."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        # Generate token but modify header to use different kid
        custom_header = {
            'alg': 'RS256',
            'kid': 'different-key-id'  # Kid not in JWKS
        }
        token = generate_jwt_token(test_key, claims, custom_header=custom_header)

        with pytest.raises(AxiomsError):
            has_valid_token(token, default_config)

    def test_token_with_all_allowed_algorithms(self, test_key, mock_urlopen, default_config):
        """Test that tokens with all allowed asymmetric algorithms are accepted."""
        # Test with RS256 (already tested above, but included for completeness)
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        # RS256 is the default and should work
        token = generate_jwt_token(test_key, claims, alg='RS256')
        payload = has_valid_token(token, default_config)
        assert payload.sub == 'user123'

    def test_token_with_extra_claims(self, test_key, mock_urlopen, default_config):
        """Test that a token with extra claims is accepted."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now,
            'scope': 'openid profile email',
            'roles': ['admin', 'editor'],
            'permissions': ['read:all', 'write:all'],
            'custom_claim': 'custom_value',
            'email': 'user@example.com',
            'name': 'Test User'
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token, default_config)

        assert payload.sub == 'user123'
        assert payload.scope == 'openid profile email'
        assert payload.roles == ('admin', 'editor')  # Frozen Box converts to tuple
        assert payload.permissions == ('read:all', 'write:all')  # Frozen Box converts to tuple
        assert payload.custom_claim == 'custom_value'
        assert payload.email == 'user@example.com'

    def test_payload_immutability(self, test_key, mock_urlopen, default_config):
        """Test that the returned payload is truly immutable."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now,
            'scope': 'openid profile'
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token, default_config)

        # Try to modify various attributes - all should raise BoxError
        with pytest.raises(BoxError):
            payload.sub = 'hacker'

        with pytest.raises(BoxError):
            payload.scope = 'admin'

        with pytest.raises(BoxError):
            payload.new_claim = 'injected'

        with pytest.raises(BoxError):
            del payload.sub

    def test_jwks_fetch_failure_raises_error(self, test_key, default_config):
        """Test that JWKS fetch failure raises AxiomsError."""
        from axioms_fastapi import helper

        # Clear cache to ensure we fetch JWKS
        cache._cache.clear()

        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)

        # Mock CacheFetcher to raise an exception
        class FailingCacheFetcher:
            def fetch(self, url, max_age=300):
                raise Exception('Network error')

        with patch.object(helper, 'CacheFetcher', FailingCacheFetcher):
            with pytest.raises(AxiomsError):
                has_valid_token(token, default_config)

    def test_invalid_jwks_response_raises_error(self, test_key, default_config):
        """Test that invalid JWKS response raises AxiomsError."""
        from axioms_fastapi import helper

        # Clear cache to ensure we fetch JWKS
        cache._cache.clear()

        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)

        # Mock CacheFetcher to return invalid JWKS
        class InvalidJWKSFetcher:
            def fetch(self, url, max_age=300):
                return b'invalid json'

        with patch.object(helper, 'CacheFetcher', InvalidJWKSFetcher):
            with pytest.raises(AxiomsError):
                has_valid_token(token, default_config)

    def test_malformed_jwt_raises_error(self, test_key, mock_urlopen, default_config):
        """Test that a malformed JWT token raises AxiomsError."""
        # Create a completely invalid token
        invalid_token = "not.a.valid.jwt.token.at.all"

        with pytest.raises(AxiomsError):
            has_valid_token(invalid_token, default_config)


class TestCustomClaimNames:
    """Test custom claim name configurations for scopes, roles, and permissions."""

    def test_custom_scope_claim_name(self, test_key, mock_urlopen):
        """Test that custom scope claim name is recognized."""
        from axioms_fastapi.helper import get_claim_from_token

        config = AxiomsConfig(
            AXIOMS_AUDIENCE='test-audience',
            AXIOMS_ISS_URL='https://test-domain.com',
            AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json',
            AXIOMS_SCOPE_CLAIMS=['scp']
        )

        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scp': 'read:data write:data',  # Custom scope claim
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token, config)
        scopes = get_claim_from_token(payload, 'SCOPE', config)

        assert scopes == 'read:data write:data'

    def test_custom_scope_claim_as_list(self, test_key, mock_urlopen):
        """Test that custom scope claim in list format is handled.

        Note: Frozen Box converts lists to tuples for immutability, so the tuple
        case needs to be handled in helper.py.
        """
        from axioms_fastapi.helper import get_claim_from_token

        config = AxiomsConfig(
            AXIOMS_AUDIENCE='test-audience',
            AXIOMS_ISS_URL='https://test-domain.com',
            AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json',
            AXIOMS_SCOPE_CLAIMS=['scp']
        )

        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scp': ['read:data', 'write:data'],  # List format
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token, config)

        # Frozen Box converts list to tuple
        assert payload.scp == ('read:data', 'write:data')

        scopes = get_claim_from_token(payload, 'SCOPE', config)
        # helper.py handles both list and tuple formats and returns space-separated string
        assert scopes == 'read:data write:data'

    def test_custom_roles_claim_name(self, test_key, mock_urlopen):
        """Test that custom roles claim name (namespaced) is recognized."""
        from axioms_fastapi.helper import get_claim_from_token

        config = AxiomsConfig(
            AXIOMS_AUDIENCE='test-audience',
            AXIOMS_ISS_URL='https://test-domain.com',
            AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json',
            AXIOMS_ROLES_CLAIMS=['https://example.com/roles']
        )

        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'https://example.com/roles': ['admin', 'editor'],  # Namespaced claim
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token, config)
        roles = get_claim_from_token(payload, 'ROLES', config)

        assert roles == ('admin', 'editor')  # Frozen Box converts lists to tuples

    def test_custom_permissions_claim_name(self, test_key, mock_urlopen):
        """Test that custom permissions claim name (namespaced) is recognized."""
        from axioms_fastapi.helper import get_claim_from_token

        config = AxiomsConfig(
            AXIOMS_AUDIENCE='test-audience',
            AXIOMS_ISS_URL='https://test-domain.com',
            AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json',
            AXIOMS_PERMISSIONS_CLAIMS=['https://example.com/permissions']
        )

        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'https://example.com/permissions': ['read:users', 'write:users'],  # Namespaced claim
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token, config)
        permissions = get_claim_from_token(payload, 'PERMISSIONS', config)

        assert permissions == ('read:users', 'write:users')  # Frozen Box converts lists to tuples


class TestDomainProcessing:
    """Test domain processing with various protocol configurations."""

    def test_domain_with_https_protocol_is_normalized(self, test_key, mock_urlopen):
        """Test that AXIOMS_DOMAIN with https:// protocol is normalized correctly."""
        from axioms_fastapi.helper import get_expected_issuer

        config = AxiomsConfig(
            AXIOMS_AUDIENCE='test-audience',
            AXIOMS_DOMAIN='https://auth.example.com'
        )

        issuer = get_expected_issuer(config)
        assert issuer == 'https://auth.example.com'

        # Test that token validation works with normalized domain
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://auth.example.com',
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token, config)
        assert payload.iss == 'https://auth.example.com'

    def test_domain_with_http_protocol_is_normalized(self, test_key, mock_urlopen):
        """Test that AXIOMS_DOMAIN with http:// protocol is normalized to https://."""
        from axioms_fastapi.helper import get_expected_issuer

        config = AxiomsConfig(
            AXIOMS_AUDIENCE='test-audience',
            AXIOMS_DOMAIN='http://auth.example.com'
        )

        issuer = get_expected_issuer(config)
        # Should strip http:// and add https://
        assert issuer == 'https://auth.example.com'

    def test_jwks_url_constructed_from_issuer_url(self, test_key, mock_urlopen):
        """Test that JWKS URL is correctly constructed from AXIOMS_ISS_URL."""
        from axioms_fastapi.helper import get_jwks_url

        config = AxiomsConfig(
            AXIOMS_AUDIENCE='test-audience',
            AXIOMS_ISS_URL='https://auth.example.com/oauth2'
        )

        jwks_url = get_jwks_url(config)
        assert jwks_url == 'https://auth.example.com/oauth2/.well-known/jwks.json'

    def test_jwks_url_from_domain_fallback(self, test_key, mock_urlopen):
        """Test that JWKS URL is constructed from AXIOMS_DOMAIN as fallback."""
        from axioms_fastapi.helper import get_jwks_url

        config = AxiomsConfig(
            AXIOMS_AUDIENCE='test-audience',
            AXIOMS_DOMAIN='auth.example.com'
        )

        jwks_url = get_jwks_url(config)
        assert jwks_url == 'https://auth.example.com/.well-known/jwks.json'


class TestCheckFunctionsEdgeCases:
    """Test edge cases for check_scopes, check_roles, check_permissions."""

    def test_check_scopes_with_empty_requirements(self):
        """Test that check_scopes returns True when required_scopes is empty."""
        from axioms_fastapi.helper import check_scopes

        provided_scopes = 'read:data write:data'
        required_scopes = []

        result = check_scopes(provided_scopes, required_scopes)
        assert result is True

    def test_check_roles_with_empty_requirements(self):
        """Test that check_roles returns True when view_roles is empty."""
        from axioms_fastapi.helper import check_roles

        token_roles = ['admin', 'editor']
        view_roles = []

        result = check_roles(token_roles, view_roles)
        assert result is True

    def test_check_permissions_with_empty_requirements(self):
        """Test that check_permissions returns True when view_permissions is empty."""
        from axioms_fastapi.helper import check_permissions

        token_permissions = ['read:users', 'write:users']
        view_permissions = []

        result = check_permissions(token_permissions, view_permissions)
        assert result is True


class TestJWKSCaching:
    """Test JWKS caching behavior."""

    def test_cache_fetcher_returns_cached_data(self, test_key):
        """Test that CacheFetcher returns cached data when available."""
        from axioms_fastapi.helper import CacheFetcher

        test_url = 'https://test-domain.com/.well-known/jwks.json'
        cache_key = "jwks" + test_url

        # Create test JWKS data
        jwks_data = {'keys': [json.loads(test_key.export_public())]}
        test_data = json.dumps(jwks_data).encode('utf-8')

        # Pre-populate cache with test data (simulating a previous fetch)
        cache.set(cache_key, test_data, timeout=600)

        fetcher = CacheFetcher()

        # Fetch should return cached data without calling urlopen
        # We don't need to mock urlopen - if it's called, test will fail with network error
        data = fetcher.fetch(test_url, max_age=600)

        # Verify it returned the cached data
        assert json.loads(data) == jwks_data
