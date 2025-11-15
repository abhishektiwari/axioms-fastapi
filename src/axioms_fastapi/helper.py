"""Token validation and JWT verification for Axioms authentication.

This module handles JWT token validation, signature verification, JWKS key retrieval,
and claim extraction. It supports configurable claim names to work with different
authorization servers (AWS Cognito, Auth0, Okta, etc.).

For complete configuration documentation, see the Configuration section in the API reference.
"""

import logging
import time
from typing import Any, List, Optional
from urllib.parse import urlparse
from urllib.request import urlopen

import jwt
from box import Box
from fastapi import Request
from jwcrypto import jwk

from .config import AxiomsConfig, get_config
from .error import AxiomsError

logger = logging.getLogger(__name__)


class SimpleCache:
    """Simple in-memory cache with timeout support."""

    def __init__(self):
        """Initialize the cache storage."""
        self._cache = {}

    def get(self, key):
        """Get value from cache if not expired.

        Args:
            key: Cache key to retrieve.

        Returns:
            Cached value or None if not found or expired.
        """
        if key in self._cache:
            value, expiry = self._cache[key]
            if expiry is None or time.time() < expiry:
                return value
            else:
                del self._cache[key]
        return None

    def set(self, key, value, timeout=300):
        """Set value in cache with optional timeout.

        Args:
            key: Cache key to store.
            value: Value to cache.
            timeout: Expiration timeout in seconds (default: 300).
        """
        expiry = time.time() + timeout if timeout else None
        self._cache[key] = (value, expiry)


cache = SimpleCache()

# Allowed signature algorithms for JWT validation
# Only asymmetric algorithms are allowed to prevent algorithm confusion attacks
ALLOWED_ALGORITHMS = frozenset(
    [
        "RS256",
        "RS384",
        "RS512",  # RSA with SHA-256, SHA-384, SHA-512
        "ES256",
        "ES384",
        "ES512",  # ECDSA with SHA-256, SHA-384, SHA-512
        "PS256",
        "PS384",
        "PS512",  # RSA-PSS with SHA-256, SHA-384, SHA-512
    ]
)


def get_claim_names(
    claim_type: str, config: Optional[AxiomsConfig] = None
) -> List[str]:
    """Get list of claim names to check for a given claim type.

    Checks configuration for custom claim names, falling back to defaults.
    Supports both single claim name and list of claim names.

    Args:
        claim_type: Type of claim ('SCOPE', 'ROLES', or 'PERMISSIONS').
        config: Optional AxiomsConfig instance. If None, uses global config.

    Returns:
        list: List of claim names to check in priority order.

    Example::

        get_claim_names('ROLES')
        # Returns: ['roles']
    """
    if config is None:
        config = get_config()

    # Check if list configuration exists (e.g., AXIOMS_ROLES_CLAIMS)
    list_attr = f"AXIOMS_{claim_type.upper()}_CLAIMS"
    claims = getattr(config, list_attr, None)
    if claims is not None:
        return claims if isinstance(claims, list) else [claims]

    # Default claim names
    defaults = {"SCOPE": ["scope"], "ROLES": ["roles"], "PERMISSIONS": ["permissions"]}

    return defaults.get(claim_type.upper(), [])


def get_claim_from_token(
    payload: Box, claim_type: str, config: Optional[AxiomsConfig] = None
) -> Any:
    """Extract claim value from token payload.

    Checks multiple possible claim names based on configuration,
    returning the first non-None value found. Handles both string and list/tuple formats.

    Args:
        payload: Decoded JWT token payload (Box object).
        claim_type: Type of claim ('SCOPE', 'ROLES', or 'PERMISSIONS').
        config: Optional AxiomsConfig instance. If None, uses global config.

    Returns:
        The claim value if found, None otherwise. For SCOPE claims in list/tuple format,
        returns a space-separated string.

    Example::

        get_claim_from_token(payload, 'ROLES')
        # Returns: ['admin', 'editor'] or ('admin', 'editor') for frozen Box

        get_claim_from_token(payload, 'SCOPE')
        # Returns: 'openid profile' (converted from list/tuple if needed)
    """
    for claim_name in get_claim_names(claim_type, config):
        value = getattr(
            payload,
            claim_name.replace(":", "_").replace("/", "_").replace("-", "_"),
            None,
        )
        if value is None:
            # Try with original claim name (for standard claims)
            try:
                value = payload.get(claim_name)
            except (AttributeError, KeyError):
                value = None
        if value is not None:
            # Handle list/tuple format for scopes (frozen Box converts lists to tuples)
            if claim_type.upper() == "SCOPE" and isinstance(value, (list, tuple)):
                return " ".join(value)
            return value
    return None


def has_bearer_token(request: Request) -> str:
    """Extract and validate bearer token from request Authorization header.

    Args:
        request: FastAPI Request object containing HTTP headers.

    Returns:
        str: The extracted bearer token.

    Raises:
        AxiomsError: If Authorization header is missing, invalid, or malformed.
    """
    header_name = "Authorization"
    token_prefix = "bearer"
    auth_header = request.headers.get(header_name.lower(), None)
    if auth_header is None:
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": "Missing Authorization Header",
            },
            401,
        )
    try:
        bearer, _, token = auth_header.partition(" ")
        if bearer.lower() == token_prefix and token != "":
            return token
        else:
            raise AxiomsError(
                {
                    "error": "unauthorized_access",
                    "error_description": "Invalid Authorization Bearer",
                },
                401,
            )
    except (ValueError, AttributeError):
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": "Invalid Authorization Header",
            },
            401,
        )


def has_valid_token(token: str, config: Optional[AxiomsConfig] = None) -> Box:
    """Validate JWT token and verify audience and issuer claims.

    Extracts the key ID from the token, retrieves the public key from JWKS,
    validates the token signature and expiration, and checks the audience claim.
    If issuer configuration is available, also validates the issuer claim.

    Args:
        token: JWT token string to validate.
        config: Optional AxiomsConfig instance. If None, uses global config.

    Returns:
        Box: Validated token payload as a Box object.

    Raises:
        AxiomsError: If token is invalid, audience doesn't match, or issuer doesn't match.
    """
    if config is None:
        config = get_config()

    # Get and validate the token header
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": "Invalid token header",
            },
            401,
        )

    # Validate algorithm - must be in allowed list to prevent algorithm confusion attacks
    alg = header.get("alg")
    if not alg or alg not in ALLOWED_ALGORITHMS:
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": f"Invalid or unsupported algorithm: {alg}",
            },
            401,
        )

    kid = header.get("kid")
    if not kid:
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": "Missing key ID in token header",
            },
            401,
        )

    key = get_key_from_jwks_json(kid, config)
    payload = check_token_validity(token, key, alg, config)

    if not payload:
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": "Invalid access token",
            },
            401,
        )

    return payload


def check_token_validity(
    token: str, key, alg: str, config: Optional[AxiomsConfig] = None
) -> Optional[Box]:
    """Check token validity including expiry, audience, and issuer.

    Validates JWT token with comprehensive security checks:
    - Signature verification using JWKS public key
    - Algorithm validation (only secure asymmetric algorithms allowed)
    - Expiration time (exp claim must exist and be valid)
    - Audience (aud claim must match AXIOMS_AUDIENCE)
    - Issuer (iss claim validated if AXIOMS_ISS_URL or AXIOMS_DOMAIN configured)
    - Issued at time (iat claim)
    - Not before time (nbf claim if present)

    Args:
        token: JWT token string to validate.
        key: JWK key for verification.
        alg: Algorithm from token header (already validated against ALLOWED_ALGORITHMS).
        config: Optional AxiomsConfig instance. If None, uses global config.

    Returns:
        Box or None: Immutable (frozen) Box containing validated payload if valid,
                     None if validation fails.
    """
    if config is None:
        config = get_config()

    try:
        # Convert JWK to PyJWT-compatible key
        key_json = key.export_public()
        algorithm = jwt.algorithms.get_default_algorithms()[alg]
        pyjwt_key = algorithm.from_jwk(key_json)

        # Build decode options
        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_aud": True,
            "verify_iss": False,  # We'll handle this conditionally
            "verify_iat": True,
            "verify_nbf": True,
            "require_exp": True,
        }

        # Get expected issuer if configured
        expected_issuer = get_expected_issuer(config)
        if expected_issuer:
            options["verify_iss"] = True

        # Decode and verify token
        # Use ALLOWED_ALGORITHMS for defense-in-depth against algorithm confusion attacks
        payload = jwt.decode(
            token,
            pyjwt_key,
            algorithms=list(ALLOWED_ALGORITHMS),
            audience=config.AXIOMS_AUDIENCE,
            issuer=expected_issuer,
            options=options,
        )

        # Explicitly verify exp claim exists (PyJWT 2.10.1 bug workaround)
        # See: https://github.com/jpadilla/pyjwt/issues/870
        if "exp" not in payload:
            return None

        # Return immutable Box to prevent payload modification
        return Box(payload, frozen_box=True)

    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidAudienceError:
        return None
    except jwt.InvalidIssuerError:
        return None
    except jwt.InvalidSignatureError:
        return None
    except jwt.DecodeError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        return None


def check_scopes(provided_scopes: str, required_scopes: List[str]) -> bool:
    """Check if any required scopes are present in provided scopes.

    Args:
        provided_scopes: Space-separated string of scopes from the token.
        required_scopes: Iterable of required scope strings.

    Returns:
        bool: True if any required scope is present in provided scopes.
    """
    if not required_scopes:
        return True

    token_scopes = set(provided_scopes.split())
    scopes = set(required_scopes)
    return len(token_scopes.intersection(scopes)) > 0


def check_roles(token_roles: List[str], view_roles: List[str]) -> bool:
    """Check if any required roles are present in token roles.

    Args:
        token_roles: List or iterable of roles from the token.
        view_roles: List or iterable of required role strings.

    Returns:
        bool: True if any required role is present in token roles.
    """
    if not view_roles:
        return True

    token_roles = set(token_roles)
    view_roles = set(view_roles)
    return len(token_roles.intersection(view_roles)) > 0


def check_permissions(
    token_permissions: List[str], view_permissions: List[str]
) -> bool:
    """Check if any required permissions are present in token permissions.

    Args:
        token_permissions: List or iterable of permissions from the token.
        view_permissions: List or iterable of required permission strings.

    Returns:
        bool: True if any required permission is present in token permissions.
    """
    if not view_permissions:
        return True

    token_permissions = set(token_permissions)
    view_permissions = set(view_permissions)
    return len(token_permissions.intersection(view_permissions)) > 0


def get_expected_issuer(config: Optional[AxiomsConfig] = None) -> Optional[str]:
    """Get expected issuer URL from application config.

    Checks for AXIOMS_ISS_URL first, then constructs from AXIOMS_DOMAIN.
    The issuer is used to validate the 'iss' claim in JWT tokens.

    Args:
        config: Optional AxiomsConfig instance. If None, uses global config.

    Returns:
        str or None: Expected issuer URL (e.g., 'https://auth.example.com'),
                     or None if neither AXIOMS_ISS_URL nor AXIOMS_DOMAIN is configured.

    Example::

        config = AxiomsConfig(
            AXIOMS_AUDIENCE="api.example.com",
            AXIOMS_ISS_URL="https://auth.example.com/oauth2"
        )
        get_expected_issuer(config)
        # Returns: 'https://auth.example.com/oauth2'

        config = AxiomsConfig(
            AXIOMS_AUDIENCE="api.example.com",
            AXIOMS_DOMAIN="auth.example.com"
        )
        get_expected_issuer(config)
        # Returns: 'https://auth.example.com'
    """
    if config is None:
        config = get_config()

    # Check for explicit issuer URL first
    if config.AXIOMS_ISS_URL:
        return config.AXIOMS_ISS_URL

    # Construct from domain if available
    if config.AXIOMS_DOMAIN:
        domain = config.AXIOMS_DOMAIN
        # Remove protocol if present
        domain = domain.replace("https://", "").replace("http://", "")
        return f"https://{domain}"

    return None


def get_jwks_url(config: Optional[AxiomsConfig] = None) -> str:
    """Get JWKS URL from application config.

    Checks for AXIOMS_JWKS_URL first, then constructs URL from AXIOMS_ISS_URL.
    If AXIOMS_ISS_URL is not set, it will be derived from AXIOMS_DOMAIN.

    Configuration hierarchy:
        1. AXIOMS_JWKS_URL (if set, used directly)
        2. AXIOMS_ISS_URL + /.well-known/jwks.json
        3. https://{AXIOMS_DOMAIN} + /.well-known/jwks.json (via AXIOMS_ISS_URL)

    Args:
        config: Optional AxiomsConfig instance. If None, uses global config.

    Returns:
        str: Full JWKS URL.

    Raises:
        Exception: If JWKS URL cannot be determined from configuration.
    """
    if config is None:
        config = get_config()

    # Check for explicit JWKS URL first
    if config.AXIOMS_JWKS_URL:
        return config.AXIOMS_JWKS_URL

    # Construct from issuer URL
    issuer_url = get_expected_issuer(config)
    if issuer_url:
        return f"{issuer_url}/.well-known/jwks.json"

    raise Exception(
        "Please set either AXIOMS_JWKS_URL, AXIOMS_ISS_URL, or AXIOMS_DOMAIN in your config. "
        "For more details review axioms-fastapi docs."
    )


def get_key_from_jwks_json(kid: str, config: Optional[AxiomsConfig] = None):
    """Retrieve public key from JWKS endpoint for token verification.

    Args:
        kid: Key ID from the JWT header.
        config: Optional AxiomsConfig instance. If None, uses global config.

    Returns:
        JWK: JSON Web Key for signature verification.

    Raises:
        AxiomsError: If key cannot be retrieved or is invalid.
    """
    try:
        fetcher = CacheFetcher()
        jwks_url = get_jwks_url(config)
        data = fetcher.fetch(jwks_url, 600)
        key = jwk.JWKSet().from_json(data).get_key(kid)
        return key
    except AxiomsError:
        # Re-raise AxiomsError as-is (e.g., invalid URL scheme)
        raise
    except Exception:
        raise AxiomsError(
            {
                "error": "unauthorized_access",
                "error_description": "Invalid access token",
            },
            401,
        )


class CacheFetcher:
    """Cache fetcher for JWKS data with simple in-memory caching."""

    def fetch(self, url: str, max_age: int = 300) -> bytes:
        """Fetch URL data with caching.

        Args:
            url: URL to fetch.
            max_age: Cache timeout in seconds (default: 300).

        Returns:
            bytes: Fetched data from URL or cache.

        Raises:
            Exception: If URL cannot be fetched (network error, HTTP error, timeout, etc.).
        """
        # Check cache first
        cached = cache.get("jwks" + url)
        if cached:
            return cached

        # Validate URL scheme for security (prevent file://, ftp://, etc.)
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ("http", "https"):
            logger.error(
                f"Invalid URL scheme detected: {parsed_url.scheme}. "
                f"URL: {url}"
            )
            raise AxiomsError(
                {
                    "error": "server_error",
                    "error_description": (
                        "Invalid JWKS URL configuration. "
                        "Only http and https schemes are allowed."
                    ),
                },
                500,
            )

        # Fetch from URL with default secure SSL context
        # Python's urlopen uses verified SSL by default (validates certificates)
        try:
            data = urlopen(url).read()
            cache.set("jwks" + url, data, timeout=max_age)
            return data
        except Exception as e:
            # Log the error with details for debugging
            logger.error(
                f"Failed to fetch JWKS from {url}: {type(e).__name__}: {str(e)}"
            )
            # Re-raise to bubble up
            raise
