"""FastAPI middleware for JWT token extraction and validation.

This module provides ASGI middleware that extracts JWT tokens from the ``Authorization``
header and validates them before the request reaches the route handler. It sets attributes
on ``request.state`` that dependencies use to determine access.

The middleware must be added to the FastAPI application using ``app.add_middleware()``.

Configuration:
    Add to FastAPI application::

        from fastapi import FastAPI
        from axioms_fastapi import init_axioms
        from axioms_fastapi.middleware import AccessTokenMiddleware

        app = FastAPI()
        init_axioms(
            app,
            AXIOMS_AUDIENCE='your-api-audience',
            AXIOMS_ISS_URL='https://your-auth-domain.com',
            AXIOMS_JWKS_URL='https://your-auth-domain.com/.well-known/jwks.json'
        )

        # Add middleware
        app.add_middleware(AccessTokenMiddleware)

Classes:
    ``AccessTokenMiddleware``: ASGI middleware for JWT token processing.
"""

import logging
from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from .config import get_config
from .helper import has_valid_token

logger = logging.getLogger(__name__)


class AccessTokenMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that extracts and validates JWT tokens from ``Authorization`` header.

    This middleware processes incoming requests to extract JWT tokens from the
    ``Authorization`` header, validates them, and sets request state attributes that
    dependencies use to grant or deny access.

    The middleware sets the following attributes on ``request.state``:
        ``auth_jwt`` (Box|False|None): Validated token payload as Box object, ``False`` if
                                       validation failed, ``None`` if no token provided.
        ``missing_auth_header`` (bool): ``True`` if ``Authorization`` header is missing.
        ``invalid_bearer_token`` (bool): ``True`` if Bearer format is invalid.

    Token validation includes:
        - Signature verification using JWKS
        - Expiration time check
        - Audience claim validation
        - Issuer claim validation (if configured)
        - Algorithm validation (only secure asymmetric algorithms allowed)

    The middleware catches all validation exceptions and sets ``auth_jwt=False``,
    allowing dependencies to handle the error appropriately.

    Example::

        from fastapi import FastAPI
        from axioms_fastapi import init_axioms
        from axioms_fastapi.middleware import AccessTokenMiddleware

        app = FastAPI()
        init_axioms(
            app,
            AXIOMS_AUDIENCE='my-api',
            AXIOMS_ISS_URL='https://auth.example.com'
        )

        # Add middleware
        app.add_middleware(AccessTokenMiddleware)

        @app.get("/protected")
        async def protected_route(request: Request):
            # Access token payload from request.state.auth_jwt
            if request.state.auth_jwt:
                return {"user": request.state.auth_jwt.sub}
            return {"error": "Unauthorized"}

    Raises:
        Exception: If required configuration is not set. ``AXIOMS_AUDIENCE`` is
            always required. At least one JWKS source must be configured:
            ``AXIOMS_JWKS_URL``, ``AXIOMS_ISS_URL``, or ``AXIOMS_DOMAIN``.

    Note:
        This middleware should be added after ``init_axioms()`` is called to ensure
        configuration is properly set.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process incoming request to extract and validate JWT token.

        This method is called for every request before it reaches the route handler.
        It extracts the JWT token from the ``Authorization`` header, validates it,
        and sets request state attributes for use by dependencies.

        Request state attributes set:
            ``auth_jwt``: Box object with token payload if valid, ``False`` if invalid,
                ``None`` if missing
            ``missing_auth_header``: ``True`` if ``Authorization`` header not present
            ``invalid_bearer_token``: ``True`` if header doesn't match
                ``Bearer <token>`` format

        Args:
            request: FastAPI Request object.
            call_next: Callable to invoke the next middleware/route handler.

        Raises:
            Exception: If ``AXIOMS_AUDIENCE`` is not configured or if none of the JWKS
                source settings (``AXIOMS_JWKS_URL``, ``AXIOMS_ISS_URL``, or
                ``AXIOMS_DOMAIN``) are configured.

        Returns:
            Response: The response from the route handler or next middleware.
        """
        header_name = "authorization"
        token_prefix = "bearer"

        # Initialize request state attributes
        request.state.auth_jwt = None
        request.state.missing_auth_header = False
        request.state.invalid_bearer_token = False

        # Get configuration
        try:
            config = get_config()
        except Exception as e:
            logger.error(f"Failed to get Axioms configuration: {e}")
            raise Exception(
                "🔥🔥 Axioms configuration error. Ensure init_axioms() was called before adding middleware."
            )

        # Validate required configuration
        if not config.AXIOMS_AUDIENCE:
            raise Exception(
                "🔥🔥 AXIOMS_AUDIENCE is required. Please set AXIOMS_AUDIENCE in init_axioms()."
            )

        # Validate that at least one JWKS source is configured
        has_jwks_url = config.AXIOMS_JWKS_URL is not None
        has_iss_url = config.AXIOMS_ISS_URL is not None
        has_domain = config.AXIOMS_DOMAIN is not None

        if not (has_jwks_url or has_iss_url or has_domain):
            raise Exception(
                "🔥🔥 JWKS URL configuration required. Please set one of: "
                "AXIOMS_JWKS_URL, AXIOMS_ISS_URL, or AXIOMS_DOMAIN in init_axioms()."
            )

        # Extract and validate token
        auth_header = request.headers.get(header_name)
        if auth_header is None:
            request.state.missing_auth_header = True
        else:
            try:
                bearer, _, token = auth_header.partition(" ")
                # Strip whitespace from token to handle multiple spaces
                token = token.strip()
                if bearer.lower() == token_prefix and token != "":
                    payload = has_valid_token(token, config)
                    request.state.auth_jwt = payload
                else:
                    request.state.invalid_bearer_token = True
            except Exception as e:
                # Catch all exceptions from token validation
                # (invalid algorithm, expired, wrong issuer, etc.)
                # Set auth_jwt to False so dependencies know the token is invalid
                logger.debug(f"Token validation failed: {e}")
                request.state.auth_jwt = False

        response = await call_next(request)
        return response
