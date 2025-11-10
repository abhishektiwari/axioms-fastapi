"""Error handling for Axioms FastAPI authentication and authorization.

This module defines custom exceptions for authentication and authorization errors
in FastAPI applications.
"""

from typing import Dict, Any
from fastapi import HTTPException, status


class AxiomsError(Exception):
    """Base exception for Axioms authentication and authorization errors.

    Args:
        error: Dictionary containing error details with 'error' and 'error_description' keys.
        status_code: HTTP status code for the error (default: 401).

    Example::

        raise AxiomsError(
            {"error": "unauthorized_access", "error_description": "Invalid token"},
            401
        )
    """

    def __init__(self, error: Dict[str, str], status_code: int = 401):
        """Initialize AxiomsError with error details and status code."""
        self.error = error
        self.status_code = status_code
        super().__init__(error.get("error_description", "Authentication error"))


class AxiomsHTTPException(HTTPException):
    """FastAPI HTTP exception for Axioms errors.

    This exception is compatible with FastAPI's exception handling system.
    It includes WWW-Authenticate header for 401 and 403 responses.

    Args:
        error: Dictionary containing error details.
        status_code: HTTP status code (default: 401).
        realm: Optional realm (issuer URL) for WWW-Authenticate header.

    Example::

        raise AxiomsHTTPException(
            {"error": "invalid_token", "error_description": "Token expired"},
            401,
            "https://auth.example.com"
        )

    Note:
        - 401 responses: Authentication failure (missing/invalid token)
        - 403 responses: Authorization failure (insufficient permissions)
    """

    def __init__(
        self,
        error: Dict[str, str],
        status_code: int = 401,
        realm: str = None,
    ):
        """Initialize AxiomsHTTPException with error details."""
        detail = error
        headers = {}

        # Add WWW-Authenticate header for 401 and 403 responses
        if status_code in (401, 403):
            realm_value = realm if realm else "API"
            error_code = error.get("error", "unauthorized_access")
            error_desc = error.get("error_description", "Authentication required")
            headers["WWW-Authenticate"] = (
                f'Bearer realm="{realm_value}", '
                f'error="{error_code}", '
                f'error_description="{error_desc}"'
            )

        super().__init__(
            status_code=status_code,
            detail=detail,
            headers=headers if headers else None,
        )
