"""Axioms FastAPI SDK for OAuth2/OIDC authentication and authorization.

OAuth2/OIDC authentication and authorization for FastAPI APIs. Supports authentication
and claim-based fine-grained authorization (scopes, roles, permissions) using JWT tokens.
"""

# Try to get version from setuptools_scm generated file
try:
    from axioms_fastapi._version import version as __version__
except ImportError:
    # Version file doesn't exist yet (development mode without build)
    __version__ = "0.0.0.dev0"

from .error import AxiomsError, AxiomsHTTPException
from .dependencies import (
    require_auth,
    require_scopes,
    require_roles,
    require_permissions,
)
from .config import init_axioms

__all__ = [
    "__version__",
    "AxiomsError",
    "AxiomsHTTPException",
    "require_auth",
    "require_scopes",
    "require_roles",
    "require_permissions",
    "init_axioms",
]
