"""FastAPI dependencies for authentication and authorization.

This module provides FastAPI dependency functions for protecting routes with JWT-based
authentication and authorization. Supports scope-based, role-based, permission-based,
and object-level ownership access control with configurable claim names for different
authorization servers.

Example::

    from fastapi import FastAPI, Depends
    from axioms_fastapi import require_auth, require_scopes, check_object_ownership, init_axioms

    app = FastAPI()
    init_axioms(app, AXIOMS_AUDIENCE="api.example.com", AXIOMS_DOMAIN="auth.example.com")

    @app.get("/protected")
    async def protected_route(payload=Depends(require_auth)):
        return {"user": payload.sub}

    @app.get("/admin")
    async def admin_route(payload=Depends(require_auth), _=Depends(require_scopes(["admin"]))):
        return {"message": "Admin access"}

    @app.patch("/articles/{article_id}")
    async def update_article(
        article_id: int,
        article=Depends(check_object_ownership(get_article))
    ):
        return {"message": "Updated"}
"""

import logging
from typing import Callable, List

from box import Box
from fastapi import Depends, Request

from .config import AxiomsConfig, get_config
from .error import AxiomsHTTPException
from .helper import (
    check_permissions,
    check_roles,
    check_scopes,
    get_claim_from_token,
    get_expected_issuer,
    has_bearer_token,
    has_valid_token,
)

logger = logging.getLogger(__name__)


def require_auth(request: Request, config: AxiomsConfig = Depends(get_config)) -> Box:
    """FastAPI dependency to require valid JWT authentication.

    Validates the JWT access token in the Authorization header and returns the
    validated payload for use in the route handler.

    Args:
        request: FastAPI Request object containing HTTP headers.
        config: Axioms configuration (injected via dependency).

    Returns:
        Box: Validated JWT token payload with claims accessible as attributes.

    Raises:
        AxiomsHTTPException: If token is missing, invalid, or expired.

    Example::

        @app.get("/api/protected")
        async def protected_route(payload=Depends(require_auth)):
            user_id = payload.sub
            return {"user_id": user_id}
    """
    try:
        token = has_bearer_token(request)
        payload = has_valid_token(token, config)
        return payload
    except Exception as ex:
        if hasattr(ex, "error") and hasattr(ex, "status_code"):
            # AxiomsError from token validation
            raise AxiomsHTTPException(
                error=ex.error,
                status_code=ex.status_code,
                realm=get_expected_issuer(config) or "",
            )
        # Unexpected error
        raise AxiomsHTTPException(
            {
                "error": "unauthorized_access",
                "error_description": "Authentication failed",
            },
            401,
            get_expected_issuer(config) or "",
        )


def require_scopes(required_scopes: List[str]) -> Callable:
    """Create a FastAPI dependency to enforce scope-based authorization.

    Checks if the authenticated user's token contains any of the required scopes.
    Uses OR logic: the token must have at least ONE of the specified scopes.

    Args:
        required_scopes: List of required scope strings.

    Returns:
        Callable: FastAPI dependency function that enforces scope check.

    Raises:
        AxiomsHTTPException: If token doesn't contain required scopes.

    Example (OR logic - requires EITHER scope)::

        @app.get("/api/resource")
        async def resource_route(
            payload=Depends(require_auth),
            _=Depends(require_scopes(["read:resource", "write:resource"]))
        ):
            return {"data": "protected"}

    Example (AND logic - requires BOTH scopes via chaining)::

        @app.get("/api/strict")
        async def strict_route(
            payload=Depends(require_auth),
            _=Depends(require_scopes(["read:resource"])),
            __=Depends(require_scopes(["write:resource"]))
        ):
            return {"data": "requires both scopes"}
    """

    def scope_dependency(
        payload: Box = Depends(require_auth), config: AxiomsConfig = Depends(get_config)
    ) -> None:
        """Dependency function to check scopes."""
        # Get scope from configured claim names
        token_scope = get_claim_from_token(payload, "SCOPE", config) or ""

        if not check_scopes(token_scope, required_scopes):
            raise AxiomsHTTPException(
                {
                    "error": "insufficient_permission",
                    "error_description": "Insufficient role, scope or permission",
                },
                403,
                get_expected_issuer(config) or "",
            )

    return scope_dependency


def require_roles(required_roles: List[str]) -> Callable:
    """Create a FastAPI dependency to enforce role-based authorization.

    Checks if the authenticated user's token contains any of the required roles.
    Uses OR logic: the token must have at least ONE of the specified roles.

    Args:
        required_roles: List of required role strings.

    Returns:
        Callable: FastAPI dependency function that enforces role check.

    Raises:
        AxiomsHTTPException: If token doesn't contain required roles.

    Example (OR logic - requires EITHER role)::

        @app.get("/admin/users")
        async def admin_route(
            payload=Depends(require_auth),
            _=Depends(require_roles(["admin", "superuser"]))
        ):
            return {"users": []}

    Example (AND logic - requires BOTH roles via chaining)::

        @app.get("/admin/critical")
        async def critical_route(
            payload=Depends(require_auth),
            _=Depends(require_roles(["admin"])),
            __=Depends(require_roles(["superuser"]))
        ):
            return {"message": "requires both roles"}
    """

    def role_dependency(
        payload: Box = Depends(require_auth), config: AxiomsConfig = Depends(get_config)
    ) -> None:
        """Dependency function to check roles."""
        # Get roles from configured claim names
        token_roles = get_claim_from_token(payload, "ROLES", config) or []

        if not check_roles(token_roles, required_roles):
            raise AxiomsHTTPException(
                {
                    "error": "insufficient_permission",
                    "error_description": "Insufficient role, scope or permission",
                },
                403,
                get_expected_issuer(config) or "",
            )

    return role_dependency


def require_permissions(required_permissions: List[str]) -> Callable:
    """Create a FastAPI dependency to enforce permission-based authorization.

    Checks if the authenticated user's token contains any of the required permissions.
    Uses OR logic: the token must have at least ONE of the specified permissions.

    Args:
        required_permissions: List of required permission strings.

    Returns:
        Callable: FastAPI dependency function that enforces permission check.

    Raises:
        AxiomsHTTPException: If token doesn't contain required permissions.

    Example (OR logic - requires EITHER permission)::

        @app.get("/api/resource")
        async def resource_route(
            payload=Depends(require_auth),
            _=Depends(require_permissions(["resource:read", "resource:write"]))
        ):
            return {"data": "success"}

    Example (AND logic - requires BOTH permissions via chaining)::

        @app.get("/api/critical")
        async def critical_route(
            payload=Depends(require_auth),
            _=Depends(require_permissions(["resource:read"])),
            __=Depends(require_permissions(["resource:admin"]))
        ):
            return {"message": "requires both permissions"}
    """

    def permission_dependency(
        payload: Box = Depends(require_auth), config: AxiomsConfig = Depends(get_config)
    ) -> None:
        """Dependency function to check permissions."""
        # Get permissions from configured claim names
        token_permissions = get_claim_from_token(payload, "PERMISSIONS", config) or []

        if not check_permissions(token_permissions, required_permissions):
            raise AxiomsHTTPException(
                {
                    "error": "insufficient_permission",
                    "error_description": "Insufficient role, scope or permission",
                },
                403,
                get_expected_issuer(config) or "",
            )

    return permission_dependency


def check_object_ownership(
    get_object: Callable,
    owner_field: str = "user",
    claim_field: str = "sub",
) -> Callable:
    """Create a FastAPI dependency to enforce object-level ownership permissions.

    Validates that the authenticated user owns the requested object by comparing
    a field in the object with a claim in the JWT token. This enables per-object
    access control where users can only access resources they own.

    Args:
        get_object: Callable dependency function that retrieves the object.
        owner_field: Field name in the object containing the owner identifier.
            Defaults to "user".
        claim_field: JWT claim field to compare with owner_field.
            Defaults to "sub".

    Returns:
        Callable: FastAPI dependency function that enforces object ownership check.

    Raises:
        AxiomsHTTPException:
            - 400 Bad Request: If object is missing the specified owner_field.
            - 403 Forbidden: If JWT is missing the claim_field or user doesn't own the object.

    Example (basic usage with defaults)::

        async def get_article(article_id: int):
            article = db.query(Article).filter(Article.id == article_id).first()
            if not article:
                raise HTTPException(status_code=404, detail="Not found")
            return article

        @app.patch("/articles/{article_id}")
        async def update_article(
            article_id: int,
            title: str,
            article = Depends(check_object_ownership(get_article))
        ):
            article.title = title
            return article

    Example (custom owner field)::

        @app.delete("/comments/{comment_id}")
        async def delete_comment(
            comment_id: int,
            comment = Depends(check_object_ownership(get_comment, owner_field="created_by"))
        ):
            db.delete(comment)
            return {"message": "Deleted"}

    Example (match by email instead of sub)::

        @app.patch("/users/{user_id}")
        async def update_user(
            user_id: int,
            name: str,
            user = Depends(check_object_ownership(
                get_user,
                owner_field="owner_email",
                claim_field="email"
            ))
        ):
            user.name = name
            return user

    Example (with SQLAlchemy)::

        class Article(Base):
            __tablename__ = "articles"
            id = Column(Integer, primary_key=True)
            title = Column(String)
            user = Column(String)

        def get_article(article_id: int, db: Session = Depends(get_db)):
            article = db.query(Article).filter(Article.id == article_id).first()
            if not article:
                raise HTTPException(status_code=404, detail="Not found")
            return article

        @app.patch("/articles/{article_id}")
        async def update_article(
            article_id: int,
            title: str,
            article: Article = Depends(check_object_ownership(get_article)),
            db: Session = Depends(get_db)
        ):
            article.title = title
            db.commit()
            return article
    """

    def ownership_dependency(
        obj=Depends(get_object),
        payload: Box = Depends(require_auth),
        config: AxiomsConfig = Depends(get_config),
    ):
        """Dependency function to check object ownership."""
        # Get owner value from object (dict or object)
        if isinstance(obj, dict):
            owner = obj.get(owner_field)
        else:
            owner = getattr(obj, owner_field, None)

        # Validate owner field exists
        if owner is None:
            logger.error(
                f"Object ownership check failed: object missing owner field '{owner_field}'. "
                f"Object type: {type(obj).__name__}"
            )
            raise AxiomsHTTPException(
                {
                    "error": "bad_request",
                    "error_description": "Invalid resource configuration",
                },
                400,
                get_expected_issuer(config) or "",
            )

        # Get claim value from JWT
        claim_value = payload.get(claim_field)
        if claim_value is None:
            raise AxiomsHTTPException(
                {
                    "error": "insufficient_permission",
                    "error_description": f"JWT missing required claim: {claim_field}",
                },
                403,
                get_expected_issuer(config) or "",
            )

        # Compare owner with JWT claim
        if owner != claim_value:
            raise AxiomsHTTPException(
                {
                    "error": "insufficient_permission",
                    "error_description": "You don't have permission to access this resource",
                },
                403,
                get_expected_issuer(config) or "",
            )

        return obj

    return ownership_dependency
