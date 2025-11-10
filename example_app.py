"""Example FastAPI application using axioms-fastapi for authentication.

This example demonstrates how to use axioms-fastapi to protect routes with
JWT-based authentication and authorization.

Run with:
    uvicorn example_app:app --reload

Test with:
    curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:8000/protected
"""

from fastapi import FastAPI, Depends
from axioms_fastapi import (
    init_axioms,
    require_auth,
    require_scopes,
    require_roles,
    require_permissions,
    register_axioms_exception_handler,
)

# Create FastAPI application
app = FastAPI(
    title="Axioms FastAPI Example",
    description="Example application using axioms-fastapi for OAuth2/OIDC authentication",
    version="1.0.0",
)

# Initialize Axioms configuration
# In production, these would come from environment variables
init_axioms(
    app,
    AXIOMS_AUDIENCE="your-api-audience",
    AXIOMS_DOMAIN="your-auth.domain.com",
    # Optional: Configure custom claim names for different auth servers
    # AXIOMS_ROLES_CLAIMS=["roles", "cognito:groups"],
    # AXIOMS_PERMISSIONS_CLAIMS=["permissions", "cognito:roles"],
)

# Register exception handler for Axioms errors
register_axioms_exception_handler(app)


# Public endpoint - no authentication required
@app.get("/")
async def root():
    """Public endpoint accessible without authentication."""
    return {
        "message": "Welcome to Axioms FastAPI Example",
        "documentation": "/docs",
    }


# Protected endpoint - requires valid JWT token
@app.get("/protected")
async def protected_endpoint(payload=Depends(require_auth)):
    """Protected endpoint requiring valid JWT authentication.

    The payload parameter contains the validated JWT claims.
    """
    return {
        "message": "You are authenticated!",
        "user_id": payload.sub,
        "claims": dict(payload),
    }


# Scope-protected endpoint
@app.get("/api/read")
async def read_data(
    payload=Depends(require_auth),
    _=Depends(require_scopes(["read:data", "admin"]))
):
    """Endpoint requiring 'read:data' OR 'admin' scope."""
    return {
        "message": "Data retrieved successfully",
        "data": ["item1", "item2", "item3"],
    }


# Role-protected endpoint
@app.get("/admin/users")
async def list_users(
    payload=Depends(require_auth),
    _=Depends(require_roles(["admin", "superuser"]))
):
    """Endpoint requiring 'admin' OR 'superuser' role."""
    return {
        "message": "User list retrieved",
        "users": [
            {"id": 1, "name": "User 1"},
            {"id": 2, "name": "User 2"},
        ],
    }


# Permission-protected endpoint
@app.post("/api/resource")
async def create_resource(
    payload=Depends(require_auth),
    _=Depends(require_permissions(["resource:create"]))
):
    """Endpoint requiring 'resource:create' permission."""
    return {
        "message": "Resource created successfully",
        "resource_id": "new-resource-123",
    }


# Multiple requirements (AND logic via chaining)
@app.get("/api/strict")
async def strict_endpoint(
    payload=Depends(require_auth),
    _=Depends(require_scopes(["openid", "profile"])),  # Needs openid OR profile
    __=Depends(require_roles(["editor"])),              # AND needs editor role
    ___=Depends(require_permissions(["resource:write"]))  # AND needs write permission
):
    """Endpoint with multiple authorization requirements.

    Requires:
    - Valid JWT token
    - Scope: openid OR profile
    - Role: editor
    - Permission: resource:write
    """
    return {
        "message": "Access granted to strict endpoint",
        "requirements": {
            "scope": "openid OR profile",
            "role": "editor",
            "permission": "resource:write",
        },
    }


# User profile endpoint
@app.get("/me")
async def get_current_user(payload=Depends(require_auth)):
    """Get current authenticated user's profile from JWT claims."""
    return {
        "sub": payload.sub,
        "email": payload.get("email"),
        "name": payload.get("name"),
        "roles": payload.get("roles", []),
        "permissions": payload.get("permissions", []),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
