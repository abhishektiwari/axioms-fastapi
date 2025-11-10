# axioms-fastapi ![PyPI](https://img.shields.io/pypi/v/axioms-fastapi) ![Pepy Total Downloads](https://img.shields.io/pepy/dt/axioms-fastapi)
OAuth2/OIDC authentication and authorization for FastAPI APIs. Supports authentication and claim-based fine-grained authorization (scopes, roles, permissions) using JWT tokens.

Works with access tokens issued by various authorization servers including [AWS Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html), [Auth0](https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles), [Okta](https://developer.okta.com/docs/api/oauth2/), [Microsoft Entra](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles), etc.

![GitHub Release](https://img.shields.io/github/v/release/abhishektiwari/axioms-fastapi)
![GitHub Actions Test Workflow Status](https://img.shields.io/github/actions/workflow/status/abhishektiwari/axioms-fastapi/test.yml?label=tests)
![PyPI - Version](https://img.shields.io/pypi/v/axioms-fastapi)
![Python Wheels](https://img.shields.io/pypi/wheel/axioms-fastapi)
![Python Versions](https://img.shields.io/pypi/pyversions/axioms-fastapi?logo=python&logoColor=white)
![GitHub last commit](https://img.shields.io/github/last-commit/abhishektiwari/axioms-fastapi)
![PyPI - Status](https://img.shields.io/pypi/status/axioms-fastapi)
![License](https://img.shields.io/github/license/abhishektiwari/axioms-fastapi)
![PyPI Downloads](https://img.shields.io/pepy/dt/axioms-fastapi?label=PyPI%20Downloads)

## Features

* JWT token validation with automatic public key retrieval from JWKS endpoints
* Algorithm validation to prevent algorithm confusion attacks (only secure asymmetric algorithms allowed)
* Issuer validation (`iss` claim) to prevent token substitution attacks
* FastAPI dependency injection for authentication and authorization
* Flexible configuration with support for custom JWKS and issuer URLs
* Support for custom claim and/or namespaced claims names to support different authorization servers
* Async-ready and production-tested

## Installation

```bash
pip install axioms-fastapi
```

## Quick Start

### 1. Configure your FastAPI application

```python
from fastapi import FastAPI, Depends
from axioms_fastapi import init_axioms, require_auth, require_scopes, register_axioms_exception_handler

app = FastAPI()

# Initialize Axioms with your configuration
init_axioms(
    app,
    AXIOMS_AUDIENCE="your-api-audience",
    AXIOMS_DOMAIN="your-auth.domain.com"
)

# Register exception handler for authentication/authorization errors
register_axioms_exception_handler(app)
```

### 2. Protect your routes

```python
from axioms_fastapi import require_auth, require_permissions

@app.get("/api/protected")
async def protected_route(payload=Depends(require_auth)):
    """Route protected by JWT authentication."""
    user_id = payload.sub
    return {"user_id": user_id, "message": "Authenticated"}

@app.get("/api/admin")
async def admin_route(
    payload=Depends(require_auth),
    _=Depends(require_permissions(["admin:write"]))
):
    """Route requiring admin:write permission."""
    return {"message": "Admin access granted"}
```

## Configuration

The SDK supports the following configuration options:

* `AXIOMS_AUDIENCE` (required): Your resource identifier or API audience
* `AXIOMS_DOMAIN` (optional): Your auth domain - constructs issuer and JWKS URLs
* `AXIOMS_ISS_URL` (optional): Full issuer URL for validating the `iss` claim (recommended for security)
* `AXIOMS_JWKS_URL` (optional): Full URL to your JWKS endpoint

**Configuration Hierarchy:**

1. `AXIOMS_DOMAIN` → constructs → `AXIOMS_ISS_URL` (if not explicitly set)
2. `AXIOMS_ISS_URL` → constructs → `AXIOMS_JWKS_URL` (if not explicitly set)

### Environment Variables

Create a `.env` file:

```bash
AXIOMS_AUDIENCE=your-api-audience
AXIOMS_DOMAIN=your-auth.domain.com

# OR for custom configurations:
# AXIOMS_ISS_URL=https://your-auth.domain.com/oauth2
# AXIOMS_JWKS_URL=https://your-auth.domain.com/.well-known/jwks.json
```

## Usage Examples

### Basic Authentication

```python
from fastapi import FastAPI, Depends
from axioms_fastapi import init_axioms, require_auth, require_scopes, register_axioms_exception_handler

app = FastAPI()
init_axioms(app, AXIOMS_AUDIENCE="api.example.com", AXIOMS_DOMAIN="auth.example.com")

register_axioms_exception_handler(app)

@app.get("/profile")
async def get_profile(payload=Depends(require_auth)):
    return {
        "user_id": payload.sub,
        "email": payload.get("email"),
        "name": payload.get("name")
    }
```

### Scope-Based Authorization (OR Logic)

```python
from axioms_fastapi import require_auth, require_scopes

@app.get("/api/resource")
async def resource_route(
    payload=Depends(require_auth),
    _=Depends(require_scopes(["read:resource", "write:resource"]))
):
    # User needs EITHER 'read:resource' OR 'write:resource' scope
    return {"data": "success"}
```

### Role-Based Authorization

```python
from axioms_fastapi import require_auth, require_roles

@app.get("/admin/users")
async def admin_route(
    payload=Depends(require_auth),
    _=Depends(require_roles(["admin", "superuser"]))
):
    # User needs EITHER 'admin' OR 'superuser' role
    return {"users": []}
```

### Permission-Based Authorization

```python
from axioms_fastapi import require_auth, require_permissions

@app.post("/api/resource")
async def create_resource(
    payload=Depends(require_auth),
    _=Depends(require_permissions(["resource:create"]))
):
    return {"message": "Resource created"}
```

### AND Logic (Chaining Dependencies)

```python
@app.get("/api/strict")
async def strict_route(
    payload=Depends(require_auth),
    _=Depends(require_scopes(["read:resource"])),
    __=Depends(require_scopes(["write:resource"]))
):
    # User needs BOTH 'read:resource' AND 'write:resource' scopes
    return {"data": "requires both scopes"}
```

### Mixed Authorization

```python
@app.get("/api/advanced")
async def advanced_route(
    payload=Depends(require_auth),
    _=Depends(require_scopes(["openid", "profile"])),  # openid OR profile
    __=Depends(require_roles(["editor"])),              # AND editor role
    ___=Depends(require_permissions(["resource:read", "resource:write"]))  # AND read OR write
):
    # User needs: (openid OR profile) AND (editor) AND (read OR write)
    return {"data": "complex authorization"}
```

## Custom Claim Names

Support for different authorization servers with custom claim names:

```python
init_axioms(
    app,
    AXIOMS_AUDIENCE="api.example.com",
    AXIOMS_DOMAIN="auth.example.com",
    AXIOMS_ROLES_CLAIMS=["cognito:groups", "roles"],
    AXIOMS_PERMISSIONS_CLAIMS=["permissions", "cognito:roles"],
    AXIOMS_SCOPE_CLAIMS=["scope", "scp"]
)
```

## Error Handling

The SDK raises `AxiomsHTTPException` for authentication and authorization errors. Register the exception handler to return proper error responses with WWW-Authenticate headers:

```python
from fastapi import FastAPI
from axioms_fastapi import init_axioms, register_axioms_exception_handler

app = FastAPI()
init_axioms(app, AXIOMS_AUDIENCE="api.example.com", AXIOMS_DOMAIN="auth.example.com")

# Register exception handler for Axioms errors
register_axioms_exception_handler(app)
```

This will automatically handle both authentication (401) and authorization (403) errors with proper WWW-Authenticate headers.

## Security Features

* **Algorithm Validation**: Only secure asymmetric algorithms allowed (RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512)
* **Issuer Validation**: Validates `iss` claim to prevent token substitution attacks
* **Automatic JWKS Retrieval**: Fetches and caches public keys from JWKS endpoints
* **Token Expiration**: Validates `exp` claim
* **Audience Validation**: Validates `aud` claim
* **Key ID Validation**: Validates `kid` header

## License

MIT

## Links

* Documentation: https://axioms-fastapi.abhishek-tiwari.com
* Source Code: https://github.com/abhishektiwari/axioms-fastapi
* Issue Tracker: https://github.com/abhishektiwari/axioms-fastapi/issues
