# axioms-fastapi ![PyPI](https://img.shields.io/pypi/v/axioms-fastapi) ![Pepy Total Downloads](https://img.shields.io/pepy/dt/axioms-fastapi)
OAuth2/OIDC authentication and authorization for FastAPI APIs. Supports authentication and claim-based fine-grained authorization (scopes, roles, permissions) using JWT tokens. Works with access tokens issued by various authorization servers including [AWS Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html), [Auth0](https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles), [Okta](https://developer.okta.com/docs/api/oauth2/), [Microsoft Entra](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles), etc.

> **Using Flask or Django REST Framework?** This package is specifically for FastAPI. For Flask applications, use [axioms-flask-py](https://github.com/abhishektiwari/axioms-flask-py). For DRF applications, use [axioms-drf-py](https://github.com/abhishektiwari/axioms-drf-py).


![GitHub Release](https://img.shields.io/github/v/release/abhishektiwari/axioms-fastapi)
![GitHub Actions Test Workflow Status](https://img.shields.io/github/actions/workflow/status/abhishektiwari/axioms-fastapi/test.yml?label=tests)
![PyPI - Version](https://img.shields.io/pypi/v/axioms-fastapi)
![Python Wheels](https://img.shields.io/pypi/wheel/axioms-fastapi)
![Python Versions](https://img.shields.io/pypi/pyversions/axioms-fastapi?logo=python&logoColor=white)
![GitHub last commit](https://img.shields.io/github/last-commit/abhishektiwari/axioms-fastapi)
![PyPI - Status](https://img.shields.io/pypi/status/axioms-fastapi)
![License](https://img.shields.io/github/license/abhishektiwari/axioms-fastapi)
![PyPI Downloads](https://img.shields.io/pepy/dt/axioms-fastapi?label=PyPI%20Downloads)
[![CodeFactor](https://www.codefactor.io/repository/github/abhishektiwari/axioms-fastapi/badge)](https://www.codefactor.io/repository/github/abhishektiwari/axioms-fastapi)
[![codecov](https://codecov.io/gh/abhishektiwari/axioms-fastapi/graph/badge.svg?token=FUZV5Q67E1)](https://codecov.io/gh/abhishektiwari/axioms-fastapi)

## When to use `axioms-fastapi`?
Use `axioms-fastapi` in your Django REST Framework backend to securely validate JWT access tokens issued by OAuth2/OIDC authorization servers like [AWS Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html), [Auth0](https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles), [Okta](https://developer.okta.com/docs/api/oauth2/), [Microsoft Entra](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles), [Keyclock](https://www.keycloak.org/securing-apps/oidc-layers#_oauth21-support) etc.  Clients - such as single-page applications (React, Vue), mobile apps, or AI agents—obtain access tokens from the authorization server and send them to your backend. In response, `axioms-fastapi` fetches JSON Web Key Set (JWKS) from the issuer, validates token signatures, enforces audience/issuer claims, and provides scope, role, and permission-based authorization for your API endpoints.

![Where to use Axioms package](https://static.abhishek-tiwari.com/axioms/oauth2-oidc-v3.png)

## How it is different?
Unlike other DRF plugins, `axioms-fastapi` focuses exclusively on protecting resource servers, by letting authorization servers do what they do best. This separation of concerns raises the security bar by:

- Delegates authorization to battle-tested OAuth2/OIDC providers
- Works seamlessly with any OAuth2/OIDC ID with simple configuration
- Enterprise-ready defaults using current JWT and OAuth 2.1 best practices

## Features
* JWT token validation with automatic public key retrieval from JWKS endpoints
* Algorithm validation to prevent algorithm confusion attacks (only secure asymmetric algorithms allowed)
* Issuer validation (`iss` claim) to prevent token substitution attacks
* Authentication classes for standard DRF integration
* Permission classes for claim-based authorization: `scopes`, `roles`, and `permissions`
* Object-level permission classes for resource ownership verification
* Support for both OR and AND logic in authorization checks
* Middleware for automatic token extraction and validation
* Flexible configuration with support for custom JWKS and issuer URLs
* Simple integration with Django REST Framework Resource Server or API backends
* Support for custom claim and/or namespaced claims names to support different authorization servers

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
    AXIOMS_ISS_URL="https://your-auth.domain.com",
    AXIOMS_JWKS_URL="https://your-auth.domain.com/.well-known/jwks.json"
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
* `AXIOMS_ISS_URL` (recommended): Full issuer URL for validating the `iss` claim
* `AXIOMS_JWKS_URL` (optional): Full URL to your JWKS endpoint - if not provided, constructed from `AXIOMS_ISS_URL`
* `AXIOMS_DOMAIN` (deprecated): Use `AXIOMS_ISS_URL` instead. If provided, constructs issuer and JWKS URLs

**Configuration Hierarchy:**

1. `AXIOMS_JWKS_URL` (if explicitly set) OR
2. `AXIOMS_ISS_URL` + `/.well-known/jwks.json` (if `AXIOMS_ISS_URL` is set) OR
3. `https://{AXIOMS_DOMAIN}` + `/.well-known/jwks.json` (if `AXIOMS_DOMAIN` is set)

### Environment Variables

Create a `.env` file:

```bash
AXIOMS_AUDIENCE=your-api-audience
AXIOMS_ISS_URL=https://your-auth.domain.com

# Optional - if JWKS endpoint is non-standard:
# AXIOMS_JWKS_URL=https://your-auth.domain.com/.well-known/jwks.json

# Deprecated - use AXIOMS_ISS_URL instead:
# AXIOMS_DOMAIN=your-auth.domain.com
```

## Middleware (Optional)

You can use middleware to automatically extract and validate JWT tokens for all incoming requests. The middleware sets attributes on `request.state` that you can access in your route handlers.

### Adding Middleware

```python
from fastapi import FastAPI, Request
from axioms_fastapi import init_axioms, register_axioms_exception_handler
from axioms_fastapi.middleware import AccessTokenMiddleware

app = FastAPI()

# Initialize Axioms configuration
init_axioms(
    app,
    AXIOMS_AUDIENCE="api.example.com",
    AXIOMS_ISS_URL="https://auth.example.com"
)

# Add middleware to automatically process tokens
app.add_middleware(AccessTokenMiddleware)

# Register exception handler
register_axioms_exception_handler(app)

@app.get("/profile")
async def get_profile(request: Request):
    # Access token payload from request.state.auth_jwt
    if request.state.auth_jwt:
        return {
            "user_id": request.state.auth_jwt.sub,
            "email": request.state.auth_jwt.get("email")
        }
    elif request.state.auth_jwt is False:
        return {"error": "Invalid token"}, 401
    else:
        return {"error": "No token provided"}, 401
```

### Request State Attributes

The middleware sets the following attributes on `request.state`:

* `auth_jwt` (Box|False|None):
  - Box object with token payload if valid
  - `False` if token is invalid (expired, wrong audience, etc.)
  - `None` if no Authorization header present
* `missing_auth_header` (bool): `True` if Authorization header is missing
* `invalid_bearer_token` (bool): `True` if Bearer format is invalid

## Usage Examples

### Basic Authentication

```python
from fastapi import FastAPI, Depends
from axioms_fastapi import init_axioms, require_auth, require_scopes, register_axioms_exception_handler

app = FastAPI()
init_axioms(
    app,
    AXIOMS_AUDIENCE="api.example.com",
    AXIOMS_ISS_URL="https://auth.example.com",
    AXIOMS_JWKS_URL="https://auth.example.com/.well-known/jwks.json"
)

register_axioms_exception_handler(app)

@app.get("/profile")
async def get_profile(payload=Depends(require_auth)):
    return {
        "user_id": payload.sub,
        "email": payload.get("email"),
        "name": payload.get("name")
    }
```

### Safe Methods (Skip Authentication for Specific HTTP Methods)

By default, `OPTIONS` requests skip authentication to support CORS preflight requests. You can customize which HTTP methods skip authentication:

```python
from functools import partial
from axioms_fastapi import require_auth

# Allow GET and OPTIONS without authentication
require_auth_safe = partial(require_auth, safe_methods=["GET", "OPTIONS"])

@app.get("/public-data")
async def public_data(payload=Depends(require_auth_safe)):
    # GET requests don't require authentication
    # payload will be an empty Box for safe methods
    if not payload:
        return {"data": "public content"}
    return {"data": "personalized content", "user": payload.sub}

# Disable safe methods (require auth for all methods including OPTIONS)
require_auth_strict = partial(require_auth, safe_methods=[])

@app.options("/strict")
async def strict_options(payload=Depends(require_auth_strict)):
    # Even OPTIONS requires authentication
    return {"allowed_methods": ["GET", "POST"]}
```

**Default behavior:**
- `OPTIONS` requests skip authentication (for CORS preflight)
- All other methods require authentication

**Common use cases:**
- CORS preflight: `safe_methods=["OPTIONS"]` (default)
- Public read, authenticated write: `safe_methods=["GET", "HEAD", "OPTIONS"]`
- Strict mode: `safe_methods=[]` (all methods require auth)

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

### Object-Level Permissions (Row-Level Security)

Protect individual resources based on ownership using `check_object_ownership`:

```python
from fastapi import FastAPI, Depends, HTTPException
from sqlmodel import Field, Session, SQLModel
from axioms_fastapi import init_axioms, check_object_ownership, register_axioms_exception_handler

app = FastAPI()
init_axioms(
    app,
    AXIOMS_AUDIENCE="api.example.com",
    AXIOMS_ISS_URL="https://auth.example.com",
    AXIOMS_JWKS_URL="https://auth.example.com/.well-known/jwks.json"
)
register_axioms_exception_handler(app)

# SQLModel with ownership field
class Article(SQLModel, table=True):
    id: int = Field(primary_key=True)
    title: str
    content: str
    user: str = Field(index=True)  # Owner field - matches JWT 'sub' claim

def get_session():
    # Your database session logic
    pass

def get_article(article_id: int, session: Session = Depends(get_session)):
    article = session.get(Article, article_id)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    return article

# Only article owner can read their article
@app.get("/articles/{article_id}")
async def read_article(
    article: Article = Depends(check_object_ownership(get_article))
):
    # check_object_ownership verifies article.user == JWT 'sub' claim
    return {"id": article.id, "title": article.title, "user": article.user}

# Only article owner can update their article
@app.patch("/articles/{article_id}")
async def update_article(
    title: str,
    article: Article = Depends(check_object_ownership(get_article)),
    session: Session = Depends(get_session)
):
    article.title = title
    session.add(article)
    session.commit()
    return {"id": article.id, "title": article.title}
```

#### Custom Owner Field

Use a different field name for ownership:

```python
class Comment(SQLModel, table=True):
    id: int = Field(primary_key=True)
    text: str
    created_by: str = Field(index=True)  # Custom owner field name

def get_comment(comment_id: int, session: Session = Depends(get_session)):
    comment = session.get(Comment, comment_id)
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    return comment

@app.patch("/comments/{comment_id}")
async def update_comment(
    text: str,
    # Specify custom owner_field parameter
    comment: Comment = Depends(check_object_ownership(get_comment, owner_field="created_by")),
    session: Session = Depends(get_session)
):
    comment.text = text
    session.commit()
    return {"id": comment.id, "text": comment.text}
```

#### Custom Claim Field

Match ownership using a different JWT claim (e.g., email):

```python
class Project(SQLModel, table=True):
    id: int = Field(primary_key=True)
    name: str
    owner_email: str = Field(index=True)  # Matches JWT 'email' claim

def get_project(project_id: int, session: Session = Depends(get_session)):
    project = session.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@app.get("/projects/{project_id}")
async def read_project(
    # Match project.owner_email with JWT 'email' claim
    project: Project = Depends(
        check_object_ownership(
            get_project,
            owner_field="owner_email",
            claim_field="email"
        )
    )
):
    return {"id": project.id, "name": project.name, "owner_email": project.owner_email}
```

## Custom Claim Names

Support for different authorization servers with custom claim names:

```python
init_axioms(
    app,
    AXIOMS_AUDIENCE="api.example.com",
    AXIOMS_ISS_URL="https://auth.example.com",
    AXIOMS_JWKS_URL="https://auth.example.com/.well-known/jwks.json",
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
init_axioms(
    app,
    AXIOMS_AUDIENCE="api.example.com",
    AXIOMS_ISS_URL="https://auth.example.com",
    AXIOMS_JWKS_URL="https://auth.example.com/.well-known/jwks.json"
)

# Register exception handler for Axioms errors
register_axioms_exception_handler(app)
```

This will automatically handle both authentication (`401`) and authorization (`403`) errors with proper `WWW-Authenticate` headers.


## Complete Example
For a complete working example, check out the [example](example/) folder in this repository or [checkout our docs](https://axioms-fastapi.abhishek-tiwari.com/examples).
