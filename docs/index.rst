Welcome to axioms-fastapi documentation!
==========================================

OAuth2/OIDC authentication and authorization for FastAPI APIs. Supports authentication and claim-based fine-grained authorization (scopes, roles, permissions) using JWT tokens.

Works with access tokens issued by various authorization servers including `AWS Cognito <https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html>`_, `Auth0 <https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles>`_, `Okta <https://developer.okta.com/docs/api/oauth2/>`_, `Microsoft Entra <https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles>`_, etc.

.. note::
   **Using Flask or Django REST Framework?** This package is specifically for FastAPI. For Flask applications, use `axioms-flask-py <https://github.com/abhishektiwari/axioms-flask-py>`_. For DRF applications, use `axioms-drf-py <https://github.com/abhishektiwari/axioms-drf-py>`_.

.. image:: https://img.shields.io/github/v/release/abhishektiwari/axioms-fastapi
   :alt: GitHub Release
   :target: https://github.com/abhishektiwari/axioms-fastapi/releases

.. image:: https://img.shields.io/github/actions/workflow/status/abhishektiwari/axioms-fastapi/test.yml?label=tests
   :alt: GitHub Actions Test Workflow Status
   :target: https://github.com/abhishektiwari/axioms-fastapi/actions/workflows/test.yml

.. image:: https://img.shields.io/github/license/abhishektiwari/axioms-fastapi
   :alt: License

.. image:: https://img.shields.io/github/last-commit/abhishektiwari/axioms-fastapi
   :alt: GitHub Last Commit

.. image:: https://img.shields.io/pypi/v/axioms-fastapi
   :alt: PyPI Version

.. image:: https://img.shields.io/pypi/status/axioms-fastapi
   :alt: PyPI - Status

.. image:: https://img.shields.io/pepy/dt/axioms-fastapi?label=PyPI%20Downloads
   :alt: PyPI Downloads
   :target: https://pypi.org/project/axioms-fastapi/

.. image:: https://img.shields.io/pypi/pyversions/axioms-fastapi?logo=python&logoColor=white
   :alt: Python Versions

.. image:: https://www.codefactor.io/repository/github/abhishektiwari/axioms-fastapi/badge
   :target: https://www.codefactor.io/repository/github/abhishektiwari/axioms-fastapi
   :alt: CodeFactor

.. image:: https://codecov.io/gh/abhishektiwari/axioms-fastapi/graph/badge.svg?token=FUZV5Q67E1 
   :target: https://codecov.io/gh/abhishektiwari/axioms-fastapi

When to use ``axioms-fastapi``?
----------------------------

Use ``axioms-fastapi`` in your Django REST Framework backend to securely validate JWT access
tokens issued by OAuth2/OIDC authorization servers like `AWS Cognito <https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html>`_,
`Auth0 <https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles>`_,
`Okta <https://developer.okta.com/docs/api/oauth2/>`_, `Microsoft Entra <https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles>`_, `Keyclock <https://www.keycloak.org/securing-apps/oidc-layers#_oauth21-support>`_,
etc. Clients - such as single-page applications (React, Vue), mobile apps, or AI agents—obtain access tokens from the authorization server and send them to your backend. In response, ``axioms-fastapi`` fetches JSON Web Key Set (JWKS) from the issuer, validates token signatures, enforces audience/issuer claims, and provides scope, role, and permission-based authorization for your API endpoints.

.. image:: https://static.abhishek-tiwari.com/axioms/oauth2-oidc-v3.png
   :alt: When to use Axioms package

How it is different?
--------------------
Unlike other DRF plugins, ``axioms-fastapi`` focuses exclusively on protecting resource servers, by letting authorization servers do what they do best. This separation of concerns raises the security bar by:

- Delegates authorization to battle-tested OAuth2/OIDC providers
- Works seamlessly with any OAuth2/OIDC ID with simple configuration
- Enterprise-ready defaults using current JWT and OAuth 2.1 best practices

Features
--------

* JWT token validation with automatic public key retrieval from JWKS endpoints
* Algorithm validation to prevent algorithm confusion attacks (only secure asymmetric algorithms allowed)
* Issuer validation (``iss`` claim) to prevent token substitution attacks
* Authentication classes for standard DRF integration
* Permission classes for claim-based authorization: ``scopes``, ``roles``, and ``permissions``
* Object-level permission classes for resource ownership verification
* Support for both OR and AND logic in authorization checks
* Middleware for automatic token extraction and validation
* Flexible configuration with support for custom JWKS and issuer URLs
* Simple integration with Django REST Framework Resource Server or API backends
* Support for custom claim and/or namespaced claims names to support different authorization servers

Installation
------------

Install the package using pip:

.. code-block:: bash

   pip install axioms-fastapi

Quick Start
-----------

1. Configure your FastAPI application:

.. code-block:: python

   from fastapi import FastAPI
   from axioms_fastapi import init_axioms, register_axioms_exception_handler

   app = FastAPI()
   init_axioms(
       app,
       AXIOMS_AUDIENCE="your-api-audience",
       AXIOMS_ISS_URL="https://your-auth.domain.com",
       AXIOMS_JWKS_URL="https://your-auth.domain.com/.well-known/jwks.json"
   )

   # Register exception handler for authentication/authorization errors
   register_axioms_exception_handler(app)

2. Create a ``.env`` file with your configuration (see `.env.example <https://github.com/abhishektiwari/axioms-fastapi/blob/main/.env.example>`_ for reference):

.. code-block:: bash

   AXIOMS_AUDIENCE=your-api-audience
   AXIOMS_ISS_URL=https://your-auth.domain.com

   # Optional - if JWKS endpoint is non-standard:
   # AXIOMS_JWKS_URL=https://your-auth.domain.com/.well-known/jwks.json

   # Deprecated - use AXIOMS_ISS_URL instead:
   # AXIOMS_DOMAIN=your-auth.domain.com

3. Use dependencies to protect your routes:

.. code-block:: python

   from fastapi import Depends
   from axioms_fastapi import require_auth, require_permissions

   @app.get("/api/protected")
   async def protected_route(payload=Depends(require_auth)):
       user_id = payload.sub
       return {"user_id": user_id}

   @app.get("/api/admin")
   async def admin_route(
       payload=Depends(require_auth),
       _=Depends(require_permissions(["admin:write"]))
   ):
       return {"message": "Admin access"}

Configuration
-------------

The SDK supports the following configuration options:

* ``AXIOMS_AUDIENCE`` (required): Your resource identifier or API audience
* ``AXIOMS_ISS_URL`` (recommended): Full issuer URL for validating the ``iss`` claim
* ``AXIOMS_JWKS_URL`` (optional): Full URL to your JWKS endpoint - if not provided, constructed from ``AXIOMS_ISS_URL``
* ``AXIOMS_DOMAIN`` (deprecated): Use ``AXIOMS_ISS_URL`` instead. If provided, constructs issuer and JWKS URLs

**Configuration Hierarchy:**

1. ``AXIOMS_JWKS_URL`` (if explicitly set) OR
2. ``AXIOMS_ISS_URL`` + ``/.well-known/jwks.json`` (if ``AXIOMS_ISS_URL`` is set) OR
3. ``https://{AXIOMS_DOMAIN}`` + ``/.well-known/jwks.json`` (if ``AXIOMS_DOMAIN`` is set)

.. important::
   You must provide at least one of: ``AXIOMS_ISS_URL``, ``AXIOMS_JWKS_URL``, or ``AXIOMS_DOMAIN`` (deprecated).

   For most use cases, setting only ``AXIOMS_ISS_URL`` is sufficient. The SDK will automatically construct the JWKS endpoint URL.

Middleware (Optional)
---------------------

You can use middleware to automatically extract and validate JWT tokens for all incoming requests. The middleware sets attributes on ``request.state`` that you can access in your route handlers.

Adding Middleware
^^^^^^^^^^^^^^^^^

.. code-block:: python

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

Request State Attributes
^^^^^^^^^^^^^^^^^^^^^^^^

The middleware sets the following attributes on ``request.state``:

* ``auth_jwt`` (Box|False|None):

  - Box object with token payload if valid
  - ``False`` if token is invalid (expired, wrong audience, etc.)
  - ``None`` if no Authorization header present

* ``missing_auth_header`` (bool): ``True`` if Authorization header is missing
* ``invalid_bearer_token`` (bool): ``True`` if Bearer format is invalid

Protect Your FastAPI Routes
----------------------------

Use the following dependencies to protect your API routes:

.. list-table::
   :header-rows: 1
   :widths: 30 50 20

   * - Dependency
     - Description
     - Parameters
   * - ``require_auth``
     - Validates JWT access token and returns the payload. Performs token signature validation, expiry datetime validation, token audience validation, and issuer validation (if configured). Should be used as the **first** dependency on protected routes.
     - Returns ``Box`` payload
   * - ``require_scopes``
     - Check any of the given scopes included in ``scope`` claim of the access token. Returns a dependency function. Should be after ``require_auth``.
     - List of strings as ``conditional OR`` representing any of the allowed scopes. For instance, to check ``openid`` or ``profile`` pass ``['profile', 'openid']``.
   * - ``require_roles``
     - Check any of the given roles included in ``roles`` claim of the access token. Returns a dependency function. Should be after ``require_auth``.
     - List of strings as ``conditional OR`` representing any of the allowed roles. For instance, to check ``sample:role1`` or ``sample:role2`` pass ``['sample:role1', 'sample:role2']``.
   * - ``require_permissions``
     - Check any of the given permissions included in ``permissions`` claim of the access token. Returns a dependency function. Should be after ``require_auth``.
     - List of strings as ``conditional OR`` representing any of the allowed permissions. For instance, to check ``sample:create`` or ``sample:update`` pass ``['sample:create', 'sample:update']``.
   * - ``check_object_ownership``
     - Factory function that creates a dependency to verify resource ownership. Validates that the authenticated user owns the specific resource by comparing a field on the object (default ``user``) with a JWT claim (default ``sub``). Automatically includes ``require_auth``.
     - ``get_object`` (callable that retrieves the resource), ``owner_field`` (default: ``"user"``), ``claim_field`` (default: ``"sub"``).

Safe Methods (Skip Authentication)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, ``require_auth`` skips authentication for ``OPTIONS`` requests to support CORS preflight. You can customize which HTTP methods skip authentication using the ``safe_methods`` parameter:

.. code-block:: python

   from functools import partial
   from fastapi import Depends
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

**Default behavior:**

- ``OPTIONS`` requests skip authentication (for CORS preflight)
- All other methods require authentication

**Common use cases:**

- CORS preflight: ``safe_methods=["OPTIONS"]`` (default)
- Public read, authenticated write: ``safe_methods=["GET", "HEAD", "OPTIONS"]``
- Strict mode: ``safe_methods=[]`` (all methods require auth)

OR vs AND Logic
^^^^^^^^^^^^^^^

By default, authorization dependencies use **OR logic** - the token must have **at least ONE** of the specified claims. To require **ALL claims (AND logic)**, chain multiple dependencies.

**OR Logic (Default)** - Requires ANY of the specified claims:

.. code-block:: python

   @app.get("/api/resource")
   async def resource_route(
       payload=Depends(require_auth),
       _=Depends(require_scopes(["read:resource", "write:resource"]))
   ):
       # User needs EITHER 'read:resource' OR 'write:resource' scope
       return {"data": "success"}

   @app.get("/admin/users")
   async def admin_route(
       payload=Depends(require_auth),
       _=Depends(require_roles(["admin", "superuser"]))
   ):
       # User needs EITHER 'admin' OR 'superuser' role
       return {"users": []}

**AND Logic (Chaining)** - Requires ALL of the specified claims:

.. code-block:: python

   @app.get("/api/strict")
   async def strict_route(
       payload=Depends(require_auth),
       _=Depends(require_scopes(["read:resource"])),
       __=Depends(require_scopes(["write:resource"]))
   ):
       # User needs BOTH 'read:resource' AND 'write:resource' scopes
       return {"data": "requires both scopes"}

   @app.get("/admin/critical")
   async def critical_route(
       payload=Depends(require_auth),
       _=Depends(require_roles(["admin"])),
       __=Depends(require_roles(["superuser"]))
   ):
       # User needs BOTH 'admin' AND 'superuser' roles
       return {"message": "requires both roles"}

**Mixed Logic** - Combine OR and AND by chaining:

.. code-block:: python

   @app.get("/api/advanced")
   async def advanced_route(
       payload=Depends(require_auth),
       _=Depends(require_scopes(["openid", "profile"])),  # Needs openid OR profile
       __=Depends(require_roles(["editor"])),              # AND must have editor role
       ___=Depends(require_permissions(["resource:read", "resource:write"]))  # AND read OR write
   ):
       # User needs: (openid OR profile) AND (editor) AND (read OR write)
       return {"data": "complex authorization"}

Object-Level Permissions (Row-Level Security)
----------------------------------------------

Protect individual resources based on ownership using ``check_object_ownership``:

.. code-block:: python

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

Custom Owner Field
^^^^^^^^^^^^^^^^^^

Use a different field name for ownership:

.. code-block:: python

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

Custom Claim Field
^^^^^^^^^^^^^^^^^^

Match ownership using a different JWT claim (e.g., email):

.. code-block:: python

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

Contents
--------

.. toctree::
   :maxdepth: 1

   api
   examples
   issuers

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
