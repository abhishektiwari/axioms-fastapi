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

Features
--------

* JWT token validation with automatic public key retrieval from JWKS endpoints
* Algorithm validation to prevent algorithm confusion attacks (only secure asymmetric algorithms allowed)
* Issuer validation (``iss`` claim) to prevent token substitution attacks
* FastAPI dependency injection for authentication and authorization
* Flexible configuration with support for custom JWKS and issuer URLs
* Support for custom claim and/or namespaced claims names to support different authorization servers
* Async-ready and production-tested

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
       AXIOMS_DOMAIN="your-auth.domain.com"
   )

   # Register exception handler for authentication/authorization errors
   register_axioms_exception_handler(app)

2. Create a ``.env`` file with your configuration (see `.env.example <https://github.com/abhishektiwari/axioms-fastapi/blob/main/.env.example>`_ for reference):

.. code-block:: bash

   AXIOMS_AUDIENCE=your-api-audience
   AXIOMS_DOMAIN=your-auth.domain.com  # Simplest option - constructs issuer and JWKS URLs

   # OR for custom configurations:
   # AXIOMS_ISS_URL=https://your-auth.domain.com/oauth2
   # AXIOMS_JWKS_URL=https://your-auth.domain.com/.well-known/jwks.json

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
* ``AXIOMS_DOMAIN`` (optional): Your auth domain - constructs issuer and JWKS URLs
* ``AXIOMS_ISS_URL`` (optional): Full issuer URL for validating the ``iss`` claim (recommended for security)
* ``AXIOMS_JWKS_URL`` (optional): Full URL to your JWKS endpoint

**Configuration Hierarchy:**

1. ``AXIOMS_DOMAIN`` → constructs → ``AXIOMS_ISS_URL`` (if not explicitly set)
2. ``AXIOMS_ISS_URL`` → constructs → ``AXIOMS_JWKS_URL`` (if not explicitly set)

.. important::
   You must provide at least one of: ``AXIOMS_DOMAIN``, ``AXIOMS_ISS_URL``, or ``AXIOMS_JWKS_URL``.

   For most use cases, setting only ``AXIOMS_DOMAIN`` is sufficient. The SDK will automatically construct the issuer URL and JWKS endpoint URL.

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

Contents
--------

.. toctree::
   :maxdepth: 2
   :caption: Documentation:

   examples
   api

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
