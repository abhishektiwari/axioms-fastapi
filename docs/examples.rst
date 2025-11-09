Examples
========

This page provides practical examples of using axioms-fastapi dependencies to secure your FastAPI routes.

Scope-Based Authorization
--------------------------

Check if ``openid`` or ``profile`` scope is present in the token:

.. code-block:: python

   from fastapi import FastAPI, Depends
   from axioms_fastapi import init_axioms, require_auth, require_scopes

   app = FastAPI()
   init_axioms(app, AXIOMS_AUDIENCE="your-api", AXIOMS_DOMAIN="auth.example.com")

   @app.get('/private')
   async def api_private(
       payload=Depends(require_auth),
       _=Depends(require_scopes(['openid', 'profile']))
   ):
       return {'message': 'All good. You are authenticated!'}

**Example JWT Token Payload (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "openid profile email",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** because the token contains ``openid`` in the ``scope`` claim.

**Example JWT Token Payload (Failure):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "email",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** with 403 Forbidden because the token does not contain ``openid`` or ``profile`` in the ``scope`` claim.

Role-Based Authorization
-------------------------

Check if ``sample:role`` role is present in the token:

.. code-block:: python

   from fastapi import FastAPI, Depends
   from axioms_fastapi import init_axioms, require_auth, require_roles

   app = FastAPI()
   init_axioms(app, AXIOMS_AUDIENCE="your-api", AXIOMS_DOMAIN="auth.example.com")

   @app.get("/role")
   async def sample_role_get(
       payload=Depends(require_auth),
       _=Depends(require_roles(["sample:role"]))
   ):
       return {"message": "Sample read."}

   @app.post("/role")
   async def sample_role_post(
       payload=Depends(require_auth),
       _=Depends(require_roles(["sample:role"]))
   ):
       return {"message": "Sample created."}

   @app.patch("/role")
   async def sample_role_patch(
       payload=Depends(require_auth),
       _=Depends(require_roles(["sample:role"]))
   ):
       return {"message": "Sample updated."}

   @app.delete("/role")
   async def sample_role_delete(
       payload=Depends(require_auth),
       _=Depends(require_roles(["sample:role"]))
   ):
       return {"message": "Sample deleted."}

**Example JWT Token Payload (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "roles": ["sample:role", "viewer"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** because the token contains ``sample:role`` in the ``roles`` claim.

**Example JWT Token Payload with Namespaced Claims (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "https://your-domain.com/claims/roles": ["sample:role", "admin"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will also **succeed** if you configure ``AXIOMS_ROLES_CLAIMS=['roles', 'https://your-domain.com/claims/roles']``.

**Example JWT Token Payload (Failure):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "roles": ["viewer", "editor"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** with 403 Forbidden because the token does not contain ``sample:role``.

Permission-Based Authorization
-------------------------------

Check permissions at the API method level:

.. code-block:: python

   from fastapi import FastAPI, Depends
   from axioms_fastapi import init_axioms, require_auth, require_permissions

   app = FastAPI()
   init_axioms(app, AXIOMS_AUDIENCE="your-api", AXIOMS_DOMAIN="auth.example.com")

   @app.post("/permission")
   async def sample_create(
       payload=Depends(require_auth),
       _=Depends(require_permissions(["sample:create"]))
   ):
       return {"message": "Sample created."}

   @app.patch("/permission")
   async def sample_update(
       payload=Depends(require_auth),
       _=Depends(require_permissions(["sample:update"]))
   ):
       return {"message": "Sample updated."}

   @app.get("/permission")
   async def sample_read(
       payload=Depends(require_auth),
       _=Depends(require_permissions(["sample:read"]))
   ):
       return {"message": "Sample read."}

   @app.delete("/permission")
   async def sample_delete(
       payload=Depends(require_auth),
       _=Depends(require_permissions(["sample:delete"]))
   ):
       return {"message": "Sample deleted."}

**Example JWT Token Payload (Success for sample:read):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "permissions": ["sample:read", "sample:update"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** for the GET endpoint because the token contains ``sample:read`` in the ``permissions`` claim.

**Example JWT Token Payload with Namespaced Claims (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "https://your-domain.com/claims/permissions": ["sample:create", "sample:delete"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** for POST and DELETE endpoints if you configure ``AXIOMS_PERMISSIONS_CLAIMS=['permissions', 'https://your-domain.com/claims/permissions']``.

**Example JWT Token Payload (Failure):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "permissions": ["other:read"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** with 403 Forbidden because the token does not contain any of the required ``sample:*`` permissions.

Complex Authorization (AND Logic)
----------------------------------

Combine multiple authorization requirements using dependency chaining:

.. code-block:: python

   from fastapi import FastAPI, Depends
   from axioms_fastapi import (
       init_axioms,
       require_auth,
       require_scopes,
       require_roles,
       require_permissions
   )

   app = FastAPI()
   init_axioms(app, AXIOMS_AUDIENCE="your-api", AXIOMS_DOMAIN="auth.example.com")

   @app.get("/api/strict")
   async def strict_endpoint(
       payload=Depends(require_auth),
       _=Depends(require_scopes(["openid", "profile"])),  # openid OR profile
       __=Depends(require_roles(["editor"])),              # AND editor role
       ___=Depends(require_permissions(["resource:write"]))  # AND write permission
   ):
       return {
           "message": "Access granted to strict endpoint",
           "requirements": {
               "scope": "openid OR profile",
               "role": "editor",
               "permission": "resource:write",
           }
       }

**Example JWT Token Payload (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "openid email",
     "roles": ["editor", "viewer"],
     "permissions": ["resource:write", "resource:read"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** because the token contains:
- ``openid`` scope (satisfies openid OR profile requirement)
- ``editor`` role
- ``resource:write`` permission

**Example JWT Token Payload (Failure - Missing Role):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "openid profile",
     "roles": ["viewer"],
     "permissions": ["resource:write"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** with 403 Forbidden because the token does not contain the required ``editor`` role.

User Profile Example
---------------------

Access user information from the validated JWT payload:

.. code-block:: python

   from fastapi import FastAPI, Depends
   from axioms_fastapi import init_axioms, require_auth

   app = FastAPI()
   init_axioms(app, AXIOMS_AUDIENCE="your-api", AXIOMS_DOMAIN="auth.example.com")

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

**Example Response:**

.. code-block:: json

   {
     "sub": "user123",
     "email": "user@example.com",
     "name": "John Doe",
     "roles": ["editor", "viewer"],
     "permissions": ["resource:read", "resource:write"]
   }

Complete FastAPI Application
-----------------------------

For a complete working example, see the ``example_app.py`` file in the `axioms-fastapi repository <https://github.com/abhishektiwari/axioms-fastapi>`_
on GitHub. The example demonstrates a fully functional FastAPI application with:

- Authentication and authorization
- Multiple endpoints with different authorization requirements
- Error handling
- Dependency injection patterns
- AND/OR logic examples

You can run the example with:

.. code-block:: bash

   uvicorn example_app:app --reload

Then access the interactive API documentation at http://localhost:8000/docs
