Examples
========

This page provides practical examples of using axioms-fastapi dependencies to secure your FastAPI routes.

Scope-Based Authorization
--------------------------

Check if ``openid`` or ``profile`` scope is present in the token:

.. code-block:: python

   from fastapi import FastAPI, Depends
   from axioms_fastapi import init_axioms, require_auth, require_scopes, register_axioms_exception_handler

   app = FastAPI()
   init_axioms(
       app,
       AXIOMS_AUDIENCE="your-api",
       AXIOMS_ISS_URL="https://auth.example.com",
       AXIOMS_JWKS_URL="https://auth.example.com/.well-known/jwks.json"
   )
   register_axioms_exception_handler(app)

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
   from axioms_fastapi import init_axioms, require_auth, require_roles, register_axioms_exception_handler

   app = FastAPI()
   init_axioms(
       app,
       AXIOMS_AUDIENCE="your-api",
       AXIOMS_ISS_URL="https://auth.example.com",
       AXIOMS_JWKS_URL="https://auth.example.com/.well-known/jwks.json"
   )
   register_axioms_exception_handler(app)

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
   from axioms_fastapi import init_axioms, require_auth, require_permissions, register_axioms_exception_handler

   app = FastAPI()
   init_axioms(
       app,
       AXIOMS_AUDIENCE="your-api",
       AXIOMS_ISS_URL="https://auth.example.com",
       AXIOMS_JWKS_URL="https://auth.example.com/.well-known/jwks.json"
   )
   register_axioms_exception_handler(app)

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
       require_permissions,
       register_axioms_exception_handler
   )

   app = FastAPI()
   init_axioms(
       app,
       AXIOMS_AUDIENCE="your-api",
       AXIOMS_ISS_URL="https://auth.example.com",
       AXIOMS_JWKS_URL="https://auth.example.com/.well-known/jwks.json"
   )
   register_axioms_exception_handler(app)

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
   from axioms_fastapi import init_axioms, require_auth, register_axioms_exception_handler

   app = FastAPI()
   init_axioms(
       app,
       AXIOMS_AUDIENCE="your-api",
       AXIOMS_ISS_URL="https://auth.example.com",
       AXIOMS_JWKS_URL="https://auth.example.com/.well-known/jwks.json"
   )
   register_axioms_exception_handler(app)

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

Object-Level Permissions (Row-Level Security)
----------------------------------------------

Protect individual resources based on ownership using ``check_object_ownership``. This enables row-level security by verifying that the authenticated user owns the specific resource they're trying to access.

Basic Usage
^^^^^^^^^^^

Verify resource ownership using the default configuration (``owner_field="user"`` matches JWT ``sub`` claim):

.. code-block:: python

   from fastapi import FastAPI, Depends, HTTPException
   from sqlmodel import Field, Session, SQLModel, create_engine
   from axioms_fastapi import init_axioms, check_object_ownership, register_axioms_exception_handler

   app = FastAPI()
   init_axioms(
       app,
       AXIOMS_AUDIENCE="your-api",
       AXIOMS_ISS_URL="https://auth.example.com",
       AXIOMS_JWKS_URL="https://auth.example.com/.well-known/jwks.json"
   )
   register_axioms_exception_handler(app)

   # Database setup
   engine = create_engine("sqlite:///./database.db")

   class Article(SQLModel, table=True):
       id: int = Field(primary_key=True)
       title: str
       content: str
       user: str = Field(index=True)  # Owner field - matches JWT 'sub' claim

   def get_session():
       with Session(engine) as session:
           yield session

   def get_article(article_id: int, session: Session = Depends(get_session)):
       article = session.get(Article, article_id)
       if not article:
           raise HTTPException(status_code=404, detail="Article not found")
       return article

   # Only the article owner can read their article
   @app.get("/articles/{article_id}")
   async def read_article(
       article: Article = Depends(check_object_ownership(get_article))
   ):
       # check_object_ownership verifies: article.user == JWT 'sub' claim
       return {"id": article.id, "title": article.title, "user": article.user}

   # Only the article owner can update their article
   @app.patch("/articles/{article_id}")
   async def update_article(
       title: str,
       article: Article = Depends(check_object_ownership(get_article)),
       session: Session = Depends(get_session)
   ):
       article.title = title
       session.add(article)
       session.commit()
       session.refresh(article)
       return {"id": article.id, "title": article.title}

   # Only the article owner can delete their article
   @app.delete("/articles/{article_id}")
   async def delete_article(
       article: Article = Depends(check_object_ownership(get_article)),
       session: Session = Depends(get_session)
   ):
       session.delete(article)
       session.commit()
       return {"message": "Article deleted"}

**Example JWT Token Payload (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "exp": 1735689600,
     "iat": 1735686000
   }

If ``article.user`` is ``"user123"``, the request will **succeed** because ``article.user == payload.sub``.

**Example JWT Token Payload (Failure):**

.. code-block:: json

   {
     "sub": "user456",
     "aud": "your-api-audience",
     "exp": 1735689600,
     "iat": 1735686000
   }

If ``article.user`` is ``"user123"``, the request will **fail** with 403 Forbidden because ``article.user != payload.sub``.

Custom Owner Field
^^^^^^^^^^^^^^^^^^

Use a different field name for ownership verification:

.. code-block:: python

   class Comment(SQLModel, table=True):
       id: int = Field(primary_key=True)
       article_id: int
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
       # Specify owner_field="created_by" to check comment.created_by == JWT 'sub'
       comment: Comment = Depends(check_object_ownership(get_comment, owner_field="created_by")),
       session: Session = Depends(get_session)
   ):
       comment.text = text
       session.add(comment)
       session.commit()
       session.refresh(comment)
       return {"id": comment.id, "text": comment.text, "created_by": comment.created_by}

   @app.delete("/comments/{comment_id}")
   async def delete_comment(
       comment: Comment = Depends(check_object_ownership(get_comment, owner_field="created_by")),
       session: Session = Depends(get_session)
   ):
       session.delete(comment)
       session.commit()
       return {"message": "Comment deleted"}

Custom Claim Field
^^^^^^^^^^^^^^^^^^

Match ownership using a different JWT claim (e.g., ``email`` instead of ``sub``):

.. code-block:: python

   class Project(SQLModel, table=True):
       id: int = Field(primary_key=True)
       name: str
       description: str
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

   @app.patch("/projects/{project_id}")
   async def update_project(
       name: str,
       project: Project = Depends(
           check_object_ownership(
               get_project,
               owner_field="owner_email",
               claim_field="email"
           )
       ),
       session: Session = Depends(get_session)
   ):
       project.name = name
       session.add(project)
       session.commit()
       session.refresh(project)
       return {"id": project.id, "name": project.name}

**Example JWT Token Payload (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "email": "user@example.com",
     "aud": "your-api-audience",
     "exp": 1735689600,
     "iat": 1735686000
   }

If ``project.owner_email`` is ``"user@example.com"``, the request will **succeed** because ``project.owner_email == payload.email``.

Error Scenarios
^^^^^^^^^^^^^^^

``check_object_ownership`` handles various error cases:

**404 Not Found** - Resource doesn't exist (handled by your ``get_*`` function):

.. code-block:: python

   def get_article(article_id: int, session: Session = Depends(get_session)):
       article = session.get(Article, article_id)
       if not article:
           raise HTTPException(status_code=404, detail="Article not found")
       return article

**403 Forbidden** - User doesn't own the resource:

When the authenticated user's claim doesn't match the resource's owner field.

**500 Internal Server Error** - Missing owner field:

When the object doesn't have the specified ``owner_field`` attribute.

**403 Forbidden** - Missing JWT claim:

When the JWT doesn't contain the specified ``claim_field``.

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
