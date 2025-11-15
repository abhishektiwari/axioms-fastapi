"""Example FastAPI application using axioms-fastapi for authentication.

This example demonstrates how to use axioms-fastapi to protect routes with
JWT-based authentication and authorization.

Run with:
    uvicorn main:app --reload

Test with:
    curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:8000/protected
"""

import os
from typing import Optional
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from sqlmodel import Field, Session, SQLModel, create_engine, select
from axioms_fastapi import (
    init_axioms,
    require_auth,
    require_scopes,
    require_roles,
    require_permissions,
    check_object_ownership,
    register_axioms_exception_handler,
)

# Load environment variables from .env file
load_dotenv()


# ============================================================================
# SQLModel Database Models
# ============================================================================

class Article(SQLModel, table=True):
    """Article model demonstrating object-level ownership with user field."""
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = Field(index=True)
    content: str
    user: str = Field(index=True)  # Matches JWT 'sub' claim for ownership


class Comment(SQLModel, table=True):
    """Comment model demonstrating custom owner field name."""
    id: Optional[int] = Field(default=None, primary_key=True)
    article_id: int = Field(foreign_key="article.id")
    text: str
    created_by: str = Field(index=True)  # Custom owner field name


# ============================================================================
# Database Setup
# ============================================================================

# SQLite database for demo - in production use PostgreSQL/MySQL
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./example.db")

# Create engine
engine = create_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL query logging
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)


def get_session():
    """Dependency to get database session."""
    with Session(engine) as session:
        yield session


def init_db():
    """Initialize database using Alembic migrations.

    This runs all pending migrations to ensure the database schema is up-to-date.
    In production, you would typically run migrations separately using:
        alembic upgrade head

    For this example app, we run migrations automatically on startup for convenience.
    """
    from alembic import command
    from alembic.config import Config

    # Get the directory where this file is located
    import os
    basedir = os.path.dirname(__file__)
    alembic_cfg = Config(os.path.join(basedir, "alembic.ini"))

    # Run migrations to latest version
    command.upgrade(alembic_cfg, "head")


# Create FastAPI application
app = FastAPI(
    title="Axioms FastAPI Example",
    description="Example application using axioms-fastapi for OAuth2/OIDC authentication",
    version="1.0.0",
)

# Initialize Axioms configuration from environment variables
init_axioms(
    app,
    AXIOMS_AUDIENCE=os.getenv("AXIOMS_AUDIENCE", "https://api.example.com"),
    AXIOMS_ISS_URL=os.getenv("AXIOMS_ISS_URL"),
    AXIOMS_JWKS_URL=os.getenv("AXIOMS_JWKS_URL"),
    AXIOMS_DOMAIN=os.getenv("AXIOMS_DOMAIN"),
)

# Register exception handler for Axioms errors
register_axioms_exception_handler(app)


# Initialize database on startup
@app.on_event("startup")
def on_startup():
    """Initialize database tables on startup."""
    init_db()


# Public endpoint - no authentication required
@app.get("/")
async def root():
    """Public endpoint accessible without authentication."""
    return {
        "message": "Welcome to Axioms FastAPI Example",
        "documentation": "/docs",
        "endpoints": {
            "public": ["/", "/health", "/docs", "/openapi.json"],
            "authenticated": ["/protected", "/me"],
            "scope_protected": ["/api/read", "/api/write"],
            "role_protected": ["/admin/users"],
            "permission_protected": ["/api/resource"],
            "strict": ["/api/strict"],
            "object_ownership": ["/articles", "/articles/{id}", "/comments/{id}"],
        }
    }


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {"status": "healthy"}


# Protected endpoint - requires valid JWT token
@app.get("/protected")
async def protected_endpoint(payload=Depends(require_auth)):
    """Protected endpoint requiring valid JWT authentication.

    The payload parameter contains the validated JWT claims.
    """
    return {
        "message": "You are authenticated!",
        "user_id": payload.sub,
        "issuer": getattr(payload, "iss", None),
        "audience": getattr(payload, "aud", None),
    }


# User profile endpoint
@app.get("/me")
async def get_current_user(payload=Depends(require_auth)):
    """Get current authenticated user's profile from JWT claims."""
    return {
        "sub": payload.sub,
        "email": getattr(payload, "email", None),
        "name": getattr(payload, "name", None),
        "scope": getattr(payload, "scope", None),
        "roles": getattr(payload, "roles", []),
        "permissions": getattr(payload, "permissions", []),
    }


# Scope-protected endpoint (OR logic)
@app.get("/api/read")
async def read_data(
    payload=Depends(require_auth),
    _=Depends(require_scopes(["read:data", "admin"]))
):
    """Endpoint requiring 'read:data' OR 'admin' scope."""
    return {
        "message": "Data retrieved successfully",
        "data": ["item1", "item2", "item3"],
        "user_scope": getattr(payload, "scope", None),
    }


# Role-protected endpoint (OR logic)
@app.get("/admin/users")
async def list_users(
    payload=Depends(require_auth),
    _=Depends(require_roles(["admin", "superuser"]))
):
    """Endpoint requiring 'admin' OR 'superuser' role."""
    return {
        "message": "User list retrieved",
        "users": [
            {"id": 1, "name": "User 1", "email": "user1@example.com"},
            {"id": 2, "name": "User 2", "email": "user2@example.com"},
        ],
        "user_roles": getattr(payload, "roles", []),
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
        "created_by": payload.sub,
        "user_permissions": getattr(payload, "permissions", []),
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
        "user": {
            "sub": payload.sub,
            "scope": getattr(payload, "scope", None),
            "roles": getattr(payload, "roles", []),
            "permissions": getattr(payload, "permissions", []),
        },
    }


# Scope-protected with AND logic (via chaining)
@app.get("/api/write")
async def write_data(
    payload=Depends(require_auth),
    _=Depends(require_scopes(["write:data"])),
    __=Depends(require_scopes(["openid"]))  # AND requires openid scope
):
    """Endpoint requiring BOTH 'write:data' AND 'openid' scopes."""
    return {
        "message": "Data written successfully",
        "data_id": "data-456",
        "user_scope": getattr(payload, "scope", None),
    }


# Role-protected with AND logic (via chaining)
@app.delete("/admin/users/{user_id}")
async def delete_user(
    user_id: int,
    payload=Depends(require_auth),
    _=Depends(require_roles(["admin"])),
    __=Depends(require_roles(["superuser"]))  # AND requires superuser role
):
    """Endpoint requiring BOTH 'admin' AND 'superuser' roles."""
    return {
        "message": f"User {user_id} deleted successfully",
        "deleted_by": payload.sub,
        "user_roles": getattr(payload, "roles", []),
    }


# ============================================================================
# Object-Level Ownership Endpoints (using check_object_ownership)
# ============================================================================

# Helper dependencies to get objects from database
def get_article(article_id: int, session: Session = Depends(get_session)):
    """Get article by ID or raise 404."""
    article = session.get(Article, article_id)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    return article


def get_comment(comment_id: int, session: Session = Depends(get_session)):
    """Get comment by ID or raise 404."""
    comment = session.get(Comment, comment_id)
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    return comment


@app.get("/articles", status_code=200)
async def list_articles(
    payload=Depends(require_auth),
    session: Session = Depends(get_session)
):
    """List all articles - requires authentication.

    Returns all articles in the database. No ownership check required for listing.
    """
    articles = session.exec(select(Article)).all()
    return {
        "articles": [
            {
                "id": article.id,
                "title": article.title,
                "user": article.user,
            }
            for article in articles
        ],
        "count": len(articles)
    }


@app.post("/articles", status_code=201)
async def create_article(
    title: str,
    content: str,
    payload=Depends(require_auth),
    session: Session = Depends(get_session)
):
    """Create a new article - sets current user as author.

    The user field is automatically set to the authenticated user's 'sub' claim.
    """
    article = Article(
        title=title,
        content=content,
        user=payload.sub  # Set ownership to authenticated user
    )
    session.add(article)
    session.commit()
    session.refresh(article)

    return {
        "message": "Article created successfully",
        "article": {
            "id": article.id,
            "title": article.title,
            "content": article.content,
            "user": article.user,
        }
    }


@app.get("/articles/{article_id}", status_code=200)
async def read_article(
    article: Article = Depends(check_object_ownership(get_article))
):
    """Read article - only the author can read their own articles.

    Uses check_object_ownership with default settings:
    - owner_field: "user" (matches Article.user)
    - claim_field: "sub" (matches JWT sub claim)

    Returns 403 if the authenticated user is not the author.
    """
    return {
        "id": article.id,
        "title": article.title,
        "content": article.content,
        "user": article.user,
    }


@app.patch("/articles/{article_id}", status_code=200)
async def update_article(
    article_id: int,
    title: Optional[str] = None,
    content: Optional[str] = None,
    article: Article = Depends(check_object_ownership(get_article)),
    session: Session = Depends(get_session)
):
    """Update article - only the author can update their own articles.

    Demonstrates object-level write protection using check_object_ownership.
    """
    if title is not None:
        article.title = title
    if content is not None:
        article.content = content

    session.add(article)
    session.commit()
    session.refresh(article)

    return {
        "message": "Article updated successfully",
        "article": {
            "id": article.id,
            "title": article.title,
            "content": article.content,
            "user": article.user,
        }
    }


@app.delete("/articles/{article_id}", status_code=204)
async def delete_article(
    article_id: int,
    article: Article = Depends(check_object_ownership(get_article)),
    session: Session = Depends(get_session)
):
    """Delete article - only the author can delete their own articles.

    Demonstrates object-level delete protection using check_object_ownership.
    """
    session.delete(article)
    session.commit()
    return None


@app.post("/articles/{article_id}/comments", status_code=201)
async def create_comment(
    article_id: int,
    text: str,
    payload=Depends(require_auth),
    session: Session = Depends(get_session)
):
    """Create a comment on an article.

    The created_by field is automatically set to the authenticated user's 'sub' claim.
    """
    # Verify article exists
    article = session.get(Article, article_id)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")

    comment = Comment(
        article_id=article_id,
        text=text,
        created_by=payload.sub  # Set ownership to authenticated user
    )
    session.add(comment)
    session.commit()
    session.refresh(comment)

    return {
        "message": "Comment created successfully",
        "comment": {
            "id": comment.id,
            "article_id": comment.article_id,
            "text": comment.text,
            "created_by": comment.created_by,
        }
    }


@app.patch("/comments/{comment_id}", status_code=200)
async def update_comment(
    comment_id: int,
    text: str,
    comment: Comment = Depends(check_object_ownership(get_comment, owner_field="created_by")),
    session: Session = Depends(get_session)
):
    """Update comment - only the comment creator can update it.

    Demonstrates custom owner_field parameter:
    - owner_field: "created_by" (matches Comment.created_by)
    - claim_field: "sub" (default, matches JWT sub claim)

    Returns 403 if the authenticated user is not the comment creator.
    """
    comment.text = text
    session.add(comment)
    session.commit()
    session.refresh(comment)

    return {
        "message": "Comment updated successfully",
        "comment": {
            "id": comment.id,
            "article_id": comment.article_id,
            "text": comment.text,
            "created_by": comment.created_by,
        }
    }


@app.delete("/comments/{comment_id}", status_code=204)
async def delete_comment(
    comment_id: int,
    comment: Comment = Depends(check_object_ownership(get_comment, owner_field="created_by")),
    session: Session = Depends(get_session)
):
    """Delete comment - only the comment creator can delete it.

    Demonstrates custom owner_field parameter for delete operations.
    """
    session.delete(comment)
    session.commit()
    return None


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
