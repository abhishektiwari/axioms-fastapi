"""End-to-end tests for object-level permissions using check_object_ownership.

This module tests the check_object_ownership dependency with SQLModel models
to ensure proper object-level access control based on JWT claims.
"""

import time
import pytest
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException
from sqlmodel import Field, Session, SQLModel, create_engine
from sqlalchemy.pool import StaticPool
from axioms_fastapi import (
    check_object_ownership,
    require_auth,
    register_axioms_exception_handler,
)
from axioms_fastapi.config import init_axioms
from conftest import generate_jwt_token


# ============================================================================
# SQLModel Test Models
# ============================================================================

class Article(SQLModel, table=True):
    """Article model with user ownership field."""
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = Field(index=True)
    content: str
    user: str = Field(index=True)  # Owner field matching JWT 'sub' claim


class Comment(SQLModel, table=True):
    """Comment model with custom owner field name."""
    id: Optional[int] = Field(default=None, primary_key=True)
    article_id: int = Field(foreign_key="article.id")
    text: str
    created_by: str = Field(index=True)  # Custom owner field name


class Project(SQLModel, table=True):
    """Project model with email-based ownership."""
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    description: str
    owner_email: str = Field(index=True)  # Owner field matching JWT 'email' claim


class Task(SQLModel, table=True):
    """Task model for testing missing owner field."""
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    # Intentionally missing owner field for error testing


# ============================================================================
# Database Setup
# ============================================================================

# Module-level database engine
test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


def get_session():
    """Get database session."""
    with Session(test_engine) as session:
        yield session


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture(name="session")
def session_fixture():
    """Create database session for testing."""
    # Recreate tables for each test
    SQLModel.metadata.drop_all(test_engine)
    SQLModel.metadata.create_all(test_engine)

    with Session(test_engine) as session:
        # Add test data
        article1 = Article(id=1, title="Article 1", content="Content 1", user="user123")
        article2 = Article(id=2, title="Article 2", content="Content 2", user="user456")

        comment1 = Comment(id=1, article_id=1, text="Comment 1", created_by="user123")
        comment2 = Comment(id=2, article_id=1, text="Comment 2", created_by="user789")

        project1 = Project(
            id=1,
            name="Project 1",
            description="Desc 1",
            owner_email="user@example.com"
        )
        project2 = Project(
            id=2,
            name="Project 2",
            description="Desc 2",
            owner_email="other@example.com"
        )

        task1 = Task(id=1, title="Task 1")

        session.add_all([article1, article2, comment1, comment2, project1, project2, task1])
        session.commit()

        yield session


@pytest.fixture
def app(monkeypatch, test_key):
    """Create FastAPI test application with object-level permissions."""
    from axioms_fastapi import helper

    # Mock get_key_from_jwks_json to return test key directly (bypassing CacheFetcher)
    def mock_get_key_from_jwks_json(kid, config=None):
        if kid == test_key.kid:
            return test_key
        raise Exception(f"Key not found: {kid}")

    monkeypatch.setattr(helper, 'get_key_from_jwks_json', mock_get_key_from_jwks_json)

    fastapi_app = FastAPI()

    init_axioms(
        fastapi_app,
        AXIOMS_AUDIENCE='test-audience',
        AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json',
        AXIOMS_DOMAIN='test-domain.com'
    )
    register_axioms_exception_handler(fastapi_app)

    # Helper dependencies to get objects
    def get_article(article_id: int, session: Session = Depends(get_session)):
        article = session.get(Article, article_id)
        if not article:
            raise HTTPException(status_code=404, detail="Article not found")
        return article

    def get_comment(comment_id: int, session: Session = Depends(get_session)):
        comment = session.get(Comment, comment_id)
        if not comment:
            raise HTTPException(status_code=404, detail="Comment not found")
        return comment

    def get_project(project_id: int, session: Session = Depends(get_session)):
        project = session.get(Project, project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        return project

    def get_task(task_id: int, session: Session = Depends(get_session)):
        task = session.get(Task, task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        return task

    # Article endpoints (default owner_field="user")
    @fastapi_app.get("/articles/{article_id}")
    async def read_article(
        article: Article = Depends(check_object_ownership(get_article))
    ):
        return {"id": article.id, "title": article.title, "user": article.user}

    @fastapi_app.patch("/articles/{article_id}")
    async def update_article(
        article_id: int,
        title: str,
        article: Article = Depends(check_object_ownership(get_article)),
        session: Session = Depends(get_session)
    ):
        article.title = title
        session.add(article)
        session.commit()
        session.refresh(article)
        return {"id": article.id, "title": article.title}

    @fastapi_app.delete("/articles/{article_id}")
    async def delete_article(
        article_id: int,
        article: Article = Depends(check_object_ownership(get_article)),
        session: Session = Depends(get_session)
    ):
        session.delete(article)
        session.commit()
        return {"message": "Deleted"}

    # Comment endpoints (custom owner_field="created_by")
    @fastapi_app.get("/comments/{comment_id}")
    async def read_comment(
        comment: Comment = Depends(
            check_object_ownership(get_comment, owner_field="created_by")
        )
    ):
        return {"id": comment.id, "text": comment.text, "created_by": comment.created_by}

    @fastapi_app.delete("/comments/{comment_id}")
    async def delete_comment(
        comment_id: int,
        comment: Comment = Depends(
            check_object_ownership(get_comment, owner_field="created_by")
        ),
        session: Session = Depends(get_session)
    ):
        session.delete(comment)
        session.commit()
        return {"message": "Deleted"}

    # Project endpoints (custom claim_field="email")
    @fastapi_app.get("/projects/{project_id}")
    async def read_project(
        project: Project = Depends(
            check_object_ownership(
                get_project,
                owner_field="owner_email",
                claim_field="email"
            )
        )
    ):
        return {"id": project.id, "name": project.name, "owner_email": project.owner_email}

    @fastapi_app.patch("/projects/{project_id}")
    async def update_project(
        project_id: int,
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

    # Task endpoint (missing owner field - for error testing)
    @fastapi_app.get("/tasks/{task_id}")
    async def read_task(
        task: Task = Depends(
            check_object_ownership(get_task, owner_field="user")
        )
    ):
        return {"id": task.id, "title": task.title}

    # Endpoint for testing missing JWT claim
    @fastapi_app.get("/projects/{project_id}/missing-claim")
    async def read_project_missing_claim(
        project: Project = Depends(
            check_object_ownership(
                get_project,
                owner_field="owner_email",
                claim_field="missing_claim"
            )
        )
    ):
        return {"id": project.id, "name": project.name}

    return fastapi_app


@pytest.fixture
def client(session, app):
    """Create test client with database session override."""
    from fastapi.testclient import TestClient

    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


# ============================================================================
# Tests for Article Ownership (Default owner_field="user")
# ============================================================================

class TestArticleOwnership:
    """Test article ownership with default owner_field."""

    def test_owner_can_read_article(self, client, test_key):
        """Test that article owner can read their article."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user123',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.get(
            "/articles/1",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == 1
        assert data["user"] == "user123"

    def test_non_owner_cannot_read_article(self, client, test_key):
        """Test that non-owner cannot read article."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user456',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.get(
            "/articles/1",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403
        data = response.json()
        assert data["error"] == "insufficient_permission"

    def test_owner_can_update_article(self, client, test_key):
        """Test that owner can update their article."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user123',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.patch(
            "/articles/1?title=Updated",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Updated"

    def test_non_owner_cannot_update_article(self, client, test_key):
        """Test that non-owner cannot update article."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user456',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.patch(
            "/articles/1?title=Hacked",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403
        data = response.json()
        assert data["error"] == "insufficient_permission"

    def test_owner_can_delete_article(self, client, test_key):
        """Test that owner can delete their article."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user123',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.delete(
            "/articles/1",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200

    def test_non_owner_cannot_delete_article(self, client, test_key):
        """Test that non-owner cannot delete article."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user456',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.delete(
            "/articles/1",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403


# ============================================================================
# Tests for Comment Ownership (Custom owner_field="created_by")
# ============================================================================

class TestCommentOwnership:
    """Test comment ownership with custom owner_field."""

    def test_owner_can_read_comment(self, client, test_key):
        """Test that comment creator can read their comment."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user123',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.get(
            "/comments/1",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["created_by"] == "user123"

    def test_non_owner_cannot_read_comment(self, client, test_key):
        """Test that non-creator cannot read comment."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user456',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.get(
            "/comments/1",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403

    def test_owner_can_delete_comment(self, client, test_key):
        """Test that creator can delete their comment."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user789',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.delete(
            "/comments/2",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200

    def test_non_owner_cannot_delete_comment(self, client, test_key):
        """Test that non-creator cannot delete comment."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user123',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.delete(
            "/comments/2",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403


# ============================================================================
# Tests for Project Ownership (Custom claim_field="email")
# ============================================================================

class TestProjectOwnershipByEmail:
    """Test project ownership using email claim."""

    def test_owner_can_read_project(self, client, test_key):
        """Test that project owner can read their project."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user123',
                'email': 'user@example.com',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.get(
            "/projects/1",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["owner_email"] == "user@example.com"

    def test_non_owner_cannot_read_project(self, client, test_key):
        """Test that non-owner cannot read project."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user456',
                'email': 'other@example.com',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.get(
            "/projects/1",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403

    def test_owner_can_update_project(self, client, test_key):
        """Test that owner can update their project."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user123',
                'email': 'user@example.com',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.patch(
            "/projects/1?name=Updated",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated"

    def test_non_owner_cannot_update_project(self, client, test_key):
        """Test that non-owner cannot update project."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user456',
                'email': 'other@example.com',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.patch(
            "/projects/1?name=Hacked",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403


# ============================================================================
# Error Cases
# ============================================================================

class TestErrorCases:
    """Test error scenarios for object ownership."""

    def test_missing_owner_field_in_object(self, client, test_key):
        """Test error when object doesn't have owner field."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user123',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.get(
            "/tasks/1",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 400
        data = response.json()
        assert data["error"] == "bad_request"
        assert "Invalid resource configuration" in data["error_description"]

    def test_missing_claim_in_jwt(self, client, test_key):
        """Test error when JWT doesn't have required claim."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user123',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.get(
            "/projects/1/missing-claim",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403

    def test_nonexistent_article(self, client, test_key):
        """Test accessing non-existent article returns 404."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user123',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.get(
            "/articles/999",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 404

    def test_unauthorized_access(self, client):
        """Test accessing without token returns 401."""
        response = client.get("/articles/1")
        assert response.status_code == 401

    def test_invalid_token(self, client):
        """Test accessing with invalid token returns 401."""
        response = client.get(
            "/articles/1",
            headers={"Authorization": "Bearer invalid-token"}
        )
        assert response.status_code == 401

    def test_different_user_owns_article(self, client, test_key):
        """Test that user456 can access their own article."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user456',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        response = client.get(
            "/articles/2",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["user"] == "user456"


# ============================================================================
# SQLModel Integration Tests
# ============================================================================

class TestSQLModelIntegration:
    """Test SQLModel database integration."""

    def test_article_persists_across_requests(self, client, test_key):
        """Test that article updates persist in database."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user123',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        # Update article
        update_response = client.patch(
            "/articles/1?title=NewTitle",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert update_response.status_code == 200

        # Read article again
        read_response = client.get(
            "/articles/1",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert read_response.status_code == 200
        data = read_response.json()
        assert data["title"] == "NewTitle"

    def test_article_deletion_removes_from_database(self, client, test_key):
        """Test that article deletion removes from database."""
        now = int(time.time())
        token = generate_jwt_token(
            test_key,
            {
                'sub': 'user123',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        # Delete article
        delete_response = client.delete(
            "/articles/1",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert delete_response.status_code == 200

        # Try to read deleted article
        read_response = client.get(
            "/articles/1",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert read_response.status_code == 404

    def test_multiple_users_different_articles(self, client, test_key):
        """Test isolation between different users' articles."""
        now = int(time.time())
        token123 = generate_jwt_token(
            test_key,
            {
                'sub': 'user123',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )
        token456 = generate_jwt_token(
            test_key,
            {
                'sub': 'user456',
                'aud': 'test-audience',
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now
            },
            alg='RS256'
        )

        # user123 can access article 1
        response1 = client.get(
            "/articles/1",
            headers={"Authorization": f"Bearer {token123}"}
        )
        assert response1.status_code == 200

        # user456 can access article 2
        response2 = client.get(
            "/articles/2",
            headers={"Authorization": f"Bearer {token456}"}
        )
        assert response2.status_code == 200

        # user123 cannot access article 2
        response3 = client.get(
            "/articles/2",
            headers={"Authorization": f"Bearer {token123}"}
        )
        assert response3.status_code == 403

        # user456 cannot access article 1
        response4 = client.get(
            "/articles/1",
            headers={"Authorization": f"Bearer {token456}"}
        )
        assert response4.status_code == 403
