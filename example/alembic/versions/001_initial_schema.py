"""Initial schema with Article and Comment tables

Revision ID: 001
Revises:
Create Date: 2025-01-14 00:00:00.000000

This is the initial migration that creates the database schema.
The Article table uses 'user' field to track ownership.
"""
from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create initial tables."""
    # Create article table
    op.create_table(
        'article',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('content', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('user', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_article_title'), 'article', ['title'], unique=False)
    op.create_index(op.f('ix_article_user'), 'article', ['user'], unique=False)

    # Create comment table
    op.create_table(
        'comment',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('article_id', sa.Integer(), nullable=False),
        sa.Column('text', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('created_by', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.ForeignKeyConstraint(['article_id'], ['article.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_comment_created_by'), 'comment', ['created_by'], unique=False)


def downgrade() -> None:
    """Drop all tables."""
    op.drop_index(op.f('ix_comment_created_by'), table_name='comment')
    op.drop_table('comment')
    op.drop_index(op.f('ix_article_user'), table_name='article')
    op.drop_index(op.f('ix_article_title'), table_name='article')
    op.drop_table('article')
