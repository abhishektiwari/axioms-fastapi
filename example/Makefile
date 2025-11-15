.PHONY: help setup install run clean check
.PHONY: db-upgrade db-downgrade db-current db-history db-revision db-reset

help:
	@echo "=========================================="
	@echo "Axioms FastAPI Example - Makefile Commands"
	@echo "=========================================="
	@echo ""
	@echo "Setup Commands:"
	@echo "  make setup        - Complete setup (env, install)"
	@echo "  make install      - Install Python dependencies"
	@echo ""
	@echo "Development Commands:"
	@echo "  make run          - Start development server"
	@echo "  make dev          - Start development server with auto-reload"
	@echo "  make check        - Check code for issues"
	@echo ""
	@echo "Database Migration Commands:"
	@echo "  make db-upgrade   - Apply all pending migrations"
	@echo "  make db-downgrade - Rollback last migration"
	@echo "  make db-current   - Show current migration version"
	@echo "  make db-history   - Show migration history"
	@echo "  make db-revision  - Create new migration (autogenerate)"
	@echo "  make db-reset     - Reset database (WARNING: destroys data)"
	@echo ""
	@echo "Testing Commands:"
	@echo "  make postman      - Run Postman collection tests via Newman CLI"
	@echo "  make postman-install - Install Newman (Postman CLI)"
	@echo ""
	@echo "Utility Commands:"
	@echo "  make clean        - Remove generated files"
	@echo ""
	@echo "Quick Start:"
	@echo "  1. make setup"
	@echo "  2. Edit .env with your configuration"
	@echo "  3. make run"
	@echo ""

setup: env-check install
	@echo ""
	@echo "========================================="
	@echo "Setup Complete!"
	@echo "========================================="
	@echo ""
	@echo "Next steps:"
	@echo "1. Edit .env and configure AXIOMS_AUDIENCE and AXIOMS_ISS_URL"
	@echo "2. Run: make run"
	@echo "3. Import Axioms_FastAPI_Example.postman_collection.json into Postman"
	@echo ""
	@echo "The API will be available at: http://localhost:8000"
	@echo "API documentation at: http://localhost:8000/docs"
	@echo ""

env-check:
	@if [ ! -f .env ]; then \
		echo "Creating .env file from .env.example..."; \
		cp .env.example .env; \
		echo "✓ .env file created"; \
		echo ""; \
		echo "⚠️  IMPORTANT: Edit .env and set your AXIOMS_AUDIENCE and AXIOMS_ISS_URL"; \
		echo ""; \
	else \
		echo "✓ .env file already exists"; \
		echo ""; \
	fi

install:
	@echo "Installing Python dependencies..."
	pip install -r requirements.txt
	@echo "✓ Dependencies installed"
	@echo ""

run:
	@echo "Starting FastAPI server..."
	@echo "API available at: http://localhost:8000"
	@echo "API documentation at: http://localhost:8000/docs"
	@echo "Interactive docs at: http://localhost:8000/redoc"
	@echo ""
	uvicorn main:app --host 0.0.0.0 --port 8000

dev:
	@echo "Starting FastAPI development server with auto-reload..."
	@echo "API available at: http://localhost:8000"
	@echo "API documentation at: http://localhost:8000/docs"
	@echo "Interactive docs at: http://localhost:8000/redoc"
	@echo ""
	uvicorn main:app --host 0.0.0.0 --port 8000 --reload

check:
	@echo "Checking code..."
	@python -m py_compile main.py
	@echo "✓ No syntax errors found"

clean:
	@echo "Cleaning up generated files..."
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete
	rm -f *.log
	@echo "✓ Cleanup complete"

# Database Migration Commands
db-upgrade:
	@echo "Applying database migrations..."
	alembic upgrade head
	@echo "✓ Migrations applied"

db-downgrade:
	@echo "Rolling back last migration..."
	alembic downgrade -1
	@echo "✓ Rollback complete"

db-current:
	@echo "Current database migration version:"
	@alembic current

db-history:
	@echo "Migration history:"
	@alembic history --verbose

db-revision:
	@if [ -z "$(msg)" ]; then \
		echo "Error: Please provide a migration message"; \
		echo "Usage: make db-revision msg=\"Description of changes\""; \
		exit 1; \
	fi
	@echo "Creating new migration: $(msg)"
	alembic revision --autogenerate -m "$(msg)"
	@echo "✓ Migration created. Review the file in alembic/versions/ before applying."

db-reset:
	@echo "⚠️  WARNING: This will delete all data in the database!"
	@echo "Press Ctrl+C to cancel, or Enter to continue..."
	@read confirmation
	@echo "Resetting database..."
	rm -f example.db
	alembic upgrade head
	@echo "✓ Database reset complete"

# Production-related commands
prod-check:
	@echo "Running production readiness checks..."
	@echo ""
	@echo "Checking environment variables..."
	@if grep -q "AXIOMS_AUDIENCE=https://api.example.com" .env 2>/dev/null; then \
		echo "❌ WARNING: Using default AXIOMS_AUDIENCE"; \
	else \
		echo "✓ AXIOMS_AUDIENCE configured"; \
	fi
	@if grep -q "AXIOMS_ISS_URL=https://jwtforge.dev" .env 2>/dev/null; then \
		echo "⚠️  WARNING: Using jwtforge.dev (development only)"; \
	else \
		echo "✓ AXIOMS_ISS_URL configured"; \
	fi
	@echo ""
