.PHONY: help install install-dev clean format lint test build publish docs docs-clean docs-serve docs-watch

help:
	@echo "Available targets:"
	@echo "  install       - Install package dependencies"
	@echo "  install-dev   - Install package with dev dependencies"
	@echo "  format        - Format code with black and ruff"
	@echo "  lint          - Lint code with ruff"
	@echo "  test          - Run tests with pytest"
	@echo "  build         - Build source and wheel distributions"
	@echo "  clean         - Remove build artifacts and caches"
	@echo "  publish       - Upload package to PyPI"
	@echo "  docs          - Build HTML documentation with Sphinx"
	@echo "  docs-clean    - Remove built documentation"
	@echo "  docs-serve    - Build and serve documentation locally"
	@echo "  docs-watch    - Auto-rebuild docs on changes (http://localhost:8000)"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf src/*.egg-info
	rm -rf .pytest_cache
	rm -rf .ruff_cache
	rm -rf docs/_build
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

format:
	black src/
	ruff check --fix src/

lint:
	ruff check src/

test:
	pytest

build: clean
	python -m build

publish: build
	twine upload dist/*

docs:
	cd docs && $(MAKE) html

docs-clean:
	rm -rf docs/_build

docs-serve: docs
	@echo "Serving documentation at http://localhost:8005"
	@echo "Press Ctrl+C to stop"
	cd docs/_build/html && python -m http.server 8000

docs-watch:
	@echo "Starting auto-build documentation server at http://localhost:8005"
	@echo "Documentation will rebuild automatically when you save changes"
	@echo "Press Ctrl+C to stop"
	sphinx-autobuild docs docs/_build/html --port 8005 --watch src/
