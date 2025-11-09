"""Basic import tests for axioms-fastapi package."""

import pytest


def test_import_axioms_fastapi():
    """Test that the main package can be imported."""
    import axioms_fastapi
    assert axioms_fastapi is not None


def test_package_version():
    """Test that package version is defined."""
    from axioms_fastapi import __version__
    assert __version__ == "0.1.0"


def test_import_error_module():
    """Test that error module can be imported."""
    from axioms_fastapi import error
    assert error is not None
    assert hasattr(error, 'AxiomsError')
    assert hasattr(error, 'AxiomsHTTPException')


def test_import_config_module():
    """Test that config module can be imported."""
    from axioms_fastapi import config
    assert config is not None
    assert hasattr(config, 'AxiomsConfig')
    assert hasattr(config, 'init_axioms')


def test_import_dependencies_module():
    """Test that dependencies module can be imported."""
    from axioms_fastapi import dependencies
    assert dependencies is not None
    assert hasattr(dependencies, 'require_auth')
    assert hasattr(dependencies, 'require_scopes')
    assert hasattr(dependencies, 'require_roles')
    assert hasattr(dependencies, 'require_permissions')


def test_import_token_module():
    """Test that token module can be imported."""
    from axioms_fastapi import token
    assert token is not None
    assert hasattr(token, 'has_valid_token')
    assert hasattr(token, 'has_bearer_token')


def test_public_api():
    """Test that public API exports are available."""
    from axioms_fastapi import (
        AxiomsError,
        AxiomsHTTPException,
        require_auth,
        require_scopes,
        require_roles,
        require_permissions,
    )

    assert AxiomsError is not None
    assert AxiomsHTTPException is not None
    assert require_auth is not None
    assert require_scopes is not None
    assert require_roles is not None
    assert require_permissions is not None
