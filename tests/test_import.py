"""Basic import tests for axioms-fastapi package."""

import pytest


def test_import_axioms_fastapi():
    """Test that the main package can be imported."""
    import axioms_fastapi
    assert axioms_fastapi is not None


def test_package_version():
    """Test that package version is accessible."""
    import axioms_fastapi

    # Check if version attribute exists (might not be defined yet)
    if hasattr(axioms_fastapi, '__version__'):
        version = axioms_fastapi.__version__
        assert isinstance(version, str)
        assert len(version) > 0
        print(f"Package version: {version}")
    else:
        # Version might not be set in development mode
        print("Version attribute not found (may not be set in development mode)")


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
    assert hasattr(dependencies, 'check_object_ownership')


def test_import_helper_module():
    """Test that helper module can be imported."""
    from axioms_fastapi import helper
    assert helper is not None
    assert hasattr(helper, 'has_valid_token')
    assert hasattr(helper, 'has_bearer_token')


def test_import_middleware_module():
    """Test that middleware module can be imported."""
    from axioms_fastapi import middleware
    assert middleware is not None
    assert hasattr(middleware, 'AccessTokenMiddleware')


def test_public_api():
    """Test that public API exports are available."""
    from axioms_fastapi import (
        AccessTokenMiddleware,
        AxiomsError,
        AxiomsHTTPException,
        require_auth,
        require_scopes,
        require_roles,
        require_permissions,
        check_object_ownership,
    )

    assert AccessTokenMiddleware is not None
    assert AxiomsError is not None
    assert AxiomsHTTPException is not None
    assert require_auth is not None
    assert require_scopes is not None
    assert require_roles is not None
    assert require_permissions is not None
    assert check_object_ownership is not None
