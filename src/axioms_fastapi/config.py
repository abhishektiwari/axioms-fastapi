"""Configuration management for Axioms FastAPI.

This module provides configuration classes for managing Axioms settings in FastAPI applications.
"""

from typing import Optional, List
from pydantic import ConfigDict
from pydantic_settings import BaseSettings


class AxiomsConfig(BaseSettings):
    """Configuration for Axioms FastAPI authentication.

    All settings can be set via environment variables with the AXIOMS_ prefix.

    Example::

        config = AxiomsConfig(
            AXIOMS_AUDIENCE="api.example.com",
            AXIOMS_DOMAIN="auth.example.com"
        )
    """

    # Required configuration
    AXIOMS_AUDIENCE: str

    # Optional domain and URL configuration
    AXIOMS_DOMAIN: Optional[str] = None
    AXIOMS_ISS_URL: Optional[str] = None
    AXIOMS_JWKS_URL: Optional[str] = None

    # Optional claim name configuration
    AXIOMS_SCOPE_CLAIMS: Optional[List[str]] = None
    AXIOMS_ROLES_CLAIMS: Optional[List[str]] = None
    AXIOMS_PERMISSIONS_CLAIMS: Optional[List[str]] = None

    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="allow",
    )


# Global configuration instance
_config: Optional[AxiomsConfig] = None


def get_config() -> AxiomsConfig:
    """Get the global Axioms configuration instance.

    Returns:
        AxiomsConfig: The configuration instance.

    Raises:
        RuntimeError: If configuration has not been initialized.
    """
    if _config is None:
        raise RuntimeError(
            "Axioms configuration not initialized. "
            "Call init_axioms() with your FastAPI app first."
        )
    return _config


def set_config(config: AxiomsConfig) -> None:
    """Set the global Axioms configuration instance.

    Args:
        config: The AxiomsConfig instance to use globally.
    """
    global _config
    _config = config


def init_axioms(app=None, **kwargs) -> AxiomsConfig:
    """Initialize Axioms configuration for a FastAPI application.

    Args:
        app: Optional FastAPI application instance.
        **kwargs: Configuration parameters to override environment variables.

    Returns:
        AxiomsConfig: The initialized configuration.

    Example::

        from fastapi import FastAPI
        from axioms_fastapi import init_axioms

        app = FastAPI()
        config = init_axioms(
            app,
            AXIOMS_AUDIENCE="api.example.com",
            AXIOMS_DOMAIN="auth.example.com"
        )
    """
    config = AxiomsConfig(**kwargs)
    set_config(config)

    # Store config in app state if app is provided
    if app is not None:
        app.state.axioms_config = config

    return config
