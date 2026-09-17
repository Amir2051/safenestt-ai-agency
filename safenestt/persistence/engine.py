from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Generator

import sqlalchemy as _sqlalchemy
from sqlalchemy import create_engine as _create_engine, Engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from safenestt.persistence.rls import set_tenant_context
from safenestt.security.secrets import get_secret

logger = logging.getLogger(__name__)

# Database connection settings from environment or secrets manager
_DB_HOST = os.getenv("DB_HOST", "172.19.0.11")
_DB_PORT = os.getenv("DB_PORT", "5432")
_DB_NAME = os.getenv("DB_NAME", "safenestt_ai")

# Passwords from secrets manager (with env fallback)
_DB_PASSWORD = get_secret("SAFENESTT_DB_PASSWORD") or os.getenv("DB_PASSWORD", "")
_DB_OWNER_PASSWORD = get_secret("SAFENESTT_OWNER_PASSWORD") or os.getenv("POSTGRES_PASSWORD", "postgres")

# Allow full URL override via env (highest priority)
_DATABASE_URL = os.getenv(
    "SAFENESTT_DATABASE_URL",
    os.getenv(
        "DATABASE_URL",
        f"postgresql://safenestt_app:{_DB_PASSWORD}@{_DB_HOST}:{_DB_PORT}/{_DB_NAME}" if _DB_PASSWORD else f"postgresql://safenestt_app:***@{_DB_HOST}:{_DB_PORT}/{_DB_NAME}",
    ),
)

_OWNER_DATABASE_URL = os.getenv(
    "SAFENESTT_OWNER_DATABASE_URL",
    os.getenv(
        "OWNER_DATABASE_URL",
        f"postgresql://postgres:{_DB_OWNER_PASSWORD}@{_DB_HOST}:{_DB_PORT}/{_DB_NAME}",
    ),
)

# SSL configuration
# Default: verify-full (strongest — encrypts AND verifies server identity)
# For development with self-signed certs, set DB_SSL_MODE=verify-ca
_DB_SSL_MODE = os.getenv("DB_SSL_MODE", "verify-full")
_DB_SSL_ROOT_CERT = os.getenv("DB_SSL_ROOT_CERT", os.path.join(os.path.dirname(__file__), "..", "..", "certs", "ca.crt"))
_DB_SSL_CLIENT_CERT = os.getenv("DB_SSL_CLIENT_CERT", None)
_DB_SSL_CLIENT_KEY = os.getenv("DB_SSL_CLIENT_KEY", None)

_engine: Engine | None = None
_sessionmaker: sessionmaker[Session] | None = None
_owner_engine: Engine | None = None


def _build_engine(url: str, **kwargs) -> Engine:
    """Create engine with SSL enforcement."""
    connect_args = {}
    if "connect_args" in kwargs:
        connect_args = kwargs.pop("connect_args") or {}
    
    # Enforce SSL/TLS for database connections
    if "postgresql" in url:
        connect_args["sslmode"] = _DB_SSL_MODE
        if _DB_SSL_ROOT_CERT:
            connect_args["sslrootcert"] = _DB_SSL_ROOT_CERT
        if _DB_SSL_CLIENT_CERT:
            connect_args["sslcert"] = _DB_SSL_CLIENT_CERT
        if _DB_SSL_CLIENT_KEY:
            connect_args["sslkey"] = _DB_SSL_CLIENT_KEY
    
    return _create_engine(url, connect_args=connect_args, **kwargs)


def create_engine(url: str | None = None, **kwargs) -> Engine:
    global _engine, _sessionmaker
    _engine = _build_engine(url or _DATABASE_URL, **kwargs)
    _sessionmaker = sessionmaker(bind=_engine)
    return _engine


def get_engine() -> Engine | None:
    return _engine


def get_sessionmaker() -> sessionmaker[Session] | None:
    return _sessionmaker


def get_owner_engine() -> Engine:
    global _owner_engine
    if _owner_engine is None:
        _owner_engine = _build_engine(_OWNER_DATABASE_URL)
    return _owner_engine


@contextmanager
def session_scope(tenant_id: str | None = None) -> Generator[Session, None, None]:
    """Provide a transactional scope with RLS tenant context set."""
    if _sessionmaker is None:
        raise RuntimeError("Session maker not initialized. Call create_engine() first.")
    session = _sessionmaker()
    try:
        set_tenant_context(session.connection(), tenant_id)
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def session_scope_bypass_rls() -> Generator[Session, None, None]:
    """Provide a transactional scope without RLS tenant filtering."""
    if _sessionmaker is None:
        raise RuntimeError("Session maker not initialized. Call create_engine() first.")
    session = _sessionmaker()
    try:
        set_tenant_context(session.connection(), None)
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
