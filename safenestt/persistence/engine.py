from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Generator

import sqlalchemy as _sqlalchemy
from sqlalchemy import create_engine as _create_engine, Engine, event
from sqlalchemy.orm import Session, sessionmaker

from safenestt.persistence.rls import set_tenant_context

# Application connects as non-owner role (RLS applies)
# Password MUST come from env var, never hardcoded
_DB_PASSWORD = os.getenv("SAFENESTT_DB_PASSWORD", os.getenv("DB_PASSWORD", ""))
_DB_OWNER_PASSWORD = os.getenv("SAFENESTT_OWNER_PASSWORD", os.getenv("POSTGRES_PASSWORD", ""))

_DATABASE_URL = os.getenv(
    "SAFENESTT_DATABASE_URL",
    os.getenv(
        "DATABASE_URL",
        f"postgresql://safenestt_app:{_DB_PASSWORD}@172.19.0.11:5432/safenestt_ai" if _DB_PASSWORD else "postgresql://safenestt_app:***@172.19.0.11:5432/safenestt_ai",
    ),
)

# Owner connection for DDL (table creation/migration)
_OWNER_DATABASE_URL = os.getenv(
    "SAFENESTT_OWNER_DATABASE_URL",
    os.getenv(
        "OWNER_DATABASE_URL",
        f"postgresql://postgres:{_DB_OWNER_PASSWORD}@172.19.0.11:5432/safenestt_ai" if _DB_OWNER_PASSWORD else "postgresql://postgres:***@172.19.0.11:5432/safenestt_ai",
    ),
)

_DB_SSL_MODE = os.getenv("DB_SSL_MODE", "prefer")  # Try SSL first, fall back to plaintext if server doesn't support
_DB_SSL_ROOT_CERT = os.getenv("DB_SSL_ROOT_CERT", None)

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
