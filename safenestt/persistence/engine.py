from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Generator

import sqlalchemy as _sqlalchemy
from sqlalchemy import create_engine as _create_engine, Engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from safenestt.persistence.rls import set_tenant_context, clear_tenant_context
from safenestt.security.secrets import get_secret

logger = logging.getLogger(__name__)

_DB_HOST = os.getenv("DB_HOST", "172.19.0.11")
_DB_PORT = os.getenv("DB_PORT", "5432")
_DB_NAME = os.getenv("DB_NAME", "safenestt_ai")


def _get_db_password() -> str:
    return get_secret("SAFENESTT_DB_PASSWORD") or os.getenv("DB_PASSWORD", "safenestt_app_pass")


def _build_database_url() -> str:
    return os.getenv(
        "SAFENESTT_DATABASE_URL",
        os.getenv(
            "DATABASE_URL",
            f"postgresql://safenestt_app:{_get_db_password()}@{_DB_HOST}:{_DB_PORT}/{_DB_NAME}",
        ),
    )


_engine: Engine | None = None
_sessionmaker: sessionmaker[Session] | None = None
_owner_engine: Engine | None = None


def _get_ssl_mode() -> str:
    return os.getenv("DB_SSL_MODE", "verify-full")


def _get_ssl_root_cert() -> str | None:
    default = os.path.join(os.path.dirname(__file__), "..", "..", "certs", "ca.crt")
    return os.getenv("DB_SSL_ROOT_CERT", default)


def _build_engine(url: str, **kwargs) -> Engine:
    connect_args = {}
    if "connect_args" in kwargs:
        connect_args = kwargs.pop("connect_args") or {}
    
    if "postgresql" in url:
        connect_args["sslmode"] = _get_ssl_mode()
        ssl_root_cert = _get_ssl_root_cert()
        if ssl_root_cert and os.path.exists(ssl_root_cert):
            connect_args["sslrootcert"] = ssl_root_cert
        if os.getenv("DB_SSL_CLIENT_CERT"):
            connect_args["sslcert"] = os.getenv("DB_SSL_CLIENT_CERT")
        if os.getenv("DB_SSL_CLIENT_KEY"):
            connect_args["sslkey"] = os.getenv("DB_SSL_CLIENT_KEY")
    
    return _create_engine(url, connect_args=connect_args, **kwargs)


def create_engine(url: str | None = None, **kwargs) -> Engine:
    global _engine, _sessionmaker
    actual_url = url or _build_database_url()
    _engine = _build_engine(actual_url, **kwargs)
    _sessionmaker = sessionmaker(bind=_engine)
    return _engine


def get_engine() -> Engine | None:
    return _engine


def get_sessionmaker() -> sessionmaker[Session] | None:
    return _sessionmaker


def _build_owner_database_url() -> str:
    """Owner credentials. No defaults — must be explicitly provided."""
    owner_url = os.getenv("SAFENESTT_OWNER_DATABASE_URL") or os.getenv("OWNER_DATABASE_URL")
    if owner_url:
        return owner_url
    
    owner_password = get_secret("SAFENESTT_OWNER_PASSWORD") or os.getenv("POSTGRES_PASSWORD")
    if not owner_password:
        raise RuntimeError(
            "Owner credentials not configured. Set SAFENESTT_OWNER_DATABASE_URL "
            "or SAFENESTT_OWNER_PASSWORD + POSTGRES_PASSWORD."
        )
    
    return f"postgresql://postgres:{owner_password}@{_DB_HOST}:{_DB_PORT}/{_DB_NAME}"


def get_owner_engine() -> Engine:
    global _owner_engine
    if _owner_engine is None:
        _owner_engine = _build_engine(_build_owner_database_url())
    return _owner_engine


@contextmanager
def session_scope(tenant_id: str | None = None, key_fingerprint: str | None = None) -> Generator[Session, None, None]:
    """Provide a transactional scope with RLS tenant context.
    
    Tenant context is established via the SECURITY DEFINER function
    establish_tenant_context(tenant_id, key_fingerprint). The app role
    cannot bypass this because:
    1. _tenant_context table has REVOKE ALL from app role
    2. The SECURITY DEFINER function verifies the fingerprint matches
       an active key in the database (prevents impersonation)
    3. pg_backend_pid() cannot be forged by the app
    """
    if _sessionmaker is None:
        create_engine()
    if _sessionmaker is None:
        raise RuntimeError("Session maker not initialized. Call create_engine() first.")
    session = _sessionmaker()
    try:
        if tenant_id and key_fingerprint:
            set_tenant_context(session.connection(), tenant_id, key_fingerprint)
        else:
            clear_tenant_context(session.connection())
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def session_scope_bypass_rls() -> Generator[Session, None, None]:
    """Scope without RLS filtering (for admin tasks only)."""
    if _sessionmaker is None:
        raise RuntimeError("Session maker not initialized.")
    session = _sessionmaker()
    try:
        clear_tenant_context(session.connection())
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


_DB_SSL_MODE = "verify-full"
_DB_SSL_ROOT_CERT = os.path.join(os.path.dirname(__file__), "..", "..", "certs", "ca.crt")
