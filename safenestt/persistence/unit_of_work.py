from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import text
from sqlalchemy.orm import Session

from safenestt.persistence.engine import get_engine, get_sessionmaker


def init_db(engine=None) -> None:
    if engine is None:
        engine = get_engine()
    if engine is None:
        raise RuntimeError("No database engine available. Call create_engine() first.")
    from safenestt.persistence.models import Base
    Base.metadata.create_all(engine)


def drop_all(engine=None) -> None:
    if engine is None:
        engine = get_engine()
    if engine is None:
        raise RuntimeError("No database engine available. Call create_engine() first.")
    from safenestt.persistence.models import Base
    Base.metadata.drop_all(engine)


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    sm = get_sessionmaker()
    if sm is None:
        raise RuntimeError("Session maker not initialized. Call create_engine() first.")
    session = sm()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def schema_exists() -> bool:
    engine = get_engine()
    if engine is None:
        return False
    with engine.connect() as conn:
        result = conn.execute(text("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'"))
        count = result.scalar()
        return bool(count and count > 0)


def table_count() -> dict[str, int]:
    engine = get_engine()
    if engine is None:
        return {}
    with engine.connect() as conn:
        tables = conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")).scalars().all()
        counts = {}
        for t in tables:
            c = conn.execute(text(f"SELECT COUNT(*) FROM \"{t}\"")).scalar()
            counts[t] = c
        return counts