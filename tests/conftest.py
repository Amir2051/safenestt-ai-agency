from __future__ import annotations

import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import safenestt  # noqa: E402
import safenestt.security.permissions as _permissions_mod  # noqa: E402

import pytest
from safenestt.persistence.engine import create_engine, get_owner_engine
from safenestt.security.secrets import clear_cache

os.environ["SAFENESTT_DB_PASSWORD"] = "safenestt_app_pass"
os.environ["SAFENESTT_OWNER_PASSWORD"] = "postgres"
os.environ["DB_SSL_MODE"] = "prefer"

try:
    create_engine()
    print("[conftest] DB engine initialized", file=sys.stderr)
except Exception as exc:
    print(f"[conftest] DB engine init failed: {exc}", file=sys.stderr)


@pytest.fixture(autouse=True)
def _clean_test_db():
    """Clean test data before each test.
    
    CRITICAL: Uses OWNER engine for schema setup AND truncation because
    the app role cannot truncate tables it doesn't own.
    The app engine is only used for actual test operations (via session_scope).
    """
    from safenestt.persistence.models import Base
    from sqlalchemy import text, inspect as sa_inspect
    
    # Use owner engine for ALL setup and cleanup operations
    owner_engine = get_owner_engine()
    
    # Create schema
    Base.metadata.create_all(owner_engine)
    
    # Apply RLS policies
    try:
        from safenestt.persistence.rls import apply_rls_policies
        apply_rls_policies(owner_engine)
    except Exception:
        pass
    
    # Truncate ALL tables using OWNER engine (app role can't truncate)
    with owner_engine.connect() as conn:
        inspector = sa_inspect(owner_engine)
        existing_tables = inspector.get_table_names()
        for table in reversed(Base.metadata.sorted_tables):
            if table.name in existing_tables:
                # Use owner engine for truncation (bypasses RLS)
                conn.execute(text(f"TRUNCATE TABLE {table.name} CASCADE"))
        conn.commit()
    
    yield


print("[conftest] safenestt:", safenestt.__file__, file=sys.stderr)
print("[conftest] permissions:", _permissions_mod.__file__, file=sys.stderr)
