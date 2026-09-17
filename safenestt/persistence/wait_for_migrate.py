"""Wait for migration to complete before starting API.

This module is used by the API container to wait for the migrate
job to finish. It polls the database for a migration marker table.
"""
from __future__ import annotations

import logging
import time

from safenestt.persistence.engine import create_engine, get_engine
from sqlalchemy import text

logger = logging.getLogger(__name__)


def wait_for_migration(timeout: int = 120) -> bool:
    """Wait for the migrate job to complete.
    
    Polls for the existence of a migration marker table that the
    migrate job creates when it finishes successfully.
    """
    logger.info("Waiting for migration to complete (timeout: %ds)...", timeout)
    
    engine = get_engine()
    if engine is None:
        engine = create_engine()
    
    start = time.time()
    while time.time() - start < timeout:
        try:
            with engine.connect() as conn:
                # Check if migration marker exists
                result = conn.execute(text("""
                    SELECT EXISTS(
                        SELECT FROM information_schema.tables 
                        WHERE table_name = '_migration_complete'
                    )
                """)).scalar()
                if result:
                    logger.info("Migration complete.")
                    return True
        except Exception:
            pass
        
        time.sleep(2)
    
    logger.warning("Migration wait timed out after %ds", timeout)
    return False


if __name__ == "__main__":
    import sys
    sys.exit(0 if wait_for_migration() else 1)
