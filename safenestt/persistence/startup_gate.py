"""Authoritative startup security gate.

ONE mechanism for the pre-traffic security contract, used by every supported
production startup path (docker-compose, systemd, start-engine.sh):

    DATABASE MIGRATION        (privileged, one-shot, separate step)
        ↓
    SECURITY/READINESS VERIFY  (this module — read-only, least privilege)
        ↓
    APPLICATION START
        ↓
    TRAFFIC

WHY A PRE-START GATE
--------------------
Starting the app and then checking readiness leaves a window in which the
process is accepting traffic before the security prerequisite is known. This
gate runs BEFORE the listener is opened and exits non-zero on failure, so the
supervisor refuses to start the application at all.

CREDENTIAL MODEL
----------------
`--verify` needs only the APPLICATION credentials and performs no writes.
`--migrate` additionally requires owner credentials, which belong exclusively
to the privileged migration step and must never be present in the long-running
API environment. This module never reads, logs or copies a password, and
never prints a connection string.

EXIT CODES
----------
  0  gate satisfied (or migration completed and verified)
  1  gate NOT satisfied — do not serve traffic
  2  usage / configuration error

USAGE
-----
    python -m safenestt.persistence.startup_gate --verify
    python -m safenestt.persistence.startup_gate --migrate   # privileged step
    python -m safenestt.persistence.startup_gate --verify --quiet
"""
from __future__ import annotations

import argparse
import logging
import sys

logger = logging.getLogger(__name__)


def _configure_logging(quiet: bool) -> None:
    logging.basicConfig(
        level=logging.WARNING if quiet else logging.INFO,
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
    )


def _run_migration() -> int:
    """Privileged step. Requires owner credentials in the environment."""
    from safenestt.persistence.migrate import main as migrate_main

    logger.info("startup_gate: running database migration (privileged step)")
    rc = migrate_main()
    if rc != 0:
        logger.error("startup_gate: migration FAILED — refusing to continue")
        return 1
    logger.info("startup_gate: migration completed")
    return 0


def _run_verify() -> int:
    """Read-only security verification on the application credentials."""
    from safenestt.persistence.engine import create_engine
    from safenestt.persistence.readiness import check_readiness

    try:
        engine = create_engine()
    except Exception as exc:
        # Do not echo the exception verbatim: connection errors can embed
        # host/database names.
        logger.error(
            "startup_gate: could not initialise the database engine (%s)",
            type(exc).__name__,
        )
        return 1

    result = check_readiness(engine)

    if result.ready:
        logger.info(
            "startup_gate: PASS (%d/%d checks) — safe to serve traffic",
            sum(1 for v in result.checks.values() if v), len(result.checks),
        )
        return 0

    logger.error(
        "startup_gate: FAIL — %d unmet prerequisite(s); refusing to serve "
        "traffic:", len(result.failures),
    )
    # Detail goes to stderr logs only, never to stdout and never to an
    # unauthenticated HTTP surface.
    for detail in result.failures:
        logger.error("  - %s", detail)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="startup_gate",
        description="Pre-start database security gate for the SENTRA engine.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--verify", action="store_true",
        help="Verify the required database security state (read-only).")
    group.add_argument(
        "--migrate", action="store_true",
        help="Run the privileged migration, then verify. Requires owner "
             "credentials; must not run in the API environment.")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress INFO logs (failures are always logged).")
    args = parser.parse_args(argv)

    _configure_logging(args.quiet)

    if args.migrate:
        rc = _run_migration()
        if rc != 0:
            return rc
        # A successful migration must still be verified, not assumed.
    return _run_verify()


if __name__ == "__main__":
    sys.exit(main())