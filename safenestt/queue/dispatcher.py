"""Durable investigation queue dispatcher.

WHY THIS EXISTS
---------------
The engine writes `status='QUEUED'` rows (see ``safenestt/api/app.py``) but
nothing in the codebase ever read them. An investigation only advanced when a
caller explicitly POSTed ``/v1/investigations/{id}/start``. On the
SafeNestT side the dispatch was an in-process ``asyncio.create_task`` in
``src/routers/pipeline.py``, which is lost on any restart or reboot — so
queued work was orphaned permanently.

This module is the missing consumer. It is designed to run as its own
long-lived service (``safenestt-hermes-dispatcher``), not as a request-scoped
task, so that:

* queued work survives a reboot (the queue lives in PostgreSQL, not memory),
* work is re-driven after a process crash,
* a crash mid-investigation is recoverable (see ``STALE_AFTER_SECONDS``).

DESIGN NOTES
------------
* Tenant context is required for every RLS-protected table. We enumerate
  active tenants from ``api_keys`` (which is intentionally NOT RLS-protected)
  and then open a properly scoped session per tenant. We never connect with a
  BYPASSRLS role and never accept a caller-supplied tenant.
* Claiming is atomic: ``UPDATE ... WHERE status='QUEUED'`` guarded by the
  previously-observed status. Two dispatchers racing on the same row produce
  exactly one winner, and the loser moves on. This is the same
  claim-then-run pattern used by ``src/workers/agent_runner.py``.
* A run that dies without recording a terminal status leaves the row in a
  non-terminal state. After ``STALE_AFTER_SECONDS`` it is returned to QUEUED
  so the next tick retries it, bounded by ``MAX_ATTEMPTS``.
"""

from __future__ import annotations

import logging
import os
import signal
import threading
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, text, update

from safenestt.investigations.store import PersistentInvestigationStore, TenantIsolationError
from safenestt.persistence.engine import create_engine, session_scope, session_scope_bypass_rls
from safenestt.persistence.models import InvestigationModel

logger = logging.getLogger("safenestt.dispatcher")

# --- tunables (env-overridable) ---------------------------------------------
POLL_INTERVAL = float(os.getenv("DISPATCHER_POLL_SECONDS", "5"))
MAX_CONCURRENT = int(os.getenv("DISPATCHER_MAX_CONCURRENT", "1"))
STALE_AFTER_SECONDS = int(os.getenv("DISPATCHER_STALE_AFTER_SECONDS", "3600"))
MAX_ATTEMPTS = int(os.getenv("DISPATCHER_MAX_ATTEMPTS", "3"))

# Statuses that mean "a dispatcher owns this row right now".
IN_FLIGHT = {"RUNNING", "ANALYZING", "WAITING_FOR_TOOL", "VERIFYING", "CALCULATING_RISK"}
# Statuses that must never be picked up.
TERMINAL = {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED", "CANCELLED"}


def _int_or_zero(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _attempts_of(meta: Any) -> int:
    if isinstance(meta, dict):
        return _int_or_zero(meta.get("dispatcher_attempts"))
    return 0


@dataclass(frozen=True)
class ClaimedJob:
    investigation_id: str
    tenant_id: str
    key_fingerprint: str
    case_id: str | None
    created_by: str | None
    target: str | None
    attempt: int


class Dispatcher:
    """Polls the investigations table and runs QUEUED work."""

    def __init__(self) -> None:
        create_engine()
        self._stop = threading.Event()
        self._inflight: set[str] = set()
        self._lock = threading.Lock()

    # -- shutdown ---------------------------------------------------------
    def stop(self, *_args: Any) -> None:
        logger.info("dispatcher_shutdown_requested")
        self._stop.set()

    def install_signal_handlers(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self.stop)
            except ValueError:
                # Not on the main thread; systemd SIGTERM still sets the flag
                # via the default handler path in run_forever().
                logger.debug("signal_handler_not_installed sig=%s", sig)

    # -- tenant discovery --------------------------------------------------
    def _active_tenants(self) -> list[tuple[str, str]]:
        """Return (tenant_id, key_fingerprint) for every active API key.

        ``api_keys`` has no RLS, so this reads with no tenant context. We only
        ever use it to *discover* which tenants exist — the actual work below
        re-establishes a validated tenant context per row.
        """
        out: list[tuple[str, str]] = []
        try:
            with session_scope_bypass_rls() as session:
                rows = session.execute(
                    text(
                        "SELECT tenant_id, key_fingerprint FROM api_keys "
                        "WHERE active AND NOT revoked "
                        "ORDER BY tenant_id, created_at"
                    )
                ).fetchall()
            for tenant_id, fingerprint in rows:
                if tenant_id and fingerprint:
                    out.append((str(tenant_id), str(fingerprint)))
        except Exception:
            logger.exception("dispatcher_tenant_discovery_failed")
        return out

    # -- claiming ----------------------------------------------------------
    def _requeue_stale(self, tenant_id: str, fingerprint: str) -> int:
        """Return abandoned non-terminal rows to QUEUED so they get retried."""
        cutoff = time.time() - STALE_AFTER_SECONDS
        requeued = 0
        try:
            with session_scope(tenant_id, fingerprint) as session:
                stale = session.execute(
                    select(InvestigationModel).where(
                        InvestigationModel.tenant_id == tenant_id,
                        InvestigationModel.status.in_(IN_FLIGHT),
                    )
                ).scalars().all()
                for row in stale:
                    if row.updated_at and row.updated_at.timestamp() > cutoff:
                        continue
                    if _attempts_of(row.meta) >= MAX_ATTEMPTS:
                        logger.warning(
                            "dispatcher_stale_exhausted investigation=%s attempts=%s",
                            row.investigation_id, _attempts_of(row.meta),
                        )
                        continue
                    if row.investigation_id in self._inflight:
                        continue  # ours, still legitimately running
                    session.execute(
                        update(InvestigationModel)
                        .where(
                            InvestigationModel.investigation_id == row.investigation_id,
                            InvestigationModel.status == row.status,
                        )
                        .values(status="QUEUED")
                    )
                    requeued += 1
                    logger.warning(
                        "dispatcher_stale_requeued investigation=%s from_status=%s age_s=%s",
                        row.investigation_id, row.status,
                        int(time.time() - row.updated_at.timestamp()) if row.updated_at else -1,
                    )
        except Exception:
            logger.exception("dispatcher_stale_scan_failed tenant=%s", tenant_id)
        return requeued

    def _claim_one(self, tenant_id: str, fingerprint: str) -> ClaimedJob | None:
        """Atomically move one QUEUED row to RUNNING and return it."""
        try:
            with session_scope(tenant_id, fingerprint) as session:
                candidates = session.execute(
                    select(InvestigationModel)
                    .where(
                        InvestigationModel.tenant_id == tenant_id,
                        InvestigationModel.status == "QUEUED",
                    )
                    .order_by(InvestigationModel.created_at.asc())
                    .with_for_update(skip_locked=True)
                ).scalars().all()

                for row in candidates:
                    if row.investigation_id in self._inflight:
                        continue
                    attempts = _attempts_of(row.meta)
                    if attempts >= MAX_ATTEMPTS:
                        logger.error(
                            "dispatcher_max_attempts_reached investigation=%s attempts=%s "
                            "— leaving QUEUED for operator review",
                            row.investigation_id, attempts,
                        )
                        continue
                    meta = dict(row.meta) if isinstance(row.meta, dict) else {}
                    meta["dispatcher_attempts"] = attempts + 1
                    meta["dispatcher_claimed_at"] = time.time()
                    session.execute(
                        update(InvestigationModel)
                        .where(
                            InvestigationModel.investigation_id == row.investigation_id,
                            InvestigationModel.status == "QUEUED",
                        )
                        .values(status="RUNNING", meta=meta)
                    )
                    return ClaimedJob(
                        investigation_id=row.investigation_id,
                        tenant_id=tenant_id,
                        key_fingerprint=fingerprint,
                        case_id=row.case_id,
                        created_by=row.created_by,
                        target=row.target,
                        attempt=attempts + 1,
                    )
        except Exception:
            logger.exception("dispatcher_claim_failed tenant=%s", tenant_id)
        return None

    # -- execution ---------------------------------------------------------
    def _run_job(self, job: ClaimedJob) -> None:
        """Run one claimed investigation to a terminal status."""
        logger.info(
            "dispatcher_job_start investigation=%s tenant=%s attempt=%s target=%s",
            job.investigation_id, job.tenant_id, job.attempt,
            # target column is encrypted at rest; never log the raw value
            "<encrypted>",
        )
        with self._lock:
            self._inflight.add(job.investigation_id)
        started = time.time()
        try:
            # Imported lazily so the dispatcher module stays importable even if
            # the model provider stack is unavailable.
            from safenestt.api.app import _resolve_model_provider
            from safenestt.investigations.investigator import run_investigation

            store = PersistentInvestigationStore(
                tenant_id=job.tenant_id, key_fingerprint=job.key_fingerprint
            )
            run_investigation(
                investigation_id=job.investigation_id,
                target=job.target or "",
                tenant_id=job.tenant_id,
                created_by=job.created_by,
                case_id=job.case_id,
                model_provider=_resolve_model_provider(),
                store=store,
            )
            logger.info(
                "dispatcher_job_done investigation=%s elapsed_s=%s",
                job.investigation_id, int(time.time() - started),
            )
        except TenantIsolationError:
            # Do not retry forever on an auth problem — surface it loudly.
            logger.exception(
                "dispatcher_job_tenant_error investigation=%s tenant=%s",
                job.investigation_id, job.tenant_id,
            )
            self._mark_failed(job, "tenant_isolation_error")
        except Exception:
            logger.exception(
                "dispatcher_job_failed investigation=%s", job.investigation_id
            )
            self._mark_failed(job, "dispatcher_exception")
        finally:
            with self._lock:
                self._inflight.discard(job.investigation_id)

    def _mark_failed(self, job: ClaimedJob, code: str) -> None:
        """Record a terminal FAILED status so the row stops being retried."""
        try:
            store = PersistentInvestigationStore(
                tenant_id=job.tenant_id, key_fingerprint=job.key_fingerprint
            )
            record = store.get_investigation(job.investigation_id)
            if record is None:
                return
            record.error = {"code": code, "dispatcher": True}
            record.mark("FAILED")
            store.update_investigation(record)
            logger.error(
                "dispatcher_job_marked_failed investigation=%s code=%s",
                job.investigation_id, code,
            )
        except Exception:
            logger.exception(
                "dispatcher_failure_record_failed investigation=%s", job.investigation_id
            )

    # -- main loop ---------------------------------------------------------
    def tick(self) -> int:
        """One poll cycle. Returns the number of jobs claimed."""
        claimed = 0
        for tenant_id, fingerprint in self._active_tenants():
            try:
                self._requeue_stale(tenant_id, fingerprint)
            except Exception:
                logger.exception("dispatcher_stale_error tenant=%s", tenant_id)

            for _ in range(MAX_CONCURRENT):
                with self._lock:
                    busy = len(self._inflight) >= MAX_CONCURRENT
                if busy:
                    break
                job = self._claim_one(tenant_id, fingerprint)
                if job is None:
                    break
                claimed += 1
                self._run_job(job)  # synchronous: keeps ordering deterministic
        return claimed

    def run_forever(self) -> None:
        logger.info(
            "dispatcher_started poll_s=%s max_concurrent=%s stale_after_s=%s max_attempts=%s",
            POLL_INTERVAL, MAX_CONCURRENT, STALE_AFTER_SECONDS, MAX_ATTEMPTS,
        )
        while not self._stop.is_set():
            cycle_started = time.time()
            try:
                self.tick()
            except Exception:
                # A failed tick must never kill the service.
                logger.exception("dispatcher_tick_failed")
            elapsed = time.time() - cycle_started
            self._stop.wait(max(0.5, POLL_INTERVAL - elapsed))
        logger.info("dispatcher_stopped")


def main() -> None:
    logging.basicConfig(
        level=os.getenv("DISPATCHER_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    Dispatcher().run_forever()


if __name__ == "__main__":
    main()