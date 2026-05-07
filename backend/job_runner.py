"""Background job runner for async scan execution.

The Flask /start-scan endpoint creates a pending DB row, returns 202 with
the scan_id immediately, then calls submit_scan() to run the pipeline in a
thread pool.  The frontend polls /scan-status/<scan_id> until the job
reaches status 'completed' or 'failed', at which point it fetches the full
result via /scan/<scan_id>.

Thread pool sizing:
  max_workers=3  — allows up to 3 simultaneous scans.  Each scan holds
  at least one subprocess (nmap) so keeping the pool small prevents the
  system from spawning too many concurrent child processes.
"""

import logging
from concurrent.futures import ThreadPoolExecutor

from backend import db_service

LOGGER = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="scan_worker")


def submit_scan(scan_id: int, target: str, mode: str) -> None:
    """Queue a scan job in the background thread pool.

    Returns immediately; the scan runs asynchronously.
    """
    _executor.submit(_run_scan_job, scan_id, target, mode)
    LOGGER.info("Scan job %d queued: target=%s mode=%s", scan_id, target, mode)


def _run_scan_job(scan_id: int, target: str, mode: str) -> None:
    """Execute the full scan pipeline in a worker thread.

    Progress signals are written to the DB at key checkpoints so the
    frontend's polling loop can show a meaningful status string.
    """
    try:
        db_service.update_scan_status(scan_id, "running", f"Starting scan for {target}…")
        LOGGER.info("Scan job %d started: target=%s mode=%s", scan_id, target, mode)

        # Lazy import avoids a circular import at module load time
        from backend.scan_service import perform_scan

        result = perform_scan(target=target, mode=mode, scan_id=scan_id)

        # perform_scan returns the finalised result dict; status is already
        # set to 'completed' inside save_scan(), but set it explicitly here
        # as well so the polling endpoint always sees a definitive terminal state.
        db_service.update_scan_status(scan_id, "completed", "Scan complete")
        LOGGER.info("Scan job %d completed: target=%s scan_id=%s", scan_id, target, result.get("scan_id"))

    except Exception as exc:
        LOGGER.exception("Scan job %d failed: %s", scan_id, exc)
        db_service.update_scan_status(scan_id, "failed", f"Scan failed: {exc}")
