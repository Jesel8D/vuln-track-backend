"""Single-process SQL queue. Durable acceptance/page commits; no broker or RAM queue."""

import hashlib
import logging
import time
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from uuid import uuid4

from sqlalchemy import func, select, text

from app.core.errors import APIError
from app.models.database_v1 import AnalysisRun as Run
from app.models.database_v1 import Finding, User
from app.services.applicability import encoded, evidence_for

logger = logging.getLogger("vulntrack.cve")
LOCK_ID = 618326104917004  # session advisory lock, same database only


class Interrupted(Exception):
    pass


class CVEWorker:
    def __init__(self, engine, session_factory, client, *, clock=time.monotonic):
        self.engine = engine
        self.sessions = session_factory
        self.client = client
        self.clock = clock
        self.stop = Event()
        self.thread = None
        self.available = False
        self.max_pages = 5
        self.page_size = 100
        self.max_seconds = 300

    def start(self):
        self.thread = Thread(target=self._loop, name="vulntrack-cve", daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=45)
            if self.thread.is_alive():
                raise RuntimeError("CVE worker failed to stop within bounded timeout")

    def _loop(self):
        # A reserved AUTOCOMMIT connection holds only a session advisory lock; no
        # row locks or idle transactions are held while awaiting NVD.
        try:
            with self.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as lock:
                if not lock.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": LOCK_ID}):
                    logger.error("worker_single_instance_lock_unavailable")
                    return
                try:
                    self.recover()
                    # Conservative restart cooldown, including CPE calls from this process.
                    self.restore_cooldown()
                    self.available = True
                    while not self.stop.is_set():
                        # Verify the lock connection is alive before claiming another task.
                        lock.execute(text("SELECT 1"))
                        if not self.process_next():
                            self.stop.wait(1)
                finally:
                    self.available = False
                    # Close session even if connection failed; never pool a live advisory lock.
                    lock.invalidate()
        except Exception as exc:
            self.available = False
            logger.error("worker_stopped type=%s", type(exc).__name__)

    def restore_cooldown(self):
        # CVE Retry-After survives a normal restart, without a distributed quota service.
        with self.sessions() as session:
            until = session.scalar(select(func.max(Run.nvd_cooldown_until)))
        seconds = max(60, (until - datetime.now(UTC)).total_seconds()) if until else 60
        self.client.quota.backoff(str(seconds))

    def recover(self):
        # Called only after exclusive process lock acquisition in production.
        with self.sessions.begin() as session:
            rows = session.scalars(
                select(Run)
                .where(Run.status == "running", Run.identification_id.is_not(None))
                .with_for_update()
            )
            for row in rows:
                self._finish_row(session, row, "INTERRUPTED")

    @staticmethod
    def _finish_row(session, row, failure=None):
        row.completed_at = session.scalar(select(func.clock_timestamp()))
        row.failure_code = failure
        if row.page_count:
            row.status = "completed"
            row.coverage = "partial" if failure or row.warning_codes else "complete"
            if failure:
                row.warning_codes = list(dict.fromkeys([*row.warning_codes, failure]))[:20]
        else:
            row.status = "failed"
            row.coverage = None
            row.failure_code = failure or "PROCESSING_ERROR"

    def _finish(self, run_id, failure=None):
        with self.sessions.begin() as session:
            row = session.scalar(select(Run).where(Run.id == run_id).with_for_update())
            if row.status == "running":
                if failure in {"NVD_THROTTLED", "NVD_UNAVAILABLE"}:
                    seconds = self.client.quota.wait_seconds()
                    now = datetime.now(UTC)
                    maximum = datetime.max.replace(tzinfo=UTC)
                    row.nvd_cooldown_until = (
                        maximum
                        if seconds >= (maximum - now).total_seconds() - 1
                        else now + timedelta(seconds=seconds)
                    )
                self._finish_row(session, row, failure)

    def _wait(self, seconds, deadline):
        if self.stop.is_set():
            raise Interrupted()
        left = deadline - self.clock()
        if left <= 0 or seconds >= left:
            raise APIError(503, "TIME_BUDGET_REACHED", "Presupuesto de ejecución agotado")
        if seconds > 0 and self.stop.wait(seconds):
            raise Interrupted()

    def process_next(self):
        with self.sessions.begin() as session:
            row = session.scalar(
                select(Run)
                .where(Run.status == "queued", Run.identification_id.is_not(None))
                .order_by(Run.created_at, Run.id)
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            if row is None:
                return False
            row.status = "running"
            row.started_at = session.scalar(select(func.clock_timestamp()))
            run_id, cpe, observed = row.id, row.selected_cpe, row.observed_version
            actor = session.get(User, row.initiated_by)
            inactive = actor is None or not actor.active
        if inactive:
            self._finish(run_id, "ACTOR_INACTIVE")
            return True
        deadline = self.clock() + self.max_seconds
        try:
            while True:
                with self.sessions() as session:
                    row = session.get(Run, run_id)
                    start, page_count = row.next_index, row.page_count
                    active = session.scalar(select(User.active).where(User.id == row.initiated_by))
                if not active:
                    raise APIError(503, "ACTOR_INACTIVE", "Usuario no activo")
                if page_count >= self.max_pages:
                    self._finish(run_id, "PAGE_BUDGET_REACHED")
                    break
                page = None
                for attempt in range(3):
                    self._wait(self.client.quota.wait_seconds(), deadline)
                    try:
                        page = self.client.page(cpe, start, self.page_size)
                        break
                    except APIError as exc:
                        if exc.code == "NVD_RATE_LIMIT":
                            # Another CPE request took the slot. No extra upstream call.
                            self._wait(self.client.quota.wait_seconds(), deadline)
                        elif exc.code not in {"NVD_TIMEOUT", "NVD_UNAVAILABLE"} or attempt == 2:
                            raise
                        if attempt == 2:
                            raise
                        with self.sessions.begin() as session:
                            run = session.get(Run, run_id)
                            run.retry_count += 1
                        self._wait(2 ** (attempt + 1), deadline)
                if page is None:
                    raise APIError(503, "NVD_UNAVAILABLE", "NVD no disponible")
                # Finishing beyond deadline cannot claim total coverage, even for one page.
                if self.clock() >= deadline:
                    raise APIError(503, "TIME_BUDGET_REACHED", "Presupuesto agotado")
                done, uncertain = self._persist_page(run_id, page, cpe, observed)
                if done or uncertain:
                    self._finish(run_id)
                    break
        except Interrupted:
            self._finish(run_id, "INTERRUPTED")
        except APIError as exc:
            self._finish(run_id, exc.code)
            logger.warning("analysis_external_failure run_id=%s code=%s", run_id, exc.code)
        except Exception as exc:
            # Previous page transactions survive; current page is rolled back.
            self._finish(run_id, "PROCESSING_ERROR")
            logger.error(
                "analysis_processing_failure run_id=%s type=%s constraint=%s",
                run_id,
                type(exc).__name__,
                getattr(getattr(getattr(exc, "orig", None), "diag", None), "constraint_name", None),
            )
        return True

    def _persist_page(self, run_id, page, cpe, observed):
        with self.sessions.begin() as session:
            row = session.scalar(select(Run).where(Run.id == run_id).with_for_update())
            if row.status != "running" or page.startIndex != row.next_index:
                raise RuntimeError("Worker page position changed")
            warnings = set(row.warning_codes)
            if row.total_results is not None and row.total_results != page.totalResults:
                warnings.add("TOTAL_CHANGED")
            existing = {
                f.external_id: f
                for f in session.scalars(select(Finding).where(Finding.analysis_id == run_id))
            }
            ids, dates = [], []
            for entry in page.vulnerabilities:
                record = entry.cve.model_dump(mode="json", exclude_none=True)
                external_id = record["id"]
                ids.append(external_id)
                dates.append(record["published"])
                if external_id in existing:
                    warnings.add("DUPLICATE_CVE")
                    if (
                        existing[external_id].evidence["source_record_sha256"]
                        != hashlib.sha256(encoded(record)).hexdigest()
                    ):
                        warnings.add("CVE_CHANGED")
                    continue
                applicability, evidence = evidence_for(cpe, observed, record)
                if evidence["truncated"]:
                    warnings.add("EVIDENCE_BUDGET_REACHED")
                descriptions = record.get("descriptions", [])
                title = next(
                    (
                        d.get("value")
                        for d in descriptions
                        if d.get("lang") == "en" and isinstance(d.get("value"), str)
                    ),
                    None,
                )
                # Title is only a bounded convenience, original descriptions are evidence.
                title = " ".join(title.split())[:500].strip() if title else None
                metrics = record.get("metrics") or None
                if metrics and len(encoded(metrics)) > 24000:
                    raise APIError(502, "NVD_METRICS_TOO_LARGE", "Métricas NVD exceden presupuesto")
                finding = Finding(
                    id=uuid4(),
                    analysis_id=run_id,
                    external_id=external_id,
                    title=title or None,
                    applicability=applicability,
                    evidence=evidence,
                    cvss=metrics,
                )
                session.add(finding)
                existing[external_id] = finding
            if dates:
                parsed = [
                    datetime.fromisoformat(d.replace("Z", "+00:00")).replace(tzinfo=UTC)
                    for d in dates
                ]
                previous = (
                    row.page_manifest[-1].get("last_published") if row.page_manifest else None
                )
                if (
                    parsed != sorted(parsed)
                    or previous
                    and parsed[0] < datetime.fromisoformat(previous)
                ):
                    warnings.add("ORDER_CHANGED")
            manifest = {
                "start_index": page.startIndex,
                "count": len(ids),
                "total": page.totalResults,
                "ids_sha256": hashlib.sha256(encoded(ids)).hexdigest(),
                "timestamp": page.timestamp.isoformat(),
                "last_published": parsed[-1].isoformat() if dates else None,
            }
            row.total_results = page.totalResults
            row.retrieved_count += len(ids)
            row.stored_count = len(existing)
            row.next_index += len(ids)
            row.page_count += 1
            row.source_timestamp = page.timestamp
            row.source_timestamps = [*row.source_timestamps, page.timestamp.isoformat()]
            row.page_manifest = [*row.page_manifest, manifest]
            row.warning_codes = sorted(warnings)[:20]
            session.flush()
            done = row.next_index >= page.totalResults
            return done, bool(warnings)
