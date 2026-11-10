import hashlib
import json
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import func, select

from app.core.errors import APIError
from app.models.cpe import CPEIdentification
from app.models.database_v1 import AnalysisRun as Run
from app.models.database_v1 import Finding
from app.schemas.analyses import Accepted, AnalysisList, AnalysisRead, FindingList, FindingRead
from app.schemas.assets import Page
from app.services.applicability import specific_cpe
from app.services.cpe import IdentificationService


class AnalysisService:
    def __init__(self, session_factory, authorization):
        self.session_factory = session_factory
        self.authorization = authorization
        self.worker_ready = lambda: True
        self.identifications = IdentificationService(session_factory, authorization, None)

    def accept(self, actor, asset_id, key, payload):
        digest = hashlib.sha256(
            json.dumps(
                {
                    "v": 1,
                    "method": "POST",
                    "route": f"/api/v1/assets/{asset_id}/analyses",
                    "body": payload.model_dump(mode="json"),
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        with self.session_factory.begin() as session:
            self.identifications._asset(session, actor, asset_id, lock=True)
            old = session.scalar(
                select(Run).where(
                    Run.asset_id == asset_id, Run.initiated_by == actor, Run.idempotency_key == key
                )
            )
            if old:
                if old.request_hash != digest:
                    raise APIError(409, "IDEMPOTENCY_CONFLICT", "Clave utilizada con otros datos")
                return Accepted(id=old.id, accepted_at=old.created_at)
            if not self.worker_ready():
                raise APIError(503, "CVE_WORKER_UNAVAILABLE", "Procesador CVE no disponible")
            ident = session.scalar(
                select(CPEIdentification).where(
                    CPEIdentification.id == payload.identification_id,
                    CPEIdentification.asset_id == asset_id,
                    CPEIdentification.valid_to.is_(None),
                    CPEIdentification.state == "confirmed",
                )
            )
            if ident is None:
                raise APIError(
                    409, "IDENTIFICATION_REQUIRED", "Se requiere identificación actual confirmada"
                )
            if ident.observed_version is None:
                raise APIError(409, "VERSION_REQUIRED", "Se requiere versión observada")
            if not specific_cpe(ident.cpe_name, ident.observed_version):
                raise APIError(
                    409, "IDENTIFICATION_INCOMPLETE", "CPE insuficiente para consulta específica"
                )
            if session.scalar(
                select(Run.id).where(
                    Run.asset_id == asset_id, Run.status.in_(["queued", "running"])
                )
            ):
                raise APIError(409, "ANALYSIS_IN_PROGRESS", "Ya existe una consulta en curso")
            now = session.scalar(select(func.clock_timestamp()))
            if session.scalar(
                select(Run.id).where(
                    Run.asset_id == asset_id, Run.created_at > now - timedelta(seconds=60)
                )
            ):
                raise APIError(429, "ANALYSIS_RATE_LIMIT", "Esperar antes de crear otra consulta")
            run = Run(
                id=uuid4(),
                asset_id=asset_id,
                initiated_by=actor,
                identification_id=ident.id,
                selected_cpe=ident.cpe_name,
                observed_version=ident.observed_version,
                idempotency_key=key,
                request_hash=digest,
                query_parameters={
                    "cpeName": ident.cpe_name,
                    "resultsPerPage": 100,
                    "max_pages": 5,
                    "max_seconds": 300,
                    "max_retries": 2,
                },
            )
            session.add(run)
            session.flush()
            return Accepted(id=run.id, accepted_at=run.created_at)

    def _run(self, session, actor, asset_id, run_id, lock=False):
        self.identifications._asset(session, actor, asset_id)
        stmt = select(Run).where(Run.id == run_id, Run.asset_id == asset_id)
        run = session.scalar(stmt.with_for_update() if lock else stmt)
        if run is None:
            raise APIError(404, "ANALYSIS_NOT_FOUND", "Consulta no encontrada")
        return run

    def get(self, actor, asset_id, run_id):
        with self.session_factory() as session:
            return AnalysisRead.model_validate(self._run(session, actor, asset_id, run_id))

    def list(self, actor, asset_id, limit, offset):
        with self.session_factory.begin() as session:
            self.identifications._asset(session, actor, asset_id, lock=True)
            query = select(Run).where(Run.asset_id == asset_id)
            total = session.scalar(select(func.count()).select_from(query.subquery()))
            runs = session.scalars(
                query.order_by(Run.created_at.desc(), Run.id).limit(limit).offset(offset)
            )
            return AnalysisList(
                items=[AnalysisRead.model_validate(r) for r in runs],
                page=Page(limit=limit, offset=offset, total=total),
            )

    def findings(self, actor, asset_id, run_id, limit, offset):
        with self.session_factory.begin() as session:
            # Lock the run briefly for a coherent page/progress snapshot, never network.
            run = self._run(session, actor, asset_id, run_id, lock=True)
            query = select(Finding).where(Finding.analysis_id == run.id)
            total = session.scalar(select(func.count()).select_from(query.subquery()))
            rows = session.scalars(
                query.order_by(Finding.external_id, Finding.id).limit(limit).offset(offset)
            )
            return FindingList(
                items=[FindingRead.model_validate(f) for f in rows],
                page=Page(limit=limit, offset=offset, total=total),
                run_status=run.status,
                coverage=run.coverage,
            )

    def _finding(self, session, actor, finding_id, lock=False):
        from app.models.database_v1 import Asset

        query = (
            select(Finding)
            .join(Run, Finding.analysis_id == Run.id)
            .join(Asset, Run.asset_id == Asset.id)
            .where(Finding.id == finding_id, self.authorization.visible_assets(actor))
        )
        row = session.scalar(query.with_for_update(of=Finding) if lock else query)
        if row is None:
            raise APIError(404, "FINDING_NOT_FOUND", "Hallazgo no encontrado")
        return row

    def finding(self, actor, finding_id):
        with self.session_factory() as session:
            return FindingRead.model_validate(self._finding(session, actor, finding_id))

    def review(self, actor, finding_id, payload):
        with self.session_factory.begin() as session:
            row = self._finding(session, actor, finding_id, lock=True)
            run = session.get(Run, row.analysis_id)
            if (
                row.status != "open"
                or row.updated_at != payload.expected_updated_at
                or row.evidence is None
                or run.status not in {"completed", "failed"}
            ):
                raise APIError(
                    409,
                    "REVIEW_CONFLICT",
                    "Revisión no disponible o modificada; consultar hallazgo",
                )
            row.status = "reviewed"
            row.applicability = payload.applicability
            row.reviewed_by = actor
            row.reviewed_at = session.scalar(select(func.clock_timestamp()))
            row.review_reason = payload.reason
            row.review_evidence = payload.evidence
            session.flush()
            session.refresh(row)
            return FindingRead.model_validate(row)
