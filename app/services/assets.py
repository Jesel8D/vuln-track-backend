import hashlib
import json
from uuid import UUID, uuid4

from sqlalchemy import func, select, true
from sqlalchemy.exc import IntegrityError

from app.core.errors import APIError
from app.models.database_v1 import Asset, RegistrationRequest
from app.schemas.assets import AssetCreate, AssetList, AssetRead, Page


def request_fingerprint(payload: AssetCreate) -> str:
    canonical = json.dumps(
        {"version": 1, "method": "POST", "route": "/assets", "body": payload.model_dump()},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AssetService:
    def __init__(self, session_factory, authorization):
        self.session_factory = session_factory
        self.authorization = authorization

    def _visible(self, user_id):
        return self.authorization.visible_assets(user_id)

    def register(self, user_id: UUID, key: UUID, payload: AssetCreate) -> dict:
        self.authorization.require_create(user_id)
        fingerprint = request_fingerprint(payload)
        identity = (user_id, "POST", "/assets", key)
        with self.session_factory() as session:
            try:
                with session.begin():
                    previous = session.get(RegistrationRequest, identity)
                    if previous:
                        return self._replay(session, user_id, previous, fingerprint)
                    asset = Asset(id=uuid4(), created_by=user_id, **payload.model_dump())
                    session.add(asset)
                    session.flush()
                    body = AssetRead.model_validate(asset).model_dump(mode="json")
                    session.add(
                        RegistrationRequest(
                            user_id=user_id,
                            method="POST",
                            route="/assets",
                            idempotency_key=key,
                            request_hash=fingerprint,
                            asset_id=asset.id,
                            response_status=201,
                            response_body=body,
                        )
                    )
                    session.flush()
                return body
            except IntegrityError as exc:
                # The losing transaction (including its asset) has been rolled back.
                if (
                    getattr(exc.orig, "sqlstate", None) != "23505"
                    or getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
                    != "asset_registration_requests_pkey"
                ):
                    raise
                with session.begin():
                    previous = session.get(RegistrationRequest, identity)
                    if previous is None:
                        raise APIError(
                            409, "RETRY_REQUEST", "Reintentar la misma solicitud"
                        ) from None
                    return self._replay(session, user_id, previous, fingerprint)

    def _replay(self, session, user_id, previous, fingerprint):
        visible = session.scalar(
            select(Asset.id).where(Asset.id == previous.asset_id, self._visible(user_id))
        )
        if visible is None:
            raise APIError(404, "ASSET_NOT_FOUND", "Activo no encontrado")
        if previous.request_hash != fingerprint:
            raise APIError(409, "IDEMPOTENCY_CONFLICT", "Clave utilizada con otros datos")
        if previous.expires_at <= session.scalar(select(func.statement_timestamp())):
            raise APIError(409, "IDEMPOTENCY_EXPIRED", "Clave expirada; requiere reconciliación")
        return previous.response_body

    def get(self, user_id: UUID, asset_id: UUID) -> AssetRead:
        with self.session_factory() as session:
            asset = session.scalar(
                select(Asset).where(Asset.id == asset_id, self._visible(user_id))
            )
            if asset is None:
                raise APIError(404, "ASSET_NOT_FOUND", "Activo no encontrado")
            return AssetRead.model_validate(asset)

    def list(self, user_id: UUID, limit: int, offset: int) -> AssetList:
        self.authorization.require_list(user_id)
        with self.session_factory() as session, session.begin():
            # A single statement includes the authorized total, even for an empty page.
            visible = select(Asset).where(self._visible(user_id)).cte("visible")
            page = (
                select(visible)
                .order_by(visible.c.created_at, visible.c.id)
                .limit(limit)
                .offset(offset)
                .cte("page")
            )
            total = select(func.count().label("total")).select_from(visible).cte("total")
            rows = (
                session.execute(
                    select(page, total.c.total)
                    .select_from(total.outerjoin(page, true()))
                    .order_by(page.c.created_at, page.c.id)
                )
                .mappings()
                .all()
            )
            return AssetList(
                items=[
                    AssetRead.model_validate(
                        {field: row[field] for field in AssetRead.model_fields}
                    )
                    for row in rows
                    if row["id"]
                ],
                page=Page(limit=limit, offset=offset, total=rows[0]["total"]),
            )
