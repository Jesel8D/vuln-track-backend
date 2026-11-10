import hashlib
import json
from typing import Literal
from uuid import uuid4

from sqlalchemy import func, select

from app.core.errors import APIError
from app.models.cpe import CPEIdentification as Event
from app.models.database_v1 import Asset
from app.schemas.assets import Page
from app.schemas.cpe import (
    Confirm,
    EventRead,
    HistoryEvent,
    IdentificationList,
    parse_cpe,
    unbind_component,
)


def fingerprint(asset_id, payload):
    data = {
        "version": 1,
        "method": "POST",
        "route": f"/api/v1/assets/{asset_id}/cpe-identifications",
        "body": payload.model_dump(mode="json"),
    }
    return hashlib.sha256(
        json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


class IdentificationService:
    def __init__(self, session_factory, authorization, nvd):
        self.session_factory = session_factory
        self.authorization = authorization
        self.nvd = nvd

    def _asset(self, session, actor, asset_id, lock=False):
        query = select(Asset).where(
            Asset.id == asset_id,
            self.authorization.visible_assets(actor),
        )
        asset = session.scalar(query.with_for_update() if lock else query)
        if asset is None:
            raise APIError(404, "ASSET_NOT_FOUND", "Activo no encontrado")
        return asset

    @staticmethod
    def _current(session, asset_id):
        return session.scalar(
            select(Event).where(Event.asset_id == asset_id, Event.valid_to.is_(None))
        )

    @staticmethod
    def _replay(session, actor, asset_id, key, digest):
        event = session.scalar(
            select(Event).where(
                Event.asset_id == asset_id,
                Event.recorded_by == actor,
                Event.idempotency_key == key,
            )
        )
        if event:
            if event.request_hash != digest:
                raise APIError(409, "IDEMPOTENCY_CONFLICT", "Clave utilizada con otros datos")
            return EventRead.model_validate(event).model_dump(mode="json")

    @staticmethod
    def _expected(current, payload):
        if (current.id if current else None) != payload.expected_current_id:
            raise APIError(409, "CURRENT_IDENTIFICATION_CHANGED", "La identificación actual cambió")
        if payload.state == "needs_review" and (not current or current.state != "confirmed"):
            raise APIError(409, "INVALID_TRANSITION", "Se requiere una identificación confirmada")

    @staticmethod
    def _match(asset, payload, candidate):
        parts = parse_cpe(candidate.cpe_name)
        required_part = {"hardware": "h", "firmware": "o", "os": "o", "software": "a"}
        if parts[0] != required_part[payload.component_kind]:
            raise APIError(409, "CPE_COMPONENT_MISMATCH", "El componente no coincide con el CPE")
        if asset.version is not None and (
            parts[3] in {"*", "-"}
            or unbind_component(parts[3]).casefold() != asset.version.casefold()
        ):
            raise APIError(
                409, "CPE_VERSION_MISMATCH", "La versión observada no coincide con el CPE"
            )

    def record(self, actor, asset_id, key, payload):
        digest = fingerprint(asset_id, payload)
        # Authorize/replay before touching NVD; release the DB connection and all
        # locks before the bounded network request. Recheck after reacquiring lock.
        with self.session_factory() as session, session.begin():
            self._asset(session, actor, asset_id)
            replay = self._replay(session, actor, asset_id, key, digest)
            if replay:
                return replay
            self._expected(self._current(session, asset_id), payload)
        candidate, validated_at = None, None
        if isinstance(payload, Confirm):
            candidate, validated_at = self.nvd.resolve(actor, payload.cpe_name_id)
        else:
            self.nvd.quota.check_user(actor, "confirm")
        with self.session_factory() as session, session.begin():
            asset = self._asset(session, actor, asset_id, lock=True)
            replay = self._replay(session, actor, asset_id, key, digest)
            if replay:
                return replay
            current = self._current(session, asset_id)
            self._expected(current, payload)
            now = session.scalar(select(func.clock_timestamp()))
            if candidate:
                self._match(asset, payload, candidate)
                snapshot = dict(
                    cpe_name=candidate.cpe_name,
                    cpe_name_id=candidate.cpe_name_id,
                    component_kind=payload.component_kind,
                    observed_version=asset.version,
                    source="NVD",
                    validated_at=validated_at,
                )
            else:
                snapshot = {
                    k: getattr(current, k)
                    for k in (
                        "cpe_name",
                        "cpe_name_id",
                        "component_kind",
                        "observed_version",
                        "source",
                        "validated_at",
                    )
                }
            if current:
                current.valid_to = now
                session.flush()  # Close the partial unique index before inserting.
            event = Event(
                id=uuid4(),
                asset_id=asset_id,
                recorded_by=actor,
                recorded_at=now,
                state=payload.state,
                reason=payload.reason,
                replaces_id=current.id if current else None,
                valid_to=None,
                idempotency_key=key,
                request_hash=digest,
                **snapshot,
            )
            session.add(event)
            session.flush()
            body = EventRead.model_validate(event).model_dump(mode="json")
        return body

    def list(self, actor, asset_id, scope: Literal["current", "history"], limit, offset):
        with self.session_factory() as session, session.begin():
            # Serialize the short read with writers for a coherent current-state,
            # total and page even under READ COMMITTED. No network under this lock.
            self._asset(session, actor, asset_id, lock=True)
            current = self._current(session, asset_id)
            query = select(Event).where(Event.asset_id == asset_id)
            if scope == "current":
                query = query.where(Event.valid_to.is_(None))
            total = session.scalar(select(func.count()).select_from(query.subquery()))
            events = session.scalars(
                query.order_by(Event.recorded_at, Event.id).limit(limit).offset(offset)
            )
            return IdentificationList(
                current_state=current.state if current else "pending",
                items=[
                    HistoryEvent(
                        **EventRead.model_validate(e).model_dump(),
                        valid_to=e.valid_to,
                        is_current=e.valid_to is None,
                    )
                    for e in events
                ],
                page=Page(limit=limit, offset=offset, total=total),
            )
