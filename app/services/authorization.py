"""Fail closed: Database V1 has no ownership/ACL. Never infer it from requests."""

from uuid import UUID

from sqlalchemy import false

from app.core.errors import APIError


class AssetAuthorization:
    def require_create(self, user_id: UUID) -> None:
        raise APIError(403, "ASSET_POLICY_PENDING", "Autorización de activos pendiente")

    def visible_assets(self, user_id: UUID):
        return false()

    def require_list(self, user_id: UUID) -> None:
        raise APIError(403, "ASSET_POLICY_PENDING", "Autorización de activos pendiente")
