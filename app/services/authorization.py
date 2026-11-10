"""PROPUESTA V1.1: ownership only, without administrators or implicit historical grants.

The API supplies a UUID from current_user after verifying active identity. This policy
never accepts an owner from a request body. NULL owners match no ordinary user.
"""

from uuid import UUID

from app.core.errors import unauthorized
from app.models.database_v1 import Asset


class AssetAuthorization:
    def require_create(self, user_id: UUID) -> None:
        if not isinstance(user_id, UUID):
            raise unauthorized()

    def visible_assets(self, user_id: UUID):
        self.require_create(user_id)
        return Asset.created_by == user_id

    def require_list(self, user_id: UUID) -> None:
        self.require_create(user_id)
