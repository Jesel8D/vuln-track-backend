"""Read-only coverage of current workspace inventory, independent of public CPE data."""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.router import Identity
from app.core.errors import APIError
from app.db.workspace_context import workspace_session

router = APIRouter(prefix="/api/v2/workspaces/{workspace_id}/inventory-coverage")
Count = Annotated[int, Field(ge=0)]


class CoverageCounts(BaseModel):
    total: Count
    confirmed: Count
    pending: Count
    needs_review: Count
    excluded_inactive: Count


class CatalogModes(BaseModel):
    live: Count
    fixture: Count
    unknown: Count


class DeviceCoverage(CoverageCounts):
    without_version: Count
    confirmed_by_mode: CatalogModes


class TechnologyCoverage(CoverageCounts):
    confirmation_provenance: Literal["per_confirmation"] = "per_confirmation"


class InventoryCoverage(BaseModel):
    workspace_id: UUID
    scope: Literal["active"] = "active"
    devices: DeviceCoverage
    technologies: TechnologyCoverage


@router.get("", response_model=InventoryCoverage)
def inventory_coverage(workspace_id: UUID, user: Identity, request: Request):
    """Count active devices and technologies separately; historical CPEs are not current.

    No dictionary reads or CVE requests. Unknown provenance is never inferred.
    Pending/review/confirmed partition each denominator. Retired devices and
    technologies of archived applications are excluded and reported separately.
    """
    params = {"workspace": workspace_id}
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        if not session.scalar(
            text(
                "SELECT vulntrack.has_workspace_role(:workspace, ARRAY['owner','editor','viewer'])"
            ),
            params,
        ):
            raise APIError(404, "WORKSPACE_NOT_FOUND", "Workspace no disponible")
        devices = dict(
            session.execute(
                text("""WITH current_devices AS (
                    SELECT d.status,d.version,i.mode,
                        CASE WHEN i.id IS NOT NULL THEN 'confirmed'
                             WHEN d.identity_generation > 1 THEN 'needs_review'
                             ELSE 'pending' END AS state
                    FROM vulntrack_devices.devices d
                    LEFT JOIN LATERAL (
                        SELECT id,mode FROM vulntrack_devices.identifications
                        WHERE workspace_id=d.workspace_id AND device_id=d.id
                          AND identity_generation=d.identity_generation
                        ORDER BY created_at DESC,id DESC LIMIT 1
                    ) i ON TRUE
                    WHERE d.workspace_id=:workspace
                ) SELECT
                    count(*) FILTER (WHERE status='active') AS total,
                    count(*) FILTER (WHERE status='active' AND state='confirmed') AS confirmed,
                    count(*) FILTER (WHERE status='active' AND state='pending') AS pending,
                    count(*) FILTER (WHERE status='active' AND state='needs_review')
                        AS needs_review,
                    count(*) FILTER (WHERE status='retired') AS excluded_inactive,
                    count(*) FILTER (WHERE status='active' AND version IS NULL) AS without_version,
                    jsonb_build_object(
                        'live',count(*) FILTER (WHERE status='active' AND mode='live'),
                        'fixture',count(*) FILTER (WHERE status='active' AND mode='fixture'),
                        'unknown',count(*) FILTER (WHERE status='active' AND mode='unknown')
                    ) AS confirmed_by_mode
                FROM current_devices"""),
                params,
            )
            .mappings()
            .one()
        )
        technologies = dict(
            session.execute(
                text("""WITH current_technologies AS (
                    SELECT a.status,
                        CASE WHEN t.selected_cpe IS NULL THEN 'pending'
                             WHEN t.confidence='user_confirmed' THEN 'confirmed'
                             ELSE 'needs_review' END AS state
                    FROM vulntrack.technologies t
                    JOIN vulntrack.applications a
                      ON a.workspace_id=t.workspace_id AND a.id=t.application_id
                    WHERE t.workspace_id=:workspace
                ) SELECT
                    count(*) FILTER (WHERE status='active') AS total,
                    count(*) FILTER (WHERE status='active' AND state='confirmed') AS confirmed,
                    count(*) FILTER (WHERE status='active' AND state='pending') AS pending,
                    count(*) FILTER (WHERE status='active' AND state='needs_review')
                        AS needs_review,
                    count(*) FILTER (WHERE status='archived') AS excluded_inactive
                FROM current_technologies"""),
                params,
            )
            .mappings()
            .one()
        )
    return InventoryCoverage(workspace_id=workspace_id, devices=devices, technologies=technologies)
