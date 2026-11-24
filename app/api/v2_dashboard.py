"""Workspace dashboard using the latest completed NVD run per technology."""

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request
from sqlalchemy import text

from app.api.router import Identity
from app.core.errors import APIError
from app.db.workspace_context import workspace_session
from app.services.v2_cve_reliability import decorate, historical_row, recover

router = APIRouter(prefix="/api/v2/workspaces/{workspace_id}/dashboard")


source_router = APIRouter(prefix="/api/v2/workspaces/{workspace_id}/nvd-dashboard")


@router.get("")
def dashboard(workspace_id: UUID, user: Identity, request: Request):
    return dashboard_data(workspace_id, user, request)


@source_router.get("/{nvd_mode}")
def dashboard_by_source(
    workspace_id: UUID,
    nvd_mode: Literal["fixture", "live", "unknown"],
    user: Identity,
    request: Request,
):
    return dashboard_data(workspace_id, user, request, nvd_mode)


def dashboard_data(workspace_id, user, request, nvd_mode=None):
    params = {"workspace": workspace_id, "mode": nvd_mode}
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        if not session.scalar(
            text(
                "SELECT vulntrack.has_workspace_role(:workspace, ARRAY['owner','editor','viewer'])"
            ),
            {"workspace": workspace_id},
        ):
            raise APIError(404, "WORKSPACE_NOT_FOUND", "Workspace no disponible")

        recover(session)
        # Bound the queries before deduplication. Device runs occupy a separate schema.
        source_predicate = (
            "(CAST(:mode AS text) IS NULL OR "
            "COALESCE(query_parameters->>'nvd_mode','unknown')=:mode)"
        )
        summary = (
            session.execute(
                text(f"""SELECT
                (SELECT count(*) FROM vulntrack.applications
                 WHERE workspace_id=:workspace AND status='active') AS applications_total,
                (SELECT count(*) FROM vulntrack.application_targets
                 WHERE workspace_id=:workspace) AS targets_total,
                (SELECT count(*) FROM vulntrack.application_targets
                 WHERE workspace_id=:workspace AND authorization_status='approved'
                   AND authorization_expires_at > clock_timestamp()) AS authorized_targets_total,
                (SELECT count(*) FROM vulntrack.technologies
                 WHERE workspace_id=:workspace) AS technologies_total,
                (SELECT count(*) FROM vulntrack.technologies
                 WHERE workspace_id=:workspace AND confidence='user_confirmed'
                   AND selected_cpe IS NOT NULL) AS confirmed_cpe_total,
                (SELECT count(*) FROM vulntrack.application_analysis_runs
                 WHERE workspace_id=:workspace AND {source_predicate}) AS analyses_total,
                (SELECT count(*) FROM vulntrack.application_analysis_runs
                 WHERE workspace_id=:workspace AND {source_predicate}
                   AND status IN ('queued','running')) AS
                 analyses_in_progress,
                (SELECT count(*) FROM vulntrack.application_analysis_runs
                 WHERE workspace_id=:workspace AND {source_predicate}
                   AND status='failed') AS analyses_failed"""),
                params,
            )
            .mappings()
            .one()
        )

        latest_stats = (
            session.execute(
                text(f"""WITH latest AS (
                SELECT DISTINCT ON (technology_id) id,technology_id
                FROM vulntrack.application_analysis_runs
                WHERE workspace_id=:workspace AND {source_predicate} AND status='completed'
                ORDER BY technology_id,created_at DESC,id DESC
            )
            SELECT count(f.id) AS findings_total,
                count(f.id) FILTER (WHERE f.status='open') AS findings_open,
                count(f.id) FILTER (WHERE f.severity='critical' AND f.status='open') AS
                critical_open,
                count(f.id) FILTER (WHERE f.severity='high' AND f.status='open') AS high_open,
                count(f.id) FILTER (WHERE f.severity='medium' AND f.status='open') AS medium_open,
                count(f.id) FILTER (WHERE f.severity='low' AND f.status='open') AS low_open,
                count(f.id) FILTER (WHERE f.severity='unknown' OR f.severity IS NULL) AS
                severity_unknown,
                count(DISTINCT latest.technology_id) AS technologies_with_completed_analysis
            FROM latest LEFT JOIN vulntrack.application_findings f
              ON f.workspace_id=:workspace AND f.analysis_id=latest.id"""),
                params,
            )
            .mappings()
            .one()
        )

        recent_analyses = (
            session.execute(
                text(f"""SELECT r.id,r.application_id,a.name AS application_name,
                r.technology_id,r.selected_cpe,r.run_context,r.lease_expires_at,r.response_received_at,r.cache_response_id,r.cache_usage,
                r.source_timestamp,COALESCE(r.query_parameters->>'nvd_mode','unknown') AS nvd_mode,
                t.product,t.version,r.status,r.coverage,r.stored_count,
                r.warning_codes,r.created_at,r.completed_at,
                (SELECT count(*) FROM vulntrack.application_findings f
                 WHERE f.workspace_id=r.workspace_id AND f.analysis_id=r.id) AS finding_count
                FROM vulntrack.application_analysis_runs r
                JOIN vulntrack.applications a
                  ON a.workspace_id=r.workspace_id AND a.id=r.application_id
                JOIN vulntrack.technologies t
                  ON t.workspace_id=r.workspace_id AND t.application_id=r.application_id
                 AND t.id=r.technology_id
                WHERE r.workspace_id=:workspace AND {source_predicate}
                ORDER BY r.created_at DESC,r.id DESC LIMIT 5"""),
                params,
            )
            .mappings()
            .all()
        )

        priority_findings = (
            session.execute(
                text(f"""WITH latest AS (
                SELECT DISTINCT ON (technology_id) id,technology_id,application_id,
                    selected_cpe,run_context,
                    lease_expires_at,
                    response_received_at,cache_response_id,cache_usage,source_timestamp,status,coverage,created_at,
                    COALESCE(query_parameters->>'nvd_mode','unknown') AS nvd_mode
                FROM vulntrack.application_analysis_runs
                WHERE workspace_id=:workspace AND {source_predicate} AND status='completed'
                ORDER BY technology_id,created_at DESC,id DESC
            )
            SELECT f.id,f.external_id,f.title,f.severity,f.applicability,f.status,
                f.observed_at,a.id AS application_id,a.name AS application_name,
                t.product,t.version,l.id AS analysis_id,l.technology_id,l.selected_cpe,
                l.run_context,
                l.lease_expires_at,l.response_received_at,l.cache_response_id,l.cache_usage,l.source_timestamp,l.coverage,
                l.status AS run_status,l.created_at,l.nvd_mode
            FROM latest l
            JOIN vulntrack.application_findings f
              ON f.workspace_id=:workspace AND f.analysis_id=l.id AND f.status='open'
            JOIN vulntrack.applications a
              ON a.workspace_id=:workspace AND a.id=l.application_id
            JOIN vulntrack.technologies t
              ON t.workspace_id=:workspace AND t.application_id=l.application_id
             AND t.id=l.technology_id
            ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                f.observed_at DESC,f.external_id LIMIT 5"""),
                params,
            )
            .mappings()
            .all()
        )

        trend = (
            session.execute(
                text(f"""WITH months AS (
                SELECT generate_series(
                    date_trunc('month',clock_timestamp()) - interval '5 months',
                    date_trunc('month',clock_timestamp()), interval '1 month'
                ) AS month
            )
            SELECT months.month,count(r.id) AS analyses
            FROM months LEFT JOIN vulntrack.application_analysis_runs r
              ON r.workspace_id=:workspace AND {source_predicate} AND r.created_at >= months.month
             AND r.created_at < months.month + interval '1 month'
            GROUP BY months.month ORDER BY months.month"""),
                params,
            )
            .mappings()
            .all()
        )

        recent = decorate(
            session,
            request.app.state.settings,
            "applications",
            [historical_row(row) for row in recent_analyses],
        )
        priority = []
        for row in priority_findings:
            item = historical_row(row)
            state = dict(item, status=item["run_status"], id=item["analysis_id"])
            analysis = decorate(session, request.app.state.settings, "applications", [state])[0]
            for field in (
                "run_context",
                "lease_expires_at",
                "response_received_at",
                "cache_response_id",
                "cache_usage",
            ):
                item.pop(field, None)
            item["analysis"] = {
                key: analysis[key]
                for key in ("assessment", "provenance", "storage")
                if key in analysis
            }
            priority.append(item)
        return {
            "cve_metrics_scope": "latest_recorded_per_technology",
            "summary": dict(summary) | dict(latest_stats),
            "recent_analyses": recent,
            "priority_findings": priority,
            "analysis_trend": [dict(row) for row in trend],
        }
