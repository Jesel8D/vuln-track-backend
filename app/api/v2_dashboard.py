"""Workspace dashboard using the latest completed NVD run per technology."""

from uuid import UUID

from fastapi import APIRouter, Request
from sqlalchemy import text

from app.api.router import Identity
from app.core.errors import APIError
from app.db.workspace_context import workspace_session

router = APIRouter(prefix="/api/v2/workspaces/{workspace_id}/dashboard")


@router.get("")
def dashboard(workspace_id: UUID, user: Identity, request: Request):
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        if not session.scalar(
            text("SELECT vulntrack.has_workspace_role(:workspace, ARRAY['owner','editor','viewer'])"),
            {"workspace": workspace_id},
        ):
            raise APIError(404, "WORKSPACE_NOT_FOUND", "Workspace no disponible")

        summary = session.execute(
            text("""SELECT
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
                 WHERE workspace_id=:workspace) AS analyses_total,
                (SELECT count(*) FROM vulntrack.application_analysis_runs
                 WHERE workspace_id=:workspace AND status IN ('queued','running')) AS analyses_in_progress,
                (SELECT count(*) FROM vulntrack.application_analysis_runs
                 WHERE workspace_id=:workspace AND status='failed') AS analyses_failed"""),
            {"workspace": workspace_id},
        ).mappings().one()

        latest_stats = session.execute(
            text("""WITH latest AS (
                SELECT DISTINCT ON (technology_id) id,technology_id
                FROM vulntrack.application_analysis_runs
                WHERE workspace_id=:workspace AND status='completed'
                ORDER BY technology_id,created_at DESC,id DESC
            )
            SELECT count(f.id) AS findings_total,
                count(f.id) FILTER (WHERE f.status='open') AS findings_open,
                count(f.id) FILTER (WHERE f.severity='critical' AND f.status='open') AS critical_open,
                count(f.id) FILTER (WHERE f.severity='high' AND f.status='open') AS high_open,
                count(f.id) FILTER (WHERE f.severity='medium' AND f.status='open') AS medium_open,
                count(f.id) FILTER (WHERE f.severity='low' AND f.status='open') AS low_open,
                count(f.id) FILTER (WHERE f.severity='unknown' OR f.severity IS NULL) AS severity_unknown,
                count(DISTINCT latest.technology_id) AS technologies_with_completed_analysis
            FROM latest LEFT JOIN vulntrack.application_findings f
              ON f.workspace_id=:workspace AND f.analysis_id=latest.id"""),
            {"workspace": workspace_id},
        ).mappings().one()

        recent_analyses = session.execute(
            text("""SELECT r.id,r.application_id,a.name AS application_name,
                r.technology_id,t.product,t.version,r.status,r.coverage,r.stored_count,
                r.warning_codes,r.created_at,r.completed_at,
                (SELECT count(*) FROM vulntrack.application_findings f
                 WHERE f.workspace_id=r.workspace_id AND f.analysis_id=r.id) AS finding_count
                FROM vulntrack.application_analysis_runs r
                JOIN vulntrack.applications a
                  ON a.workspace_id=r.workspace_id AND a.id=r.application_id
                JOIN vulntrack.technologies t
                  ON t.workspace_id=r.workspace_id AND t.application_id=r.application_id
                 AND t.id=r.technology_id
                WHERE r.workspace_id=:workspace
                ORDER BY r.created_at DESC,r.id DESC LIMIT 5"""),
            {"workspace": workspace_id},
        ).mappings().all()

        priority_findings = session.execute(
            text("""WITH latest AS (
                SELECT DISTINCT ON (technology_id) id,technology_id,application_id
                FROM vulntrack.application_analysis_runs
                WHERE workspace_id=:workspace AND status='completed'
                ORDER BY technology_id,created_at DESC,id DESC
            )
            SELECT f.id,f.external_id,f.title,f.severity,f.applicability,f.status,
                f.observed_at,a.id AS application_id,a.name AS application_name,
                t.product,t.version
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
            {"workspace": workspace_id},
        ).mappings().all()

        trend = session.execute(
            text("""WITH months AS (
                SELECT generate_series(
                    date_trunc('month',clock_timestamp()) - interval '5 months',
                    date_trunc('month',clock_timestamp()), interval '1 month'
                ) AS month
            )
            SELECT months.month,count(r.id) AS analyses
            FROM months LEFT JOIN vulntrack.application_analysis_runs r
              ON r.workspace_id=:workspace AND r.created_at >= months.month
             AND r.created_at < months.month + interval '1 month'
            GROUP BY months.month ORDER BY months.month"""),
            {"workspace": workspace_id},
        ).mappings().all()

        return {
            "summary": dict(summary) | dict(latest_stats),
            "recent_analyses": [dict(row) for row in recent_analyses],
            "priority_findings": [dict(row) for row in priority_findings],
            "analysis_trend": [dict(row) for row in trend],
        }
