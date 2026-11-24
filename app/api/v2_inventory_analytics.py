"""Bounded analytics of recorded inventory, never of the public CPE dictionary."""

from datetime import date, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import text

from app.api.router import Identity
from app.api.v2_inventory import CatalogModes, Count
from app.core.errors import APIError
from app.db.inventory_labels import display_label, label_key
from app.db.workspace_context import workspace_session

router = APIRouter(prefix="/api/v2/workspaces/{workspace_id}/inventory-analytics")
InventoryKind = Literal["devices", "technologies"]
Dimension = Literal["vendor", "product"]
TopLimit = Annotated[int, Query(ge=1, le=10)]
WindowDays = Literal[30, 90]


class InventoryCategory(BaseModel):
    vendor_key: str = Field(min_length=1, max_length=200)
    product_key: str | None = Field(default=None, max_length=200)
    label: str = Field(min_length=1, max_length=512)
    count: Count


class InventoryDistribution(BaseModel):
    workspace_id: UUID
    inventory_kind: InventoryKind
    dimension: Dimension
    scope: Literal["active"] = "active"
    normalization: Literal["case_whitespace_v1"] = "case_whitespace_v1"
    limit: int = Field(ge=1, le=10)
    total: Count
    excluded_inactive: Count
    unknown: Count
    other: Count
    categories: list[InventoryCategory] = Field(max_length=10)
    observed_at: datetime

    @model_validator(mode="after")
    def partition(self):
        if self.total != self.unknown + self.other + sum(c.count for c in self.categories):
            raise ValueError("Inventory categories must partition the denominator")
        if len(self.categories) > self.limit:
            raise ValueError("Too many categories")
        return self


class InventoryEventCounts(BaseModel):
    first_confirmations: Count = 0
    subsequent_confirmations: Count = 0
    technology_confirmations: Count = 0
    version_changes: Count = 0
    identity_changes_without_version: Count = 0


EVENT_KEYS = tuple(InventoryEventCounts.model_fields)


class InventoryEventDay(BaseModel):
    date: date
    counts: InventoryEventCounts


class InventoryEventWindow(BaseModel):
    days: WindowDays
    start: date
    end_exclusive: date
    timezone: Literal["UTC"] = "UTC"
    observed_at: datetime


class InventoryEvents(BaseModel):
    workspace_id: UUID
    inventory_kind: InventoryKind
    scope: Literal["recorded_history"] = "recorded_history"
    window: InventoryEventWindow
    totals: InventoryEventCounts
    confirmation_modes: CatalogModes
    daily: list[InventoryEventDay] = Field(min_length=30, max_length=90)
    selections_without_confirmation_events: Count
    version_history_available: bool

    @model_validator(mode="after")
    def sums(self):
        if len(self.daily) != self.window.days:
            raise ValueError("Invalid event window")
        for key in EVENT_KEYS:
            if getattr(self.totals, key) != sum(getattr(d.counts, key) for d in self.daily):
                raise ValueError("Daily counts do not match totals")
        confirmations = sum(getattr(self.totals, k) for k in EVENT_KEYS[:3])
        if confirmations != sum(self.confirmation_modes.model_dump().values()):
            raise ValueError("Confirmation provenance does not match events")
        return self


def authorize(session, workspace_id):
    if not session.scalar(
        text("SELECT vulntrack.has_workspace_role(:workspace, ARRAY['owner','editor','viewer'])"),
        {"workspace": workspace_id},
    ):
        raise APIError(404, "WORKSPACE_NOT_FOUND", "Workspace no disponible")


@router.get("/distribution", response_model=InventoryDistribution)
def inventory_distribution(
    workspace_id: UUID,
    user: Identity,
    request: Request,
    inventory_kind: InventoryKind = "devices",
    dimension: Dimension = "vendor",
    limit: TopLimit = 10,
):
    """Active entities, top complete categories plus explicit other/unknown counts.

    Devices use physical manufacturer/model; technologies use vendor/product.
    Only case and whitespace are normalized. No commercial alias inference.
    """
    if inventory_kind == "devices":
        table = "vulntrack_devices.devices d"
        active, vendor, product = "d.status='active'", "d.manufacturer", "d.model"
    else:
        table = (
            "vulntrack.technologies d JOIN vulntrack.applications a "
            "ON a.workspace_id=d.workspace_id AND a.id=d.application_id"
        )
        active, vendor, product = "a.status='active'", "d.vendor", "d.product"
    query = f"""WITH inventory AS MATERIALIZED (
        SELECT {active} AS active,{label_key(vendor)} AS vendor_key,
            {label_key(product)} AS product_key,{display_label(vendor)} AS vendor_label,
            {display_label(product)} AS product_label
        FROM {table} WHERE d.workspace_id=:workspace
    ), complete AS (
        SELECT vendor_key,CASE WHEN :dimension='product' THEN product_key END AS product_key,
            min(vendor_label COLLATE "C") AS vendor_label,
            CASE WHEN :dimension='product' THEN min(product_label COLLATE "C") END AS product_label,
            count(*) AS count
        FROM inventory WHERE active AND vendor_key IS NOT NULL
            AND (:dimension='vendor' OR product_key IS NOT NULL)
        GROUP BY vendor_key,CASE WHEN :dimension='product' THEN product_key END
    ), ranked AS MATERIALIZED (
        SELECT *,row_number() OVER (ORDER BY count DESC,vendor_key COLLATE "C",
            product_key COLLATE "C") AS rank FROM complete
    ) SELECT statement_timestamp() AS observed_at,
        (SELECT count(*) FROM inventory WHERE active) AS total,
        (SELECT count(*) FROM inventory WHERE NOT active) AS excluded_inactive,
        (SELECT count(*) FROM inventory WHERE active AND
            (vendor_key IS NULL OR (:dimension='product' AND product_key IS NULL))) AS unknown,
        (SELECT coalesce(sum(count),0) FROM ranked WHERE rank>:limit) AS other,
        (SELECT coalesce(jsonb_agg(jsonb_build_object('vendor_key',vendor_key,
            'product_key',product_key,'label',vendor_label || coalesce(' · ' || product_label,''),
            'count',count) ORDER BY rank),'[]') FROM ranked WHERE rank<=:limit) AS categories"""
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        authorize(session, workspace_id)
        result = (
            session.execute(
                text(query),
                {
                    "workspace": workspace_id,
                    "dimension": dimension,
                    "limit": limit,
                },
            )
            .mappings()
            .one()
        )
        return InventoryDistribution(
            workspace_id=workspace_id,
            inventory_kind=inventory_kind,
            dimension=dimension,
            limit=limit,
            **result,
        )


def counts_sql():
    # All keys are fixed model fields, never request-supplied SQL.
    return (
        "jsonb_build_object("
        + ",".join(f"'{key}',count(*) FILTER (WHERE kind='{key}')" for key in EVENT_KEYS)
        + ")"
    )


@router.get("/events", response_model=InventoryEvents)
def inventory_events(
    workspace_id: UUID,
    user: Identity,
    request: Request,
    inventory_kind: InventoryKind = "devices",
    days: Annotated[
        int,
        Query(
            ge=30,
            le=90,
            json_schema_extra={"enum": [30, 90]},
            description="Ventana diaria UTC: únicamente 30 o 90 días.",
        ),
    ] = 30,
):
    """Recorded events, including inactive entities; no reconstructed state history.

    Date is the stored confirmation/revision timestamp, in UTC. The current day
    is partial. A revision changing version and product counts only once.
    Technology version changes have no ledger and are deliberately not inferred.
    """
    if days not in (30, 90):
        raise APIError(422, "WINDOW_INVALID", "La ventana debe ser de 30 o 90 días")
    query = f"""WITH clock AS (
        SELECT statement_timestamp() AS observed_at,
            (statement_timestamp() AT TIME ZONE 'UTC')::date AS today
    ), bounds AS (
        SELECT observed_at,today-(:days-1) AS start,today+1 AS end_exclusive FROM clock
    ), identities AS (
        SELECT id,created_at,mode,row_number() OVER
            (PARTITION BY device_id ORDER BY created_at,id) AS ordinal
        FROM vulntrack_devices.identifications WHERE workspace_id=:workspace
            AND :inventory_kind='devices'
    ), events AS (
        SELECT created_at AS happened_at,mode,
            CASE WHEN ordinal=1 THEN 'first_confirmations'
                ELSE 'subsequent_confirmations' END AS kind FROM identities
        UNION ALL
        SELECT recorded_at,NULL,
            CASE WHEN 'version'=ANY(changed_fields) THEN 'version_changes'
                ELSE 'identity_changes_without_version' END
        FROM vulntrack_devices.revisions WHERE workspace_id=:workspace
            AND :inventory_kind='devices' AND change_kind='technological'
        UNION ALL
        SELECT confirmed_at,mode,'technology_confirmations'
        FROM vulntrack_technology_cpe.confirmations WHERE workspace_id=:workspace
            AND :inventory_kind='technologies'
    ), bounded AS MATERIALIZED (
        SELECT * FROM events CROSS JOIN bounds WHERE
            happened_at >= (start::timestamp AT TIME ZONE 'UTC')
            AND happened_at < (end_exclusive::timestamp AT TIME ZONE 'UTC')
            AND happened_at <= observed_at
    ), per_day AS (
        SELECT (happened_at AT TIME ZONE 'UTC')::date AS date,{counts_sql()} AS counts
        FROM bounded GROUP BY 1
    ), days AS (
        SELECT generate_series(start::timestamp,(end_exclusive-1)::timestamp,
            interval '1 day')::date AS date FROM bounds
    ) SELECT observed_at,start,end_exclusive,
        (SELECT {counts_sql()} FROM bounded) AS totals,
        (SELECT jsonb_build_object('live',count(*) FILTER (WHERE mode='live'),
            'fixture',count(*) FILTER (WHERE mode='fixture'),
            'unknown',count(*) FILTER (WHERE mode='unknown')) FROM bounded) AS confirmation_modes,
        (SELECT jsonb_agg(jsonb_build_object('date',days.date,'counts',
            coalesce(per_day.counts,CAST(:zero AS jsonb))) ORDER BY days.date)
            FROM days LEFT JOIN per_day USING(date)) AS daily,
        CASE WHEN :inventory_kind='technologies' THEN (
            SELECT count(*) FROM vulntrack.technologies t WHERE t.workspace_id=:workspace
                AND t.selected_cpe IS NOT NULL AND NOT EXISTS (
                    SELECT 1 FROM vulntrack_technology_cpe.confirmations c
                    WHERE c.workspace_id=t.workspace_id AND c.technology_id=t.id
                        AND c.application_id=t.application_id)
        ) ELSE 0 END AS selections_without_confirmation_events FROM bounds"""
    with workspace_session(
        request.app.state.session_factory, request.app.state.settings, user.id, workspace_id
    ) as session:
        authorize(session, workspace_id)
        result = dict(
            session.execute(
                text(query),
                {
                    "workspace": workspace_id,
                    "inventory_kind": inventory_kind,
                    "days": days,
                    "zero": InventoryEventCounts().model_dump_json(),
                },
            )
            .mappings()
            .one()
        )
        window = InventoryEventWindow(
            days=days,
            **{
                k: result.pop(k)
                for k in (
                    "start",
                    "end_exclusive",
                    "observed_at",
                )
            },
        )
        return InventoryEvents(
            workspace_id=workspace_id,
            inventory_kind=inventory_kind,
            window=window,
            version_history_available=inventory_kind == "devices",
            **result,
        )
