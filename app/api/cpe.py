from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Header, Query, Request
from fastapi.responses import JSONResponse

from app.api.router import Identity
from app.schemas.cpe import CandidateList, EventInput, EventRead, IdentificationList, SearchInput

router = APIRouter(prefix="/api/v1")
Key = Annotated[
    str,
    Header(
        alias="Idempotency-Key",
        min_length=36,
        max_length=36,
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    ),
]


@router.get("/cpe-candidates", response_model=CandidateList)
def candidates(user: Identity, request: Request, search: Annotated[SearchInput, Query()]):
    return request.app.state.nvd.search(user.id, search)


@router.post("/assets/{asset_id}/cpe-identifications", status_code=201, response_model=EventRead)
def identify(
    asset_id: UUID, payload: EventInput, user: Identity, request: Request, idempotency_key: Key
):
    body = request.app.state.identifications.record(
        user.id, asset_id, UUID(idempotency_key), payload
    )
    return JSONResponse(
        body,
        status_code=201,
        headers={
            "Location": f"/api/v1/assets/{asset_id}/cpe-identifications",
            "Cache-Control": "no-store",
        },
    )


@router.get("/assets/{asset_id}/cpe-identifications", response_model=IdentificationList)
def identifications(
    asset_id: UUID,
    user: Identity,
    request: Request,
    scope: Literal["current", "history"] = "current",
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0, le=1000000)] = 0,
):
    return request.app.state.identifications.list(user.id, asset_id, scope, limit, offset)
