from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from app.api.cpe import Key
from app.api.router import Identity
from app.schemas.analyses import (
    Accepted,
    AnalysisInput,
    AnalysisList,
    AnalysisRead,
    FindingList,
    FindingRead,
    ReviewInput,
)

router = APIRouter(prefix="/api/v1")
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=1000000)]


@router.post("/assets/{asset_id}/analyses", status_code=202, response_model=Accepted)
def accept(
    asset_id: UUID, payload: AnalysisInput, user: Identity, request: Request, idempotency_key: Key
):
    result = request.app.state.analyses.accept(user.id, asset_id, UUID(idempotency_key), payload)
    return JSONResponse(
        result.model_dump(mode="json"),
        status_code=202,
        headers={
            "Location": f"/api/v1/assets/{asset_id}/analyses/{result.id}",
            "Cache-Control": "no-store",
        },
    )


@router.get("/assets/{asset_id}/analyses", response_model=AnalysisList)
def runs(asset_id: UUID, user: Identity, request: Request, limit: Limit = 20, offset: Offset = 0):
    return request.app.state.analyses.list(user.id, asset_id, limit, offset)


@router.get("/assets/{asset_id}/analyses/{run_id}", response_model=AnalysisRead)
def run(asset_id: UUID, run_id: UUID, user: Identity, request: Request):
    return request.app.state.analyses.get(user.id, asset_id, run_id)


@router.get("/assets/{asset_id}/analyses/{run_id}/findings", response_model=FindingList)
def findings(
    asset_id: UUID,
    run_id: UUID,
    user: Identity,
    request: Request,
    limit: Limit = 20,
    offset: Offset = 0,
):
    return request.app.state.analyses.findings(user.id, asset_id, run_id, limit, offset)


@router.get("/findings/{finding_id}", response_model=FindingRead)
def finding(finding_id: UUID, user: Identity, request: Request):
    return request.app.state.analyses.finding(user.id, finding_id)


@router.patch("/findings/{finding_id}", response_model=FindingRead)
def review(finding_id: UUID, payload: ReviewInput, user: Identity, request: Request):
    return request.app.state.analyses.review(user.id, finding_id, payload)
