from fastapi import APIRouter, HTTPException, Query, status
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from app.schemas.analysis import ScanHistoryItem, ScanHistoryResponse
from app.services.history_service import history_service

router = APIRouter(prefix="/api/v1/history", tags=["Scan History Dashboard"])


class RecordScanRequest(BaseModel):
    analysis: Optional[Dict[str, Any]] = None
    url: Optional[str] = None
    risk_level: Optional[str] = None
    final_score: Optional[int] = None
    score: Optional[int] = None
    reasons: Optional[List[str]] = None
    analysis_snapshot: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


@router.get(
    "",
    response_model=ScanHistoryResponse,
    summary="Retrieve scan history audit log with relative dates and risk classifications"
)
async def api_get_history(
    limit: int = Query(50, ge=1, le=200, description="Maximum number of historical records to return"),
    risk: Optional[str] = Query(None, description="Filter by risk level: ALL, HIGH, MEDIUM, LOW"),
    q: Optional[str] = Query(None, description="Search query matching URL or domain")
):
    items = history_service.get_history(limit=limit, risk_filter=risk, query=q)
    return ScanHistoryResponse(
        success=True,
        total_count=len(items),
        total=len(items),
        items=[ScanHistoryItem(**item) for item in items]
    )


@router.get(
    "/{scan_id}",
    response_model=ScanHistoryItem,
    summary="Retrieve a specific historical scan and its complete analysis snapshot"
)
async def api_get_scan_details(scan_id: str):
    scan = history_service.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan record '{scan_id}' not found.")
    return ScanHistoryItem(**scan)


@router.post(
    "",
    summary="Record a newly completed scan into the history dashboard log"
)
async def api_record_scan(payload: RecordScanRequest):
    data_dict = payload.analysis or payload.analysis_snapshot or payload.dict()
    if not data_dict.get("url"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Valid URL is required.")
    item = history_service.record_scan(data_dict)
    item_model = ScanHistoryItem(**item)
    dump_data = item_model.model_dump() if hasattr(item_model, "model_dump") else item_model.dict()
    return {
        "success": True,
        "item": item_model,
        **dump_data
    }


@router.delete(
    "",
    summary="Clear all recorded scan history"
)
async def api_clear_history():
    history_service.clear_history()
    return {"success": True, "message": "Scan history cleared successfully."}


@router.post(
    "/reset",
    response_model=ScanHistoryResponse,
    summary="Reset scan history to the default baseline seed dataset"
)
async def api_reset_seed_history():
    items = history_service.reset_seed_history()
    return ScanHistoryResponse(
        success=True,
        total_count=len(items),
        items=[ScanHistoryItem(**item) for item in items]
    )
