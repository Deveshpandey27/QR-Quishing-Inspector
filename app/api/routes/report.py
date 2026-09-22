from fastapi import APIRouter, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import re
from app.services.report_service import generate_text_report, generate_pdf_report
from app.services.history_service import history_service

router = APIRouter(prefix="/api/v1/report", tags=["Security Report Generation"])


class ReportGenerateRequest(BaseModel):
    analysis: Optional[Dict[str, Any]] = None
    url: Optional[str] = None
    hostname: Optional[str] = None
    score: Optional[int] = None
    final_score: Optional[int] = None
    risk_level: Optional[str] = None
    status: Optional[str] = None
    detected: Optional[List[str]] = None
    ml_detail: Optional[Dict[str, Any]] = None
    reasons: Optional[List[str]] = None
    indicators: Optional[List[Any]] = None

    class Config:
        extra = "allow"


class TextReportResponse(BaseModel):
    success: bool = True
    report_text: str


def _clean_filename(hostname_or_url: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]", "_", hostname_or_url)
    return cleaned[:40] or "target"


@router.post(
    "/text",
    response_model=TextReportResponse,
    summary="Generate a formatted plain-text security analysis report"
)
async def api_generate_text_report(payload: ReportGenerateRequest):
    data_dict = payload.analysis or payload.model_dump()
    if not data_dict.get("url"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL is required to generate a security report."
        )
    text_report = generate_text_report(data_dict)
    return TextReportResponse(success=True, report_text=text_report)


@router.post(
    "/pdf",
    summary="Generate and download a formal PDF security analysis report"
)
async def api_generate_pdf_report(payload: ReportGenerateRequest):
    data_dict = payload.analysis or payload.model_dump()
    if not data_dict.get("url"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL is required to generate a PDF security report."
        )
    
    try:
        pdf_bytes = generate_pdf_report(data_dict)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PDF generation failed: {str(e)}"
        )

    host_token = _clean_filename(data_dict.get("hostname") or data_dict.get("url") or "target")
    filename = f"quishing_security_report_{host_token}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache"
        }
    )


@router.get(
    "/{scan_id}/pdf",
    summary="Download PDF report for a historical scan from the dashboard"
)
async def api_get_historical_pdf_report(scan_id: str):
    scan = history_service.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record '{scan_id}' not found in audit history."
        )
    
    analysis_data = scan.get("analysis_snapshot") or scan
    try:
        pdf_bytes = generate_pdf_report(analysis_data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PDF generation failed: {str(e)}"
        )

    host_token = _clean_filename(scan.get("hostname") or scan.get("url") or scan_id)
    filename = f"quishing_security_report_{host_token}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache"
        }
    )


@router.get(
    "/{scan_id}/text",
    response_model=TextReportResponse,
    summary="Get text report for a historical scan from the dashboard"
)
async def api_get_historical_text_report(scan_id: str):
    scan = history_service.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record '{scan_id}' not found in audit history."
        )
    
    analysis_data = scan.get("analysis_snapshot") or scan
    text_report = generate_text_report(analysis_data)
    return TextReportResponse(success=True, report_text=text_report)
