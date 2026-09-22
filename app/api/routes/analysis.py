import os
import json
from fastapi import APIRouter, HTTPException, File, UploadFile, Query, status
from app.schemas.analysis import (
    AnalyzeRequest,
    AnalyzeResponse,
    DomainIntelligence,
    TlsAnalysis,
    ScanResponse,
    ModelBenchmarksResponse,
    WeightsCalibrationResponse,
    ThreatIntelligenceResult,
    DetectPayloadRequest,
    DetectPayloadResponse,
    PayloadClassification,
    DetectObfuscationRequest,
    DetectObfuscationResponse,
    ObfuscationDetail,
    DetectBrandImpersonationRequest,
    DetectBrandImpersonationResponse,
    BrandImpersonationDetail,
)
from app.services.inspector_service import inspect_url, inspect_qr_bytes
from app.detection.domain_intel import get_domain_intelligence
from app.detection.tls_analyzer import inspect_tls
from app.detection.ml import get_model_benchmarks
from app.detection.threat_intel import query_threat_intelligence
from app.detection.payload_classifier import classify_qr_payload, sanitize_payload_for_storage
from app.detection.obfuscation import detect_obfuscation
from app.detection.brand_impersonation import detect_brand_impersonation

router = APIRouter(tags=["Inspection Engine"])

CALIBRATION_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "ml", "models", "weights_calibration.json")


@router.get(
    "/api/v1/risk-calibration",
    response_model=WeightsCalibrationResponse,
    summary="Retrieve empirical weight validation experiment metrics and optimal allocation rationale"
)
async def api_risk_calibration():
    if os.path.exists(CALIBRATION_PATH):
        try:
            with open(CALIBRATION_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    from ml.experiments.calibrate_weights import run_weight_calibration_experiment
    return run_weight_calibration_experiment()


@router.get(
    "/api/v1/ml/benchmarks",
    response_model=ModelBenchmarksResponse,
    summary="Retrieve multi-model evaluation metrics (Accuracy, Precision, Recall, F1) across 5 classifiers"
)
async def api_ml_benchmarks():
    return get_model_benchmarks()


@router.get(
    "/api/v1/domain-intel",
    response_model=DomainIntelligence,
    summary="Retrieve domain WHOIS registration and DNS infrastructure intelligence"
)
async def api_domain_intel(domain: str = Query(..., description="Target domain or URL to inspect")):
    if not domain or not domain.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please provide a valid domain or URL.")
    result = get_domain_intelligence(domain.strip())
    return result


@router.get(
    "/api/v1/tls-analysis",
    response_model=TlsAnalysis,
    summary="Perform SSL/TLS certificate security verification, hostname matching, and expiration analysis"
)
async def api_tls_analysis(url: str = Query(..., description="Target URL or domain to inspect TLS for")):
    if not url or not url.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please provide a valid URL.")
    result = inspect_tls(url.strip())
    return result


@router.get(
    "/api/v1/threat-intel",
    response_model=ThreatIntelligenceResult,
    summary="Query multi-source threat intelligence feeds (Google Safe Browsing, VirusTotal, URLhaus, PhishTank, OpenPhish)"
)
async def api_threat_intel(url: str = Query(..., description="Target URL to check against threat databases")):
    if not url or not url.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please provide a valid URL.")
    result = query_threat_intelligence(url.strip())
    return result


@router.post(
    "/api/v1/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze a URL for Quishing and Phishing indicators"
)
async def api_analyze_url(payload: AnalyzeRequest):
    if not payload.url or not payload.url.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please provide a valid URL.")
    result = inspect_url(payload.url.strip())
    if not result.get("success"):
        raise HTTPException(
            status_code=result.get("status_code", status.HTTP_400_BAD_REQUEST),
            detail=result.get("error", "Failed to analyze URL.")
        )
    return result


@router.post(
    "/api/v1/detect-payload",
    response_model=DetectPayloadResponse,
    summary="Detect QR code content type (URL, Plain text, Email, Phone number, Wi-Fi configuration, vCard/contact)"
)
async def api_detect_payload(payload: DetectPayloadRequest):
    if not payload.payload or not payload.payload.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please provide a valid QR payload.")
    classification = classify_qr_payload(payload.payload.strip())
    sanitized = sanitize_payload_for_storage(payload.payload.strip())
    model = PayloadClassification(
        content_type=classification.get("content_type", "text"),
        type_label=classification.get("type_label", "Plain text"),
        security_warning=classification.get("security_warning"),
        raw_preview=payload.payload.strip()[:120],
        sanitized_text=sanitized,
        details=classification,
        embedded_urls=classification.get("embedded_urls", [])
    )
    return DetectPayloadResponse(success=True, classification=model)
 
 
@router.post(
    "/api/v1/detect-obfuscation",
    response_model=DetectObfuscationResponse,
    summary="Detect URL obfuscation techniques (Unicode/Punycode, Hex IP, URL encoding, multiple redirects, nested URLs)"
)
async def api_detect_obfuscation(payload: DetectObfuscationRequest):
    if not payload.url or not payload.url.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please provide a valid URL to inspect.")
    res = detect_obfuscation(payload.url.strip())
    model = ObfuscationDetail(**res)
    return DetectObfuscationResponse(success=True, obfuscation=model)


@router.post(
    "/api/v1/detect-brand-impersonation",
    response_model=DetectBrandImpersonationResponse,
    summary="Detect unauthorized brand impersonation, leetspeak character substitutions, typosquatting, and misleading subdomains"
)
async def api_detect_brand_impersonation(payload: DetectBrandImpersonationRequest):
    if not payload.url or not payload.url.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please provide a valid URL or domain to inspect.")
    res = detect_brand_impersonation(payload.url.strip())
    model = BrandImpersonationDetail(**res)
    return DetectBrandImpersonationResponse(success=True, impersonation=model)


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    include_in_schema=False
)
async def legacy_analyze_url(payload: AnalyzeRequest):
    return await api_analyze_url(payload)


@router.post(
    "/api/v1/scan-image",
    response_model=ScanResponse,
    summary="Upload and decode a QR code image, then analyze its target destination"
)
async def api_scan_qr_image(file: UploadFile = File(..., description="QR code image (PNG, JPG, WEBP, BMP)")):
    try:
        contents = await file.read()
        if not contents:
            return ScanResponse(success=False, error="The uploaded file is empty.")

        scan_result = inspect_qr_bytes(contents)
        if not scan_result.get("success"):
            return ScanResponse(
                success=False,
                extracted_text=scan_result.get("extracted_text"),
                error=scan_result.get("error", "Could not process QR code from image.")
            )

        return ScanResponse(
            success=True,
            extracted_text=scan_result["extracted_text"],
            method=scan_result.get("method"),
            analysis=AnalyzeResponse(**scan_result["analysis"])
        )
    except Exception as exc:
        return ScanResponse(success=False, error=f"Internal scanning error: {str(exc)}")
