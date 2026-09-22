from fastapi import APIRouter
from app.schemas.health import HealthResponse
from app.detection.ml import load_model

router = APIRouter(prefix="/api/v1", tags=["System Health"])


@router.get("/health", response_model=HealthResponse, summary="System & ML Health Status")
async def get_health():
    model_loaded = False
    model_type = None
    metrics = None
    try:
        data = load_model()
        model_loaded = True
        if isinstance(data, dict):
            model_type = data.get("model_type", "HistGradientBoostingClassifier")
            metrics = data.get("metrics")
    except Exception:
        pass

    return HealthResponse(
        status="healthy",
        version="2.0.0",
        framework="FastAPI",
        ml_model_loaded=model_loaded,
        model_type=model_type,
        metrics=metrics,
    )
