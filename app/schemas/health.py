from typing import Optional
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    version: str
    framework: str
    ml_model_loaded: bool
    model_type: Optional[str] = None
    metrics: Optional[dict] = None
