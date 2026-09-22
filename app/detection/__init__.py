from app.detection.normalizer import normalize_url
from app.detection.features import extract_url_features
from app.detection.reputation import is_trusted_domain, TRUSTED_DOMAINS, HIGH_TARGET_BRANDS
from app.detection.rules import analyze_url_security
from app.detection.ml import predict_url, load_model
from app.detection.risk_engine import calculate_composite_risk
from app.detection.brand_impersonation import detect_brand_impersonation, BRAND_PROFILES
from app.detection.guidance import get_what_should_i_do, get_user_education_advisory

__all__ = [
    "normalize_url",
    "extract_url_features",
    "is_trusted_domain",
    "TRUSTED_DOMAINS",
    "HIGH_TARGET_BRANDS",
    "analyze_url_security",
    "predict_url",
    "load_model",
    "calculate_composite_risk",
    "detect_brand_impersonation",
    "BRAND_PROFILES",
    "get_what_should_i_do",
    "get_user_education_advisory",
]
