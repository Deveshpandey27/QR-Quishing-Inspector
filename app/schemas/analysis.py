from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="Target URL extracted from QR code or user input", example="https://example.com")


class IndicatorModel(BaseModel):
    name: str
    severity: str
    weight: int
    detail: Optional[str] = None


class WhoisData(BaseModel):
    domain: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    registrar: Optional[str] = None
    age_days: Optional[int] = None
    age_text: Optional[str] = None
    is_recently_registered: bool = False
    warning: Optional[str] = None
    status: str = "unknown"


class DnsData(BaseModel):
    a_records: List[str] = Field(default_factory=list)
    mx_records: List[str] = Field(default_factory=list)
    nameservers: List[str] = Field(default_factory=list)
    status: str = "unknown"


class DomainIntelligence(BaseModel):
    domain: str
    is_ip: bool = False
    whois: WhoisData = Field(default_factory=WhoisData)
    dns: DnsData = Field(default_factory=DnsData)


class TlsAnalysis(BaseModel):
    has_https: bool = False
    certificate_valid: bool = False
    certificate_status: str = "unknown"
    hostname_match: bool = False
    issuer: Optional[str] = None
    subject_cn: Optional[str] = None
    issued_date: Optional[str] = None
    expiration_date: Optional[str] = None
    expiry_days: Optional[int] = None
    expiry_text: Optional[str] = None
    warning: Optional[str] = None
    raw_error: Optional[str] = None


class ShortenerInfo(BaseModel):
    is_shortener: bool = False
    service_name: Optional[str] = None
    warning: Optional[str] = "Destination cannot be trusted based only on the visible short URL."
    redirect_target: Optional[str] = None
    status_code: Optional[int] = None


class FeatureContribution(BaseModel):
    feature: str = Field(..., description="Raw feature key (e.g. url_length)")
    name: str = Field(..., description="Human-readable feature name (e.g. URL length)")
    direction: str = Field(..., description="'up' (escalates risk) or 'down' (mitigates risk)")
    symbol: str = Field(..., description="'↑' or '↓'")
    value: Any = Field(..., description="Observed value of the feature")
    impact_score: float = Field(..., description="Magnitude of attribution contribution")
    signed_score: Optional[float] = Field(None, description="Signed log-odds contribution")
    impact_level: str = Field(..., description="'high', 'medium', or 'low'")
    explanation: str = Field(..., description="Security explanation for why this feature contributed")


class MlExplanation(BaseModel):
    signals: List[FeatureContribution] = Field(default_factory=list)
    top_suspicious: List[FeatureContribution] = Field(default_factory=list)
    top_legitimate: List[FeatureContribution] = Field(default_factory=list)
    summary_text: Optional[str] = None


class MlAnalysisDetail(BaseModel):
    suspicious_probability: float = Field(..., description="Calibrated probability that URL is malicious (0.0 - 100.0%)")
    legitimate_probability: float = Field(..., description="Calibrated probability that URL is legitimate (0.0 - 100.0%)")
    label: str = Field(..., description="'suspicious' or 'legitimate'")
    is_suspicious: bool = Field(...)
    model_name: str = Field(..., description="Name of the active estimator")
    features: Dict[str, Any] = Field(default_factory=dict, description="24 extracted lexical & structural features")
    explanation: Optional[MlExplanation] = None


class ModelBenchmarkEntry(BaseModel):
    model: str
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: Optional[float] = None
    training_time_sec: Optional[float] = None
    is_active: bool = False
    active_badge: Optional[str] = None


class DatasetMeta(BaseModel):
    name: str
    total_samples: int
    benchmark_samples: Optional[int] = None
    train_samples: Optional[int] = None
    test_samples: Optional[int] = None
    features_count: int
    features_list: List[str] = Field(default_factory=list)


class ModelBenchmarksResponse(BaseModel):
    dataset: DatasetMeta
    active_model: str
    generated_at: str
    models: List[ModelBenchmarkEntry]


class WeightCalibrationConfig(BaseModel):
    name: str
    weights: Dict[str, float]
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    brier_score: float
    is_optimal: bool
    status: str


class WeightsCalibrationResponse(BaseModel):
    experiment: str
    generated_at: str
    calibration_dataset: Dict[str, int]
    selected_weights: Dict[str, float]
    synergy_amplification: float
    rationale: str
    configurations: List[WeightCalibrationConfig]


class ThreatIntelProviderResult(BaseModel):
    name: str
    checked: bool
    matched: bool
    threat_type: Optional[str] = None
    details: Optional[str] = None
    reference_url: Optional[str] = None
    status: str


class ThreatIntelligenceResult(BaseModel):
    known_malicious: bool
    matches_count: int
    sources_checked: int
    providers: List[ThreatIntelProviderResult] = Field(default_factory=list)
    warning_message: Optional[str] = None
    summary_text: str


class PayloadClassification(BaseModel):
    content_type: str = Field("url", description="'url', 'text', 'email', 'phone', 'wifi', or 'vcard'")
    type_label: str = Field("URL", description="Human-readable label: URL, Plain text, Email, Phone number, Wi-Fi configuration, vCard/contact")
    security_warning: Optional[str] = None
    raw_preview: Optional[str] = None
    sanitized_text: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    embedded_urls: List[str] = Field(default_factory=list)


class DetectPayloadRequest(BaseModel):
    payload: str = Field(..., description="Raw QR code payload text to classify")


class DetectPayloadResponse(BaseModel):
    success: bool = True
    classification: PayloadClassification


class ObfuscationDetail(BaseModel):
    is_obfuscated: bool = Field(False, description="Whether any URL obfuscation technique was detected")
    detected_techniques: List[str] = Field(default_factory=list, description="List of detected obfuscation techniques")
    techniques_count: int = Field(0, description="Total number of distinct obfuscation techniques detected")
    warning_title: str = Field("No Obfuscation Detected", description="Obfuscation alert heading")
    warning_message: str = Field("Destination does not exhibit evasive obfuscation techniques.", description="Explanatory obfuscation warning")
    penalty: int = Field(0, description="Risk penalty added to rule score")
    punycode_info: Optional[Dict[str, Any]] = None
    encoding_info: Optional[Dict[str, Any]] = None
    ip_obfuscation_info: Optional[Dict[str, Any]] = None
    nested_url_info: Optional[Dict[str, Any]] = None
    redirect_chain_info: Optional[Dict[str, Any]] = None


class DetectObfuscationRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect for obfuscation")


class DetectObfuscationResponse(BaseModel):
    success: bool = True
    obfuscation: ObfuscationDetail


class BrandImpersonationDetail(BaseModel):
    is_impersonation: bool = Field(False, description="Whether brand impersonation was detected")
    warning_title: str = Field("No Brand Impersonation Detected", description="Brand impersonation heading")
    detected_brand: Optional[str] = Field(None, description="Target brand identified (e.g. Google, PayPal, Microsoft)")
    actual_domain: str = Field(..., description="Actual domain being inspected")
    warning_message: str = Field("Domain does not exhibit brand impersonation characteristics.", description="Explanatory warning message")
    impersonation_types: List[str] = Field(default_factory=list, description="Techniques detected: character_substitution, compound_keyword, misleading_subdomain, typosquatting")
    substitutions: List[Dict[str, Any]] = Field(default_factory=list, description="Character substitutions/leetspeak detected")
    similarity_score: Optional[float] = Field(None, description="Similarity ratio to official brand name")
    matched_token: Optional[str] = Field(None, description="Specific token that triggered the impersonation alert")
    is_official_domain: bool = Field(False, description="Whether the host is an official verified domain of the brand")
    official_domains_sample: List[str] = Field(default_factory=list, description="Sample of authoritative official domains for the brand")
    penalty: int = Field(0, description="Risk penalty added to rule score")
    reasons: List[str] = Field(default_factory=list, description="Detailed explanatory findings")


class DetectBrandImpersonationRequest(BaseModel):
    url: str = Field(..., description="Target URL or domain to inspect for brand impersonation")


class DetectBrandImpersonationResponse(BaseModel):
    success: bool = True
    impersonation: BrandImpersonationDetail


class WhatShouldIDoGuidance(BaseModel):
    tier: str = Field(..., description="Risk tier: LOW, MEDIUM, or HIGH")
    badge_text: str = Field(..., description="Action badge text (e.g. ✓ LOW RISK, ⚠ SUSPICIOUS, 🚨 HIGH RISK)")
    summary: str = Field(..., description="Summary statement for the tier")
    recommendation: str = Field(..., description="Primary user action recommendation")
    action_items: List[str] = Field(default_factory=list, description="Action items to take or avoid")
    severity_color: str = Field("primary", description="UI color indicator (success, warning, danger)")
    risk_level: Optional[str] = None
    lead_text: Optional[str] = None
    action_text: Optional[str] = None
    full_text: Optional[str] = None


class UserEducationAdvisory(BaseModel):
    title: str = Field("WHY IS THIS DANGEROUS?", description="Educational alert title")
    context: str = Field(..., description="Contextual explanation of QR quishing threat vectors")
    prohibited_lead: str = Field("Never enter:", description="Heading for restricted data entry")
    prohibited_items: List[str] = Field(default_factory=list, description="List of sensitive data categories")
    condition_note: str = Field("unless you have verified the destination.", description="Qualifying safety condition")
    formatted_text: str = Field(..., description="Full multi-line formatted educational text")
    heading: Optional[str] = None
    text: Optional[str] = None
    closing_note: Optional[str] = None


class AnalyzeResponse(BaseModel):
    success: bool
    url: str
    hostname: str
    score: int = Field(..., ge=0, le=100, description="Composite Quishing Risk Score (0-100)")
    risk_level: str = Field("LOW", description="Categorical risk level: 'HIGH', 'MEDIUM', or 'LOW'")
    ml_score: int = Field(..., ge=0, le=100, description="Machine Learning Suspicious Probability %")
    rule_score: int = Field(..., ge=0, le=100, description="Rule-based heuristic risk penalty %")
    domain_score: int = Field(0, ge=0, le=100, description="Domain & network infrastructure risk score (0-100)")
    risk_weights: Dict[str, float] = Field(default_factory=lambda: {"rule": 0.35, "ml": 0.45, "domain": 0.20})
    status: str = Field(..., description="'safe', 'suspicious', or 'dangerous'")
    title: str
    message: str
    reasons: List[str]
    indicators: List[IndicatorModel]
    detected: List[str] = Field(default_factory=list, description="Itemized checklist of detected suspicious characteristics")
    is_trusted: bool
    is_shortener: bool
    is_ip: bool
    domain_intel: Optional[DomainIntelligence] = None
    tls_analysis: Optional[TlsAnalysis] = None
    shortener_info: Optional[ShortenerInfo] = None
    ml_detail: Optional[MlAnalysisDetail] = None
    threat_intel: Optional[ThreatIntelligenceResult] = None
    payload_info: Optional[PayloadClassification] = None
    obfuscation_analysis: Optional[ObfuscationDetail] = None
    brand_impersonation: Optional[BrandImpersonationDetail] = None
    what_should_i_do: Optional[WhatShouldIDoGuidance] = None
    user_education: Optional[UserEducationAdvisory] = None


class ScanResponse(BaseModel):
    success: bool
    extracted_text: Optional[str] = None
    method: Optional[str] = None
    analysis: Optional[AnalyzeResponse] = None
    error: Optional[str] = None


class ScanHistoryItem(BaseModel):
    id: str
    url: str
    hostname: str
    display_url: str
    score: int
    final_score: Optional[int] = None
    risk_level: str
    status: str
    timestamp: str
    date_label: str
    relative_date: Optional[str] = None
    analysis_snapshot: Optional[Dict[str, Any]] = None


class ScanHistoryResponse(BaseModel):
    success: bool
    total_count: int
    total: Optional[int] = None
    items: List[ScanHistoryItem]

