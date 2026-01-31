"""
API Request/Response Models
Pydantic models for type validation
"""
from pydantic import BaseModel, Field, HttpUrl, validator
from typing import Optional, List, Dict, Any
from datetime import datetime


class URLAnalysisRequest(BaseModel):
    """Request model for URL analysis"""
    url: str = Field(..., description="URL to analyze", min_length=10, max_length=2048)
    page_title: Optional[str] = Field(None, description="Page title (optional)")
    page_text: Optional[str] = Field(None, description="Page text content (optional)")
    css_colors: Optional[List[str]] = Field(None, description="CSS colors found on page (optional)")
    user_id: Optional[str] = Field(None, description="User ID for analytics (optional)")
    
    @validator('url')
    def validate_url(cls, v):
        """Validate URL format"""
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v


class ThreatReason(BaseModel):
    """Individual threat reason"""
    factor: str = Field(..., description="Threat factor description")
    severity: str = Field(..., description="Severity level: low, medium, high, critical")
    weight: int = Field(..., description="Contribution weight (0-100)")
    source: str = Field(..., description="Source: ml, heuristic, threat_intel, lookalike, brand_impersonation")


class URLAnalysisResponse(BaseModel):
    """Response model for URL analysis"""
    threat_score: int = Field(..., description="Composite threat score (0-100)", ge=0, le=100)
    risk_level: str = Field(..., description="Risk level: safe, suspicious, dangerous, critical")
    is_phishing: bool = Field(..., description="Is this URL phishing?")
    confidence: float = Field(..., description="Confidence in prediction (0-1)", ge=0, le=1)
    recommendation: str = Field(..., description="Recommended action: allow, warn, block")
    analysis: Dict[str, Any] = Field(..., description="Detailed analysis breakdown")
    timestamp: str = Field(..., description="Analysis timestamp (ISO format)")


class EmailAnalysisRequest(BaseModel):
    """Request model for email analysis"""
    sender: str = Field(..., description="Sender email address")
    sender_name: Optional[str] = Field(None, description="Sender display name")
    subject: str = Field(..., description="Email subject")
    body: str = Field(..., description="Email body (text or HTML)")
    links: Optional[List[str]] = Field(None, description="Links found in email")
    attachments: Optional[List[Dict[str, str]]] = Field(None, description="Attachments metadata")
    headers: Optional[Dict[str, str]] = Field(None, description="Email headers")
    user_id: Optional[str] = Field(None, description="User ID for analytics")


class EmailAnalysisResponse(BaseModel):
    """Response model for email analysis"""
    phishing_probability: float = Field(..., description="Phishing probability (0-1)", ge=0, le=1)
    threat_score: int = Field(..., description="Threat score (0-100)", ge=0, le=100)
    risk_level: str = Field(..., description="Risk level")
    is_phishing: bool = Field(..., description="Is this email phishing?")
    reasons: List[ThreatReason] = Field(..., description="Threat reasons")
    suspicious_links: List[str] = Field(..., description="Suspicious links found")
    sender_spoofing: bool = Field(..., description="Sender spoofing detected?")
    urgency_detected: bool = Field(..., description="Urgency keywords detected?")
    recommendation: str = Field(..., description="Recommended action")
    timestamp: str


class DomainReputationResponse(BaseModel):
    """Response model for domain reputation lookup"""
    domain: str
    is_malicious: bool
    threat_score: int
    sources: Dict[str, Any]
    first_seen: Optional[str]
    last_seen: Optional[str]
    timestamp: str


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: float
    version: str
    cache_status: Dict[str, Any]
    ml_model_loaded: bool


class ErrorResponse(BaseModel):
    """Error response"""
    error: str
    message: str
    path: Optional[str] = None
    timestamp: str
