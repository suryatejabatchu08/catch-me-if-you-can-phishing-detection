"""
API v1 Routes
Main API endpoints for phishing detection
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Optional
import logging
import asyncio
from datetime import datetime

from api.models import (
    URLAnalysisRequest,
    URLAnalysisResponse,
    EmailAnalysisRequest,
    EmailAnalysisResponse,
    DomainReputationResponse
)
from features.url_features import url_feature_extractor
from features.heuristic_scorer import heuristic_scorer
from features.lookalike_detector import lookalike_detector
from features.brand_impersonation import brand_impersonation_detector
from threatintel import threat_intelligence
from ml.model import ml_model
from scoring.composite_scorer import composite_scorer
from utils.cache import threat_cache

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/analyze/url", response_model=URLAnalysisResponse)
async def analyze_url(request: URLAnalysisRequest):
    """
    Analyze URL for phishing threats
    
    Performs comprehensive analysis including:
    - ML-based classification
    - Heuristic pattern matching
    - Threat intelligence lookup
    - Lookalike domain detection
    - Brand impersonation detection
    
    Returns threat score (0-100) with detailed explanation
    """
    try:
        url = request.url
        logger.info(f"Analyzing URL: {url}")
        
        # Check cache first
        cached_result = threat_cache.get_url_analysis(url)
        if cached_result:
            logger.info(f"Cache hit for {url}")
            return URLAnalysisResponse(**cached_result)
        
        # Extract URL features
        logger.debug("Extracting URL features...")
        url_features = url_feature_extractor.extract_all_features(url)
        
        # Run all analyses in parallel
        logger.debug("Running parallel analyses...")
        heuristic_result, lookalike_result, threat_intel_result, ml_result = await asyncio.gather(
            asyncio.to_thread(heuristic_scorer.calculate_score, url_features),
            asyncio.to_thread(lookalike_detector.detect_lookalike, url),
            asyncio.to_thread(threat_intelligence.check_all, url),
            asyncio.to_thread(ml_model.predict, url_features)
        )
        
        # Brand impersonation detection (optional, if page data provided)
        brand_impersonation_result = None
        if request.page_title or request.page_text:
            brand_impersonation_result = brand_impersonation_detector.detect_impersonation(
                url=url,
                page_title=request.page_title,
                page_text=request.page_text,
                css_colors=request.css_colors
            )
        
        # Calculate composite score
        logger.debug("Calculating composite score...")
        result = composite_scorer.calculate_score(
            ml_score=ml_result['ml_prediction'],
            heuristic_score=heuristic_result['score'],
            threat_intel_score=threat_intel_result['threat_intel_score'],
            lookalike_score=lookalike_result['lookalike_score'],
            ml_details=ml_result,
            heuristic_details=heuristic_result,
            threat_intel_details=threat_intel_result,
            lookalike_details=lookalike_result,
            brand_impersonation_details=brand_impersonation_result
        )
        
        # Cache result
        threat_cache.set_url_analysis(url, result)
        
        logger.info(f"Analysis complete: {url} - Score: {result['threat_score']}, Risk: {result['risk_level']}")
        
        return URLAnalysisResponse(**result)
    
    except Exception as e:
        logger.error(f"Error analyzing URL {request.url}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={
                "error": "analysis_failed",
                "message": f"Failed to analyze URL: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
        )


@router.post("/analyze/email", response_model=EmailAnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    """
    Analyze email for phishing threats (BONUS FEATURE)
    
    Checks:
    - Sender spoofing
    - Suspicious links
    - Urgency keywords
    - Grammar/spelling errors
    - Attachment analysis
    """
    try:
        logger.info(f"Analyzing email from: {request.sender}")
        
        reasons = []
        suspicious_links = []
        threat_score = 0
        
        # Check sender spoofing
        sender_spoofing = False
        if request.sender_name and request.sender:
            sender_domain = request.sender.split('@')[-1].lower()
            sender_name_lower = request.sender_name.lower()
            
            # Check if display name mentions a brand but email domain doesn't match
            for brand in ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'facebook']:
                if brand in sender_name_lower and brand not in sender_domain:
                    sender_spoofing = True
                    threat_score += 30
                    reasons.append({
                        'factor': f"Sender spoofing: Display name mentions '{brand}' but domain is '{sender_domain}'",
                        'severity': 'critical',
                        'weight': 30,
                        'source': 'sender_analysis'
                    })
                    break
        
        # Check for urgency keywords
        urgency_keywords = [
            'urgent', 'immediate', 'suspend', 'locked', 'verify', 'confirm',
            'expire', 'within 24 hours', 'act now', 'limited time', 'unusual activity'
        ]
        urgency_detected = False
        combined_text = f"{request.subject} {request.body}".lower()
        
        urgency_count = sum(1 for keyword in urgency_keywords if keyword in combined_text)
        if urgency_count >= 2:
            urgency_detected = True
            threat_score += 20
            reasons.append({
                'factor': f"Urgency tactics detected ({urgency_count} urgency keywords)",
                'severity': 'high',
                'weight': 20,
                'source': 'content_analysis'
            })
        
        # Analyze links
        if request.links:
            for link in request.links:
                try:
                    # Quick heuristic check for links
                    link_features = url_feature_extractor.extract_all_features(link)
                    link_heuristic = heuristic_scorer.calculate_score(link_features)
                    
                    if link_heuristic['score'] >= 50:
                        suspicious_links.append(link)
                        threat_score += 15
                        reasons.append({
                            'factor': f"Suspicious link detected: {link[:50]}...",
                            'severity': 'high',
                            'weight': 15,
                            'source': 'link_analysis'
                        })
                except Exception as e:
                    logger.warning(f"Error analyzing link {link}: {e}")
        
        # Check attachments
        if request.attachments:
            suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js']
            for attachment in request.attachments:
                filename = attachment.get('filename', '').lower()
                if any(filename.endswith(ext) for ext in suspicious_extensions):
                    threat_score += 25
                    reasons.append({
                        'factor': f"Suspicious attachment: {filename}",
                        'severity': 'critical',
                        'weight': 25,
                        'source': 'attachment_analysis'
                    })
        
        # Normalize score
        threat_score = min(threat_score, 100)
        phishing_probability = threat_score / 100
        
        # Determine risk level
        if threat_score >= 85:
            risk_level = 'critical'
        elif threat_score >= 60:
            risk_level = 'dangerous'
        elif threat_score >= 30:
            risk_level = 'suspicious'
        else:
            risk_level = 'safe'
        
        is_phishing = threat_score >= 60
        recommendation = 'block' if threat_score >= 60 else 'warn' if threat_score >= 30 else 'allow'
        
        result = {
            'phishing_probability': round(phishing_probability, 4),
            'threat_score': threat_score,
            'risk_level': risk_level,
            'is_phishing': is_phishing,
            'reasons': reasons,
            'suspicious_links': suspicious_links,
            'sender_spoofing': sender_spoofing,
            'urgency_detected': urgency_detected,
            'recommendation': recommendation,
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"Email analysis complete: {request.sender} - Score: {threat_score}")
        
        return EmailAnalysisResponse(**result)
    
    except Exception as e:
        logger.error(f"Error analyzing email from {request.sender}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={
                "error": "email_analysis_failed",
                "message": f"Failed to analyze email: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
        )


@router.get("/threat-intel/domain/{domain}", response_model=DomainReputationResponse)
async def get_domain_reputation(domain: str):
    """
    Get domain reputation from threat intelligence sources
    """
    try:
        logger.info(f"Looking up domain reputation: {domain}")
        
        # Check cache
        cache_key = f"domain_reputation:{domain}"
        cached = threat_cache.get_threat_intel('domain', domain)
        if cached:
            return DomainReputationResponse(**cached)
        
        # Check threat intelligence
        url = f"https://{domain}"
        threat_intel_result = threat_intelligence.check_all(url)
        
        is_malicious = threat_intel_result['threat_intel_score'] >= 60
        
        result = {
            'domain': domain,
            'is_malicious': is_malicious,
            'threat_score': threat_intel_result['threat_intel_score'],
            'sources': {
                'virustotal': threat_intel_result.get('virustotal', {}),
                'abuseipdb': threat_intel_result.get('abuseipdb', {}),
                'openphish': threat_intel_result.get('openphish', {})
            },
            'first_seen': None,
            'last_seen': datetime.now().isoformat(),
            'timestamp': datetime.now().isoformat()
        }
        
        # Cache result
        threat_cache.set_threat_intel('domain', domain, result, ttl=3600)
        
        return DomainReputationResponse(**result)
    
    except Exception as e:
        logger.error(f"Error looking up domain {domain}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={
                "error": "lookup_failed",
                "message": f"Failed to lookup domain: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
        )


@router.get("/health")
async def health_check():
    """Extended health check with system status"""
    from utils.cache import cache
    
    return {
        'status': 'healthy',
        'timestamp': datetime.now().timestamp(),
        'version': 'v1.0',
        'cache_status': cache.get_stats(),
        'ml_model_loaded': ml_model.model_primary is not None,
        'services': {
            'threat_intelligence': 'operational',
            'ml_inference': 'operational',
            'cache': 'operational'
        }
    }
