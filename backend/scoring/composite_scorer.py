"""
Composite Scoring Engine
Combines ML, heuristic, threat intel, and lookalike scores with explanation
"""
from typing import Dict, Any, List, Tuple
from datetime import datetime
import logging

from config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class CompositeScorer:
    """Calculate final threat score and generate explanations"""
    
    def __init__(self):
        # Weights from PRD (configurable)
        self.weight_ml = settings.WEIGHT_ML  # 0.40
        self.weight_heuristic = settings.WEIGHT_HEURISTIC  # 0.25
        self.weight_threat_intel = settings.WEIGHT_THREAT_INTEL  # 0.30
        self.weight_lookalike = settings.WEIGHT_LOOKALIKE  # 0.05
        
        # Risk thresholds
        self.threshold_safe = settings.THRESHOLD_SAFE  # 30
        self.threshold_suspicious = settings.THRESHOLD_SUSPICIOUS  # 60
        self.threshold_dangerous = settings.THRESHOLD_DANGEROUS  # 85
    
    def calculate_score(
        self,
        ml_score: float,  # 0-1
        heuristic_score: int,  # 0-100
        threat_intel_score: int,  # 0-100
        lookalike_score: int,  # 0-100
        ml_details: Dict[str, Any],
        heuristic_details: Dict[str, Any],
        threat_intel_details: Dict[str, Any],
        lookalike_details: Dict[str, Any],
        brand_impersonation_details: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Calculate composite threat score using weighted formula
        
        Formula:
        Final Score = (
            ML_Prediction * 0.40 +
            Heuristic_Score * 0.25 +
            ThreatIntel_Score * 0.30 +
            Lookalike_Score * 0.05
        ) * 100
        
        Returns comprehensive analysis with explanations
        """
        # Normalize ML score to 0-100
        ml_score_normalized = ml_score * 100
        
        # Adaptive weighting: Boost lookalike weight when high-confidence detection
        weight_ml = self.weight_ml
        weight_heuristic = self.weight_heuristic
        weight_threat_intel = self.weight_threat_intel
        weight_lookalike = self.weight_lookalike
        
        # If high-confidence lookalike detected, redistribute weights
        if lookalike_details.get('is_lookalike', False) and lookalike_score >= 90:
            # Increase lookalike weight to 35%, reduce ML to 20%
            weight_lookalike = 0.35
            weight_ml = 0.20
            weight_heuristic = 0.25
            weight_threat_intel = 0.20
        
        # Calculate weighted composite score
        composite_score = (
            (ml_score_normalized * weight_ml) +
            (heuristic_score * weight_heuristic) +
            (threat_intel_score * weight_threat_intel) +
            (lookalike_score * weight_lookalike)
        )
        
        # Clamp to 0-100
        composite_score = max(0, min(100, int(composite_score)))
        
        # Determine risk level
        risk_level = self._get_risk_level(composite_score)
        
        # Determine if phishing (threshold-based OR high-confidence lookalike)
        is_phishing = composite_score >= self.threshold_suspicious
        
        # Override: High-confidence lookalike with evidence = phishing
        # Rule 1: Very high lookalike (≥90) + moderate heuristic (≥60)
        # Rule 2: High lookalike (≥80) + high heuristic (≥70) + homoglyphs
        if (lookalike_details.get('is_lookalike', False) and 
            ((lookalike_score >= 90 and heuristic_score >= 60) or
             (lookalike_score >= 80 and heuristic_score >= 50) or
             (lookalike_score >= 75 and lookalike_details.get('homoglyph_detected', False)))):
            is_phishing = True
            # Boost score to at least "dangerous" threshold
            composite_score = max(composite_score, self.threshold_suspicious + 10)
            risk_level = self._get_risk_level(composite_score)
        
        # Calculate confidence
        confidence = self._calculate_confidence(
            ml_details.get('confidence', 0),
            threat_intel_details.get('hits', 0),
            lookalike_details.get('is_lookalike', False)
        )
        
        # Generate reasons
        reasons = self._generate_reasons(
            composite_score,
            ml_score,
            heuristic_score,
            threat_intel_score,
            lookalike_score,
            heuristic_details,
            threat_intel_details,
            lookalike_details,
            brand_impersonation_details
        )
        
        # Get recommendation
        recommendation = self._get_recommendation(risk_level, is_phishing)
        
        # Build comprehensive response
        result = {
            'threat_score': composite_score,
            'risk_level': risk_level,
            'is_phishing': is_phishing,
            'confidence': round(confidence, 2),
            'recommendation': recommendation,
            'analysis': {
                'ml_prediction': round(ml_score, 4),
                'ml_contribution': round(ml_score_normalized * weight_ml, 2),
                'heuristic_score': heuristic_score,
                'heuristic_contribution': round(heuristic_score * weight_heuristic, 2),
                'threat_intel_score': threat_intel_score,
                'threat_intel_contribution': round(threat_intel_score * weight_threat_intel, 2),
                'threat_intel_hits': threat_intel_details.get('hits', 0),
                'lookalike_detected': lookalike_details.get('is_lookalike', False),
                'lookalike_score': lookalike_score,
                'lookalike_contribution': round(lookalike_score * weight_lookalike, 2),
                'lookalike_brand': lookalike_details.get('matched_brand'),
                'brand_impersonation': brand_impersonation_details.get('is_impersonating', False) if brand_impersonation_details else False,
                'impersonated_brand': brand_impersonation_details.get('suspected_brand') if brand_impersonation_details else None,
                'reasons': reasons,
                'model_used': ml_details.get('model_used', 'primary'),
                'inference_time_ms': ml_details.get('inference_time_ms', 0)
            },
            'timestamp': datetime.now().isoformat()
        }
        
        return result
    
    def _get_risk_level(self, score: int) -> str:
        """Determine risk level from score"""
        if score <= self.threshold_safe:
            return 'safe'
        elif score <= self.threshold_suspicious:
            return 'suspicious'
        elif score <= self.threshold_dangerous:
            return 'dangerous'
        else:
            return 'critical'
    
    def _calculate_confidence(
        self,
        ml_confidence: float,
        threat_intel_hits: int,
        lookalike_detected: bool
    ) -> float:
        """Calculate overall confidence in prediction"""
        confidence = ml_confidence * 0.6  # Base confidence from ML
        
        # Boost confidence with threat intel hits
        if threat_intel_hits > 0:
            confidence += min(threat_intel_hits * 0.15, 0.3)
        
        # Boost confidence with lookalike detection
        if lookalike_detected:
            confidence += 0.1
        
        return min(confidence, 0.99)  # Cap at 99%
    
    def _generate_reasons(
        self,
        composite_score: int,
        ml_score: float,
        heuristic_score: int,
        threat_intel_score: int,
        lookalike_score: int,
        heuristic_details: Dict,
        threat_intel_details: Dict,
        lookalike_details: Dict,
        brand_impersonation_details: Dict = None
    ) -> List[Dict[str, Any]]:
        """Generate ranked list of threat reasons"""
        reasons = []
        
        # Calculate contributions
        ml_contribution = (ml_score * 100) * self.weight_ml
        heuristic_contribution = heuristic_score * self.weight_heuristic
        threat_intel_contribution = threat_intel_score * self.weight_threat_intel
        lookalike_contribution = lookalike_score * self.weight_lookalike
        
        contributions = [
            ('ml', ml_contribution),
            ('heuristic', heuristic_contribution),
            ('threat_intel', threat_intel_contribution),
            ('lookalike', lookalike_contribution)
        ]
        
        # Sort by contribution
        contributions.sort(key=lambda x: x[1], reverse=True)
        
        # Add reasons based on contribution
        for source, contribution in contributions:
            if contribution < 5:  # Skip negligible contributions
                continue
            
            weight_percent = int((contribution / composite_score) * 100) if composite_score > 0 else 0
            severity = self._get_severity_from_contribution(weight_percent)
            
            if source == 'threat_intel' and threat_intel_details.get('reasons'):
                # Add threat intel reasons
                for reason_text in threat_intel_details['reasons'][:3]:
                    reasons.append({
                        'factor': reason_text,
                        'severity': 'critical' if 'OpenPhish' in reason_text else 'high',
                        'weight': weight_percent,
                        'source': 'threat_intelligence'
                    })
            
            elif source == 'lookalike' and lookalike_details.get('is_lookalike'):
                # Add lookalike reason
                brand = lookalike_details.get('matched_brand', 'unknown brand')
                homoglyph = lookalike_details.get('homoglyph_details')
                
                reason_text = f"Lookalike domain detected: similar to {brand}"
                if homoglyph:
                    reason_text = f"Lookalike domain: {homoglyph} (impersonating {brand})"
                
                reasons.append({
                    'factor': reason_text,
                    'severity': 'critical',
                    'weight': weight_percent,
                    'source': 'lookalike_detection'
                })
            
            elif source == 'heuristic' and heuristic_details.get('matched_rules'):
                # Add top heuristic rules
                for rule in heuristic_details['matched_rules'][:3]:
                    reasons.append({
                        'factor': rule['explanation'],
                        'severity': rule['severity'],
                        'weight': int((rule['score'] / heuristic_score) * weight_percent) if heuristic_score > 0 else 0,
                        'source': 'heuristic_analysis'
                    })
            
            elif source == 'ml':
                # Add ML contribution
                confidence_pct = int(ml_score * 100)
                reasons.append({
                    'factor': f"ML model predicts {confidence_pct}% probability of phishing",
                    'severity': severity,
                    'weight': weight_percent,
                    'source': 'machine_learning'
                })
        
        # Add brand impersonation if detected
        if brand_impersonation_details and brand_impersonation_details.get('is_impersonating'):
            brand = brand_impersonation_details.get('suspected_brand', 'unknown brand')
            reasons.insert(0, {
                'factor': f"Page is impersonating {brand.title()}",
                'severity': 'critical',
                'weight': brand_impersonation_details.get('impersonation_score', 0),
                'source': 'brand_impersonation'
            })
        
        # Sort by weight (descending) and limit to top 10
        reasons.sort(key=lambda x: x['weight'], reverse=True)
        return reasons[:10]
    
    def _get_severity_from_contribution(self, weight_percent: int) -> str:
        """Get severity level from contribution percentage"""
        if weight_percent >= 30:
            return 'critical'
        elif weight_percent >= 20:
            return 'high'
        elif weight_percent >= 10:
            return 'medium'
        else:
            return 'low'
    
    def _get_recommendation(self, risk_level: str, is_phishing: bool) -> str:
        """Get action recommendation based on risk level"""
        recommendations = {
            'safe': 'allow',
            'suspicious': 'warn',
            'dangerous': 'block',
            'critical': 'block'
        }
        return recommendations.get(risk_level, 'warn')
    
    def get_risk_color(self, risk_level: str) -> str:
        """Get color code for risk level"""
        colors = {
            'safe': 'green',
            'suspicious': 'yellow',
            'dangerous': 'orange',
            'critical': 'red'
        }
        return colors.get(risk_level, 'gray')


# Global instance
composite_scorer = CompositeScorer()
