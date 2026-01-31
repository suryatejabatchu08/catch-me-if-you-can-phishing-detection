"""
Heuristic Scoring Engine
Rule-based threat detection using URL patterns and features
"""
from typing import Dict, Any, List, Tuple
import logging

logger = logging.getLogger(__name__)


class HeuristicScorer:
    """Calculate heuristic threat score based on URL features"""
    
    def __init__(self):
        self.rules = self._initialize_rules()
    
    def _initialize_rules(self) -> List[Dict[str, Any]]:
        """Initialize scoring rules with weights"""
        return [
            # Length-based rules
            {
                'name': 'Extremely long URL',
                'condition': lambda f: f.get('url_length', 0) > 75,
                'score': 15,
                'severity': 'medium',
                'explanation': 'URL length exceeds 75 characters (common in phishing)'
            },
            {
                'name': 'Very long domain',
                'condition': lambda f: f.get('domain_length', 0) > 30,
                'score': 10,
                'severity': 'low',
                'explanation': 'Domain name is unusually long'
            },
            
            # Structural rules
            {
                'name': 'Multiple subdomains',
                'condition': lambda f: f.get('subdomain_count', 0) >= 3,
                'score': 20,
                'severity': 'high',
                'explanation': 'Contains 3+ subdomains (obfuscation technique)'
            },
            {
                'name': 'Deep path structure',
                'condition': lambda f: f.get('path_depth', 0) > 5,
                'score': 12,
                'severity': 'medium',
                'explanation': 'Path depth exceeds 5 levels (suspicious structure)'
            },
            {
                'name': 'Many query parameters',
                'condition': lambda f: f.get('query_param_count', 0) > 10,
                'score': 8,
                'severity': 'low',
                'explanation': 'Contains excessive query parameters'
            },
            
            # Character pattern rules
            {
                'name': 'High digit ratio',
                'condition': lambda f: f.get('digit_ratio', 0) > 0.2,
                'score': 15,
                'severity': 'medium',
                'explanation': 'Unusually high number of digits in URL'
            },
            {
                'name': 'High special character ratio',
                'condition': lambda f: f.get('special_char_ratio', 0) > 0.3,
                'score': 12,
                'severity': 'medium',
                'explanation': 'Excessive special characters detected'
            },
            {
                'name': 'Multiple hyphens in domain',
                'condition': lambda f: f.get('hyphen_count', 0) > 3,
                'score': 15,
                'severity': 'medium',
                'explanation': 'Domain contains multiple hyphens (typosquatting indicator)'
            },
            
            # Entropy rules
            {
                'name': 'High URL entropy',
                'condition': lambda f: f.get('url_entropy', 0) > 4.5,
                'score': 18,
                'severity': 'high',
                'explanation': 'High entropy suggests randomly generated or obfuscated URL'
            },
            {
                'name': 'High domain entropy',
                'condition': lambda f: f.get('domain_entropy', 0) > 4.0,
                'score': 15,
                'severity': 'medium',
                'explanation': 'Domain has high entropy (possibly DGA-generated)'
            },
            
            # Suspicious pattern rules
            {
                'name': 'IP address instead of domain',
                'condition': lambda f: f.get('has_ip_address', 0) == 1,
                'score': 30,
                'severity': 'critical',
                'explanation': 'Uses IP address instead of domain name'
            },
            {
                'name': 'Suspicious TLD',
                'condition': lambda f: f.get('has_suspicious_tld', 0) == 1,
                'score': 20,
                'severity': 'high',
                'explanation': 'Uses commonly abused TLD (.tk, .ml, .xyz, etc.)'
            },
            {
                'name': 'Multiple suspicious keywords',
                'condition': lambda f: f.get('suspicious_keyword_count', 0) >= 2,
                'score': 25,
                'severity': 'high',
                'explanation': lambda f: f"Contains {f.get('suspicious_keyword_count', 0)} phishing-related keywords"
            },
            {
                'name': 'At symbol in URL',
                'condition': lambda f: f.get('at_symbol', 0) == 1,
                'score': 20,
                'severity': 'high',
                'explanation': '@ symbol used for URL manipulation'
            },
            {
                'name': 'Double slash redirecting',
                'condition': lambda f: f.get('has_double_slash_redirecting', 0) == 1,
                'score': 18,
                'severity': 'medium',
                'explanation': 'Multiple // detected (redirect obfuscation)'
            },
            {
                'name': 'Prefix/suffix in domain',
                'condition': lambda f: f.get('prefix_suffix_in_domain', 0) == 1,
                'score': 15,
                'severity': 'medium',
                'explanation': 'Domain contains hyphens (brand imitation technique)'
            },
            
            # Port rules
            {
                'name': 'Non-standard port',
                'condition': lambda f: f.get('uses_non_standard_port', 0) == 1,
                'score': 12,
                'severity': 'medium',
                'explanation': 'Uses non-standard port number'
            },
            
            # Security rules
            {
                'name': 'No HTTPS',
                'condition': lambda f: f.get('is_https', 0) == 0,
                'score': 10,
                'severity': 'low',
                'explanation': 'Not using secure HTTPS protocol'
            },
            {
                'name': 'Invalid or missing SSL',
                'condition': lambda f: f.get('has_valid_ssl', 0) == 0 and f.get('is_https', 0) == 1,
                'score': 25,
                'severity': 'high',
                'explanation': 'HTTPS but invalid/missing SSL certificate'
            },
            {
                'name': 'Very new SSL certificate',
                'condition': lambda f: 0 <= f.get('ssl_certificate_age_days', -1) < 30,
                'score': 15,
                'severity': 'medium',
                'explanation': 'SSL certificate issued less than 30 days ago'
            },
            
            # Domain age rules
            {
                'name': 'Recently registered domain',
                'condition': lambda f: f.get('domain_registered_recently', 0) == 1,
                'score': 20,
                'severity': 'high',
                'explanation': 'Domain registered less than 6 months ago'
            },
            {
                'name': 'Very new domain',
                'condition': lambda f: 0 <= f.get('domain_age_days', -1) < 30,
                'score': 30,
                'severity': 'critical',
                'explanation': 'Domain registered less than 30 days ago'
            }
        ]
    
    def calculate_score(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate heuristic score and return detailed analysis
        
        Returns:
            {
                'score': int (0-100),
                'matched_rules': List[Dict],
                'total_possible': int
            }
        """
        matched_rules = []
        total_score = 0
        max_possible_score = 100  # Normalize to 100
        
        # Evaluate each rule
        for rule in self.rules:
            try:
                if rule['condition'](features):
                    explanation = rule['explanation']
                    # Handle lambda explanations
                    if callable(explanation):
                        explanation = explanation(features)
                    
                    matched_rules.append({
                        'name': rule['name'],
                        'score': rule['score'],
                        'severity': rule['severity'],
                        'explanation': explanation
                    })
                    total_score += rule['score']
            except Exception as e:
                logger.error(f"Error evaluating rule {rule['name']}: {e}")
        
        # Normalize score to 0-100 range
        normalized_score = min(total_score, max_possible_score)
        
        # Sort matched rules by score (descending)
        matched_rules.sort(key=lambda x: x['score'], reverse=True)
        
        return {
            'score': normalized_score,
            'matched_rules': matched_rules,
            'rule_count': len(matched_rules)
        }
    
    def get_top_reasons(self, matched_rules: List[Dict], top_n: int = 5) -> List[Dict]:
        """Get top N contributing reasons"""
        return matched_rules[:top_n]


# Global instance
heuristic_scorer = HeuristicScorer()
