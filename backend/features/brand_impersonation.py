"""
Brand Impersonation Detector
Detects when pages impersonate trusted brands using visual/CSS analysis
"""
from typing import Dict, Any, Optional, List
import re
import logging
import tldextract

logger = logging.getLogger(__name__)


class BrandImpersonationDetector:
    """Detect brand impersonation through page content analysis"""
    
    def __init__(self):
        # Brand signatures (colors, patterns, common terms)
        self.brand_signatures = self._load_brand_signatures()
    
    def _load_brand_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load brand visual/textual signatures"""
        return {
            # Tech Giants
            'google': {
                'colors': ['#4285F4', '#EA4335', '#FBBC04', '#34A853'],
                'keywords': ['google', 'gmail', 'sign in', 'account'],
                'patterns': [r'google\s+account', r'gmail\s+sign', r'@gmail\.com']
            },
            'microsoft': {
                'colors': ['#00A4EF', '#7FBA00', '#FFB900', '#F25022'],
                'keywords': ['microsoft', 'office', 'outlook', 'onedrive', 'microsoft 365'],
                'patterns': [r'microsoft\s+account', r'office\s+365', r'outlook\s+sign']
            },
            'apple': {
                'colors': ['#000000', '#FFFFFF', '#555555'],
                'keywords': ['apple', 'icloud', 'apple id', 'app store'],
                'patterns': [r'apple\s+id', r'icloud\s+sign', r'@icloud\.com']
            },
            'amazon': {
                'colors': ['#FF9900', '#146EB4', '#232F3E'],
                'keywords': ['amazon', 'prime', 'aws', 'sign in'],
                'patterns': [r'amazon\s+account', r'amazon\s+prime', r'aws\s+console']
            },
            'facebook': {
                'colors': ['#1877F2', '#4267B2', '#385898'],
                'keywords': ['facebook', 'meta', 'log in', 'sign up'],
                'patterns': [r'facebook\s+log', r'@facebook\.com', r'meta\s+account']
            },
            'meta': {
                'colors': ['#0081FB', '#0668E1'],
                'keywords': ['meta', 'facebook', 'instagram', 'whatsapp'],
                'patterns': [r'meta\s+account', r'meta\s+quest']
            },
            
            # Financial
            'paypal': {
                'colors': ['#003087', '#009CDE', '#012169'],
                'keywords': ['paypal', 'payment', 'send money', 'log in'],
                'patterns': [r'paypal\s+account', r'paypal\s+log', r'@paypal\.com']
            },
            'chase': {
                'colors': ['#117ACA', '#005CB9'],
                'keywords': ['chase', 'jpmorgan', 'bank', 'sign in'],
                'patterns': [r'chase\s+bank', r'chase\s+online', r'jpmorgan\s+chase']
            },
            'bankofamerica': {
                'colors': ['#012169', '#E31837'],
                'keywords': ['bank of america', 'bofa', 'online banking'],
                'patterns': [r'bank\s+of\s+america', r'bofa\s+online']
            },
            'wellsfargo': {
                'colors': ['#D71E28', '#FFCD41'],
                'keywords': ['wells fargo', 'banking', 'sign on'],
                'patterns': [r'wells\s+fargo', r'wellsfargo\s+online']
            },
            
            # Communication
            'outlook': {
                'colors': ['#0078D4', '#106EBE'],
                'keywords': ['outlook', 'hotmail', 'live', 'sign in'],
                'patterns': [r'outlook\s+sign', r'@outlook\.com', r'@hotmail\.com']
            },
            'yahoo': {
                'colors': ['#5F01D1', '#720E9E'],
                'keywords': ['yahoo', 'mail', 'sign in'],
                'patterns': [r'yahoo\s+mail', r'@yahoo\.com', r'yahoo\s+account']
            },
            
            # Social Media
            'linkedin': {
                'colors': ['#0A66C2', '#0077B5'],
                'keywords': ['linkedin', 'professional network', 'sign in'],
                'patterns': [r'linkedin\s+sign', r'@linkedin\.com']
            },
            'twitter': {
                'colors': ['#1DA1F2', '#14171A'],
                'keywords': ['twitter', 'tweet', 'log in'],
                'patterns': [r'twitter\s+log', r'@twitter\.com']
            },
            'instagram': {
                'colors': ['#E4405F', '#833AB4', '#FD1D1D', '#F77737'],
                'keywords': ['instagram', 'insta', 'log in'],
                'patterns': [r'instagram\s+log', r'@instagram\.com']
            },
            
            # E-commerce
            'ebay': {
                'colors': ['#E53238', '#F5AF02', '#86B817', '#0064D2'],
                'keywords': ['ebay', 'buy', 'sell', 'sign in'],
                'patterns': [r'ebay\s+sign', r'@ebay\.com']
            },
            'walmart': {
                'colors': ['#0071CE', '#FFC220'],
                'keywords': ['walmart', 'shop', 'sign in'],
                'patterns': [r'walmart\s+account', r'walmart\s+online']
            },
            
            # Crypto
            'coinbase': {
                'colors': ['#0052FF', '#1652F0'],
                'keywords': ['coinbase', 'crypto', 'bitcoin', 'sign in'],
                'patterns': [r'coinbase\s+sign', r'coinbase\s+wallet']
            },
            'binance': {
                'colors': ['#F3BA2F', '#FCD535'],
                'keywords': ['binance', 'crypto', 'trading', 'log in'],
                'patterns': [r'binance\s+log', r'binance\s+account']
            }
        }
    
    def detect_impersonation(
        self, 
        url: str, 
        page_title: Optional[str] = None,
        page_text: Optional[str] = None,
        css_colors: Optional[list] = None
    ) -> Dict[str, Any]:
        """
        Detect brand impersonation based on page content
        
        Args:
            url: The URL being analyzed
            page_title: Page title/meta description
            page_text: Text content from page
            css_colors: List of hex colors found in CSS
        
        Returns:
            {
                'is_impersonating': bool,
                'impersonation_score': int (0-100),
                'suspected_brand': str or None,
                'confidence': float,
                'indicators': List[str]
            }
        """
        import tldextract
        
        try:
            extracted = tldextract.extract(url)
            domain = extracted.domain.lower()
            full_domain = f"{domain}.{extracted.suffix}".lower()
            
            indicators = []
            suspected_brand = None
            max_score = 0
            
            # Combine all text for analysis
            combined_text = ' '.join(filter(None, [
                page_title or '',
                page_text or '',
                url
            ])).lower()
            
            # Check each brand
            for brand, signature in self.brand_signatures.items():
                score = 0
                brand_indicators = []
                
                # Check if domain contains brand name (legitimate)
                if brand in domain or brand.replace(' ', '') in domain:
                    # This is likely the legitimate site
                    continue
                
                # Check if brand name appears in title/content but NOT in domain
                keyword_matches = 0
                for keyword in signature['keywords']:
                    if keyword.lower() in combined_text:
                        keyword_matches += 1
                        brand_indicators.append(f"Contains '{keyword}' keyword")
                
                if keyword_matches >= 2:
                    score += 30
                
                # Check patterns
                pattern_matches = 0
                for pattern in signature['patterns']:
                    if re.search(pattern, combined_text, re.IGNORECASE):
                        pattern_matches += 1
                        brand_indicators.append(f"Matches {brand} pattern")
                
                if pattern_matches >= 1:
                    score += 25
                
                # Check color scheme (if CSS colors provided)
                if css_colors:
                    color_matches = 0
                    for brand_color in signature['colors']:
                        # Normalize colors
                        normalized_colors = [c.upper() for c in css_colors]
                        if brand_color.upper() in normalized_colors:
                            color_matches += 1
                    
                    if color_matches >= 2:
                        score += 20
                        brand_indicators.append(f"Uses {brand}'s color scheme ({color_matches} colors matched)")
                
                # Check title specifically
                if page_title:
                    title_lower = page_title.lower()
                    if any(kw in title_lower for kw in signature['keywords'][:3]):
                        score += 15
                        brand_indicators.append(f"Page title references {brand}")
                
                # Domain dissimilarity penalty
                from Levenshtein import distance
                domain_distance = distance(domain, brand.replace(' ', ''))
                if domain_distance > 3:
                    score += 10
                    brand_indicators.append(f"Domain doesn't match {brand} (distance: {domain_distance})")
                
                # Update if this is the best match
                if score > max_score and score >= 40:  # Threshold for impersonation
                    max_score = score
                    suspected_brand = brand
                    indicators = brand_indicators
            
            # Normalize score to 0-100
            impersonation_score = min(max_score, 100)
            
            # Calculate confidence
            confidence = min(impersonation_score / 100, 0.95)
            
            # Determine if impersonating
            is_impersonating = (
                suspected_brand is not None and
                impersonation_score >= 40 and
                suspected_brand not in full_domain
            )
            
            return {
                'is_impersonating': is_impersonating,
                'impersonation_score': impersonation_score,
                'suspected_brand': suspected_brand,
                'confidence': round(confidence, 2),
                'indicators': indicators[:5],  # Top 5 indicators
                'brand_in_title': bool(suspected_brand and page_title and suspected_brand in page_title.lower())
            }
            
        except Exception as e:
            logger.error(f"Error in brand impersonation detection: {e}")
            return self._get_default_result()
    
    def _get_default_result(self) -> Dict[str, Any]:
        """Return default result on error"""
        return {
            'is_impersonating': False,
            'impersonation_score': 0,
            'suspected_brand': None,
            'confidence': 0.0,
            'indicators': [],
            'brand_in_title': False
        }
    
    def get_supported_brands(self) -> list:
        """Get list of brands with impersonation detection"""
        return sorted(self.brand_signatures.keys())


# Global instance
brand_impersonation_detector = BrandImpersonationDetector()
