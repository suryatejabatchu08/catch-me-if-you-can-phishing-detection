"""
URL Feature Extraction Module
Extracts advanced features from URLs for phishing detection
"""
import re
import math
import ssl
import socket
try:
    import whois
except ImportError:
    try:
        import python_whois as whois
    except ImportError:
        whois = None
import tldextract
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class URLFeatureExtractor:
    """Extract comprehensive features from URLs"""
    
    def __init__(self):
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
            '.click', '.link', '.stream', '.download', '.loan', '.win'
        }
        self.suspicious_keywords = {
            'verify', 'account', 'update', 'secure', 'banking', 'confirm',
            'login', 'signin', 'password', 'urgent', 'suspended', 'locked',
            'validate', 'restore', 'limited', 'unusual', 'activity'
        }
    
    def extract_all_features(self, url: str) -> Dict[str, Any]:
        """Extract all URL features"""
        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            features = {
                # Basic structure
                'url': url,
                'protocol': parsed.scheme,
                'domain': extracted.domain + '.' + extracted.suffix,
                'subdomain': extracted.subdomain,
                'path': parsed.path,
                'query': parsed.query,
                
                # Length features
                'url_length': len(url),
                'domain_length': len(extracted.domain),
                'path_length': len(parsed.path),
                'subdomain_length': len(extracted.subdomain) if extracted.subdomain else 0,
                
                # Structural features
                'subdomain_count': len(extracted.subdomain.split('.')) if extracted.subdomain else 0,
                'path_depth': len([p for p in parsed.path.split('/') if p]),
                'query_param_count': len(parse_qs(parsed.query)),
                
                # Character analysis
                'digit_count': sum(c.isdigit() for c in url),
                'letter_count': sum(c.isalpha() for c in url),
                'special_char_count': sum(not c.isalnum() for c in url),
                'hyphen_count': url.count('-'),
                'underscore_count': url.count('_'),
                'dot_count': url.count('.'),
                'slash_count': url.count('/'),
                'at_symbol': 1 if '@' in url else 0,
                
                # Ratios
                'digit_ratio': self._safe_ratio(sum(c.isdigit() for c in url), len(url)),
                'special_char_ratio': self._safe_ratio(sum(not c.isalnum() for c in url), len(url)),
                
                # Entropy
                'url_entropy': self._calculate_entropy(url),
                'domain_entropy': self._calculate_entropy(extracted.domain),
                
                # Suspicious patterns
                'has_ip_address': 1 if self._has_ip_address(url) else 0,
                'has_suspicious_tld': 1 if '.' + extracted.suffix in self.suspicious_tlds else 0,
                'suspicious_keyword_count': self._count_suspicious_keywords(url.lower()),
                'has_double_slash_redirecting': 1 if url.count('//') > 1 else 0,
                'prefix_suffix_in_domain': 1 if '-' in extracted.domain else 0,
                
                # Port analysis
                'uses_non_standard_port': self._check_non_standard_port(url),
                'port': parsed.port if parsed.port else (443 if parsed.scheme == 'https' else 80),
                
                # HTTPS
                'is_https': 1 if parsed.scheme == 'https' else 0,
            }
            
            # Add advanced features (may be slower)
            features.update(self._extract_ssl_features(url))
            features.update(self._extract_domain_age(extracted.domain + '.' + extracted.suffix))
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features from {url}: {e}")
            return self._get_default_features(url)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in freq.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return round(entropy, 4)
    
    def _safe_ratio(self, numerator: int, denominator: int) -> float:
        """Safely calculate ratio"""
        if denominator == 0:
            return 0.0
        return round(numerator / denominator, 4)
    
    def _has_ip_address(self, url: str) -> bool:
        """Check if URL contains IP address instead of domain"""
        ip_pattern = re.compile(
            r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
            r'([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
        )
        return bool(ip_pattern.search(url))
    
    def _count_suspicious_keywords(self, url_lower: str) -> int:
        """Count suspicious keywords in URL"""
        return sum(1 for keyword in self.suspicious_keywords if keyword in url_lower)
    
    def _check_non_standard_port(self, url: str) -> int:
        """Check if URL uses non-standard port"""
        parsed = urlparse(url)
        if parsed.port:
            standard_ports = {80, 443, 8080}
            return 0 if parsed.port in standard_ports else 1
        return 0
    
    def _extract_ssl_features(self, url: str) -> Dict[str, Any]:
        """Extract SSL certificate features"""
        features = {
            'has_valid_ssl': 0,
            'ssl_certificate_age_days': -1,
            'ssl_issuer_trusted': 0
        }
        
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                return features
            
            hostname = parsed.hostname
            if not hostname:
                return features
            
            # Get SSL certificate with timeout
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        features['has_valid_ssl'] = 1
                        
                        # Calculate certificate age
                        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        age_days = (datetime.now() - not_before).days
                        features['ssl_certificate_age_days'] = age_days
                        
                        # Check if certificate is very new (< 30 days = suspicious)
                        features['ssl_issuer_trusted'] = 1 if age_days > 30 else 0
        
        except Exception as e:
            logger.debug(f"SSL check failed for {url}: {e}")
        
        return features
    
    def _extract_domain_age(self, domain: str) -> Dict[str, Any]:
        """Extract domain registration age using WHOIS"""
        features = {
            'domain_age_days': -1,
            'domain_registered_recently': 0
        }
        
        if whois is None:
            logger.debug("WHOIS module not available")
            return features
        
        try:
            w = whois.whois(domain)
            
            if w.creation_date:
                creation_date = w.creation_date
                # Handle list of dates
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                age_days = (datetime.now() - creation_date).days
                features['domain_age_days'] = age_days
                
                # Domains < 180 days old are suspicious
                features['domain_registered_recently'] = 1 if age_days < 180 else 0
        
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
        
        return features
    
    def _get_default_features(self, url: str) -> Dict[str, Any]:
        """Return default features when extraction fails"""
        return {
            'url': url,
            'url_length': len(url),
            'error': True
        }


# Global instance
url_feature_extractor = URLFeatureExtractor()
