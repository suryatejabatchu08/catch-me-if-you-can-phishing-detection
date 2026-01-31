"""
Threat Intelligence Integration
Integrates VirusTotal, AbuseIPDB, and OpenPhish feeds
"""
import requests
import time
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import deque
import logging
from urllib.parse import urlparse

from config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class RateLimiter:
    """Simple rate limiter for API calls"""
    
    def __init__(self, max_calls: int, time_window: int):
        """
        Args:
            max_calls: Maximum number of calls allowed
            time_window: Time window in seconds
        """
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = deque()
    
    def can_call(self) -> bool:
        """Check if a call can be made"""
        now = time.time()
        
        # Remove old calls outside time window
        while self.calls and self.calls[0] < now - self.time_window:
            self.calls.popleft()
        
        # Check if under limit
        return len(self.calls) < self.max_calls
    
    def add_call(self):
        """Record a new call"""
        self.calls.append(time.time())
    
    def wait_time(self) -> float:
        """Get time to wait before next call (seconds)"""
        if self.can_call():
            return 0.0
        
        oldest_call = self.calls[0]
        wait = (oldest_call + self.time_window) - time.time()
        return max(0.0, wait)


class ThreatIntelligence:
    """Unified threat intelligence service"""
    
    def __init__(self):
        self.virustotal_api_key = settings.VIRUSTOTAL_API_KEY
        self.abuseipdb_api_key = settings.ABUSEIPDB_API_KEY
        self.openphish_feed_url = settings.OPENPHISH_FEED_URL
        
        # Rate limiters
        self.vt_limiter = RateLimiter(settings.VIRUSTOTAL_RATE_LIMIT, 60)  # 4 per minute
        self.abuse_limiter = RateLimiter(settings.ABUSEIPDB_RATE_LIMIT, 86400)  # 1000 per day
        
        # Cache for OpenPhish feed
        self.openphish_cache = set()
        self.openphish_last_update = None
        self.openphish_update_interval = 900  # 15 minutes
        
        # Request timeout
        self.timeout = settings.REQUEST_TIMEOUT
    
    def check_all(self, url: str) -> Dict[str, Any]:
        """
        Check URL against all threat intelligence sources
        
        Returns:
            {
                'threat_intel_score': int (0-100),
                'virustotal': {...},
                'abuseipdb': {...},
                'openphish': {...},
                'hits': int,
                'reasons': List[str]
            }
        """
        results = {
            'threat_intel_score': 0,
            'virustotal': {},
            'abuseipdb': {},
            'openphish': {},
            'hits': 0,
            'reasons': []
        }
        
        # Check OpenPhish first (fastest, no API key)
        openphish_result = self.check_openphish(url)
        results['openphish'] = openphish_result
        if openphish_result.get('is_phishing'):
            results['hits'] += 1
            results['threat_intel_score'] += 40  # Critical weight
            results['reasons'].append('Listed in OpenPhish feed (confirmed phishing)')
        
        # Check VirusTotal
        if self.virustotal_api_key:
            vt_result = self.check_virustotal(url)
            results['virustotal'] = vt_result
            
            if vt_result.get('success'):
                detections = vt_result.get('detections', 0)
                if detections >= 5:
                    results['hits'] += 1
                    results['threat_intel_score'] += 35
                    results['reasons'].append(f'VirusTotal: {detections} vendors flagged as malicious')
                elif detections >= 2:
                    results['threat_intel_score'] += 20
                    results['reasons'].append(f'VirusTotal: {detections} vendors flagged (suspicious)')
        
        # Check AbuseIPDB
        if self.abuseipdb_api_key:
            abuse_result = self.check_abuseipdb(url)
            results['abuseipdb'] = abuse_result
            
            if abuse_result.get('success'):
                abuse_score = abuse_result.get('abuse_confidence_score', 0)
                if abuse_score >= 75:
                    results['hits'] += 1
                    results['threat_intel_score'] += 25
                    results['reasons'].append(f'AbuseIPDB: {abuse_score}% abuse confidence')
                elif abuse_score >= 50:
                    results['threat_intel_score'] += 15
                    results['reasons'].append(f'AbuseIPDB: Moderate risk ({abuse_score}%)')
        
        # Normalize score to 0-100
        results['threat_intel_score'] = min(results['threat_intel_score'], 100)
        
        return results
    
    def check_virustotal(self, url: str) -> Dict[str, Any]:
        """Check URL against VirusTotal"""
        if not self.virustotal_api_key:
            return {'success': False, 'error': 'API key not configured'}
        
        # Check rate limit
        if not self.vt_limiter.can_call():
            wait_time = self.vt_limiter.wait_time()
            logger.warning(f"VirusTotal rate limit hit, need to wait {wait_time:.1f}s")
            return {'success': False, 'error': 'rate_limited', 'wait_time': wait_time}
        
        try:
            # URL analysis endpoint
            headers = {
                'x-apikey': self.virustotal_api_key
            }
            
            # Submit URL for analysis
            response = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers=headers,
                data={'url': url},
                timeout=self.timeout
            )
            
            self.vt_limiter.add_call()
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data['data']['id']
                
                # Get analysis results
                analysis_response = requests.get(
                    f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                    headers=headers,
                    timeout=self.timeout
                )
                
                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()
                    stats = analysis_data['data']['attributes']['stats']
                    
                    return {
                        'success': True,
                        'detections': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'harmless': stats.get('harmless', 0),
                        'undetected': stats.get('undetected', 0),
                        'total_vendors': sum(stats.values()),
                        'timestamp': datetime.now().isoformat()
                    }
            
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        except requests.exceptions.Timeout:
            logger.error("VirusTotal request timeout")
            return {'success': False, 'error': 'timeout'}
        except Exception as e:
            logger.error(f"VirusTotal error: {e}")
            return {'success': False, 'error': str(e)}
    
    def check_abuseipdb(self, url: str) -> Dict[str, Any]:
        """Check domain/IP against AbuseIPDB"""
        if not self.abuseipdb_api_key:
            return {'success': False, 'error': 'API key not configured'}
        
        # Check rate limit
        if not self.abuse_limiter.can_call():
            wait_time = self.abuse_limiter.wait_time()
            logger.warning(f"AbuseIPDB rate limit hit, need to wait {wait_time:.1f}s")
            return {'success': False, 'error': 'rate_limited', 'wait_time': wait_time}
        
        try:
            # Extract domain/IP
            parsed = urlparse(url)
            host = parsed.hostname or parsed.netloc
            
            if not host:
                return {'success': False, 'error': 'Could not extract host'}
            
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': host,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params,
                timeout=self.timeout
            )
            
            self.abuse_limiter.add_call()
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('data'):
                    abuse_data = data['data']
                    return {
                        'success': True,
                        'abuse_confidence_score': abuse_data.get('abuseConfidenceScore', 0),
                        'total_reports': abuse_data.get('totalReports', 0),
                        'is_whitelisted': abuse_data.get('isWhitelisted', False),
                        'country': abuse_data.get('countryCode'),
                        'timestamp': datetime.now().isoformat()
                    }
            
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        except requests.exceptions.Timeout:
            logger.error("AbuseIPDB request timeout")
            return {'success': False, 'error': 'timeout'}
        except Exception as e:
            logger.error(f"AbuseIPDB error: {e}")
            return {'success': False, 'error': str(e)}
    
    def check_openphish(self, url: str) -> Dict[str, Any]:
        """Check URL against OpenPhish feed"""
        try:
            # Update cache if needed
            self._update_openphish_cache()
            
            # Normalize URL
            normalized_url = url.lower().strip()
            
            # Check if URL is in feed
            is_phishing = normalized_url in self.openphish_cache
            
            return {
                'success': True,
                'is_phishing': is_phishing,
                'feed_size': len(self.openphish_cache),
                'last_updated': self.openphish_last_update.isoformat() if self.openphish_last_update else None
            }
            
        except Exception as e:
            logger.error(f"OpenPhish error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _update_openphish_cache(self):
        """Update OpenPhish feed cache"""
        now = datetime.now()
        
        # Check if update needed
        if (self.openphish_last_update and 
            (now - self.openphish_last_update).total_seconds() < self.openphish_update_interval):
            return
        
        try:
            logger.info("Updating OpenPhish feed...")
            response = requests.get(
                self.openphish_feed_url,
                timeout=10
            )
            
            if response.status_code == 200:
                # Parse feed (one URL per line)
                urls = set(line.strip().lower() for line in response.text.split('\n') if line.strip())
                self.openphish_cache = urls
                self.openphish_last_update = now
                logger.info(f"OpenPhish feed updated: {len(urls)} URLs")
            else:
                logger.error(f"Failed to update OpenPhish feed: HTTP {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error updating OpenPhish feed: {e}")


# Global instance
threat_intelligence = ThreatIntelligence()
