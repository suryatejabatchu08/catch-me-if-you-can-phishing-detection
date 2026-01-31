"""
Caching Layer
Redis-based caching with TTL management
"""
import json
import hashlib
from typing import Optional, Any
from datetime import datetime, timedelta
import logging

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logging.warning("Redis not available, using in-memory cache")

from config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class Cache:
    """Thread-safe caching layer with TTL support"""
    
    def __init__(self):
        self.redis_client = None
        self.memory_cache = {}  # Fallback in-memory cache
        self.use_redis = REDIS_AVAILABLE
        
        if REDIS_AVAILABLE:
            try:
                self.redis_client = redis.Redis(
                    host=settings.REDIS_HOST,
                    port=settings.REDIS_PORT,
                    db=settings.REDIS_DB,
                    password=settings.REDIS_PASSWORD if settings.REDIS_PASSWORD else None,
                    decode_responses=True,
                    socket_timeout=2,
                    socket_connect_timeout=2
                )
                # Test connection
                self.redis_client.ping()
                logger.info("✅ Redis cache connected")
            except Exception as e:
                logger.warning(f"Redis unavailable, using in-memory cache: {e}")
                self.use_redis = False
                self.redis_client = None
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            if self.use_redis and self.redis_client:
                value = self.redis_client.get(key)
                if value:
                    return json.loads(value)
            else:
                # In-memory cache with expiry check
                if key in self.memory_cache:
                    data, expires_at = self.memory_cache[key]
                    if expires_at and datetime.now() > expires_at:
                        del self.memory_cache[key]
                        return None
                    return data
        except Exception as e:
            logger.error(f"Cache get error: {e}")
        
        return None
    
    def set(self, key: str, value: Any, ttl: int = None):
        """
        Set value in cache with optional TTL
        
        Args:
            key: Cache key
            value: Value to cache (will be JSON serialized)
            ttl: Time to live in seconds (None = no expiration)
        """
        try:
            if self.use_redis and self.redis_client:
                serialized = json.dumps(value)
                if ttl:
                    self.redis_client.setex(key, ttl, serialized)
                else:
                    self.redis_client.set(key, serialized)
            else:
                # In-memory cache
                expires_at = None
                if ttl:
                    expires_at = datetime.now() + timedelta(seconds=ttl)
                self.memory_cache[key] = (value, expires_at)
                
                # Limit memory cache size
                if len(self.memory_cache) > 10000:
                    # Remove 10% oldest entries
                    to_remove = int(len(self.memory_cache) * 0.1)
                    for old_key in list(self.memory_cache.keys())[:to_remove]:
                        del self.memory_cache[old_key]
        
        except Exception as e:
            logger.error(f"Cache set error: {e}")
    
    def delete(self, key: str):
        """Delete key from cache"""
        try:
            if self.use_redis and self.redis_client:
                self.redis_client.delete(key)
            else:
                self.memory_cache.pop(key, None)
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
    
    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        try:
            if self.use_redis and self.redis_client:
                return bool(self.redis_client.exists(key))
            else:
                if key in self.memory_cache:
                    _, expires_at = self.memory_cache[key]
                    if expires_at and datetime.now() > expires_at:
                        del self.memory_cache[key]
                        return False
                    return True
                return False
        except Exception as e:
            logger.error(f"Cache exists error: {e}")
            return False
    
    def clear(self):
        """Clear entire cache"""
        try:
            if self.use_redis and self.redis_client:
                self.redis_client.flushdb()
            else:
                self.memory_cache.clear()
            logger.info("Cache cleared")
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        try:
            if self.use_redis and self.redis_client:
                info = self.redis_client.info()
                return {
                    'type': 'redis',
                    'connected': True,
                    'keys': self.redis_client.dbsize(),
                    'memory_used': info.get('used_memory_human'),
                    'hits': info.get('keyspace_hits', 0),
                    'misses': info.get('keyspace_misses', 0)
                }
            else:
                return {
                    'type': 'memory',
                    'connected': True,
                    'keys': len(self.memory_cache),
                    'hits': 'N/A',
                    'misses': 'N/A'
                }
        except Exception as e:
            logger.error(f"Cache stats error: {e}")
            return {'type': 'unknown', 'connected': False, 'error': str(e)}


class ThreatCache:
    """Specialized cache for threat analysis results"""
    
    def __init__(self, cache: Cache):
        self.cache = cache
        self.ttl_positive = settings.CACHE_TTL_POSITIVE  # 7 days
        self.ttl_negative = settings.CACHE_TTL_NEGATIVE  # 24 hours
        self.ttl_critical = settings.CACHE_TTL_CRITICAL  # Permanent (-1)
    
    def get_url_analysis(self, url: str) -> Optional[dict]:
        """Get cached URL analysis result"""
        key = self._make_url_key(url)
        return self.cache.get(key)
    
    def set_url_analysis(self, url: str, result: dict):
        """
        Cache URL analysis result with appropriate TTL
        
        TTL Rules (from PRD):
        - Positive hits (phishing detected): 7 days
        - Negative hits (safe): 24 hours
        - Critical hits (high threat): Permanent until manual review
        """
        key = self._make_url_key(url)
        
        # Determine TTL based on threat level
        threat_score = result.get('threat_score', 0)
        risk_level = result.get('risk_level', 'safe')
        
        if risk_level == 'critical' or threat_score >= 90:
            # Critical threats cached permanently
            ttl = None
            logger.info(f"Caching critical threat permanently: {url}")
        elif threat_score >= 60:
            # Positive hits (phishing/suspicious)
            ttl = self.ttl_positive
        else:
            # Negative hits (safe)
            ttl = self.ttl_negative
        
        self.cache.set(key, result, ttl)
    
    def get_threat_intel(self, source: str, identifier: str) -> Optional[dict]:
        """Get cached threat intelligence result"""
        key = f"threatintel:{source}:{self._hash(identifier)}"
        return self.cache.get(key)
    
    def set_threat_intel(self, source: str, identifier: str, result: dict, ttl: int = None):
        """Cache threat intelligence result"""
        key = f"threatintel:{source}:{self._hash(identifier)}"
        if ttl is None:
            ttl = self.ttl_negative
        self.cache.set(key, result, ttl)
    
    def _make_url_key(self, url: str) -> str:
        """Generate cache key for URL"""
        # Hash URL to create consistent key
        url_hash = self._hash(url.lower().strip())
        return f"url_analysis:{url_hash}"
    
    def _hash(self, text: str) -> str:
        """Generate hash of text"""
        return hashlib.sha256(text.encode()).hexdigest()[:16]


# Global instances
cache = Cache()
threat_cache = ThreatCache(cache)
