"""
Configuration management for PhishGuard AI Backend
"""
import os
from typing import Optional
try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings"""
    
    # API Configuration
    API_VERSION: str = "v1"
    API_PREFIX: str = f"/api/{API_VERSION}"
    APP_NAME: str = "PhishGuard AI"
    DEBUG: bool = False
    
    # Threat Intelligence API Keys
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    OPENPHISH_FEED_URL: str = "https://openphish.com/feed.txt"
    
    # Redis Configuration
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: Optional[str] = None
    
    # Supabase Configuration
    SUPABASE_URL: Optional[str] = None
    SUPABASE_KEY: Optional[str] = None
    
    # Performance Settings
    MAX_WORKERS: int = 4
    REQUEST_TIMEOUT: int = 3
    CACHE_TTL_POSITIVE: int = 604800  # 7 days
    CACHE_TTL_NEGATIVE: int = 86400   # 24 hours
    CACHE_TTL_CRITICAL: int = -1      # Permanent (until manual review)
    
    # Rate Limiting
    VIRUSTOTAL_RATE_LIMIT: int = 4    # requests per minute
    ABUSEIPDB_RATE_LIMIT: int = 1000  # requests per day
    
    # ML Model Configuration
    ML_MODEL_PATH: str = "models/"
    MODEL_VERSION: str = "v1.0"
    ML_INFERENCE_TIMEOUT: float = 0.05  # 50ms
    
    # Performance Targets
    TARGET_LATENCY_MS: int = 200
    TARGET_ML_INFERENCE_MS: int = 50
    
    # Threat Scoring Weights
    WEIGHT_ML: float = 0.40
    WEIGHT_HEURISTIC: float = 0.25
    WEIGHT_THREAT_INTEL: float = 0.30
    WEIGHT_LOOKALIKE: float = 0.05
    
    # Risk Thresholds
    THRESHOLD_SAFE: int = 30
    THRESHOLD_SUSPICIOUS: int = 60
    THRESHOLD_DANGEROUS: int = 85
    THRESHOLD_CRITICAL: int = 86
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()
