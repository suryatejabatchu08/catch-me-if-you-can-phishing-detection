"""
PhishGuard AI - FastAPI Backend
Real-time Phishing Detection API
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time
import logging

from config import get_settings
from api.v1 import router as api_v1_router
from ml.model import ml_model

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info(f"Starting {settings.APP_NAME} {settings.API_VERSION}")
    logger.info("Loading ML models...")
    
    # Load ML models
    try:
        ml_model.load_models()
        logger.info("✅ ML models loaded successfully")
    except Exception as e:
        logger.error(f"❌ Failed to load ML models: {e}")
        logger.warning("⚠️  API will run with degraded functionality (no ML scoring)")
    
    yield
    
    # Shutdown
    logger.info("Shutting down gracefully...")
    # TODO: Close connections, save cache, cleanup


# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description="Real-time Phishing Detection and Prevention API",
    version=settings.MODEL_VERSION,
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add processing time to response headers"""
    start_time = time.time()
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000  # Convert to ms
    response.headers["X-Process-Time"] = f"{process_time:.2f}ms"
    
    # Log slow requests
    if process_time > settings.TARGET_LATENCY_MS:
        logger.warning(f"Slow request: {request.url.path} took {process_time:.2f}ms")
    
    return response


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle uncaught exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "path": str(request.url.path)
        }
    )


# Include API routers
app.include_router(api_v1_router, prefix=settings.API_PREFIX)


@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "name": settings.APP_NAME,
        "version": settings.MODEL_VERSION,
        "status": "operational",
        "api_docs": f"{settings.API_PREFIX}/docs",
        "endpoints": {
            "url_analysis": f"{settings.API_PREFIX}/analyze/url",
            "email_analysis": f"{settings.API_PREFIX}/analyze/email",
            "threat_intel": f"{settings.API_PREFIX}/threat-intel/domain/{{domain}}"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": settings.MODEL_VERSION
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info"
    )
