"""
API v1 Router
"""
from fastapi import APIRouter
from api.v1 import routes

router = APIRouter()

# Include all v1 routes
router.include_router(routes.router, tags=["Analysis"])
