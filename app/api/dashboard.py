from fastapi import APIRouter
from app.core.database import db
from app.models.schemas import SystemMetrics

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats", response_model=SystemMetrics)
def get_dashboard_stats():
    return db.get_metrics()

@router.get("/mitre-coverage")
def get_mitre_coverage():
    return db.get_mitre_coverage()
