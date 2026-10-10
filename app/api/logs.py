from fastapi import APIRouter, Query
from typing import List, Optional
from app.core.database import db
from app.core.simulator import simulator
from app.models.schemas import LogEvent, CloudProvider

router = APIRouter(prefix="/logs", tags=["Logs"])

@router.get("", response_model=List[LogEvent])
def get_logs(
    limit: int = Query(default=100, ge=1, le=500),
    provider: Optional[CloudProvider] = None
):
    return db.get_logs(limit=limit, provider=provider)

@router.post("/ingest", response_model=LogEvent)
def ingest_log_event(log: LogEvent):
    simulator.process_and_store_event(log)
    return log
