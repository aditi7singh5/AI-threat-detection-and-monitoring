from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from app.core.database import db
from app.models.schemas import SecurityAlert, SeverityLevel, AlertStatus, MitigationRequest

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("", response_model=List[SecurityAlert])
def get_alerts(
    limit: int = Query(default=50, ge=1, le=200),
    severity: Optional[SeverityLevel] = None,
    status: Optional[AlertStatus] = None
):
    return db.get_alerts(limit=limit, severity=severity, status=status)

@router.get("/{alert_id}", response_model=SecurityAlert)
def get_alert_detail(alert_id: str):
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.post("/{alert_id}/mitigate")
def mitigate_alert(alert_id: str, req: MitigationRequest):
    success = db.update_alert_status(alert_id, AlertStatus.MITIGATED)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "status": "success",
        "message": f"Mitigation executed: {req.action_type}",
        "alert_id": alert_id,
        "new_status": AlertStatus.MITIGATED
    }

@router.post("/{alert_id}/dismiss")
def dismiss_alert(alert_id: str):
    success = db.update_alert_status(alert_id, AlertStatus.DISMISSED)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "status": "success",
        "message": "Alert marked as dismissed",
        "alert_id": alert_id,
        "new_status": AlertStatus.DISMISSED
    }
