from fastapi import APIRouter
from app.core.database import db
from app.core.simulator import simulator
from app.models.schemas import AttackInjectionRequest

router = APIRouter(prefix="/simulation", tags=["Simulation"])

@router.post("/start")
def start_simulation():
    db.simulator_active = True
    return {"status": "active", "message": "Telemetry simulation started"}

@router.post("/stop")
def stop_simulation():
    db.simulator_active = False
    return {"status": "paused", "message": "Telemetry simulation paused"}

@router.post("/inject-attack")
def inject_attack_scenario(req: AttackInjectionRequest):
    event = simulator.inject_attack(req.scenario)
    return {
        "status": "attack_injected",
        "scenario": req.scenario,
        "event_id": event.id,
        "target_identity": event.identity,
        "message": f"Injected cyber attack scenario: {req.scenario}"
    }
