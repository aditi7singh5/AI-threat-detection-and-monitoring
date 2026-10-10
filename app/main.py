import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
import json
import os

from app.config import settings
from app.api import dashboard, logs, alerts, simulation
from app.core.simulator import simulator
from app.core.database import db

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: launch telemetry simulator loop
    task = asyncio.create_task(simulator.start_loop())
    yield
    # Shutdown
    simulator.is_running = False
    task.cancel()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(dashboard.router, prefix=settings.API_V1_STR)
app.include_router(logs.router, prefix=settings.API_V1_STR)
app.include_router(alerts.router, prefix=settings.API_V1_STR)
app.include_router(simulation.router, prefix=settings.API_V1_STR)

# SSE Real-time Telemetry Stream
@app.get("/api/stream")
async def stream_events(request: Request):
    async def event_generator():
        last_log_id = None
        while True:
            if await request.is_disconnected():
                break
            latest_logs = db.get_logs(limit=1)
            if latest_logs:
                current = latest_logs[0]
                if current.id != last_log_id:
                    last_log_id = current.id
                    payload = {
                        "metrics": db.get_metrics().model_dump(),
                        "latest_log": current.model_dump(),
                        "latest_alerts": [a.model_dump() for a in db.get_alerts(limit=5)]
                    }
                    yield f"data: {json.dumps(payload)}\n\n"
            await asyncio.sleep(1.5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

# Mount Static Files
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
def read_root():
    return FileResponse(os.path.join(static_dir, "index.html"))
