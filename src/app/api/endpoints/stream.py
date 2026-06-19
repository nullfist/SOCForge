import asyncio
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, HTTPException, Query
from sqlalchemy.orm import Session
from src.app.db.session import get_db
from src.app.db.models import Company
from src.app.core.environment_generator import generate_company_environment
from src.app.core.timeline_engine import generate_timeline
from src.app.telemetry.windows import format_windows_event
from src.app.telemetry.linux import format_linux_event
from src.app.telemetry.network import format_network_event

router = APIRouter()

# Share active streaming configurations with the core app
active_simulations = {}

@router.websocket("/stream/{simulation_run_id}")
async def websocket_stream(websocket: WebSocket, simulation_run_id: str, db: Session = Depends(get_db)):
    await websocket.accept()
    
    active_simulations[simulation_run_id] = {
        "status": "RUNNING",
        "speed": 5
    }
    
    company = db.query(Company).first()
    if not company:
        company = generate_company_environment(db, "DefaultCorp", "Technology", "small")
        
    dataset = generate_timeline(db, company, "APT Campaign", 12)
    events = dataset["events"]
    
    try:
        for idx, event in enumerate(events):
            state = active_simulations.get(simulation_run_id, {"status": "STOPPED", "speed": 5})
            while state["status"] == "PAUSED":
                await asyncio.sleep(0.5)
                state = active_simulations.get(simulation_run_id, {"status": "STOPPED", "speed": 5})
                
            if state["status"] == "STOPPED":
                break
                
            if event.get("os_type") == "Windows":
                fmt_event = format_windows_event(event)
            elif event.get("os_type") == "Linux":
                fmt_event = format_linux_event(event)
            else:
                fmt_event = format_network_event(event)
                
            await websocket.send_json({
                "index": idx,
                "event": fmt_event
            })
            
            delay = 1.0 / state["speed"]
            await asyncio.sleep(delay)
            
    except WebSocketDisconnect:
        pass
    finally:
        active_simulations.pop(simulation_run_id, None)

@router.post("/simulations/{simulation_run_id}/control")
def control_simulation(
    simulation_run_id: str,
    action: str = Query(..., description="actions: pause, resume, stop, speed_up"),
    value: int = Query(1, description="Speed multiplier for speed_up action")
):
    if simulation_run_id not in active_simulations:
        raise HTTPException(status_code=404, detail="Simulation run not active or not found")
        
    if action == "pause":
        active_simulations[simulation_run_id]["status"] = "PAUSED"
    elif action == "resume":
        active_simulations[simulation_run_id]["status"] = "RUNNING"
    elif action == "stop":
        active_simulations[simulation_run_id]["status"] = "STOPPED"
    elif action == "speed_up":
        active_simulations[simulation_run_id]["speed"] = value
        
    return {"status": "success", "config": active_simulations[simulation_run_id]}
