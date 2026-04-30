from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
from dotenv import load_dotenv
import threading
import asyncio

from log_watcher import tail_file
from live_processing import process_live_log

from dashboard_routes import router as dashboard_router
from api_routes import router as api_router
import app_state
from state_loader import restore_state

from database import engine, Base
import models


# Load environment variables
load_dotenv()

app = FastAPI()
Base.metadata.create_all(bind=engine)
app.include_router(dashboard_router)
app.include_router(api_router)

restore_state(app_state.live_logs)

async def broadcast_log(data):
    for client in app_state.clients:
        try:
            await client.send_json(data)
        except Exception:
            if client in app_state.clients:
               app_state.clients.remove(client)

def handle_live_log(log_line):
    process_live_log(
        log_line=log_line,
        live_logs=app_state.live_logs,
        max_logs=app_state.MAX_LOGS,
        main_loop=app_state.main_loop,
        broadcast_callback=broadcast_log
    )


@app.on_event("startup")
async def start_log_watcher():
    global main_loop
    app_state.main_loop = asyncio.get_running_loop()

    watcher_thread = threading.Thread(
        target=tail_file,
        args=("test.log", handle_live_log),
        daemon=True
    )
    watcher_thread.start()


@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    app_state.clients.append(websocket)

    try:
        while True:
            await websocket.receive_text()  # Keep connection alive
    except Exception:
        if websocket in app_state.clients:
            app_state.clients.remove(websocket)

def trigger_alert(entry):
    if entry["severity"] == "HIGH":
        print(f"ALERT: High threat detected from {entry['features'].get('ip', 'unknown')} - {entry['log']}")

