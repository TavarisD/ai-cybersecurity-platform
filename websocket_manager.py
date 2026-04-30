from fastapi import WebSocket

active_connections = []

async def connect(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)

def disconnect(websocket: WebSocket):
    active_connections.remove(websocket)

async def broadcast(message: dict):
    for connection in active_connections:
        await connection.send_json(message)