import asyncio
import json
import threading
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from logs import monitor_security_events
from statuses import Statuses

app = FastAPI(
    title="LVNΛR GUΛRD API",
    version="0.1.0",
    description="The API Route for LunarGuard's backend services",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/status/cpu", tags=["Status"])
def get_cpu_status():
    """Get current CPU usage percentage"""
    return {"cpu": Statuses.get_cpu_usage()}


@app.get("/status/memory", tags=["Status"])
def get_memory_status():
    """Get current memory usage percentage"""
    return {"memory": Statuses.get_memory_usage()}


@app.get("/status/disk", tags=["Status"])
def get_disk_status():
    """Get current disk usage percentage"""
    return {"disk": Statuses.get_disk_usage()}


@app.get("/status/network", tags=["Status"])
def get_network_status():
    """Get current network usage"""
    return {"network": Statuses.get_network_usage()}


@app.websocket("/ws/logs")
async def logs_websocket(websocket: WebSocket):
    await websocket.accept()

    await websocket.send_text(
        json.dumps(
            {
                "time": datetime.now().strftime("%H:%M:%S"),
                "tag": "[SYS]",
                "msg": "Connected to LunarGuard log stream",
            }
        )
    )

    event_queue = asyncio.Queue(maxsize=200)
    stop_event = threading.Event()
    loop = asyncio.get_running_loop()

    def on_log(log_entry):
        def enqueue():
            if event_queue.full():
                event_queue.get_nowait()
            event_queue.put_nowait(log_entry)

        loop.call_soon_threadsafe(enqueue)

    worker = threading.Thread(
        target=monitor_security_events,
        kwargs={
            "on_log": on_log,
            "stop_event": stop_event,
            "poll_interval": 0.5,
        },
        daemon=True,
    )
    worker.start()

    try:
        while True:
            log_entry = await event_queue.get()
            await websocket.send_text(json.dumps(log_entry))
    except WebSocketDisconnect:
        pass
    finally:
        stop_event.set()
        worker.join(timeout=2)


@app.websocket("/ws/statuses")
async def statuses_websocket(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            await websocket.send_text(json.dumps(Statuses.get_network_usage()))
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass


def main():
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    main()
