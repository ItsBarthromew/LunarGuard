import asyncio
import json
import os
import subprocess
import sys
import threading
from collections import deque
from datetime import datetime, timezone

from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
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


RECENT_LOGS = deque(maxlen=1000)
LOG_SUBSCRIBERS: set[asyncio.Queue] = set()
LOG_THREAD_STARTED = False


def _broadcast_log(log_entry: dict):
    RECENT_LOGS.append(log_entry)

    for queue in list(LOG_SUBSCRIBERS):
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            queue.put_nowait(log_entry)
        except asyncio.QueueFull:
            pass


def _start_log_monitor(loop: asyncio.AbstractEventLoop):
    def on_log(log_entry):
        loop.call_soon_threadsafe(_broadcast_log, log_entry)

    worker = threading.Thread(
        target=monitor_security_events,
        kwargs={
            "on_log": on_log,
            "poll_interval": 0.5,
        },
        daemon=True,
    )
    worker.start()


@app.on_event("startup")
async def startup_event():
    global LOG_THREAD_STARTED

    if LOG_THREAD_STARTED:
        return

    LOG_THREAD_STARTED = True
    _start_log_monitor(asyncio.get_running_loop())


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/status/cpu", tags=["Status"])
def get_cpu_status():
    """Get current CPU usage percentage"""
    return {"cpu": Statuses.get_cpu_usage()}


@app.get("/status/memory", tags=["Status"])
def get_memory_status(t0: int | None = Query(default=None)):
    """Get current memory usage percentage"""
    response = {
        "memory": Statuses.get_memory_usage(),
        "t1": int(datetime.now(timezone.utc).timestamp() * 1000),
    }

    if t0 is not None:
        response["t0"] = t0

    return response


@app.get("/status/disk", tags=["Status"])
def get_disk_status():
    """Get current disk usage percentage"""
    return {"disk": Statuses.get_disk_usage()}


@app.get("/status/network", tags=["Status"])
def get_network_status():
    """Get current network usage"""
    return {"network": Statuses.get_network_usage()}


@app.get("/logs/ws-info", tags=["Logs"])
def get_logs_websocket_info(request: Request):
    """Return the websocket URL and related log endpoints for the live log stream."""
    scheme = "wss" if request.url.scheme == "https" else "ws"
    host = request.headers.get("host") or request.url.netloc

    return {
        "websocket_url": f"{scheme}://{host}/ws/logs",
        "websocket_path": "/ws/logs",
        "recent_logs_path": "/logs/recent",
        "description": "Connect a websocket client to /ws/logs to receive live Windows security logs.",
    }


@app.get("/logs/recent", tags=["Logs"])
def get_recent_logs(limit: int = Query(default=100, ge=1, le=1000)):
    """Return the most recent log entries being streamed to websocket clients."""
    recent_logs = list(RECENT_LOGS)
    return {"count": len(recent_logs), "logs": recent_logs[-limit:]}


@app.websocket("/ws/logs")
async def logs_websocket(websocket: WebSocket):
    await websocket.accept()

    event_queue = asyncio.Queue(maxsize=500)
    LOG_SUBSCRIBERS.add(event_queue)

    for log_entry in RECENT_LOGS:
        await websocket.send_text(json.dumps(log_entry))

    await websocket.send_text(
        json.dumps(
            {
                "time": datetime.now().strftime("%H:%M:%S"),
                "tag": "[SYS]",
                "msg": "Connected to LunarGuard log stream",
            }
        )
    )

    try:
        while True:
            log_entry = await event_queue.get()
            await websocket.send_text(json.dumps(log_entry))
    except WebSocketDisconnect:
        pass
    finally:
        LOG_SUBSCRIBERS.discard(event_queue)


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

    _ensure_admin_rights_windows()
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)


def _ensure_admin_rights_windows():
    """On Windows, relaunch this process with admin rights before running the API."""
    if os.name != "nt":
        return

    import ctypes

    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False

    if is_admin:
        return

    params = subprocess.list2cmdline(sys.argv)
    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        None,
        1,
    )

    if result <= 32:
        raise RuntimeError("Unable to request administrator privileges.")

    raise SystemExit(0)


if __name__ == "__main__":
    main()
