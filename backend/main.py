import asyncio
import json
import os
import subprocess
import sys
import threading
from collections import deque
from datetime import datetime, timezone
from enum import IntEnum

from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from logs import get_logs_processed_count, monitor_security_events
from rules import ACTIVE_ALERT_SEVERITIES, generate_alerts, should_emit_alert
from statuses import Statuses

app = FastAPI(
    title=
    "LVNΛR GUΛRD API",
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
RECENT_ALERTS = deque(maxlen=1000)
ALERT_SUBSCRIBERS: set[asyncio.Queue] = set()


class HealthLevel(IntEnum):
    GOOD = 0
    FAIR = 1
    POOR = 2


class HealthTracker:
    def __init__(self, batch_size: int = 20):
        self.batch_size = batch_size
        self._batch: list[dict[str, float]] = []
        self._current_level: HealthLevel | None = None
        self._lock = threading.Lock()

    @staticmethod
    def _sample_score(cpu: float, memory: float) -> float:
        return (float(cpu) + float(memory)) / 2

    @staticmethod
    def _score_to_level(score: float) -> HealthLevel:
        if score < 55:
            return HealthLevel.GOOD
        if score < 75:
            return HealthLevel.FAIR
        return HealthLevel.POOR

    @staticmethod
    def _level_to_label(level: HealthLevel) -> str:
        if level == HealthLevel.GOOD:
            return "GOOD"
        if level == HealthLevel.FAIR:
            return "FAIR"
        return "POOR"

    def add_sample(self, cpu: float, memory: float) -> dict[str, int | str]:
        with self._lock:
            self._batch.append({"cpu": float(cpu), "memory": float(memory)})

            # First sample decides initial health until first full batch is ready.
            if self._current_level is None:
                first_score = self._sample_score(cpu, memory)
                self._current_level = self._score_to_level(first_score)

            if len(self._batch) >= self.batch_size:
                average_score = sum(
                    self._sample_score(sample["cpu"], sample["memory"])
                    for sample in self._batch
                ) / len(self._batch)
                batch_level = self._score_to_level(average_score)

                # Blend previous and new batch level to avoid abrupt swings.
                if self._current_level is not None:
                    blended_level = round((int(self._current_level) + int(batch_level)) / 2)
                    self._current_level = HealthLevel(blended_level)
                else:
                    self._current_level = batch_level

                self._batch = []

            assert self._current_level is not None
            return {
                "health": self._level_to_label(self._current_level),
                "samples_collected": len(self._batch),
                "sample_window": self.batch_size,
            }


HEALTH_TRACKER = HealthTracker(batch_size=20)


def _broadcast_alert(alert_entry: dict):
    if not should_emit_alert(alert_entry):
        return

    RECENT_ALERTS.append(alert_entry)

    for queue in list(ALERT_SUBSCRIBERS):
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            queue.put_nowait(alert_entry)
        except asyncio.QueueFull:
            pass


def _active_alert_count() -> int:
    return sum(1 for alert in RECENT_ALERTS if alert.get("severity") in ACTIVE_ALERT_SEVERITIES)


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

    for alert in generate_alerts(log_entry):
        _broadcast_alert(alert)


def _start_log_monitor(loop: asyncio.AbstractEventLoop):
    def on_log(log_entry):
        loop.call_soon_threadsafe(_broadcast_log, log_entry)

    def monitor_worker():
        on_log(
            {
                "time": datetime.now().strftime("%H:%M:%S"),
                "tag": "[SYS]",
                "msg": "Security log monitor thread started",
            }
        )

        try:
            monitor_security_events(
                on_log=on_log,
                poll_interval=0.5,
            )
        except Exception as exc:
            on_log(
                {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "tag": "[ERROR]",
                    "msg": f"Log monitor stopped: {exc}",
                }
            )

    worker = threading.Thread(
        target=monitor_worker,
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


@app.get("/network/devices", tags=["Network"])
def get_connected_devices(
    refresh: bool = Query(default=False),
    active_probe: bool = Query(default=True),
):
    """Discover connected LAN devices from local ARP cache."""
    ttl = 5 if refresh else 45
    return Statuses.get_connected_devices(active_probe=active_probe, cache_ttl_seconds=ttl)


@app.get("/status/logs", tags=["Status"])
def get_logs_status():
    """Get total processed log count."""
    return {"logs_processed": get_logs_processed_count()}


@app.get("/status/alerts", tags=["Status"])
def get_alerts_status():
    """Get currently active alerts count."""
    return {"active_alerts": _active_alert_count()}


@app.get("/status/health", tags=["Status"])
def get_health_status():
    """Get health derived from rolling CPU and memory samples."""
    cpu = Statuses.get_cpu_usage()
    memory = Statuses.get_memory_usage()
    return HEALTH_TRACKER.add_sample(cpu=cpu, memory=memory)


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


@app.get("/alerts/ws-info", tags=["Alerts"])
def get_alerts_websocket_info(request: Request):
    """Return websocket metadata for alert streaming."""
    scheme = "wss" if request.url.scheme == "https" else "ws"
    host = request.headers.get("host") or request.url.netloc

    return {
        "websocket_url": f"{scheme}://{host}/ws/alerts",
        "websocket_path": "/ws/alerts",
        "recent_alerts_path": "/alerts/recent",
        "description": "Connect a websocket client to /ws/alerts to receive live alert events.",
    }


@app.get("/alerts/recent", tags=["Alerts"])
def get_recent_alerts(limit: int = Query(default=50, ge=1, le=1000)):
    """Return the most recent generated alerts."""
    recent_alerts = list(RECENT_ALERTS)
    return {"count": len(recent_alerts), "alerts": recent_alerts[-limit:]}


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


@app.websocket("/ws/alerts")
async def alerts_websocket(websocket: WebSocket):
    await websocket.accept()

    event_queue = asyncio.Queue(maxsize=500)
    ALERT_SUBSCRIBERS.add(event_queue)

    for alert_entry in RECENT_ALERTS:
        await websocket.send_text(json.dumps(alert_entry))

    try:
        while True:
            alert_entry = await event_queue.get()
            await websocket.send_text(json.dumps(alert_entry))
    except WebSocketDisconnect:
        pass
    finally:
        ALERT_SUBSCRIBERS.discard(event_queue)


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
