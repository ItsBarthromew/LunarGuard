import json
import os
import time
from datetime import datetime
import threading
from collections import defaultdict, deque

try:
    import win32evtlog
except ModuleNotFoundError:  # pragma: no cover - Windows-only optional dependency
    win32evtlog = None


TARGET_EVENT_ID = 5379
LOGS_PROCESSED_COUNT = 0
LOGS_COUNT_LOCK = threading.Lock()

# These must never be filtered.
CRITICAL_EVENT_IDS = {4625, 4720, 4728, 1102}

# High-volume events routinely seen in noisy environments.
SUPPRESSED_EVENT_IDS = {16394}

# Process paths commonly responsible for high-volume routine process events.
NOISY_PROCESS_IMAGES = {
    "c:\\windows\\system32\\svchost.exe",
    "c:\\windows\\system32\\taskhostw.exe",
    "c:\\windows\\system32\\runtimebroker.exe",
    "c:\\windows\\system32\\wmiprvse.exe",
    "c:\\windows\\system32\\dllhost.exe",
    "c:\\windows\\explorer.exe",
    "c:\\windows\\system32\\searchindexer.exe",
}

# For non-critical noise, cap per (log_type, event_id, source) tuple.
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_PER_WINDOW = 8

RATE_LIMIT_BUCKETS = defaultdict(deque)
RATE_LIMIT_LOCK = threading.Lock()
LAST_READ_ERROR_EMITTED: dict[str, float] = {}
READ_ERROR_COOLDOWN_SECONDS = 30
INITIAL_BACKFILL_EVENTS_PER_LOG = max(
    0,
    int(os.getenv("LG_LOG_BACKFILL_EVENTS", "0")),
)

# Suppress repetitive known-noise combinations (source + event_id).
# Critical IDs are explicitly exempted in _should_drop_event.
SUPPRESSED_SOURCE_EVENT_IDS = {
    ("DCOM", 10016),
    ("Service Control Manager", 7031),
    ("Service Control Manager", 7034),
    ("Service Control Manager", 7040),
    ("SecurityCenter", 15),
    ("SecurityCenter", 16),
    ("Software Protection Platform Service", 16384),
    ("Edge", 256),
    ("Chrome", 256),
    ("Microsoft-Windows-RestartManager", 10000),
    ("Microsoft-Windows-RestartManager", 10001),
}


def record_log_processed(count: int = 1):
    global LOGS_PROCESSED_COUNT

    with LOGS_COUNT_LOCK:
        LOGS_PROCESSED_COUNT += count


def get_logs_processed_count() -> int:
    with LOGS_COUNT_LOCK:
        return LOGS_PROCESSED_COUNT


def _build_log_entry(event):
    """Build a normalized log entry from a Windows event."""
    eid = event.EventID & 0x0000FFFF
    event_timestamp = event.TimeGenerated.strftime("%H:%M:%S")
    ingested_timestamp = datetime.now().strftime("%H:%M:%S")

    raw_message = getattr(event, "StringInserts", None)
    source_name = getattr(event, "SourceName", None)
    log_type = getattr(event, "LogType", None)

    if eid == 4624:
        tag = "[AUTH]"
        msg = "Successful logon detected"
    elif eid == 4625:
        tag = "[AUTH]"
        msg = "Critical: Failed logon attempt"
    elif eid == 4688:
        tag = "[PROC]"
        msg = f"New process started: {event.SourceName}"
    elif eid == 5379:
        tag = "[CRED]"
        msg = "Credential Manager reading requested"
    else:
        tag = "[SYS]"
        msg = f"Event {eid} logged by {source_name or 'unknown source'}"

    return {
        "time": event_timestamp,
        "event_time": event_timestamp,
        "ingested_time": ingested_timestamp,
        "tag": tag,
        "msg": msg,
        "event_id": eid,
        "source": source_name,
        "log_type": log_type,
        "record_number": getattr(event, "RecordNumber", None),
        "computer": getattr(event, "ComputerName", None),
        "category": getattr(event, "EventCategory", None),
        "raw_message": raw_message,
    }


def _raw_message_text(raw_message) -> str:
    if isinstance(raw_message, list):
        return " ".join(str(value) for value in raw_message if value is not None)
    return str(raw_message or "")


def _contains_noisy_image(raw_message_text: str) -> bool:
    lowered = raw_message_text.lower()
    return any(image in lowered for image in NOISY_PROCESS_IMAGES)


def _is_rate_limited(log_entry: dict, now_ts: float) -> bool:
    event_id = int(log_entry.get("event_id") or -1)
    if event_id in CRITICAL_EVENT_IDS:
        return False

    key = (
        str(log_entry.get("log_type") or "unknown"),
        event_id,
        str(log_entry.get("source") or "unknown"),
    )

    with RATE_LIMIT_LOCK:
        bucket = RATE_LIMIT_BUCKETS[key]
        cutoff = now_ts - RATE_LIMIT_WINDOW_SECONDS

        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= RATE_LIMIT_MAX_PER_WINDOW:
            return True

        bucket.append(now_ts)

        stale_before = now_ts - (RATE_LIMIT_WINDOW_SECONDS * 3)
        stale_keys = [k for k, v in RATE_LIMIT_BUCKETS.items() if not v or v[-1] < stale_before]
        for stale_key in stale_keys:
            RATE_LIMIT_BUCKETS.pop(stale_key, None)

    return False


def _should_drop_event(log_entry: dict) -> bool:
    event_id = int(log_entry.get("event_id") or -1)
    if event_id in CRITICAL_EVENT_IDS:
        return False

    if event_id in SUPPRESSED_EVENT_IDS:
        return True

    raw_text = _raw_message_text(log_entry.get("raw_message"))
    source = str(log_entry.get("source") or "")

    if (source, event_id) in SUPPRESSED_SOURCE_EVENT_IDS:
        return True

    # Drop repetitive process-create noise from known trusted binaries.
    if event_id in {1, 4688} and _contains_noisy_image(raw_text):
        return True

    return _is_rate_limited(log_entry, now_ts=time.time())


def _should_emit_read_error(log_type: str, now_ts: float) -> bool:
    last_ts = LAST_READ_ERROR_EMITTED.get(log_type)
    if last_ts is not None and (now_ts - last_ts) < READ_ERROR_COOLDOWN_SECONDS:
        return False

    LAST_READ_ERROR_EMITTED[log_type] = now_ts
    return True


def _emit_log(log_entry, on_log):
    if _should_drop_event(log_entry):
        return

    record_log_processed()
    print(json.dumps(log_entry))
    if on_log:
        on_log(log_entry)


def monitor_security_events(on_log=None, stop_event=None, poll_interval=0.5):
    if win32evtlog is None:
        error_log = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "tag": "[ERROR]",
            "msg": (
                "pywin32 is not installed in this Python environment, so Windows "
                "Event Log monitoring is disabled."
            ),
        }
        _emit_log(error_log, on_log)
        return

    server = "localhost"
    preferred_logs = ["Security", "Application", "System"]
    active_logs = []

    for log_type in preferred_logs:
        try:
            hand = win32evtlog.OpenEventLog(server, log_type)
            active_logs.append((log_type, hand))
        except Exception:
            continue

    if not active_logs:
        error_log = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "tag": "[ERROR]",
            "msg": "Unable to open Security, Application, or System event logs.",
        }
        _emit_log(error_log, on_log)
        return

    active_log_types = [log_type for log_type, _ in active_logs]

    if "Security" not in active_log_types:
        fallback_log = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "tag": "[WARN]",
            "msg": f"Security log unavailable; streaming {', '.join(active_log_types)} log(s) instead.",
        }
        _emit_log(fallback_log, on_log)

    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
    next_record_by_log = {}

    for log_type, hand in active_logs:
        try:
            oldest = win32evtlog.GetOldestEventLogRecord(hand)
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            # Default behavior is real-time only (no historical replay). Set
            # LG_LOG_BACKFILL_EVENTS to a positive number to include a recent slice.
            start_from = oldest + max(total - INITIAL_BACKFILL_EVENTS_PER_LOG, 0)
            next_record_by_log[log_type] = start_from
        except Exception:
            next_record_by_log[log_type] = 0

    while stop_event is None or not stop_event.is_set():
        for log_type, hand in active_logs:
            try:
                oldest = win32evtlog.GetOldestEventLogRecord(hand)
                total = win32evtlog.GetNumberOfEventLogRecords(hand)

                if total <= 0:
                    continue

                max_record = oldest + total - 1
                read_offset = next_record_by_log.get(log_type, oldest)
                if read_offset < oldest:
                    read_offset = oldest

                # No new events yet; avoid invalid seek beyond the newest record.
                if read_offset > max_record:
                    continue

                events = win32evtlog.ReadEventLog(hand, flags, read_offset)
            except Exception as exc:
                now_ts = time.time()
                if _should_emit_read_error(log_type, now_ts):
                    _emit_log(
                        {
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "tag": "[WARN]",
                            "msg": f"Unable to read {log_type} log: {exc}",
                        },
                        on_log,
                    )
                continue

            if not events:
                continue

            for event in events:
                log_entry = _build_log_entry(event)
                if not log_entry.get("log_type"):
                    log_entry["log_type"] = log_type

                try:
                    next_record_by_log[log_type] = int(event.RecordNumber) + 1
                except Exception:
                    pass

                _emit_log(log_entry, on_log)

        time.sleep(poll_interval)


if __name__ == "__main__":
    monitor_security_events()
