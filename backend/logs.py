import json
import time
from datetime import datetime
import threading

import win32evtlog


TARGET_EVENT_ID = 5379
LOGS_PROCESSED_COUNT = 0
LOGS_COUNT_LOCK = threading.Lock()


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
    timestamp = event.TimeGenerated.strftime("%H:%M:%S")

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
        "time": timestamp,
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


def _emit_log(log_entry, on_log):
    print(json.dumps(log_entry))
    if on_log:
        on_log(log_entry)


def monitor_security_events(on_log=None, stop_event=None, poll_interval=0.5):
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

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while stop_event is None or not stop_event.is_set():
        for log_type, hand in active_logs:
            try:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
            except Exception as exc:
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

                record_log_processed()
                _emit_log(log_entry, on_log)

        time.sleep(poll_interval)


if __name__ == "__main__":
    monitor_security_events()
