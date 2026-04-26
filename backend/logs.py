import json
import time
from datetime import datetime

import win32evtlog


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
    if on_log:
        on_log(log_entry)
    else:
        print(json.dumps(log_entry))


def monitor_security_events(on_log=None, stop_event=None, poll_interval=0.5):
    server = "localhost"
    preferred_logs = ["Security", "Application"]
    hand = None
    active_log_type = None

    for log_type in preferred_logs:
        try:
            hand = win32evtlog.OpenEventLog(server, log_type)
            active_log_type = log_type
            break
        except Exception:
            continue

    if hand is None:
        error_log = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "tag": "[ERROR]",
            "msg": "Unable to open Security or Application event logs.",
        }
        _emit_log(error_log, on_log)
        return

    if active_log_type != "Security":
        fallback_log = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "tag": "[WARN]",
            "msg": f"Security log unavailable; streaming {active_log_type} log instead.",
        }
        _emit_log(fallback_log, on_log)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    seen_records = set()

    while stop_event is None or not stop_event.is_set():
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                record_number = getattr(event, "RecordNumber", None)
                if record_number is not None:
                    if record_number in seen_records:
                        continue
                    seen_records.add(record_number)

                log_entry = _build_log_entry(event)
                _emit_log(log_entry, on_log)

            if len(seen_records) > 3000:
                seen_records.clear()

        time.sleep(poll_interval)


if __name__ == "__main__":
    monitor_security_events()
