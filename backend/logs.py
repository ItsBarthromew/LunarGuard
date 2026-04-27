import json
import time
from datetime import datetime

import win32evtlog


TARGET_EVENT_ID = 5379
SUPPRESSION_WINDOW_SECONDS = 30


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
    startup_cutoff_record = None
    suppression_window_started_at = None
    suppressed_credential_events = 0

    # Prime the stream cursor so websocket clients receive only events that occur
    # after monitor startup, not historical backlog.
    try:
        initial_events = win32evtlog.ReadEventLog(hand, flags, 0)
        initial_record_numbers = [
            getattr(event, "RecordNumber", None)
            for event in initial_events or []
            if getattr(event, "RecordNumber", None) is not None
        ]
        if initial_record_numbers:
            startup_cutoff_record = max(initial_record_numbers)
            seen_records.update(initial_record_numbers)
    except Exception:
        startup_cutoff_record = None

    def emit_credential_summary_if_due(force=False):
        nonlocal suppression_window_started_at, suppressed_credential_events

        if suppression_window_started_at is None:
            return

        elapsed = time.monotonic() - suppression_window_started_at
        if not force and elapsed < SUPPRESSION_WINDOW_SECONDS:
            return

        if suppressed_credential_events > 0:
            summary_log = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "tag": "[CRED]",
                "msg": f"Suppressed {suppressed_credential_events} repeated Credential Manager reading requested events in last {SUPPRESSION_WINDOW_SECONDS}s",
                "event_id": TARGET_EVENT_ID,
                "source": "LunarGuard",
                "log_type": active_log_type,
                "record_number": None,
                "computer": server,
                "category": None,
                "raw_message": None,
            }
            _emit_log(summary_log, on_log)

        suppression_window_started_at = None
        suppressed_credential_events = 0

    while stop_event is None or not stop_event.is_set():
        emit_credential_summary_if_due()
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                record_number = getattr(event, "RecordNumber", None)
                if record_number is not None:
                    if startup_cutoff_record is not None and record_number <= startup_cutoff_record:
                        continue
                    if record_number in seen_records:
                        continue
                    seen_records.add(record_number)

                log_entry = _build_log_entry(event)
                event_id = log_entry.get("event_id")

                if event_id != TARGET_EVENT_ID:
                    _emit_log(log_entry, on_log)
                    continue

                emit_credential_summary_if_due()

                if suppression_window_started_at is None:
                    _emit_log(log_entry, on_log)
                    suppression_window_started_at = time.monotonic()
                    continue

                if (time.monotonic() - suppression_window_started_at) < SUPPRESSION_WINDOW_SECONDS:
                    suppressed_credential_events += 1
                    continue

                emit_credential_summary_if_due(force=True)
                _emit_log(log_entry, on_log)
                suppression_window_started_at = time.monotonic()

            if len(seen_records) > 3000:
                seen_records.clear()

        time.sleep(poll_interval)

    emit_credential_summary_if_due(force=True)


if __name__ == "__main__":
    monitor_security_events()
