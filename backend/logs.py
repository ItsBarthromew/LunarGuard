import json
import time
from datetime import datetime

import win32evtlog


def _build_log_entry(event):
    """Build a normalized log entry from a Windows security event."""
    eid = event.EventID & 0x0000FFFF
    timestamp = event.TimeGenerated.strftime("%H:%M:%S")

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
        msg = f"Security event {eid} logged by {event.SourceName}"

    return {
        "time": timestamp,
        "tag": tag,
        "msg": msg,
    }


def _emit_log(log_entry, on_log):
    if on_log:
        on_log(log_entry)
    else:
        print(json.dumps(log_entry))


def monitor_security_events(on_log=None, stop_event=None, poll_interval=0.5):
    server = "localhost"
    log_type = "Security"

    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
    except Exception:
        error_log = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "tag": "[ERROR]",
            "msg": "Access Denied. Run as Admin.",
        }
        _emit_log(error_log, on_log)
        return

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
