import re
import threading
from collections import deque
from datetime import datetime, timedelta

FAILED_LOGINS_WINDOW = deque()
FILE_CHANGE_WINDOW = deque()

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 30
RANSOMWARE_THRESHOLD = 20
RANSOMWARE_WINDOW_SECONDS = 5
ACTIVE_ALERT_SEVERITIES = {"CRITICAL", "WARN"}
ALERT_TITLE_COOLDOWNS = {
    "Sensitive File Access": 30 * 60,
    "Admin Account Access": 30 * 60,
}
ALERT_LAST_EMITTED: dict[str, datetime] = {}
ALERT_DEDUP_LOCK = threading.Lock()
MALICIOUS_IPS = {
    "185.220.101.1",
    "45.95.147.93",
    "103.27.202.122",
}


def _normalize_message_text(log_entry: dict) -> str:
    msg = str(log_entry.get("msg") or "")
    raw_message = log_entry.get("raw_message")
    if isinstance(raw_message, list):
        raw_text = " ".join(str(value) for value in raw_message if value is not None)
    else:
        raw_text = str(raw_message or "")
    return f"{msg} {raw_text}".strip()


def _extract_timestamp(log_entry: dict) -> datetime:
    stamp = log_entry.get("time")
    if isinstance(stamp, str):
        try:
            parsed = datetime.strptime(stamp, "%H:%M:%S")
            now = datetime.now()
            return now.replace(
                hour=parsed.hour,
                minute=parsed.minute,
                second=parsed.second,
                microsecond=0,
            )
        except ValueError:
            pass
    return datetime.now()


def _extract_ipv4(text: str) -> list[str]:
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)


def _extract_ports(text: str) -> list[int]:
    return [int(value) for value in re.findall(r"\b(?:port|tcp|udp)\s*[:=]?\s*(\d{2,5})\b", text)]


def _build_alert(log_entry: dict, severity: str, title: str, description: str) -> dict:
    return {
        "time": log_entry.get("time") or datetime.now().strftime("%H:%M:%S"),
        "severity": severity,
        "title": title,
        "description": description,
        "event_id": log_entry.get("event_id"),
        "source": log_entry.get("source"),
        "log_type": log_entry.get("log_type"),
        "created_at": datetime.now().isoformat(),
    }


def _alert_signature(alert_entry: dict) -> str:
    return "|".join(
        [
            str(alert_entry.get("title") or ""),
            str(alert_entry.get("severity") or ""),
            str(alert_entry.get("event_id") or ""),
            str(alert_entry.get("source") or ""),
            str(alert_entry.get("log_type") or ""),
            str(alert_entry.get("description") or ""),
        ]
    )


def should_emit_alert(alert_entry: dict) -> bool:
    title = str(alert_entry.get("title") or "")
    cooldown_seconds = ALERT_TITLE_COOLDOWNS.get(title, 0)
    if cooldown_seconds <= 0:
        return True

    now = datetime.now()
    signature = _alert_signature(alert_entry)

    with ALERT_DEDUP_LOCK:
        last_emitted = ALERT_LAST_EMITTED.get(signature)
        if last_emitted is not None and (now - last_emitted).total_seconds() < cooldown_seconds:
            return False

        ALERT_LAST_EMITTED[signature] = now

        # Keep the dedup map bounded while preserving per-title cooldown windows.
        max_cooldown = max(ALERT_TITLE_COOLDOWNS.values(), default=0)
        stale_cutoff = now - timedelta(seconds=max_cooldown + 600)
        stale_keys = [
            key for key, value in ALERT_LAST_EMITTED.items() if value < stale_cutoff
        ]
        for key in stale_keys:
            ALERT_LAST_EMITTED.pop(key, None)

    return True


def generate_alerts(log_entry: dict) -> list[dict]:
    alerts: list[dict] = []
    event_id = int(log_entry.get("event_id") or -1)
    text = _normalize_message_text(log_entry)
    lowered = text.lower()
    event_time = _extract_timestamp(log_entry)
    now = datetime.now()

    if event_id == 4625:
        FAILED_LOGINS_WINDOW.append(event_time)
        cutoff = now - timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)
        while FAILED_LOGINS_WINDOW and FAILED_LOGINS_WINDOW[0] < cutoff:
            FAILED_LOGINS_WINDOW.popleft()
        if len(FAILED_LOGINS_WINDOW) > BRUTE_FORCE_THRESHOLD:
            alerts.append(
                _build_alert(
                    log_entry,
                    "CRITICAL",
                    "Brute Force Attempt",
                    f"More than {BRUTE_FORCE_THRESHOLD} failed logins within {BRUTE_FORCE_WINDOW_SECONDS}s.",
                )
            )

    if event_id == 4624 and event_time.hour == 3:
        alerts.append(
            _build_alert(
                log_entry,
                "WARN",
                "Logon At Unusual Hours",
                "Successful logon detected around 03:00.",
            )
        )

    if event_id == 4672:
        alerts.append(
            _build_alert(
                log_entry,
                "INFO",
                "Admin Account Access",
                "Special privileges assigned to a new logon session.",
            )
        )

    if event_id == 1102:
        alerts.append(
            _build_alert(
                log_entry,
                "CRITICAL",
                "Log Cleared",
                "Windows audit log was cleared.",
            )
        )

    if event_id == 4104 and ("encodedcommand" in lowered or " -enc " in lowered):
        alerts.append(
            _build_alert(
                log_entry,
                "CRITICAL",
                "Suspicious PowerShell",
                "Encoded PowerShell command detected.",
            )
        )

    if event_id == 4697:
        alerts.append(
            _build_alert(
                log_entry,
                "WARN",
                "New Service Installed",
                "A new Windows service was installed.",
            )
        )

    if event_id == 4663 and any(token in lowered for token in ["rename", "modified", "write"]):
        if any(token in lowered for token in ["c:\\users\\", "\\desktop\\", "\\documents\\"]):
            FILE_CHANGE_WINDOW.append(event_time)
            file_cutoff = now - timedelta(seconds=RANSOMWARE_WINDOW_SECONDS)
            while FILE_CHANGE_WINDOW and FILE_CHANGE_WINDOW[0] < file_cutoff:
                FILE_CHANGE_WINDOW.popleft()
            if len(FILE_CHANGE_WINDOW) > RANSOMWARE_THRESHOLD:
                alerts.append(
                    _build_alert(
                        log_entry,
                        "CRITICAL",
                        "Potential Ransomware",
                        f"More than {RANSOMWARE_THRESHOLD} user file changes within {RANSOMWARE_WINDOW_SECONDS}s.",
                    )
                )

    if any(token in lowered for token in ["hosts", "password", "credential", "vault"]):
        if event_id in {4663, 4656, 5379}:
            alerts.append(
                _build_alert(
                    log_entry,
                    "WARN",
                    "Sensitive File Access",
                    "Access to hosts/credential-related data detected.",
                )
            )

    if any(token in lowered for token in [".ini", ".config"]) and any(token in lowered for token in ["modify", "change", "write"]):
        alerts.append(
            _build_alert(
                log_entry,
                "INFO",
                "Configuration Change",
                "System configuration file activity detected.",
            )
        )

    for ip in _extract_ipv4(lowered):
        if ip in MALICIOUS_IPS:
            alerts.append(
                _build_alert(
                    log_entry,
                    "CRITICAL",
                    "Known Malicious IP",
                    f"Connection involving blacklisted IP {ip}.",
                )
            )

    if any(token in lowered for token in ["upload", "exfil", "sent", "outbound"]) and re.search(r"\b([5-9]\d{2,}|\d{4,})\s*mb\b", lowered):
        alerts.append(
            _build_alert(
                log_entry,
                "WARN",
                "Data Exfiltration",
                "Unusually large outbound transfer detected.",
            )
        )

    opened_ports = _extract_ports(lowered)
    if any(port in {4444, 8080} for port in opened_ports) and any(token in lowered for token in ["listen", "listening", "opened"]):
        alerts.append(
            _build_alert(
                log_entry,
                "WARN",
                "New Listening Port",
                "Potential reverse-shell listener opened (4444/8080).",
            )
        )

    return alerts
