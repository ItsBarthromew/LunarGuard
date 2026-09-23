import psutil
import re
import socket
import subprocess
import ipaddress
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


_ARP_LINE_PATTERN = re.compile(
    r"^\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})\s+(?P<entry_type>\w+)\s*$"
)

DISCOVERY_CACHE_LOCK = threading.Lock()
DISCOVERY_CACHE = {
    "timestamp": 0.0,
    "payload": {
        "count": 0,
        "devices": [],
    },
}


def _is_private_ipv4(ip_address: str) -> bool:
    try:
        octets = [int(part) for part in ip_address.split(".")]
        if len(octets) != 4:
            return False
    except ValueError:
        return False

    first, second, _, _ = octets
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    return False


def _normalize_mac(mac_address: str) -> str:
    return mac_address.replace("-", ":").lower()


def _is_broadcast_or_multicast(ip_address: str, mac_address: str) -> bool:
    if mac_address == "ff:ff:ff:ff:ff:ff":
        return True

    try:
        octets = [int(part) for part in ip_address.split(".")]
    except ValueError:
        return True

    if len(octets) != 4:
        return True

    if ip_address == "255.255.255.255":
        return True

    # Exclude subnet broadcast endings commonly shown by ARP cache.
    if octets[3] in {0, 255}:
        return True

    # 224.0.0.0/4 multicast space
    if 224 <= octets[0] <= 239:
        return True

    return False


def _infer_device_type(hostname: str, ip_address: str) -> str:
    name = hostname.lower()
    
    # 1. Infrastructure (Primary Router)
    if ip_address.endswith(".1") or name == "fritz.box" or name == "fritz" or name == "gateway":
        return "router"
    
    # 2. Mobile Devices (Prioritize over generic fritz domain noise)
    mobile_tokens = [
        "iphone", "android", "pixel", "samsung", "mobile", 
        "galaxy", "sm-a", "sm-s", "sm-g", "sm-n", "huawei", "xiaomi", "redmi", "oppo", "vivo", "oneplus"
    ]
    if any(token in name for token in mobile_tokens):
        return "mobile"
    
    # 3. Media Devices
    if any(token in name for token in ["tv", "roku", "chromecast", "firetv", "appletv", "smart-tv", "kodi"]):
        return "media"
    
    # 4. Other Networking Gear
    if any(token in name for token in ["router", "tplink", "netgear", "unifi", "ubnt", "switch", "hub"]):
        return "router"

    return "host"


def _iter_probe_targets(max_hosts_per_subnet: int = 254) -> list[str]:
    targets: set[str] = set()

    for addresses in psutil.net_if_addrs().values():
        for addr in addresses:
            if getattr(addr, "family", None) != socket.AF_INET:
                continue

            ip_address = str(getattr(addr, "address", "") or "")
            netmask = str(getattr(addr, "netmask", "") or "")

            if not ip_address or not netmask:
                continue
            if ip_address.startswith("127."):
                continue
            if ip_address.startswith("169.254."):
                continue

            try:
                iface = ipaddress.IPv4Interface(f"{ip_address}/{netmask}")
            except Exception:
                continue

            network = iface.network
            # Avoid scanning massive private ranges; cap to /24 around interface IP.
            if network.prefixlen < 24:
                network = ipaddress.ip_network(f"{ip_address}/24", strict=False)

            host_count = 0
            for host_ip in network.hosts():
                host_text = str(host_ip)
                if host_text == ip_address:
                    continue
                targets.add(host_text)
                host_count += 1
                if host_count >= max_hosts_per_subnet:
                    break

    return sorted(targets)


def _probe_host(ip_address: str, timeout_ms: int = 250) -> float | None:
    """Ping a host and return latency in ms, or None if unreachable."""
    try:
        # Use -n 1 for Windows, -c 1 for Linux
        count_flag = "-n" if socket.os.name == "nt" else "-c"
        start = time.time()
        result = subprocess.run(
            ["ping", count_flag, "1", "-w", str(timeout_ms), ip_address],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return round((time.time() - start) * 1000, 1)
    except Exception:
        pass
    return None


def _active_arp_warmup():
    targets = _iter_probe_targets(max_hosts_per_subnet=254)
    if not targets:
        return {}

    latencies = {}
    # Parallel pings populate local ARP cache with reachable peers.
    max_workers = min(64, max(8, len(targets) // 4))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(_probe_host, target): target for target in targets}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                latency = future.result()
                if latency is not None:
                    latencies[ip] = latency
            except Exception:
                pass
    return latencies

class Statuses:

    @staticmethod
    def get_cpu_usage():
        # Non-blocking read avoids long per-request waits that can cause client timeouts.
        return psutil.cpu_percent(interval=None)

    @staticmethod
    def get_memory_usage():
        memory = psutil.virtual_memory()
        return memory.percent

    @staticmethod
    def get_disk_usage():
        disk = psutil.disk_usage('/')
        return disk.percent

    @staticmethod
    def get_network_usage():
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv
        }

    @staticmethod
    def get_connected_devices(active_probe: bool = True, cache_ttl_seconds: int = 45):
        now = time.time()
        with DISCOVERY_CACHE_LOCK:
            cached_age = now - float(DISCOVERY_CACHE.get("timestamp") or 0.0)
            if cached_age < max(5, int(cache_ttl_seconds)):
                return DISCOVERY_CACHE["payload"]

        latencies = {}
        if active_probe:
            latencies = _active_arp_warmup()

        devices: list[dict[str, str | float | None]] = []
        seen_ips: set[str] = set()

        local_ipv4s: set[str] = set()
        for addresses in psutil.net_if_addrs().values():
            for addr in addresses:
                if getattr(addr, "family", None) == socket.AF_INET and addr.address:
                    local_ipv4s.add(str(addr.address))

        try:
            arp_output = subprocess.check_output(
                ["arp", "-a"],
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except Exception:
            payload = {
                "count": 0,
                "devices": [],
                "error": "Unable to run arp -a",
            }
            with DISCOVERY_CACHE_LOCK:
                DISCOVERY_CACHE["timestamp"] = time.time()
                DISCOVERY_CACHE["payload"] = payload
            return payload

        for line in arp_output.splitlines():
            match = _ARP_LINE_PATTERN.match(line)
            if not match:
                continue

            ip_address = match.group("ip")
            mac_address = _normalize_mac(match.group("mac"))
            entry_type = match.group("entry_type").lower()

            if ip_address in seen_ips:
                continue
            if ip_address in local_ipv4s:
                continue
            if not _is_private_ipv4(ip_address):
                continue
            if _is_broadcast_or_multicast(ip_address=ip_address, mac_address=mac_address):
                continue

            seen_ips.add(ip_address)

            hostname = ip_address
            try:
                resolved_name = socket.gethostbyaddr(ip_address)[0]
                if resolved_name:
                    # Aggressively strip local domain suffixes (.fritz.box, .local, .lan, etc.)
                    hostname = re.sub(r'\.(fritz\.box|local|lan|home|gateway)\.?$', '', resolved_name, flags=re.IGNORECASE)
            except Exception:
                pass

            devices.append(
                {
                    "name": hostname,
                    "ip": ip_address,
                    "mac": mac_address,
                    "state": "Active" if entry_type == "dynamic" else "Known",
                    "type": _infer_device_type(hostname=hostname, ip_address=ip_address),
                    "entry_type": entry_type,
                    "latency": latencies.get(ip_address),
                }
            )

        devices.sort(key=lambda item: item["ip"])
        payload = {
            "count": len(devices),
            "devices": devices,
            "scan_time": datetime.now().strftime("%H:%M:%S"),
        }
        with DISCOVERY_CACHE_LOCK:
            DISCOVERY_CACHE["timestamp"] = time.time()
            DISCOVERY_CACHE["payload"] = payload
        return payload
