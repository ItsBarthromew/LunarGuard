import hashlib
import os
import time
import threading
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Signature database path
SIGNATURES_FILE = os.path.join(os.path.dirname(__file__), "data", "signatures.json")
# Folders to monitor (Downloads and Desktop are high-risk)
MONITOR_PATHS = [
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Desktop"),
]

class MalwareScanner:
    def __init__(self, on_alert=None):
        self.on_alert = on_alert
        self.signatures = set()
        self.load_signatures()
        self.stats = {
            "files_scanned": 0,
            "threats_found": 0,
            "last_scan_time": None
        }

    def load_signatures(self):
        """Load SHA-256 hashes from the local database."""
        os.makedirs(os.path.dirname(SIGNATURES_FILE), exist_ok=True)
        if not os.path.exists(SIGNATURES_FILE):
            # Seed with EICAR test hash and some placeholders
            initial_data = {
                "updated_at": datetime.now().isoformat(),
                "hashes": [
                    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", # EICAR SHA-256
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", # Empty file hash (often used by malware loaders)
                ]
            }
            with open(SIGNATURES_FILE, "w") as f:
                json.dump(initial_data, f)
        
        try:
            with open(SIGNATURES_FILE, "r") as f:
                data = json.load(f)
                self.signatures = set(data.get("hashes", []))
        except Exception:
            self.signatures = set()

    def calculate_sha256(self, file_path):
        """Calculate the SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Read in 4KB chunks
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (PermissionError, FileNotFoundError):
            return None
        except Exception:
            return None

    def scan_file(self, file_path):
        """Scan a single file against the hash database."""
        if not os.path.isfile(file_path):
            return

        # Skip very large files (> 50MB) for now to maintain performance
        try:
            if os.path.getsize(file_path) > 50 * 1024 * 1024:
                return
        except Exception:
            return

        self.stats["files_scanned"] += 1
        file_hash = self.calculate_sha256(file_path)
        
        if file_hash and file_hash in self.signatures:
            self.stats["threats_found"] += 1
            filename = os.path.basename(file_path)
            
            alert = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "severity": "CRITICAL",
                "title": "Malware Detected",
                "description": f"Known malicious hash match found in: {filename}",
                "source": "Antivirus Scanner",
                "log_type": "ANTIVIRUS",
                "file_path": file_path,
                "file_hash": file_hash
            }
            
            if self.on_alert:
                self.on_alert(alert)
            return True
            
        # Extension-based heuristics
        filename = os.path.basename(file_path).lower()
        if filename.count('.') > 1:
            # Check for double extensions like file.pdf.exe
            parts = filename.split('.')
            if parts[-1] in ['exe', 'vbs', 'ps1', 'scr', 'bat', 'cmd']:
                alert = {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "severity": "WARN",
                    "title": "Suspicious File Extension",
                    "description": f"Double extension detected: {filename}",
                    "source": "Antivirus Scanner",
                    "log_type": "ANTIVIRUS",
                    "file_path": file_path
                }
                if self.on_alert:
                    self.on_alert(alert)

        return False

class ScanHandler(FileSystemEventHandler):
    def __init__(self, scanner):
        self.scanner = scanner

    def on_created(self, event):
        if not event.is_directory:
            # Move the wait to a thread to avoid blocking the observer
            threading.Thread(target=self._delayed_scan, args=(event.src_path,), daemon=True).start()

    def _delayed_scan(self, file_path):
        time.sleep(0.5)
        self.scanner.scan_file(file_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.scanner.scan_file(event.src_path)
            self.scanner.scan_file(event.src_path)

def start_realtime_scanner(on_alert):
    scanner = MalwareScanner(on_alert=on_alert)
    event_handler = ScanHandler(scanner)
    observer = Observer()
    
    for path in MONITOR_PATHS:
        if os.path.exists(path):
            observer.schedule(event_handler, path, recursive=False)
    
    observer.start()
    return observer, scanner
