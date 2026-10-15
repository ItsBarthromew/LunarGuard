# LunarGuard - Working Features & Capabilities Summary

This document outlines all operational features, system metrics, and architectural components currently working in LunarGuard.

---

## 1. System Monitoring & Hardware Metrics

### CPU Usage (`/status/cpu`)
- **What it does:** Continuously samples and reports current system CPU utilization percentage.
- **How it works:** Queries operating system performance counters via `psutil` in a non-blocking background thread, instantly feeding the live CPU gauge on the dashboard.

### RAM / Memory Usage (`/status/memory`)
- **What it does:** Reports current physical RAM consumption percentage.
- **How it works:** Uses `psutil.virtual_memory()` to inspect total, available, and used system memory in real time, triggering warning indicators if memory usage exceeds 80%.

### Latency (`LATENCY: --MS`)
- **What it does:** Measures the exact round-trip network response time between the frontend dashboard and backend API endpoints.
- **How it works:** 
  1. The frontend records a high-resolution timestamp (`t0 = Date.now()`) right before initiating an asynchronous status fetch batch (`Promise.all`).
  2. The backend processes the request and responds with metrics and timestamp parameters (`t1`).
  3. When the response arrives, the frontend computes `Round-Trip Latency = t_receive - t0` (in milliseconds), reflecting live network and server processing speed.

---

## 2. Email & Log Checker (MobileBERT + Whitelist + Heuristics)

### AI Email & Log Classifier (`/ai/analyze-email`, `/ai/analyze-log`)
- **What it does:** Allows pasting email bodies, sender addresses, subjects, or system log snippets to instantly classify security risk.
- **AI Model & Engine:** Built around **`google/mobilebert-uncased`** (via Hugging Face `transformers` and PyTorch) with an instant rule-based fallback engine for zero-downtime availability.
- **Classification Categories:**
  - **`1 - Bad`**: Malicious threats, phishing attacks, credential harvesting, or critical log anomalies.
  - **`2 - Good`**: Clean, safe, benign emails or routine system log events.
  - **`3 - Potential Bad`**: Suspicious indicators, high-urgency rush tactics, or unverified sender mismatch requiring user review.
- **Advanced Threat Detection & Whitelist Verification:**
  - **Whitelisted Domains Check:** Compares all email links against [whitelisted_domains.txt](file:///C:/Users/Barthromew/Documents/Projects/LunarGuard/backend/data/whitelisted_domains.txt) (e.g., `google.com`, `fnb.co.za`, `yourcompany.com`) down to the top-level domain (TLD). Unknown external domains are flagged.
  - **Insecure Protocol Flagging:** Flags any URL using unencrypted `http://` instead of `https://`.
  - **Dangerous File Extension Inspection:** Detects file extensions in URL paths (`.pdf`, `.exe`, `.zip`, `.scr`, `.bat`, `.doc`, etc.).
  - Urgency & time-pressure tactics ("expire in 24 hours", "account locked").
  - Credential harvesting triggers ("password reset", "update credentials", sso/auth portals).
  - Business Email Compromise (BEC) & Invoice Wire Fraud ("updated bank details", "wire transfer").
  - Malicious document & macro enablement lures ("enable macros").
  - Sender domain mismatch & spoofing detection.

---

## 3. Network Discovery & Device Inventory (`/network/devices`)
- **What it does:** Discovers all active devices connected to the local network.
- **How it works:** Reads the OS ARP cache (`arp -a`) alongside non-blocking reverse DNS lookups and IP range inference to map hostnames, MAC addresses, connection states, and device types (Routers, Hosts, Mobile devices, Media units).

---

## 4. Real-time Event Logs & SIEM Streaming (`/ws/logs`, `/ws/alerts`)
- **What it does:** Streams live Windows Security, Application, and System event logs to connected WebSocket clients.
- **Noise Reduction:** Filters out high-volume trusted background noise (such as routine svchost process creation) while preserving critical security events (Failed logons [4625], New user accounts [4720], Audit log clearing [1102]).

---

## 5. Log Filtering Toolbar (Logs Page Only)
- **What it does:** Provides dedicated filtering controls exclusively on the **Logs** page.
- **Filter Parameters:**
  - **Severity / Tag:** Filter by log category (`[AUTH]`, `[PROC]`, `[CRED]`, `[SYS]`, `[WARN]`, `[ERROR]`, `[INFO]`).
  - **Source:** Filter by event source name (e.g., `Security`, `Application`, `DCOM`).
  - **Event ID:** Filter by exact or partial Windows Event ID (e.g., `4625`, `1102`).
  - **Keyword Search:** Search terms within log messages or raw data.
- **Controls:** Includes **Filter** and **Reset** buttons to instantly update the active log stream.

---

## 6. Antivirus Shield & Scanned Files View
- **What it does:** Real-time monitoring of **Downloads, Desktop, and Documents** folders for malicious files.
- **Hash Signature Engine:** Utilizes a robust database of **3,500+ known malware and threat SHA-256 hashes** (`signatures.json`) alongside double-extension heuristic detection.
- **UI & Features:** Displays files scanned count, threats blocked count, shield active status, and real-time scanner activity logs showing detected malware results, hashes, and file paths.

---

## 7. Automatic Frontend Hosting & Browser Launch
- **What it does:** When `main.py` is executed, the backend FastAPI server automatically mounts the frontend dashboard static files (`/`) and spins up a background thread to launch the user's default web browser directly to `http://localhost:8000/`.
