Core Features
Real-time file scanning (create, open, download)
Incoming email scanning (attachments + threats)
Continuous system log monitoring
Detect suspicious activity from logs
Automatic actions (Ignore, Alert, Block, Quarantine)
Real-time threat alerts dashboard

Monitoring & Visibility
Live log stream viewer
View running processes
Track user activity (logins, admin actions)
System health overview (CPU, memory, status)

Network & Devices
View all connected devices on network
Detect new/unknown devices instantly
Monitor IP connections and activity
Identify suspicious network behavior
Block or restrict devices

Security & Protection
Detect brute-force login attempts
Monitor credential access
Detect privilege escalation
Auto block suspicious processes or actions
Quarantine malicious files

Control & Actions
Manual override (block, quarantine, ignore)
Rule-based engine (EventID → action)
Custom rule creation (basic)
Action history (what was blocked, when, why)

Dashboard
Live alerts feed
Severity levels (low, medium, high)
Event details view
Search and filter logs

Windows Log Noise Reduction (SIEM Source Filtering)
Goal: reduce high-volume Sysmon and background noise before forwarding to SIEM.

Files added:
- backend/log_filters/Generate-NoiseFilterConfig.ps1
- backend/log_filters/sysmon-noise-reduction.xml
- backend/log_filters/Apply-SysmonNoiseReduction.ps1

Critical security events explicitly preserved (never suppressed):
- 4625 (failed login)
- 4720 (new user account)
- 4728 (user added to privileged global group)
- 1102 (audit log cleared)

Quick start (PowerShell as Administrator):
1. Generate WEF/log-shipper query filter artifacts
	powershell -ExecutionPolicy Bypass -File backend\log_filters\Generate-NoiseFilterConfig.ps1 -LookbackMinutes 20 -ShowBaseline

2. Use generated query file in your collector or shipper
	Output file: C:\ProgramData\LunarGuard\filters\wef-querylist-noise-reduction.xml

3. Apply Sysmon source filtering (optional, if Sysmon is deployed)
	powershell -ExecutionPolicy Bypass -File backend\log_filters\Apply-SysmonNoiseReduction.ps1 -SysmonExePath "C:\Tools\Sysmon\sysmon64.exe" -ConfigPath "backend\log_filters\sysmon-noise-reduction.xml"

Recommended:
- Start with this baseline for 24 hours.
- Review baseline JSON at C:\ProgramData\LunarGuard\filters\noise-filter-summary.json.
- Only add exclusions for signed/expected binaries after validation.

Advanced / Later
Multi-device monitoring (multiple PCs)
Centralized dashboard
Network intrusion detection
Behavior-based detection
Automated response playbooks
Offline mode (works without internet)
Optional AI for explanations & suggestions
