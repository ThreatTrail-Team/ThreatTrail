DET-004 — Privilege Escalation

Rule ID:
PRIV-ESC-001

Scenario ID:
ATK-004

Rule Name:
Suspicious Privilege Escalation

Purpose:
Detect suspicious assignment or use of elevated privileges by a previously low-privileged account.

Input Logs:

Windows Security
Sysmon

Required Events:

4672 — Special privileges assigned
4688 — Process Creation
4624 — Successful Logon

Required Fields:

Username - john
Source host - WS01
Target host - DC01
Process name - whoami.exe
Process ID - 4672
Privilege information - Administrators
Timestamp - 2026-09-22T15:30:00Z

Detection Logic:

IF
    User is normally low-privileged
AND
    User receives elevated privileges
AND
    Event ID = 4672
AND
    Suspicious process/activity is associated
    with the same user/session

THEN
    Generate PRIV-ESC-001

Example IOC:

User: john
Previous Role: Standard User
New Privilege: Administrator
Event: 4672
Process: suspicious process
Host: WS01

Severity:
Critical

Alert Output:

Alert: Possible Privilege Escalation
Rule: PRIV-ESC-001
User: john
Host: WS01
Privilege: Administrator
Severity: Critical

Success Criteria:
ThreatTrail generates an alert when suspicious privilege escalation activity is detected.