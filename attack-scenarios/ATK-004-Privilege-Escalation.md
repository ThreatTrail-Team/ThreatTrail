ATK-004 — Privilege Escalation

Scenario ID:
ATK-004

Scenario Name:
Privilege Escalation

Objective:
Simulate an attempt by a low-privileged user to obtain elevated privileges.

Attacker:
Kali / Compromised Windows User

Target:
Windows Server

Attack Type:
Privilege Escalation

Expected Logs:
Windows Security
Sysmon

Expected Events:

4672 — Special privileges assigned to new logon
4688 — Process Creation
4624 — Successful Logon
User/group membership changes where applicable

Expected IOC:

Low-privileged account - john
Privileged account/group - Administrators
Suspicious process - whoami.exe
Privilege assignment - 4672

Expected Detection:
PRIV-ESC-001

Expected Severity:
Critical

Success Criteria:
ThreatTrail generates an alert when suspicious privilege escalation activity is detected.