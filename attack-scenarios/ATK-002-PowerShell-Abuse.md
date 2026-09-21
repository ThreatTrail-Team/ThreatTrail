ATK-002 — PowerShell Abuse

Scenario ID:
ATK-002

Scenario Name:
PowerShell Abuse

Objective:
Simulate suspicious PowerShell execution on a Windows endpoint.

Attacker:
Kali

Target:
Windows Server

Attack Type:
Command/Scripting Abuse

Expected Logs:
Windows PowerShell
Windows Security
Sysmon

Expected Events:

PowerShell process creation
Script execution
Event ID 4104 — Script Block Logging
Event ID 4688 — Process Creation

Expected IOC:

powershell.exe 
Encoded commands - 
Suspicious command arguments
Unusual parent process
Source/user account - john

Expected Detection:
PS-ABUSE-001

Expected Severity:
High

Success Criteria:
ThreatTrail generates an alert when suspicious PowerShell execution is detected.