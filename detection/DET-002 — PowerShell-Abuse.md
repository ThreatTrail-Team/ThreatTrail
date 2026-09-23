DET-002 — PowerShell Abuse

Rule ID:
PS-ABUSE-001

Scenario ID:
ATK-002

Rule Name:
Suspicious PowerShell Execution

Purpose:
Detect potentially suspicious PowerShell execution based on command-line and process behavior.

Input Logs:

Windows PowerShell
Windows Security
Sysmon

Required Events:

4104 — PowerShell Script Block Logging
4688 — Process Creation

Required Fields:

Username - john
Hostname - WS01
Process name - powershell.exe
Parent process - cmd.exe
Command line - powershell.exe -nop -w hidden -encodedcommand aW52b2tl...
Timestamp - 2026-09-22T14:15:00Z
Source IP - 192.168.1.50

Detection Logic:

IF
    Process = powershell.exe
AND
    (
        Command contains encoded/suspicious execution
        OR
        PowerShell launched by an unusual parent process
        OR
        Script Block contains suspicious commands
    )

THEN
    Generate PS-ABUSE-001

Example IOC:

Process: powershell.exe
User: john
Command Line: suspicious PowerShell command
Parent Process: unusual process
Host: WS01

Severity:
High

Alert Output:

Alert: Suspicious PowerShell Activity
Rule: PS-ABUSE-001
User: john
Host: WS01
Process: powershell.exe
Severity: High

Success Criteria:
ThreatTrail generates an alert when the defined suspicious PowerShell conditions are met.