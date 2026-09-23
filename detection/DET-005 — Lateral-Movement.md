DET-005 — Lateral Movement

Rule ID:
LATERAL-MOVE-001

Scenario ID:
ATK-005

Rule Name:
Suspicious Lateral Movement

Purpose:
Detect suspicious remote authentication or administrative activity from one host to another.

Input Logs:

Windows Security
Sysmon
Firewall/Network Logs

Required Events:

4624 — Successful logon
4625 — Failed logon
4648 — Explicit credential logon
4672 — Special privileges assigned
4688 — Process creation

Required Fields:

Source IP - 192.168.1.105
Destination IP - 192.168.1.10
Source hostname - WS01
Destination hostname - DC01
Username - CORP\jdoe
Logon Type - 3
Authentication method - Kerberos
Timestamp - 2026-09-22T15:45:00Z
Destination port - 445

Detection Logic:

IF
    Source Host != Destination Host
AND
    Remote authentication occurs
AND
    (
        Logon Type indicates remote access
        OR
        Explicit credentials are used
        OR
        Privileged access follows the remote logon
    )

THEN
    Generate LATERAL-MOVE-001

Example IOC:

Source Host: WS01
Source IP: 192.168.1.20
Destination Host: WS02
Destination IP: 192.168.1.21
User: admin
Remote Logon: Yes

Severity:
Critical

Alert Output:

Alert: Possible Lateral Movement
Rule: LATERAL-MOVE-001
Source: WS01 / 192.168.1.20
Destination: WS02 / 192.168.1.21
Account: admin
Severity: Critical

Success Criteria:
ThreatTrail generates an alert when suspicious remote authentication or administrative activity is detected.