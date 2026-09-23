DET-001 — RDP Brute Force

Rule ID:
AUTH-BRUTE-001

Scenario ID:
ATK-001

Rule Name:
RDP Brute Force Detection

Purpose:
Detect repeated failed RDP authentication attempts from the same source.

Input Logs:
Windows Security

Required Events:

4625 — Failed logon
4624 — Successful logon

Required Fields:

Source IP - 192.168.1.50
Target IP - 192.168.1.10
Target username - john
Timestamp - 2026-09-21T10:30:00Z
Logon Type - 10
Destination port - 3389

Detection Logic:

IF
    Event ID = 4625
AND
    Logon Type = 10 (RDP)
AND
    Same Source IP
AND
    Same Target Account
AND
    Failed Attempts >= 10
AND
    Time Window <= 2 minutes

THEN
    Generate AUTH-BRUTE-001

Threshold:
10+ failures / 2 minutes

Expected Example:

Source IP: 192.168.1.50
Target Account: john
Failures: 25
Port: 3389
Time: 2 minutes

Severity:
High

Alert Output:

Alert: RDP Brute Force
Rule: AUTH-BRUTE-001
Source: 192.168.1.50
Account: john
Attempts: 25
Severity: High

Success Criteria:
ThreatTrail generates an alert when the threshold is exceeded.