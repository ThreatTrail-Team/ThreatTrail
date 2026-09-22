ATK-001 — RDP Brute Force

Scenario ID:
ATK-001

Scenario Name:
RDP Brute Force

Objective:
Simulate repeated RDP authentication attempts against a Windows Server.

Attacker:
Kali

Target:
Windows Server

Attack Type:
Authentication Attack

Expected Logs:
Windows Security

Expected Events:
4625 — Failed logon
4624 — Successful logon

Expected IOC:

Source IP - 192.168.1.50
Target account - john
Repeated authentication failures - 25 failed attempts
Multiple attempts within a short period - RDP/3389

Expected Detection:
AUTH-BRUTE-001

Expected Severity:
High

Success Criteria:
ThreatTrail generates an alert when repeated failed RDP authentication attempts exceed the defined threshold.