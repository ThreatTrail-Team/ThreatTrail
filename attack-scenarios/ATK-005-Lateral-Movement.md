ATK-005 — Lateral Movement

Scenario ID:
ATK-005

Scenario Name:
Lateral Movement

Objective:
Simulate movement from one compromised Windows machine to another system in the environment.

Attacker:
Compromised Windows Host / Kali

Target:
Another Windows Server or Domain-Joined Host

Attack Type:
Lateral Movement

Expected Logs:
Windows Security
Sysmon
Firewall/Network Logs

Expected Events:

4624 — Successful Logon
4625 — Failed Logon
4648 — Explicit Credential Logon
4672 — Special Privileges Assigned
4688 — Process Creation

Expected IOC:

Source host/IP - 192.168.1.105 (WS01-FINANCE)
Destination host/IP - 192.168.1.10 (DC01-SERVERS)
Source account - CORP\jdoe
Destination account - CORP\DomainAdmin
Remote logon - 4624

Expected Detection:
LATERAL-MOVE-001

Expected Severity:
Critical

Success Criteria:
ThreatTrail generates an alert when suspicious remote authentication or administrative activity indicates movement between hosts.