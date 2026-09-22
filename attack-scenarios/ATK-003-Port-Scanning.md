ATK-003 — Port Scanning

Scenario ID:
ATK-003

Scenario Name:
Port Scanning

Objective:
Simulate reconnaissance against a Windows Server by scanning multiple ports.

Attacker:
Kali

Target:
Windows Server

Attack Type:
Network Reconnaissance

Expected Logs:
Firewall Logs
Network/IDS Logs
Windows Firewall

Expected Events:

Multiple connection attempts
Multiple destination ports
Repeated connections from one source IP

Expected IOC:

Source IP - 192.168.1.50 
target IP - 192.168.1.10
Large number of destination ports - 1000 destination ports 
High connection rate - high

Expected Detection:
RECON-SCAN-001

Expected Severity:
Medium

Success Criteria:
ThreatTrail generates an alert when one source IP scans multiple ports within the defined time window.
