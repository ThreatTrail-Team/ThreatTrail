DET-003 — Port Scanning

Rule ID:
RECON-SCAN-001

Scenario ID:
ATK-003

Rule Name:
Port Scan Detection

Purpose:
Detect a host attempting connections to a large number of ports on a target.

Input Logs:

Firewall Logs
Network Logs
IDS Logs

Required Events:

Connection attempts
Blocked connections
Accepted connections

Required Fields:

Source IP - 192.168.1.50
Destination IP - 192.168.1.10
Destination port - 80, 443, 22, 3389
Protocol - TCP
Timestamp - 2026-09-22T15:00:00Z
Connection status - Blocked

Detection Logic:

IF
    Same Source IP
AND
    Same Destination IP
AND
    Unique Destination Ports >= 20
AND
    Time Window <= 1 minute

THEN
    Generate RECON-SCAN-001

Example IOC:

Source IP: 192.168.1.50
Target IP: 192.168.1.10
Unique Ports: 100+
Protocol: TCP
Time Window: 1 minute

Severity:
Medium

Alert Output:

Alert: Possible Port Scan
Rule: RECON-SCAN-001
Source: 192.168.1.50
Target: 192.168.1.10
Ports Scanned: 100
Severity: Medium

Success Criteria:
ThreatTrail generates an alert when one source scans multiple ports within the defined threshold.