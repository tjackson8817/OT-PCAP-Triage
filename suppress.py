"""
Severity levels and the mitigation / remediation / ATT&CK-for-ICS knowledge
base. ATT&CK IDs are checked against attack.mitre.org and secondary sources
describing the same behavior; each entry is tagged "confirmed" (well
documented for this exact behavior) or "suggested" (a reasonable but not
definitive association). Where no defensible single technique exists,
`attack` is None rather than a guessed ID -- same anti-hallucination
discipline as Fenceline's mitigation-confidence tagging.
"""

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def escalate(severity, steps=1):
    idx = SEVERITY_ORDER.index(severity)
    return SEVERITY_ORDER[min(idx + steps, len(SEVERITY_ORDER) - 1)]


KB = {
    "port_scanning": {
        "title": "Possible port scanning",
        "severity": "HIGH",
        "attack": [{"id": "T0846", "name": "Remote System Discovery", "tactic": "Discovery", "confidence": "confirmed"}],
        "why": "A single host probing many destination ports/hosts without completing the TCP handshake is a classic reconnaissance signature -- often the first step before an adversary targets a specific PLC, RTU, or HMI.",
        "immediate": "Identify the source host and confirm authorized use (e.g., an approved vulnerability scan during a maintenance window). If unauthorized, isolate the host and preserve full packet detail for forensics.",
        "remediation": "Segment IT from OT with a firewall/DMZ (zone-and-conduit model) so scanning from the business network can't reach control-system hosts at all; deploy passive OT monitoring to alert on new scanning behavior automatically.",
        "reference": "NIST SP 800-82 Rev.3 (network segmentation); IEC 62443-3-3 SR 5.1/5.2",
    },
    "uncommon_port": {
        "title": "Connections to uncommon/high-order ports",
        "severity": "MEDIUM",
        "attack": None,
        "why": "Traffic to ports outside your known OT protocol set (502, 44818, 102, 2404, 20000, 47808, etc.) can indicate an unauthorized service, remote-access tool, or misconfigured device. This is a general anomaly indicator rather than a single documented technique.",
        "immediate": "Confirm what's actually listening on the flagged port at the destination host and check it against your asset inventory / change records.",
        "remediation": "Maintain an explicit allow-list of expected ports per asset/zone and alert on any deviation -- most OT monitoring platforms (Dragos/Nozomi/Claroty/Armis) automate this once assets are onboarded.",
        "reference": "IEC 62443-3-3 SR 5.2 (zone boundary protection)",
    },
    "modbus_nonstandard_port": {
        "title": "Modbus-shaped traffic on a non-standard port",
        "severity": "MEDIUM",
        "attack": [{"id": "T0869", "name": "Standard Application Layer Protocol", "tactic": "Command and Control", "confidence": "suggested"}],
        "why": "Modbus/TCP framing appearing on a port other than 502 is unusual -- either a nonstandard-but-legitimate deployment, or an attempt to move Modbus traffic past port-based firewall rules.",
        "immediate": "Verify with the asset owner whether this port choice is an intentional, documented configuration.",
        "remediation": "Enforce protocol-aware (deep packet inspection) filtering at OT zone boundaries instead of relying on port numbers alone.",
        "reference": "NIST SP 800-82 Rev.3 (boundary protection)",
    },
    "malformed_packets": {
        "title": "Malformed / zero-length packets",
        "severity": "LOW",
        "attack": None,
        "why": "Zero-length or undersized packets are often just faulty devices or link noise, but can also result from scanning tools or malformed-packet exploit attempts -- many OT protocol stacks are fragile and can crash on unexpected input.",
        "immediate": "Correlate the source against other findings in this report (e.g., the same host showing up under port scanning). If isolated and tied to one known device, it's likely benign.",
        "remediation": "Keep OT device firmware current against known parsing vulnerabilities; where supported, deploy an OT-aware IPS that drops malformed protocol frames before they reach field devices.",
        "reference": "NIST SP 800-82 Rev.3 (patch management / compensating controls for OT)",
    },
    "long_tcp_sessions": {
        "title": "Long-lived, high-volume TCP sessions",
        "severity": "MEDIUM",
        "attack": [{"id": "T0884", "name": "Connection Proxy", "tactic": "Command and Control", "confidence": "suggested"}],
        "why": "Unusually large, long-lived TCP sessions can indicate tunneling or a proxied command-and-control channel riding over what otherwise looks like normal OT traffic.",
        "immediate": "Inspect the actual protocol/payload inside the flagged session and confirm it matches what's expected for that port.",
        "remediation": "Set session-length / byte-volume alerting thresholds in your OT monitoring platform; restrict which hosts are permitted persistent long-lived sessions.",
        "reference": "IEC 62443-3-3 SR 5.1/5.2",
    },
    "ot_to_internet": {
        "title": "OT/ICS traffic reaching a public (non-RFC1918) address",
        "severity": "CRITICAL",
        "attack": [{"id": "T0884", "name": "Connection Proxy", "tactic": "Command and Control", "confidence": "suggested"}],
        "why": "OT devices communicating directly with public IP space bypasses intended segmentation and is one of the most common paths for both initial compromise and data exfiltration.",
        "immediate": "Identify the specific host and destination. Confirm whether this is a documented, approved path (e.g., a historian replicating to a cloud analytics service through a controlled gateway) or something unexpected.",
        "remediation": "Route all OT-to-internet traffic through a single, monitored DMZ egress point rather than direct routing; add explicit deny-by-default egress rules at the OT firewall.",
        "reference": "NIST SP 800-82 Rev.3 (DMZ architecture); IEC 62443-3-3 SR 5.1",
    },
    "modbus_write": {
        "title": "Modbus write commands (Write Single Coil / Write Multiple Registers)",
        "severity": "HIGH",
        "attack": [
            {"id": "T0855", "name": "Unauthorized Command Message", "tactic": "Impair Process Control", "confidence": "confirmed"},
            {"id": "T0831", "name": "Manipulation of Control", "tactic": "Impact", "confidence": "suggested"},
        ],
        "why": "Write commands change live process state (toggling an output, altering a register value). Confirming the source is an authorized engineering workstation, HMI, or SCADA server is the single most important check in this whole report -- an unrecognized source issuing write commands is a strong signal of active manipulation, not passive monitoring.",
        "immediate": "Cross-reference the source IP against your engineering workstation / HMI / SCADA server inventory right now. If it's not recognized, treat this as a potential active incident and escalate per your IR plan.",
        "remediation": "Implement command-source allow-listing at the PLC/RTU or OT firewall so only designated engineering/HMI hosts can issue write function codes; enable source-IP/unit-ID logging on the PLC itself where the vendor supports it.",
        "reference": "IEC 62443-3-3 SR 1.1/SR 2.1 (authentication of control commands); NIST SP 800-82 Rev.3 \u00a76",
    },
    "modbus_device_id": {
        "title": "Modbus Device Identification requests",
        "severity": "LOW",
        "attack": [{"id": "T0888", "name": "Remote System Information Discovery", "tactic": "Discovery", "confidence": "suggested"}],
        "why": "Device Identification requests enumerate vendor/model/firmware -- routine for a legitimate asset-inventory tool, but also the first step an adversary takes to fingerprint a target device and find a matching exploit.",
        "immediate": "Confirm this traffic originates from your asset-management/inventory tool rather than an unrecognized host.",
        "remediation": "Where supported, restrict which hosts may issue diagnostic/identification function codes at the network layer.",
        "reference": "IEC 62443-3-3 SR 1.1",
    },
}
