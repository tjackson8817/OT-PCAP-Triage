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
        "attack": [{"id": "T0846.001", "name": "Remote System Discovery: Port Scan", "tactic": "Discovery", "confidence": "confirmed"}],
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
        "title": "Malformed / crafted packets",
        "severity": "LOW",
        "attack": None,
        "why": "Undersized IP packets and impossible TCP flag combinations (NULL, SYN+FIN, XMAS) don't occur in normal traffic: they come from scanning tools, crafted-packet exploit attempts, or faulty devices -- and many OT protocol stacks are fragile and can crash on unexpected input.",
        "immediate": "Correlate the source against other findings in this report (e.g., the same host showing up under port scanning). If isolated and tied to one known device, it's likely benign.",
        "remediation": "Keep OT device firmware current against known parsing vulnerabilities; where supported, deploy an OT-aware IPS that drops malformed protocol frames before they reach field devices.",
        "reference": "NIST SP 800-82 Rev.3 (patch management / compensating controls for OT)",
    },
    "long_tcp_sessions": {
        "title": "Long-lived, high-volume TCP sessions",
        "severity": "MEDIUM",
        "attack": [{"id": "T0884", "name": "Connection Proxy", "tactic": "Command and Control", "confidence": "suggested"}],
        "why": "Large sessions with an internet endpoint, or very large internal sessions on ports that aren't a known OT/IT service, can indicate tunneling, a remote-access tool, or a proxied command-and-control channel. Ordinary long-lived OT polling (Modbus, EtherNet/IP, OPC UA, DNP3...) is not flagged.",
        "immediate": "Inspect the actual protocol/payload inside the flagged session and confirm it matches what's expected for that port.",
        "remediation": "Set session-length / byte-volume alerting thresholds in your OT monitoring platform; restrict which hosts are permitted persistent long-lived sessions.",
        "reference": "IEC 62443-3-3 SR 5.1/5.2",
    },
    "ot_to_internet": {
        "title": "OT/ICS traffic reaching a public (non-RFC1918) address",
        "severity": "CRITICAL",
        "attack": [{"id": "T0883", "name": "Internet Accessible Device", "tactic": "Initial Access", "confidence": "suggested"},
                   {"id": "T0884", "name": "Connection Proxy", "tactic": "Command and Control", "confidence": "suggested"}],
        "why": "OT devices communicating directly with public IP space bypasses intended segmentation and is one of the most common paths for both initial compromise and data exfiltration.",
        "immediate": "Identify the specific host and destination. Confirm whether this is a documented, approved path (e.g., a historian replicating to a cloud analytics service through a controlled gateway) or something unexpected.",
        "remediation": "Route all OT-to-internet traffic through a single, monitored DMZ egress point rather than direct routing; add explicit deny-by-default egress rules at the OT firewall.",
        "reference": "NIST SP 800-82 Rev.3 (DMZ architecture); IEC 62443-3-3 SR 5.1",
    },
    "modbus_write": {
        "title": "Modbus write commands",
        "severity": "HIGH",
        "attack": [
            {"id": "T1692.001", "name": "Unauthorized Message: Command Message", "tactic": "Impair Process Control", "confidence": "confirmed"},
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
    "ot_control_commands": {
        "title": "Control / write commands on other OT protocols",
        "severity": "HIGH",
        "attack": [
            {"id": "T1692.001", "name": "Unauthorized Message: Command Message", "tactic": "Impair Process Control", "confidence": "confirmed"},
            {"id": "T0831", "name": "Manipulation of Control", "tactic": "Impact", "confidence": "suggested"},
        ],
        "why": "DNP3 Select/Operate/Direct Operate, IEC 104 command ASDUs, EtherNet/IP CIP tag writes, S7 variable writes and BACnet WriteProperty all change live process state -- breakers, valves, setpoints. Each should come only from an authorized SCADA master, HMI or engineering workstation.",
        "immediate": "Check every source against your list of authorized masters and HMIs. A command from any other host is a potential active incident.",
        "remediation": "Allow-list which hosts may send control commands per protocol at the OT firewall or with protocol-aware filtering; enable command logging on the RTU/PLC/gateway where supported.",
        "reference": "IEC 62443-3-3 SR 1.1/SR 2.1/SR 3.1; NIST SP 800-82 Rev.3 \u00a76",
    },
    "ot_restart": {
        "title": "Device restart / STOP commands",
        "severity": "CRITICAL",
        "attack": [
            {"id": "T0816", "name": "Device Restart/Shutdown", "tactic": "Inhibit Response Function", "confidence": "confirmed"},
            {"id": "T0858", "name": "Change Operating Mode", "tactic": "Execution", "confidence": "suggested"},
        ],
        "why": "PLC STOP/START, DNP3 cold/warm restart, Modbus Restart Communications, BACnet ReinitializeDevice and IEC 104 reset-process commands halt or reboot controllers -- an immediate loss of control or view over the process.",
        "immediate": "Treat any unplanned stop/restart as a potential incident: confirm with operations whether it was scheduled, and identify the sending host.",
        "remediation": "Put controllers in RUN with the key switch or password protection where supported; restrict which hosts may send stop/restart function codes; alert in real time on them.",
        "reference": "IEC 62443-3-3 SR 3.1/SR 7.6; NIST SP 800-82 Rev.3 \u00a75",
    },
    "program_download": {
        "title": "Program / logic download to a controller",
        "severity": "HIGH",
        "attack": [{"id": "T0843", "name": "Program Download", "tactic": "Lateral Movement", "confidence": "confirmed"}],
        "why": "Downloading or modifying controller logic changes how the process behaves and is how attacks such as Stuxnet and TRITON took effect.",
        "immediate": "Confirm the download matches an approved change ticket and came from the designated engineering workstation; compare the running logic with your last known-good backup.",
        "remediation": "Require change control for logic downloads, keep controllers in RUN/locked mode, and restrict programming protocols to engineering workstations.",
        "reference": "IEC 62443-3-3 SR 3.4; NIST SP 800-82 Rev.3 \u00a76",
    },
    "goose_spoof": {
        "title": "IEC 61850 GOOSE control block published from more than one device",
        "severity": "CRITICAL",
        "attack": [
            {"id": "T1692.002", "name": "Unauthorized Message: Reporting Message", "tactic": "Impair Process Control", "confidence": "suggested"},
            {"id": "T1692.001", "name": "Unauthorized Message: Command Message", "tactic": "Impair Process Control", "confidence": "suggested"},
        ],
        "why": "Each GOOSE control block should be published by exactly one IED. A second MAC address publishing the same control block -- often with a jump in stNum -- is the signature of GOOSE spoofing, which can trip breakers or block protection.",
        "immediate": "Identify the extra MAC address on the station bus and isolate it; check protection relays for unexpected trips.",
        "remediation": "Lock down switch ports on the station bus (port security, 802.1X), monitor GOOSE publishers continuously, and consider IEC 62351-6 authentication where IEDs support it.",
        "reference": "IEC 61850-8-1; IEC 62351-6; IEC 62443-3-3 SR 3.1",
    },
}


def summary_counts(sus, mb, ctrl):
    """(kb_key, count) pairs for every finding category -- shared by the technical and executive reports."""
    ctrl = ctrl or {}
    writes = (len(mb.get("write_single_coil_events", [])) + len(mb.get("write_multiple_registers_events", []))
              + len(mb.get("write_single_register_events", [])) + len(mb.get("write_other_events", [])))
    return [
        ("port_scanning", len(sus.get("possible_port_scanners", {}))),
        ("uncommon_port", len(sus.get("uncommon_port_connections", []))),
        ("modbus_nonstandard_port", len(sus.get("modbus_over_nonstandard_port", []))),
        ("malformed_packets", len(sus.get("malformed_packet_flags", []))),
        ("long_tcp_sessions", len(sus.get("long_tcp_sessions_bytes_in_flight", {}))),
        ("ot_to_internet", len(sus.get("ot_traffic_to_internet", []))),
        ("modbus_write", writes),
        ("modbus_device_id", len(mb.get("device_identification_events", []))),
        ("ot_control_commands", len(ctrl.get("commands", []))),
        ("ot_restart", len(ctrl.get("restarts", []))),
        ("program_download", len(ctrl.get("program_changes", []))),
        ("goose_spoof", len(ctrl.get("goose_multiple_publishers", {}))),
    ]


def modbus_writers(mb):
    out = set()
    for key in ("write_single_coil_events", "write_multiple_registers_events", "write_single_register_events", "write_other_events"):
        out |= {item[0] for item in mb.get(key, [])}
    return out
