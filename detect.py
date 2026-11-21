"""Core detection logic: parses a pcap and produces structured findings."""

import ipaddress
import struct
from collections import defaultdict, Counter
from datetime import datetime, timezone

from scapy.all import rdpcap, Ether, ARP, IP, TCP, UDP, Raw

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
STANDARD_ALLOWANCE = {502, 44818}

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
# Not "the internet" either: CGNAT, link-local, loopback, multicast, limited broadcast, "this network"
NON_PUBLIC_RANGES = PRIVATE_RANGES + [
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("0.0.0.0/8"),
]

PORT_SCAN_SYN_THRESHOLD = 15
LONG_SESSION_BYTES = 10000            # sessions with an internet endpoint
LONG_SESSION_BYTES_INTERNAL = 1000000  # internal sessions on ports that aren't a known OT/IT service
MALFORMED_MIN_IP_LEN = 20

# Well-known service ports: a conversation's "server" is the side using one of these.
KNOWN_OT_PORTS = {
    502: "Modbus/TCP", 20000: "DNP3", 44818: "EtherNet/IP", 2222: "EtherNet/IP I/O", 102: "S7comm / IEC 61850 MMS",
    47808: "BACnet/IP", 2404: "IEC 60870-5-104", 4840: "OPC UA", 1962: "PCWorx", 1911: "Niagara Fox", 4911: "Niagara Fox TLS",
    789: "Red Lion Crimson", 5094: "HART-IP", 9600: "Omron FINS", 5006: "MELSEC MC", 5007: "MELSEC MC", 1200: "CODESYS",
    2455: "CODESYS", 18245: "GE SRTP", 18246: "GE SRTP", 34962: "PROFINET", 34963: "PROFINET", 34964: "PROFINET",
    20547: "ProConOS", 4000: "Emerson ROC", 319: "PTP", 320: "PTP",
}
KNOWN_IT_PORTS = {53, 67, 68, 88, 123, 135, 137, 138, 139, 161, 162, 389, 443, 445, 514, 636, 1433, 8530, 8531}
EPHEMERAL_MIN = 49152

# EtherTypes for OT protocols that ride raw Ethernet rather than IP/TCP
ETHERTYPE_PROFINET = 0x8892
ETHERTYPE_GOOSE = 0x88B8       # IEC 61850-8-1 GOOSE
ETHERTYPE_SV = 0x88BA          # IEC 61850-9-2 Sampled Values (related, same family)

# Modbus function codes that change process state
MODBUS_WRITE_CODES = {5: "Write Single Coil", 6: "Write Single Register", 15: "Write Multiple Coils",
                      16: "Write Multiple Registers", 22: "Mask Write Register", 23: "Read/Write Multiple Registers"}
DNP3_CONTROL = {0x03: "Select", 0x04: "Operate", 0x05: "Direct Operate", 0x06: "Direct Operate (no ack)",
                0x02: "Write", 0x12: "Stop Application", 0x13: "Save Configuration"}
DNP3_RESTART = {0x0D: "Cold Restart", 0x0E: "Warm Restart"}
IEC104_COMMAND_TYPES = set(range(45, 52)) | set(range(58, 65))
CIP_WRITE = {0x4D: "Write Tag", 0x4E: "Read Modify Write Tag", 0x53: "Write Tag Fragmented", 0x10: "Set Attribute Single",
             0x02: "Set Attribute All", 0x05: "Reset"}
BACNET_WRITE = {15: "WriteProperty", 16: "WritePropertyMultiple"}
BACNET_RESTART = {20: "ReinitializeDevice", 17: "DeviceCommunicationControl"}


def is_private(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return any(ip in net for net in PRIVATE_RANGES)


def is_public(ip_str):
    """True only for genuinely internet-routable unicast addresses."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip_str == "255.255.255.255":
        return False
    return not any(ip in net for net in NON_PUBLIC_RANGES)


def in_192_range(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return ip in ipaddress.ip_network("192.168.0.0/16")


def service_port(sport, dport):
    """(port, server_is_dst): the listening side of a conversation."""
    def known(p):
        return p in KNOWN_OT_PORTS or p in KNOWN_IT_PORTS or p < 1024
    if known(dport) and not known(sport):
        return dport, True
    if known(sport) and not known(dport):
        return sport, False
    if dport >= EPHEMERAL_MIN and sport < EPHEMERAL_MIN:
        return sport, False
    if sport >= EPHEMERAL_MIN and dport < EPHEMERAL_MIN:
        return dport, True
    return (dport, True) if dport <= sport else (sport, False)


def parse_modbus_function(payload_bytes):
    """MBAP header: txn id (2B), protocol id (2B, must be 0x0000), length (2B),
    unit id (1B), then function code (1B). The length field must match the frame."""
    if len(payload_bytes) < 8:
        return None
    protocol_id = int.from_bytes(payload_bytes[2:4], "big")
    if protocol_id != 0x0000:
        return None
    length = int.from_bytes(payload_bytes[4:6], "big")
    # MBAP length counts unit id + PDU, so it must fit the frame (a segment may hold several ADUs)
    if length < 2 or length + 6 > len(payload_bytes):
        return None
    return payload_bytes[7]


def parse_dnp3(payload):
    """Returns (function_code, from_master) for a DNP3 link frame carrying an application request."""
    if len(payload) < 13 or payload[0] != 0x05 or payload[1] != 0x64:
        return None, None
    from_master = bool(payload[3] & 0x80)        # DIR bit
    return payload[12], from_master


def parse_s7(payload):
    """Yields S7 Job function codes (and PI-service names) found in TPKT/COTP frames."""
    out = []
    off = 0
    while off + 7 <= len(payload) and payload[off] == 0x03:
        tlen = int.from_bytes(payload[off + 2:off + 4], "big")
        if tlen < 7:
            break
        frame = payload[off:off + tlen]
        off += tlen
        if len(frame) < 6 or frame[5] != 0xF0:
            continue
        s7 = frame[5 + frame[4]:]
        if len(s7) < 11 or s7[0] != 0x32 or s7[1] != 0x01:
            continue
        plen = int.from_bytes(s7[6:8], "big")
        param = s7[10:10 + plen]
        if param:
            out.append((param[0], param))
    return out


def parse_iec104(payload):
    out = []
    off = 0
    while off + 6 <= len(payload) and payload[off] == 0x68:
        n = payload[off + 1]
        apdu = payload[off:off + 2 + n]
        off += 2 + n
        if len(apdu) >= 12 and not (apdu[2] & 0x01):
            out.append((apdu[6], apdu[8] & 0x3F))
    return out


def parse_enip_cip_service(payload):
    """SendRRData / SendUnitData: return the CIP service code of a request, or None."""
    if len(payload) < 24:
        return None
    cmd = int.from_bytes(payload[0:2], "little")
    if cmd not in (0x6F, 0x70):
        return None
    data = payload[24:]
    if len(data) < 8:
        return None
    count = int.from_bytes(data[6:8], "little")
    i = 8
    for _ in range(count):
        if i + 4 > len(data):
            return None
        itype = int.from_bytes(data[i:i + 2], "little")
        ilen = int.from_bytes(data[i + 2:i + 4], "little")
        body = data[i + 4:i + 4 + ilen]
        i += 4 + ilen
        if itype in (0xB2, 0xB1) and body:
            svc = body[2] if itype == 0xB1 and len(body) > 2 else body[0]
            if svc & 0x80:               # reply
                return None
            return svc
    return None


def parse_bacnet(payload):
    """(pdu_type, service) for a BACnet/IP frame."""
    if len(payload) < 6 or payload[0] != 0x81 or payload[4] != 0x01:
        return None, None
    ctrl = payload[5]
    i = 6
    if ctrl & 0x80:
        return None, None
    if ctrl & 0x20:
        i += 3 + payload[i + 2]
    if ctrl & 0x08:
        i += 3 + payload[i + 2]
    if ctrl & 0x20:
        i += 1
    if i >= len(payload):
        return None, None
    t = payload[i] >> 4
    if t == 0:
        j = i + 3 + (2 if payload[i] & 0x08 else 0)
        return 0, payload[j] if j < len(payload) else None
    return t, None


def parse_goose_gocb(payload):
    """Return (gocbRef, stNum) from a GOOSE PDU, or (None, None)."""
    try:
        if len(payload) < 10:
            return None, None
        i = 8
        if payload[i] != 0x61:
            return None, None
        i += 1
        n = payload[i]
        i += 1 + ((n & 0x7F) if n & 0x80 else 0)
        gocb, st = None, None
        end = len(payload)
        while i + 2 <= end:
            tag, ln = payload[i], payload[i + 1]
            i += 2
            if ln & 0x80:
                k = ln & 0x7F
                ln = int.from_bytes(payload[i:i + k], "big")
                i += k
            val = payload[i:i + ln]
            i += ln
            if tag == 0x80:
                gocb = val.decode("ascii", "replace")
            elif tag == 0x85:
                st = int.from_bytes(val, "big")
            elif tag == 0xAB:
                break
        return gocb, st
    except Exception:
        return None, None


class Findings:
    def __init__(self):
        self.network_discovery = {}
        self.suspicious = {}
        self.modbus = {}
        self.control = {}
        self.other_protocols = {}
        self.meta = {}
        self.signature = {}

    def as_dict(self):
        """Everything the reports, JSON export, executive PDF and Fenceline cross-reference need."""
        return {"meta": self.meta, "network_discovery": self.network_discovery, "suspicious": self.suspicious,
                "modbus": self.modbus, "control": self.control, "other_protocols": self.other_protocols}


def triage(pcap_path, assets=None):
    packets = rdpcap(pcap_path)
    findings = Findings()

    macs = set()
    broadcast_count = 0
    arp_responses = []
    dhcp_events = []
    unique_ips_192 = set()

    syn_no_ack_by_src = defaultdict(set)
    uncommon_port_hits = {}          # (client, server, port) -> first seen order
    high_order_hits = Counter()
    modbus_nonstandard = {}
    malformed = []
    tcp_stream_bytes = Counter()
    internet_pairs = {}              # frozenset(pair) -> (initiator, responder)

    modbus_conversations = set()
    modbus_func_codes = Counter()
    modbus_write_single_coil = []
    modbus_write_multi_reg = []
    modbus_write_single_reg = []
    modbus_write_other = []
    modbus_device_id = []
    modbus_restart = []

    control_commands = []            # (src, dst, protocol, detail)
    restart_commands = []
    program_changes = []
    goose_publishers = defaultdict(set)
    goose_stnum = defaultdict(lambda: defaultdict(set))
    udp_initiator = {}

    other_proto_conversations = defaultdict(set)

    total_packets = len(packets)

    for pkt in packets:
        if Ether in pkt:
            eth = pkt[Ether]
            if eth.dst.lower() != ZERO_MAC:
                macs.add(eth.src.lower())
                macs.add(eth.dst.lower())
            if eth.dst.lower() == BROADCAST_MAC:
                broadcast_count += 1
            if eth.type == ETHERTYPE_PROFINET:
                other_proto_conversations["Profinet"].add((eth.src, eth.dst))
            if eth.type == ETHERTYPE_GOOSE:
                other_proto_conversations["IEC 61850 GOOSE"].add((eth.src, eth.dst))
                gocb, st = parse_goose_gocb(bytes(eth.payload))
                if gocb:
                    goose_publishers[gocb].add(eth.src.lower())
                    if st is not None:
                        goose_stnum[gocb][eth.src.lower()].add(st)
            if eth.type == ETHERTYPE_SV:
                other_proto_conversations["IEC 61850 Sampled Values"].add((eth.src, eth.dst))

        if ARP in pkt:
            arp = pkt[ARP]
            if arp.op == 2:
                arp_responses.append((arp.psrc, arp.hwsrc))

        if UDP in pkt and pkt[UDP].dport in (67, 68):
            raw = bytes(pkt[UDP].payload)
            if b"\x35\x01" in raw:
                dhcp_events.append(True)

        if IP not in pkt:
            continue
        ip_layer = pkt[IP]
        src, dst = ip_layer.src, ip_layer.dst

        if in_192_range(src):
            unique_ips_192.add(src)
        if in_192_range(dst):
            unique_ips_192.add(dst)

        if ip_layer.len is not None and ip_layer.len < MALFORMED_MIN_IP_LEN:
            malformed.append((src, dst, "IP total length < 20 bytes"))

        # Internet: either end publicly routable; keep the direction of the first packet seen
        if is_public(src) != is_public(dst):
            key = frozenset((src, dst))
            internet_pairs.setdefault(key, (src, dst))

        l4 = pkt[TCP] if TCP in pkt else (pkt[UDP] if UDP in pkt else None)
        if l4 is None:
            continue
        payload = bytes(l4.payload)
        sport, dport = l4.sport, l4.dport
        port, server_is_dst = service_port(sport, dport)
        client, server = (src, dst) if server_is_dst else (dst, src)
        is_request = server_is_dst
        if sport == dport:
            pair = (port, frozenset((src, dst)))
            first = udp_initiator.setdefault(pair, src)
            client, server = (src, dst) if first == src else (dst, src)
            is_request = first == src

        if TCP in pkt:
            tcp = pkt[TCP]
            flags = int(tcp.flags)

            if flags & 0x02 and not (flags & 0x10):
                syn_no_ack_by_src[src].add((dst, dport))

            # suspicious flag combinations (scanner / crafted packets) rather than ordinary ACKs
            if flags == 0:
                malformed.append((src, dst, "TCP NULL scan (no flags set)"))
            elif flags & 0x03 == 0x03:
                malformed.append((src, dst, "TCP SYN+FIN set together"))
            elif flags & 0x29 == 0x29 and not (flags & 0x10):
                malformed.append((src, dst, "TCP XMAS (FIN+PSH+URG)"))
            elif flags & 0x08 and not payload:
                malformed.append((src, dst, "TCP PSH with zero-length payload"))

            if port > 1024 and port not in KNOWN_OT_PORTS and port not in KNOWN_IT_PORTS and port not in STANDARD_ALLOWANCE \
                    and not (flags & 0x04 and not payload):
                if (flags & 0x02 and not flags & 0x10) or payload:
                    uncommon_port_hits.setdefault((client, server, port), len(uncommon_port_hits))
            if dport > 1024 and server_is_dst:
                high_order_hits[dport] += 1

            stream_key = tuple(sorted([(src, sport), (dst, dport)]))
            tcp_stream_bytes[stream_key] += len(payload)

            if port == 502:
                modbus_conversations.add((client, server))
                func = parse_modbus_function(payload) if payload else None
                if func is not None:
                    modbus_func_codes[func] += 1
                    if is_request:
                        if func == 5:
                            modbus_write_single_coil.append((src, dst))
                        elif func == 16:
                            modbus_write_multi_reg.append((src, dst))
                        elif func == 6:
                            modbus_write_single_reg.append((src, dst))
                        elif func in MODBUS_WRITE_CODES:
                            modbus_write_other.append((src, dst, MODBUS_WRITE_CODES[func]))
                        elif func == 43:
                            modbus_device_id.append((src, dst))
                        elif func == 8 and len(payload) >= 10 and payload[8:10] == b"\x00\x01":
                            modbus_restart.append((src, dst))
            elif payload and port not in KNOWN_OT_PORTS:
                func = parse_modbus_function(payload)
                if func is not None and (func in (1, 2, 3, 4) or func in MODBUS_WRITE_CODES):
                    modbus_nonstandard.setdefault((client, server, port), True)

            # Port 102 is shared by S7comm and IEC 61850 MMS -- label accordingly rather than assume S7.
            if port == 102:
                other_proto_conversations["S7 / IEC 61850 MMS (port 102)"].add((client, server))
                for func, param in parse_s7(payload):
                    if func == 0x29:
                        restart_commands.append((src, dst, "S7comm", "PLC STOP"))
                    elif func == 0x28:
                        if b"P_PROGRAM" in param:
                            restart_commands.append((src, dst, "S7comm", "PLC START (P_PROGRAM)"))
                        else:
                            program_changes.append((src, dst, "S7comm", "PI-Service (block insert/delete)"))
                    elif func in (0x1A, 0x1B):
                        program_changes.append((src, dst, "S7comm", "Program/block download"))
                    elif func == 0x05:
                        control_commands.append((src, dst, "S7comm", "Write Var"))
            if port == 20000:
                other_proto_conversations["DNP3"].add((client, server))
                fc, from_master = parse_dnp3(payload)
                if fc is not None and from_master:
                    if fc in DNP3_RESTART:
                        restart_commands.append((src, dst, "DNP3", DNP3_RESTART[fc]))
                    elif fc in DNP3_CONTROL:
                        control_commands.append((src, dst, "DNP3", DNP3_CONTROL[fc]))
            if port == 44818:
                other_proto_conversations["EtherNet/IP"].add((client, server))
                svc = parse_enip_cip_service(payload)
                if svc in CIP_WRITE and is_request:
                    (restart_commands if svc == 0x05 else control_commands).append((src, dst, "EtherNet/IP CIP", CIP_WRITE[svc]))
            if port == 2404:
                other_proto_conversations["IEC 60870-5-104"].add((client, server))
                for type_id, cot in parse_iec104(payload):
                    if cot != 6:
                        continue
                    if type_id in IEC104_COMMAND_TYPES:
                        control_commands.append((src, dst, "IEC 60870-5-104", f"Command ASDU type {type_id}"))
                    elif type_id == 105:
                        restart_commands.append((src, dst, "IEC 60870-5-104", "Reset process (C_RP_NA_1)"))

        if UDP in pkt:
            if port == 47808:
                other_proto_conversations["BACnet/IP"].add((client, server))
                t, svc = parse_bacnet(payload)
                if t == 0 and svc in BACNET_WRITE:
                    control_commands.append((src, dst, "BACnet/IP", BACNET_WRITE[svc]))
                elif t == 0 and svc in BACNET_RESTART:
                    restart_commands.append((src, dst, "BACnet/IP", BACNET_RESTART[svc]))

    findings.meta = {
        "total_packets": total_packets,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "assets_provided": assets is not None,
    }

    findings.network_discovery = {
        "broadcast_frames": broadcast_count,
        "unique_mac_addresses": sorted(macs),
        "arp_responses": arp_responses[:50],
        "arp_response_count": len(arp_responses),
        "dhcp_event_count": len(dhcp_events),
        "unique_192_ips": sorted(unique_ips_192),
    }

    port_scanners = {
        src: sorted(targets)
        for src, targets in syn_no_ack_by_src.items()
        if len(targets) >= PORT_SCAN_SYN_THRESHOLD
    }

    def session_flag(a, b, total):
        external = is_public(a[0]) or is_public(b[0])
        if external:
            return total >= LONG_SESSION_BYTES
        port, _ = service_port(a[1], b[1])
        return total >= LONG_SESSION_BYTES_INTERNAL and port not in KNOWN_OT_PORTS and port not in KNOWN_IT_PORTS

    long_sessions = {
        f"{a[0]}:{a[1]} <-> {b[0]}:{b[1]}": total
        for (a, b), total in tcp_stream_bytes.items()
        if session_flag(a, b, total)
    }

    findings.suspicious = {
        "possible_port_scanners": port_scanners,
        "uncommon_port_connections": [k for k, _ in sorted(uncommon_port_hits.items(), key=lambda x: x[1])],
        "high_order_port_hits_by_port": dict(high_order_hits.most_common(20)),
        "modbus_over_nonstandard_port": list(modbus_nonstandard.keys()),
        "malformed_packet_flags": malformed,
        "long_tcp_sessions_bytes_in_flight": long_sessions,
        "ot_traffic_to_internet": sorted(internet_pairs.values()),
    }

    findings.modbus = {
        "conversations": sorted(modbus_conversations),
        "function_code_counts": {str(k): v for k, v in modbus_func_codes.items()},
        "write_single_coil_events": modbus_write_single_coil,
        "write_multiple_registers_events": modbus_write_multi_reg,
        "write_single_register_events": modbus_write_single_reg,
        "write_other_events": modbus_write_other,
        "device_identification_events": modbus_device_id,
        "restart_events": modbus_restart,
    }

    spoofed = {}
    for gocb, pubs in goose_publishers.items():
        if len(pubs) > 1:
            spoofed[gocb] = {m: sorted(goose_stnum[gocb][m])[:3] + (["..."] if len(goose_stnum[gocb][m]) > 3 else [])
                             for m in sorted(pubs)}

    findings.control = {
        "commands": control_commands,
        "restarts": restart_commands + [(s, d, "Modbus/TCP", "Diagnostics: Restart Communications") for s, d in modbus_restart],
        "program_changes": program_changes,
        "goose_multiple_publishers": spoofed,
    }

    findings.other_protocols = {proto: sorted(convs) for proto, convs in other_proto_conversations.items()}

    findings.signature = {
        "macs": sorted(macs),
        "arp_pairs": sorted(set(arp_responses)),
        "high_order_ports": sorted(high_order_hits.keys()),
        "modbus_conversations": sorted(str(c) for c in modbus_conversations),
        "other_protocol_conversations": {
            proto: sorted(str(c) for c in convs) for proto, convs in other_proto_conversations.items()
        },
        "internet_destinations": sorted(set(d if is_public(d) else s for s, d in internet_pairs.values())),
    }

    return findings
