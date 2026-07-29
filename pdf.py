"""Core detection logic: parses a pcap and produces structured findings."""

import ipaddress
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

PORT_SCAN_SYN_THRESHOLD = 15
LONG_SESSION_BYTES = 10000
MALFORMED_MIN_IP_LEN = 20

# EtherTypes for OT protocols that ride raw Ethernet rather than IP/TCP
ETHERTYPE_PROFINET = 0x8892
ETHERTYPE_GOOSE = 0x88B8       # IEC 61850-8-1 GOOSE
ETHERTYPE_SV = 0x88BA          # IEC 61850-9-2 Sampled Values (related, same family)


def is_private(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return any(ip in net for net in PRIVATE_RANGES)


def in_192_range(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return ip in ipaddress.ip_network("192.168.0.0/16")


def parse_modbus_function(payload_bytes):
    """MBAP header: txn id (2B), protocol id (2B, must be 0x0000), length (2B),
    unit id (1B), then function code (1B)."""
    if len(payload_bytes) < 8:
        return None
    protocol_id = int.from_bytes(payload_bytes[2:4], "big")
    if protocol_id != 0x0000:
        return None
    return payload_bytes[7]


class Findings:
    def __init__(self):
        self.network_discovery = {}
        self.suspicious = {}
        self.modbus = {}
        self.other_protocols = {}
        self.meta = {}
        self.signature = {}


def triage(pcap_path, assets=None):
    packets = rdpcap(pcap_path)
    findings = Findings()

    macs = set()
    broadcast_count = 0
    arp_responses = []
    dhcp_events = []
    unique_ips_192 = set()

    syn_no_ack_by_src = defaultdict(set)
    uncommon_port_hits = []
    high_order_hits = Counter()
    modbus_nonstandard = []
    malformed = []
    tcp_stream_bytes = Counter()
    internet_comms = []

    modbus_conversations = set()
    modbus_func_codes = Counter()
    modbus_write_single_coil = []
    modbus_write_multi_reg = []
    modbus_device_id = []

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
            if eth.type == ETHERTYPE_SV:
                other_proto_conversations["IEC 61850 Sampled Values"].add((eth.src, eth.dst))

        if ARP in pkt:
            arp = pkt[ARP]
            if arp.op == 2:
                arp_responses.append((arp.psrc, arp.hwsrc))

        if UDP in pkt and pkt[UDP].dport in (67, 68) and Raw in pkt:
            raw = bytes(pkt[Raw].load)
            if b"\x35\x01" in raw:
                dhcp_events.append(True)

        if IP in pkt:
            ip_layer = pkt[IP]
            src, dst = ip_layer.src, ip_layer.dst

            if in_192_range(src):
                unique_ips_192.add(src)
            if in_192_range(dst):
                unique_ips_192.add(dst)

            if ip_layer.len is not None and ip_layer.len < MALFORMED_MIN_IP_LEN:
                malformed.append((src, dst, "ip.len < 20"))

            if not is_private(dst):
                internet_comms.append((src, dst))

            if TCP in pkt:
                tcp = pkt[TCP]
                flags = tcp.flags

                if flags & 0x02 and not (flags & 0x10):
                    syn_no_ack_by_src[src].add((dst, tcp.dport))

                if tcp.dport > 1024 and tcp.dport not in STANDARD_ALLOWANCE:
                    uncommon_port_hits.append((src, dst, tcp.dport))
                if tcp.dport > 1024:
                    high_order_hits[tcp.dport] += 1

                payload_len = len(bytes(pkt[Raw].load)) if Raw in pkt else 0
                if payload_len == 0 and not (flags & 0x02) and not (flags & 0x01) and not (flags & 0x04):
                    malformed.append((src, dst, "zero-length TCP payload"))

                stream_key = tuple(sorted([(src, tcp.sport), (dst, tcp.dport)]))
                tcp_stream_bytes[stream_key] += payload_len

                if tcp.sport == 502 or tcp.dport == 502:
                    modbus_conversations.add((src, dst))
                    if Raw in pkt:
                        func = parse_modbus_function(bytes(pkt[Raw].load))
                        if func is not None:
                            modbus_func_codes[func] += 1
                            if func == 5:
                                modbus_write_single_coil.append((src, dst))
                            elif func == 16:
                                modbus_write_multi_reg.append((src, dst))
                            elif func == 43:
                                modbus_device_id.append((src, dst))
                elif Raw in pkt:
                    func = parse_modbus_function(bytes(pkt[Raw].load))
                    if func is not None:
                        modbus_nonstandard.append((src, dst, tcp.dport if tcp.dport != 502 else tcp.sport))

                # Port 102 is shared by S7comm and IEC 61850 MMS -- label
                # accordingly rather than assume S7.
                if tcp.dport == 102 or tcp.sport == 102:
                    other_proto_conversations["S7 / IEC 61850 MMS (port 102)"].add((src, dst))
                if tcp.dport == 20000 or tcp.sport == 20000:
                    other_proto_conversations["DNP3"].add((src, dst))
                if tcp.dport == 44818 or tcp.sport == 44818:
                    other_proto_conversations["EtherNet/IP"].add((src, dst))
                if tcp.dport == 2404 or tcp.sport == 2404:
                    other_proto_conversations["IEC 60870-5-104"].add((src, dst))

            if UDP in pkt:
                udp = pkt[UDP]
                if udp.dport == 47808 or udp.sport == 47808:
                    other_proto_conversations["BACnet/IP"].add((src, dst))

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
    long_sessions = {
        f"{a[0]}:{a[1]} <-> {b[0]}:{b[1]}": total
        for (a, b), total in tcp_stream_bytes.items()
        if total >= LONG_SESSION_BYTES
    }

    findings.suspicious = {
        "possible_port_scanners": port_scanners,
        "uncommon_port_connections": uncommon_port_hits,
        "high_order_port_hits_by_port": dict(high_order_hits.most_common(20)),
        "modbus_over_nonstandard_port": modbus_nonstandard,
        "malformed_packet_flags": malformed,
        "long_tcp_sessions_bytes_in_flight": long_sessions,
        "ot_traffic_to_internet": sorted(set(internet_comms)),
    }

    findings.modbus = {
        "conversations": sorted(modbus_conversations),
        "function_code_counts": {str(k): v for k, v in modbus_func_codes.items()},
        "write_single_coil_events": modbus_write_single_coil,
        "write_multiple_registers_events": modbus_write_multi_reg,
        "device_identification_events": modbus_device_id,
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
        "internet_destinations": sorted(set(dst for _, dst in internet_comms)),
    }

    return findings
