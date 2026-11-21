import struct
from scapy.all import Ether, IP, TCP, Raw, wrpcap
from ot_pcap_triage import triage


def _tpkt(s7):
    body = b"\x02\xf0\x80" + s7
    return struct.pack(">BBH", 3, 0, len(body) + 4) + body


def test_s7_stop_detected(tmp_path):
    param = b"\x29\x00\x00\x00\x00\x00\x09P_PROGRAM"
    s7 = struct.pack(">BBHHHH", 0x32, 1, 0, 1, len(param), 0) + param
    path = str(tmp_path / "s7.pcap")
    wrpcap(path, [Ether() / IP(src="10.0.0.99", dst="10.0.0.10") / TCP(sport=50000, dport=102, flags="PA") / Raw(_tpkt(s7))])
    f = triage(path)
    assert ("10.0.0.99", "10.0.0.10", "S7comm", "PLC STOP") in f.control["restarts"]


def test_internet_excludes_broadcast_and_multicast(tmp_path):
    path = str(tmp_path / "bc.pcap")
    wrpcap(path, [Ether() / IP(src="10.0.0.5", dst="255.255.255.255") / TCP(sport=1, dport=2),
                  Ether() / IP(src="10.0.0.5", dst="224.0.0.251") / TCP(sport=1, dport=2)])
    assert triage(path).suspicious["ot_traffic_to_internet"] == []


def test_plain_acks_are_not_malformed(tmp_path):
    path = str(tmp_path / "ack.pcap")
    wrpcap(path, [Ether() / IP(src="10.0.0.5", dst="10.0.0.6") / TCP(sport=50000, dport=502, flags="A")])
    assert triage(path).suspicious["malformed_packet_flags"] == []
