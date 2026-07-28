import struct
import pytest
from scapy.all import Ether, ARP, IP, TCP, UDP, Raw, wrpcap


def modbus_payload(function_code, transaction_id=1, unit_id=1):
    """Builds a minimal Modbus/TCP MBAP + PDU byte string."""
    protocol_id = 0
    length = 2  # unit id + function code (+ any extra, kept minimal for tests)
    header = struct.pack(">HHHB", transaction_id, protocol_id, length, unit_id)
    return header + bytes([function_code])


@pytest.fixture
def tmp_pcap_path(tmp_path):
    return str(tmp_path / "test.pcap")


@pytest.fixture
def modbus_write_pcap(tmp_path):
    """One legit-looking Modbus conversation with a Write Multiple Registers (16) call."""
    path = str(tmp_path / "modbus_write.pcap")
    pkts = [
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src="10.0.0.5", dst="10.0.0.50")
        / TCP(sport=51000, dport=502)
        / Raw(load=modbus_payload(16)),
    ]
    wrpcap(path, pkts)
    return path


@pytest.fixture
def port_scan_pcap(tmp_path):
    """SYN-without-ACK from one source across 20 destination ports."""
    path = str(tmp_path / "port_scan.pcap")
    pkts = [
        Ether() / IP(src="10.0.0.99", dst="10.0.0.5") / TCP(sport=44000 + p, dport=p, flags="S")
        for p in range(1, 21)
    ]
    wrpcap(path, pkts)
    return path


@pytest.fixture
def internet_traffic_pcap(tmp_path):
    """One OT-looking host (private) talking to a public IP address."""
    path = str(tmp_path / "internet_traffic.pcap")
    pkts = [
        Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / TCP(sport=51000, dport=443, flags="S"),
    ]
    wrpcap(path, pkts)
    return path


@pytest.fixture
def iec104_pcap(tmp_path):
    """Traffic on TCP/2404 (IEC 60870-5-104)."""
    path = str(tmp_path / "iec104.pcap")
    pkts = [
        Ether() / IP(src="10.0.0.5", dst="10.0.0.60") / TCP(sport=51000, dport=2404) / Raw(load=b"\x68\x04\x07\x00\x00\x00"),
    ]
    wrpcap(path, pkts)
    return path


@pytest.fixture
def goose_pcap(tmp_path):
    """Raw-Ethernet GOOSE frame (EtherType 0x88B8)."""
    path = str(tmp_path / "goose.pcap")
    pkts = [
        Ether(src="aa:bb:cc:00:00:01", dst="01:0c:cd:01:00:01", type=0x88B8) / Raw(load=b"\x00" * 40),
    ]
    wrpcap(path, pkts)
    return path


@pytest.fixture
def arp_pcap(tmp_path):
    path = str(tmp_path / "arp.pcap")
    pkts = [
        Ether() / ARP(op=2, psrc="10.0.0.5", hwsrc="aa:bb:cc:dd:ee:01"),
    ]
    wrpcap(path, pkts)
    return path
