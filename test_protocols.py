from ot_pcap_triage import triage


def test_port_scan_detected(port_scan_pcap):
    findings = triage(port_scan_pcap)
    scanners = findings.suspicious["possible_port_scanners"]
    assert "10.0.0.99" in scanners
    assert len(scanners["10.0.0.99"]) == 20


def test_no_false_positive_scan_on_normal_traffic(modbus_write_pcap):
    findings = triage(modbus_write_pcap)
    assert findings.suspicious["possible_port_scanners"] == {}


def test_internet_traffic_flagged(internet_traffic_pcap):
    findings = triage(internet_traffic_pcap)
    assert ("10.0.0.5", "8.8.8.8") in findings.suspicious["ot_traffic_to_internet"]


def test_private_traffic_not_flagged_as_internet(modbus_write_pcap):
    findings = triage(modbus_write_pcap)
    assert findings.suspicious["ot_traffic_to_internet"] == []
