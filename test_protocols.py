from ot_pcap_triage import triage


def test_iec104_detected(iec104_pcap):
    findings = triage(iec104_pcap)
    assert "IEC 60870-5-104" in findings.other_protocols
    assert ("10.0.0.5", "10.0.0.60") in findings.other_protocols["IEC 60870-5-104"]


def test_goose_detected(goose_pcap):
    findings = triage(goose_pcap)
    assert "IEC 61850 GOOSE" in findings.other_protocols


def test_arp_response_recorded(arp_pcap):
    findings = triage(arp_pcap)
    assert findings.network_discovery["arp_response_count"] == 1
    assert ("10.0.0.5", "aa:bb:cc:dd:ee:01") in findings.network_discovery["arp_responses"]
