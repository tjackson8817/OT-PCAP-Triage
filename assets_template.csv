from ot_pcap_triage import triage, diff_baseline


def test_baseline_diff_detects_new_mac(modbus_write_pcap, port_scan_pcap):
    baseline_findings = triage(modbus_write_pcap)
    current_findings = triage(port_scan_pcap)

    diff = diff_baseline(current_findings.signature, baseline_findings.signature)
    # port_scan_pcap uses scapy default random-ish MACs, distinct from modbus_write_pcap's explicit ones
    assert len(diff["new_macs"]) > 0


def test_baseline_diff_no_new_items_against_self(modbus_write_pcap):
    findings = triage(modbus_write_pcap)
    diff = diff_baseline(findings.signature, findings.signature)
    assert diff["new_macs"] == []
    assert diff["new_modbus_conversations"] == []
    assert diff["new_internet_destinations"] == []
