from ot_pcap_triage import triage, apply_suppressions


def test_suppress_specific_modbus_write(modbus_write_pcap):
    findings = triage(modbus_write_pcap)
    assert len(findings.modbus["write_multiple_registers_events"]) == 1

    rules = [{"src": "10.0.0.5", "dst": "10.0.0.50", "category": "modbus_write"}]
    suppressed_count = apply_suppressions(findings, rules)

    assert suppressed_count == 1
    assert findings.modbus["write_multiple_registers_events"] == []


def test_suppress_wildcard_category_does_not_match_other_categories(internet_traffic_pcap):
    findings = triage(internet_traffic_pcap)
    assert len(findings.suspicious["ot_traffic_to_internet"]) == 1

    # rule targets a totally different category -- should not suppress internet traffic
    rules = [{"src": "*", "dst": "*", "category": "modbus_write"}]
    suppressed_count = apply_suppressions(findings, rules)

    assert suppressed_count == 0
    assert len(findings.suspicious["ot_traffic_to_internet"]) == 1


def test_suppress_wildcard_matches_correct_category(internet_traffic_pcap):
    findings = triage(internet_traffic_pcap)
    rules = [{"src": "*", "dst": "*", "category": "ot_to_internet"}]
    suppressed_count = apply_suppressions(findings, rules)
    assert suppressed_count == 1
    assert findings.suspicious["ot_traffic_to_internet"] == []


def test_no_suppressions_is_noop(modbus_write_pcap):
    findings = triage(modbus_write_pcap)
    suppressed_count = apply_suppressions(findings, [])
    assert suppressed_count == 0
    assert len(findings.modbus["write_multiple_registers_events"]) == 1
