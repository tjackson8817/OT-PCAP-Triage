from ot_pcap_triage import triage, build_summary_rows
from ot_pcap_triage.assets import annotate_host


def test_modbus_write_detected(modbus_write_pcap):
    findings = triage(modbus_write_pcap)
    assert len(findings.modbus["write_multiple_registers_events"]) == 1
    assert findings.modbus["write_multiple_registers_events"][0] == ("10.0.0.5", "10.0.0.50")


def test_modbus_write_baseline_severity_is_high(modbus_write_pcap):
    findings = triage(modbus_write_pcap)
    rows = build_summary_rows(findings, assets=None)
    write_rows = [r for r in rows if r[1].lower().startswith("modbus write")]
    assert write_rows and write_rows[0][0] == "HIGH"


def test_modbus_write_escalates_with_unrecognized_asset(modbus_write_pcap):
    findings = triage(modbus_write_pcap)
    # asset list that does NOT include the writer 10.0.0.5
    assets = {"10.0.0.50": {"role": "PLC", "name": "PLC-1"}}
    rows = build_summary_rows(findings, assets=assets)
    write_rows = [r for r in rows if r[1].lower().startswith("modbus write")]
    assert write_rows and write_rows[0][0] == "CRITICAL"


def test_modbus_write_stays_high_with_recognized_asset(modbus_write_pcap):
    findings = triage(modbus_write_pcap)
    assets = {"10.0.0.5": {"role": "Engineering Workstation", "name": "EWS-1"},
              "10.0.0.50": {"role": "PLC", "name": "PLC-1"}}
    rows = build_summary_rows(findings, assets=assets)
    write_rows = [r for r in rows if r[1].lower().startswith("modbus write")]
    assert write_rows and write_rows[0][0] == "HIGH"


def test_annotate_host_recognized_and_unrecognized():
    assets = {"10.0.0.5": {"role": "PLC", "name": "PLC-1"}}
    assert "recognized" in annotate_host("10.0.0.5", assets)
    assert "UNRECOGNIZED" in annotate_host("10.0.0.99", assets)
    assert annotate_host("10.0.0.5", None) == "10.0.0.5"


def test_modbus_write_single_register_and_echo_not_double_counted(tmp_path):
    """FC6 counts as a write, and the PLC's echoed response is not counted again."""
    import struct
    from scapy.all import Ether, IP, TCP, Raw, wrpcap
    req = struct.pack(">HHHBBHH", 7, 0, 6, 1, 6, 10, 11100)
    path = str(tmp_path / "fc6.pcap")
    wrpcap(path, [
        Ether() / IP(src="10.0.0.5", dst="10.0.0.50") / TCP(sport=51000, dport=502, flags="PA") / Raw(req),
        Ether() / IP(src="10.0.0.50", dst="10.0.0.5") / TCP(sport=502, dport=51000, flags="PA") / Raw(req),
    ])
    findings = triage(path)
    assert findings.modbus["write_single_register_events"] == [("10.0.0.5", "10.0.0.50")]
    assert findings.modbus["conversations"] == [("10.0.0.5", "10.0.0.50")]
