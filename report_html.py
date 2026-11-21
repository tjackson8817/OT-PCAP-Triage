"""HTML report rendering: same content as the Markdown report, with
severity color-coded badges for at-a-glance skimming."""

import html as _html

SEVERITY_COLORS = {
    "CRITICAL": "#8b0000",
    "HIGH": "#c0392b",
    "MEDIUM": "#e67e22",
    "LOW": "#b8960c",
    "INFO": "#607d8b",
}

CSS = """
body { font-family: -apple-system, Segoe UI, Arial, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; line-height: 1.5; }
h1 { border-bottom: 3px solid #1F3B57; padding-bottom: .3rem; }
h2 { color: #1F3B57; border-bottom: 1px solid #ccc; padding-bottom: .2rem; margin-top: 2rem; }
h3 { margin-top: 1.3rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #ddd; padding: .4rem .6rem; text-align: left; }
th { background: #f3f3f3; }
.badge { display: inline-block; padding: .15rem .55rem; border-radius: .8rem; color: white; font-weight: 600; font-size: .85rem; }
.kb { background: #f8f8f8; border-left: 4px solid #1F3B57; padding: .6rem 1rem; margin: .5rem 0 1rem 0; }
.exec-summary { background: #fff8e6; border: 1px solid #e8d68a; padding: 1rem 1.2rem; border-radius: 6px; }
code { background: #f0f0f0; padding: .1rem .3rem; border-radius: 3px; }
ul { margin-top: .2rem; }
"""


def badge(sev):
    color = SEVERITY_COLORS.get(sev, "#607d8b")
    return f'<span class="badge" style="background:{color}">{_html.escape(sev)}</span>'


def e(s):
    return _html.escape(str(s))


def markdown_bold_to_html(line):
    """Minimal **bold** -> <strong> conversion for the few inline-bold lines we generate."""
    parts = line.split("**")
    out = []
    for i, part in enumerate(parts):
        out.append(f"<strong>{e(part)}</strong>" if i % 2 == 1 else e(part))
    return "".join(out)


def render_html(findings, source_file, summary_rows, assets=None, baseline_diff=None,
                 suppressed_count=0, trend_md=None, exec_summary_text=""):
    from .assets import annotate_host
    from .kb import KB

    sus = findings.suspicious
    mb = findings.modbus
    nd = findings.network_discovery

    parts = [f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
             f"<title>OT PCAP Triage Report</title><style>{CSS}</style></head><body>"]

    parts.append("<h1>OT PCAP Triage Report</h1>")
    parts.append(f"<p><strong>Source file:</strong> <code>{e(source_file)}</code><br>"
                 f"<strong>Generated:</strong> {e(findings.meta['generated_at'])}<br>"
                 f"<strong>Total packets analyzed:</strong> {e(findings.meta['total_packets'])}<br>"
                 f"<strong>Asset context provided:</strong> {'Yes' if assets else 'No'}</p>")

    parts.append("<h2>Executive Summary</h2>")
    parts.append(f"<div class='exec-summary'>{exec_summary_text}</div>")

    parts.append("<h2>Findings Summary</h2>")
    if summary_rows:
        parts.append("<table><tr><th>Severity</th><th>Finding</th><th>Count</th></tr>")
        for sev, title, cnt in summary_rows:
            parts.append(f"<tr><td>{badge(sev)}</td><td>{e(title)}</td><td>{e(cnt)}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p>No findings triggered against current thresholds.</p>")

    parts.append("<h2>Network Discovery</h2><ul>")
    parts.append(f"<li>Broadcast frames: <strong>{e(nd['broadcast_frames'])}</strong></li>")
    parts.append(f"<li>Unique MAC addresses seen: <strong>{e(len(nd['unique_mac_addresses']))}</strong></li>")
    parts.append(f"<li>ARP responses: <strong>{e(nd['arp_response_count'])}</strong></li>")
    parts.append(f"<li>DHCP Discover/Request events: <strong>{e(nd['dhcp_event_count'])}</strong></li>")
    parts.append(f"<li>Unique IPs in 192.168.0.0/16: <strong>{e(len(nd['unique_192_ips']))}</strong></li>")
    parts.append("</ul>")

    def kb_div(key):
        kb = KB[key]
        tags = (", ".join(f"{a['id']} {a['name']} ({a['tactic']}, {a['confidence']})" for a in kb["attack"])
                if kb["attack"] else "no single confirmed technique mapping")
        return (f"<div class='kb'>{badge(kb['severity'])} "
                f"&nbsp;<strong>ATT&amp;CK for ICS:</strong> {e(tags)}<br>"
                f"<strong>Why it matters:</strong> {e(kb['why'])}<br>"
                f"<strong>Immediate action:</strong> {e(kb['immediate'])}<br>"
                f"<strong>Remediation:</strong> {e(kb['remediation'])}<br>"
                f"<strong>Reference:</strong> {e(kb['reference'])}</div>")

    parts.append("<h2>Suspicious Activity</h2>")

    scanners = sus["possible_port_scanners"]
    parts.append(f"<h3>Possible port scanning: {e(len(scanners))} source(s) flagged</h3><ul>")
    for src, targets in scanners.items():
        parts.append(f"<li>{e(annotate_host(src, assets))} hit <strong>{e(len(targets))}</strong> "
                      f"distinct dest ports/IPs (SYN-no-ACK)</li>")
    parts.append("</ul>")
    if scanners:
        parts.append(kb_div("port_scanning"))

    parts.append(f"<h3>Connections to uncommon ports: {e(len(sus['uncommon_port_connections']))}</h3><ul>")
    for src, dst, port in sus["uncommon_port_connections"][:15]:
        parts.append(f"<li>{e(annotate_host(src, assets))} → {e(annotate_host(dst, assets))}:{e(port)}</li>")
    parts.append("</ul>")
    if sus["uncommon_port_connections"]:
        parts.append(kb_div("uncommon_port"))

    parts.append(f"<h3>Modbus over non-standard port: {e(len(sus['modbus_over_nonstandard_port']))}</h3><ul>")
    for src, dst, port in sus["modbus_over_nonstandard_port"][:15]:
        parts.append(f"<li>{e(annotate_host(src, assets))} → {e(annotate_host(dst, assets))} on port {e(port)}</li>")
    parts.append("</ul>")
    if sus["modbus_over_nonstandard_port"]:
        parts.append(kb_div("modbus_nonstandard_port"))

    parts.append(f"<h3>Malformed / suspect packets: {e(len(sus['malformed_packet_flags']))}</h3><ul>")
    for src, dst, reason in sus["malformed_packet_flags"][:15]:
        parts.append(f"<li>{e(annotate_host(src, assets))} → {e(annotate_host(dst, assets))}: {e(reason)}</li>")
    parts.append("</ul>")
    if sus["malformed_packet_flags"]:
        parts.append(kb_div("malformed_packets"))

    parts.append(f"<h3>Long TCP sessions: {e(len(sus['long_tcp_sessions_bytes_in_flight']))}</h3><ul>")
    for conv, total in sus["long_tcp_sessions_bytes_in_flight"].items():
        parts.append(f"<li>{e(conv)}: {e(total)} bytes</li>")
    parts.append("</ul>")
    if sus["long_tcp_sessions_bytes_in_flight"]:
        parts.append(kb_div("long_tcp_sessions"))

    parts.append(f"<h3>OT/ICS traffic reaching the public internet: {e(len(sus['ot_traffic_to_internet']))}</h3><ul>")
    for src, dst in sus["ot_traffic_to_internet"][:15]:
        parts.append(f"<li>{e(annotate_host(src, assets))} → {e(annotate_host(dst, assets))}</li>")
    parts.append("</ul>")
    if sus["ot_traffic_to_internet"]:
        parts.append(kb_div("ot_to_internet"))

    parts.append("<h2>Modbus Protocol Detail</h2>")
    parts.append(f"<p>Modbus conversations (port 502): <strong>{e(len(mb['conversations']))}</strong></p><ul>")
    for src, dst in mb["conversations"][:15]:
        parts.append(f"<li>{e(annotate_host(src, assets))} ↔ {e(annotate_host(dst, assets))}</li>")
    parts.append("</ul>")

    w_events = ([(s_, d_, "Write Single Coil") for s_, d_ in mb["write_single_coil_events"]]
                + [(s_, d_, "Write Single Register") for s_, d_ in mb.get("write_single_register_events", [])]
                + [(s_, d_, "Write Multiple Registers") for s_, d_ in mb["write_multiple_registers_events"]]
                + list(mb.get("write_other_events", [])))
    write_total = len(w_events)
    parts.append(f"<h3>Write commands: {e(write_total)}</h3><ul>")
    for src, dst, name in w_events[:15]:
        parts.append(f"<li>{e(annotate_host(src, assets))} &rarr; {e(annotate_host(dst, assets))}: {e(name)}</li>")
    parts.append("</ul>")
    if write_total:
        parts.append(kb_div("modbus_write"))

    parts.append(f"<h3>Device Identification requests: {e(len(mb['device_identification_events']))}</h3><ul>")
    for src, dst in mb["device_identification_events"][:15]:
        parts.append(f"<li>{e(annotate_host(src, assets))} → {e(annotate_host(dst, assets))}</li>")
    parts.append("</ul>")
    if mb["device_identification_events"]:
        parts.append(kb_div("modbus_device_id"))

    ctrl = getattr(findings, "control", {}) or {}
    parts.append("<h2>Control, Restart and Logic Commands</h2>")
    for key, label, items in (("ot_restart", "Device restart / STOP commands", ctrl.get("restarts", [])),
                              ("program_download", "Program / logic changes", ctrl.get("program_changes", [])),
                              ("ot_control_commands", "Control / write commands (non-Modbus)", ctrl.get("commands", []))):
        parts.append(f"<h3>{e(label)}: {e(len(items))}</h3><ul>")
        for src, dst, proto, detail in items[:15]:
            parts.append(f"<li>{e(annotate_host(src, assets))} &rarr; {e(annotate_host(dst, assets))}: {e(proto)} {e(detail)}</li>")
        parts.append("</ul>")
        if items:
            parts.append(kb_div(key))
    gs = ctrl.get("goose_multiple_publishers", {})
    parts.append(f"<h3>GOOSE control blocks with more than one publisher: {e(len(gs))}</h3><ul>")
    for gocb, pubs in gs.items():
        parts.append(f"<li><code>{e(gocb)}</code>: " + "; ".join(f"{e(m)} (stNum {e(', '.join(str(x) for x in sts))})" for m, sts in pubs.items()) + "</li>")
    parts.append("</ul>")
    if gs:
        parts.append(kb_div("goose_spoof"))
    parts.append("<h2>Other OT/ICS Protocols Observed</h2>")
    if findings.other_protocols:
        for proto, convs in findings.other_protocols.items():
            parts.append(f"<h3>{e(proto)}: {e(len(convs))} conversation(s)</h3><ul>")
            for src, dst in convs[:10]:
                parts.append(f"<li>{e(annotate_host(src, assets))} ↔ {e(annotate_host(dst, assets))}</li>")
            parts.append("</ul>")
    else:
        parts.append("<p>None observed in this capture.</p>")

    if baseline_diff is not None:
        bd = baseline_diff
        parts.append("<h2>New Since Baseline</h2><ul>")
        parts.append(f"<li>New MAC addresses: <strong>{e(len(bd['new_macs']))}</strong></li>")
        parts.append(f"<li>New ARP pairs: <strong>{e(len(bd['new_arp_pairs']))}</strong></li>")
        parts.append(f"<li>New high-order ports: <strong>{e(len(bd['new_high_order_ports']))}</strong></li>")
        parts.append(f"<li>New Modbus conversations: <strong>{e(len(bd['new_modbus_conversations']))}</strong></li>")
        parts.append(f"<li>New internet destinations: <strong>{e(len(bd['new_internet_destinations']))}</strong></li>")
        parts.append("</ul>")

    parts.append("<hr><p><em>Generated by ot_pcap_triage. Severity, ATT&amp;CK tagging, and "
                  "remediation guidance are decision support, not a substitute for analyst "
                  "judgment.</em></p>")
    parts.append("</body></html>")
    return "\n".join(parts)
