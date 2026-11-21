"""Markdown report rendering, including a plain-English executive summary."""

from .kb import KB, SEVERITY_ORDER, escalate, summary_counts, modbus_writers
from .assets import annotate_host


def build_summary_rows(findings, assets):
    sus = findings.suspicious
    mb = findings.modbus
    ctrl = getattr(findings, "control", {}) or {}
    rows = [(KB[k]["severity"], KB[k]["title"], n) for k, n in summary_counts(sus, mb, ctrl) if n]

    if assets:
        escalate_titles = set()
        if any(w not in assets for w in modbus_writers(mb)):
            escalate_titles.add(KB["modbus_write"]["title"])
        if any(c[0] not in assets for c in ctrl.get("commands", [])):
            escalate_titles.add(KB["ot_control_commands"]["title"])
        rows = [(escalate(sev, 1) if title in escalate_titles else sev, title, cnt) for sev, title, cnt in rows]

    rows.sort(key=lambda r: -SEVERITY_ORDER.index(r[0]))
    return rows


def render_executive_summary(summary_rows, source_file, suppressed_count=0):
    md = ["## Executive Summary\n"]

    if not summary_rows:
        md.append("**No findings triggered against current thresholds in this capture.** "
                   "Nothing in this report requires action.")
        if suppressed_count:
            md.append(f"\n({suppressed_count} previously-triaged item(s) were suppressed per your allowlist.)")
        return "\n".join(md)

    critical = sum(c for s, _, c in summary_rows if s == "CRITICAL")
    high = sum(c for s, _, c in summary_rows if s == "HIGH")
    top = summary_rows[0]

    if critical:
        urgency = f"**{critical} Critical** finding(s) need review today."
    elif high:
        urgency = f"**{high} High** finding(s) should be reviewed this week."
    else:
        urgency = "Nothing Critical or High -- lower urgency, but worth a look."

    md.append(f"**What happened:** This capture ({source_file}) was checked against "
               f"{len(summary_rows)} categories of known OT/ICS network risk indicators; "
               f"{sum(c for _, _, c in summary_rows)} individual events were flagged.")
    md.append(f"\n**How urgent:** {urgency}")
    md.append(f"\n**Look at this first:** {top[1]} ({top[2]} occurrence(s), severity {top[0]}).")
    if suppressed_count:
        md.append(f"\n*{suppressed_count} previously-triaged item(s) were suppressed per your allowlist "
                   f"and are not counted above.*")
    return "\n".join(md)


def kb_block(md, key):
    kb = KB[key]
    md.append(f"**Severity: {kb['severity']}**")
    if kb["attack"]:
        tags = ", ".join(f"{a['id']} {a['name']} ({a['tactic']}, {a['confidence']})" for a in kb["attack"])
        md.append(f"**ATT&CK for ICS:** {tags}")
    else:
        md.append("**ATT&CK for ICS:** no single confirmed technique mapping -- treated as a general anomaly indicator")
    md.append(f"**Why it matters:** {kb['why']}")
    md.append(f"**Immediate action:** {kb['immediate']}")
    md.append(f"**Remediation:** {kb['remediation']}")
    md.append(f"**Reference:** {kb['reference']}")


def render_markdown(findings, source_file, assets=None, baseline_diff=None,
                     suppressed_count=0, trend_md=None, crossref_md=None):
    summary_rows = build_summary_rows(findings, assets)

    md = []
    md.append("# OT PCAP Triage Report\n")
    md.append(f"**Source file:** `{source_file}`  ")
    md.append(f"**Generated:** {findings.meta['generated_at']}  ")
    md.append(f"**Total packets analyzed:** {findings.meta['total_packets']}  ")
    md.append(f"**Asset context provided:** {'Yes' if assets else 'No -- pass --assets to enable recognized/unrecognized host labeling'}  ")
    if baseline_diff is not None:
        md.append("**Baseline comparison:** enabled -- see 'New Since Baseline' section  ")
    md.append("")

    md.append(render_executive_summary(summary_rows, source_file, suppressed_count))
    md.append("")

    md.append("## Findings Summary (highest severity first)\n")
    if summary_rows:
        md.append("| Severity | Finding | Count |")
        md.append("|---|---|---|")
        for sev, title, cnt in summary_rows:
            md.append(f"| {sev} | {title} | {cnt} |")
    else:
        md.append("No findings triggered against current thresholds.")
    md.append("")

    nd = findings.network_discovery
    md.append("## Network Discovery\n")
    md.append(f"- Broadcast frames: **{nd['broadcast_frames']}**")
    md.append(f"- Unique MAC addresses seen: **{len(nd['unique_mac_addresses'])}**")
    md.append(f"- ARP responses (IP -> MAC mappings): **{nd['arp_response_count']}**")
    md.append(f"- DHCP Discover/Request events: **{nd['dhcp_event_count']}**")
    md.append(f"- Unique IPs in 192.168.0.0/16: **{len(nd['unique_192_ips'])}**\n")

    sus = findings.suspicious
    mb = findings.modbus

    md.append("## Suspicious Activity\n")

    scanners = sus["possible_port_scanners"]
    md.append(f"### Possible port scanning: {len(scanners)} source(s) flagged")
    for src, targets in scanners.items():
        md.append(f"- {annotate_host(src, assets)} hit **{len(targets)}** distinct dest ports/IPs (SYN-no-ACK)")
    if scanners:
        kb_block(md, "port_scanning")
    md.append("")

    md.append(f"### Connections to uncommon ports: {len(sus['uncommon_port_connections'])}")
    for src, dst, port in sus["uncommon_port_connections"][:15]:
        md.append(f"- {annotate_host(src, assets)} → {annotate_host(dst, assets)}:{port}")
    if len(sus["uncommon_port_connections"]) > 15:
        md.append(f"- ... and {len(sus['uncommon_port_connections']) - 15} more")
    if sus["uncommon_port_connections"]:
        kb_block(md, "uncommon_port")
    md.append("")

    md.append(f"### Modbus over non-standard port: {len(sus['modbus_over_nonstandard_port'])}")
    for src, dst, port in sus["modbus_over_nonstandard_port"][:15]:
        md.append(f"- {annotate_host(src, assets)} → {annotate_host(dst, assets)} on port {port}")
    if sus["modbus_over_nonstandard_port"]:
        kb_block(md, "modbus_nonstandard_port")
    md.append("")

    md.append(f"### Malformed / suspect packets: {len(sus['malformed_packet_flags'])}")
    for src, dst, reason in sus["malformed_packet_flags"][:15]:
        md.append(f"- {annotate_host(src, assets)} → {annotate_host(dst, assets)}: {reason}")
    if sus["malformed_packet_flags"]:
        kb_block(md, "malformed_packets")
    md.append("")

    md.append(f"### Long TCP sessions (possible tunneling): "
               f"{len(sus['long_tcp_sessions_bytes_in_flight'])}")
    md.append("*Sessions with an internet endpoint over 10 KB, or internal sessions over 1 MB on ports that aren't a known OT/IT service.*")
    for conv, total in sus["long_tcp_sessions_bytes_in_flight"].items():
        md.append(f"- {conv}: {total} bytes")
    if sus["long_tcp_sessions_bytes_in_flight"]:
        kb_block(md, "long_tcp_sessions")
    md.append("")

    md.append(f"### OT/ICS traffic reaching the public internet: {len(sus['ot_traffic_to_internet'])}")
    from .detect import is_public
    for src, dst in sus["ot_traffic_to_internet"][:15]:
        direction = "inbound from the internet" if is_public(src) else "outbound to the internet"
        md.append(f"- {annotate_host(src, assets)} → {annotate_host(dst, assets)} ({direction})")
    if sus["ot_traffic_to_internet"]:
        kb_block(md, "ot_to_internet")
    else:
        md.append("- None detected -- no packets left private address space.")
    md.append("")

    md.append("## Modbus Protocol Detail\n")
    md.append(f"- Modbus conversations (port 502): **{len(mb['conversations'])}**")
    for src, dst in mb["conversations"][:15]:
        md.append(f"  - {annotate_host(src, assets)} ↔ {annotate_host(dst, assets)}")

    w_events = ([(s, d, "Write Single Coil") for s, d in mb["write_single_coil_events"]]
                + [(s, d, "Write Single Register") for s, d in mb.get("write_single_register_events", [])]
                + [(s, d, "Write Multiple Registers") for s, d in mb["write_multiple_registers_events"]]
                + list(mb.get("write_other_events", [])))
    write_total = len(w_events)
    by_type = {}
    for _, _, name in w_events:
        by_type[name] = by_type.get(name, 0) + 1
    md.append(f"\n### Write commands: {write_total}"
              + (" (" + ", ".join(f"{k}: {v}" for k, v in by_type.items()) + ")" if by_type else ""))
    for src, dst, name in w_events[:15]:
        md.append(f"- {annotate_host(src, assets)} → {annotate_host(dst, assets)}: {name}")
    if write_total:
        kb_block(md, "modbus_write")
    md.append("")

    md.append(f"### Device Identification requests: {len(mb['device_identification_events'])}")
    for src, dst in mb["device_identification_events"][:15]:
        md.append(f"- {annotate_host(src, assets)} → {annotate_host(dst, assets)}")
    if mb["device_identification_events"]:
        kb_block(md, "modbus_device_id")
    md.append("")

    if mb["function_code_counts"]:
        md.append("### Full function code distribution")
        for code, count in sorted(mb["function_code_counts"].items(), key=lambda x: -x[1]):
            md.append(f"- code {code}: {count}")
    md.append("")

    ctrl = getattr(findings, "control", {}) or {}
    md.append("## Control, Restart and Logic Commands (all OT protocols)\n")
    for key, label, items in (("ot_restart", "Device restart / STOP commands", ctrl.get("restarts", [])),
                              ("program_download", "Program / logic changes", ctrl.get("program_changes", [])),
                              ("ot_control_commands", "Control / write commands (non-Modbus)", ctrl.get("commands", []))):
        md.append(f"### {label}: {len(items)}")
        for src, dst, proto, detail in items[:15]:
            md.append(f"- {annotate_host(src, assets)} → {annotate_host(dst, assets)}: {proto} {detail}")
        if len(items) > 15:
            md.append(f"- ... and {len(items) - 15} more")
        if items:
            kb_block(md, key)
        md.append("")
    gs = ctrl.get("goose_multiple_publishers", {})
    md.append(f"### GOOSE control blocks with more than one publisher: {len(gs)}")
    for gocb, pubs in gs.items():
        md.append(f"- `{gocb}`: " + "; ".join(f"{mac} (stNum {', '.join(str(x) for x in sts)})" for mac, sts in pubs.items()))
    if gs:
        kb_block(md, "goose_spoof")
    md.append("")

    md.append("## Other OT/ICS Protocols Observed\n")
    if findings.other_protocols:
        for proto, convs in findings.other_protocols.items():
            md.append(f"### {proto}: {len(convs)} conversation(s)")
            for src, dst in convs[:10]:
                md.append(f"- {annotate_host(src, assets)} ↔ {annotate_host(dst, assets)}")
    else:
        md.append("- None of Modbus / S7 / IEC 61850 MMS / DNP3 / IEC 60870-5-104 / EtherNet/IP / "
                   "Profinet / GOOSE / Sampled Values / BACnet observed in this capture.")
    md.append("")

    if baseline_diff is not None:
        md.append("## New Since Baseline\n")
        bd = baseline_diff
        md.append(f"- New MAC addresses: **{len(bd['new_macs'])}**")
        for m in bd["new_macs"][:20]:
            md.append(f"  - {m}")
        md.append(f"- New ARP IP↔MAC pairs: **{len(bd['new_arp_pairs'])}**")
        for p in bd["new_arp_pairs"][:20]:
            md.append(f"  - {p}")
        md.append(f"- New high-order ports observed: **{len(bd['new_high_order_ports'])}**")
        for p in bd["new_high_order_ports"][:20]:
            md.append(f"  - {p}")
        md.append(f"- New Modbus conversations: **{len(bd['new_modbus_conversations'])}**")
        for c in bd["new_modbus_conversations"][:20]:
            md.append(f"  - {c}")
        md.append(f"- New public-internet destinations: **{len(bd['new_internet_destinations'])}**")
        for d in bd["new_internet_destinations"][:20]:
            md.append(f"  - {d}")
        if bd["new_other_protocol_conversations"]:
            md.append("- New conversations in other OT/ICS protocols:")
            for proto, convs in bd["new_other_protocol_conversations"].items():
                md.append(f"  - **{proto}**: {len(convs)} new")
                for c in convs[:10]:
                    md.append(f"    - {c}")
        md.append("")

    if trend_md:
        md.append(trend_md)
        md.append("")

    if crossref_md:
        md.append(crossref_md)
        md.append("")

    md.append("---")
    md.append("*Generated by ot_pcap_triage. Detection logic mirrors the \"Wireshark for "
               "OT Cybersecurity\" filter reference. Severity, ATT&CK tagging, and remediation "
               "guidance are decision support, not a substitute for analyst judgment -- confirm "
               "flagged items against asset ownership and change records before treating them as "
               "confirmed incidents.*")

    return "\n".join(md), summary_rows
