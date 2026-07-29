"""
Suppressions let you silence findings you've already triaged and confirmed
benign, e.g. "the historian legitimately reaches the internet." A CSV with
columns: src,dst,category (any field may be '*' as a wildcard).

category values match the finding-list keys used internally:
  port_scanning, uncommon_port, modbus_nonstandard_port, malformed_packets,
  long_tcp_sessions, ot_to_internet, modbus_write, modbus_device_id
"""

import csv


def load_suppressions(path):
    rules = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rules.append({
                "src": row.get("src", "*").strip() or "*",
                "dst": row.get("dst", "*").strip() or "*",
                "category": row.get("category", "*").strip() or "*",
            })
    return rules


def _matches(rule, src, dst, category):
    if rule["category"] != "*" and rule["category"] != category:
        return False
    if rule["src"] != "*" and rule["src"] != src:
        return False
    if rule["dst"] != "*" and rule["dst"] != dst:
        return False
    return True


def is_suppressed(rules, src, dst, category):
    return any(_matches(r, src, dst, category) for r in rules)


def apply_suppressions(findings, rules):
    """Filters findings.suspicious / findings.modbus lists in place given
    a list of suppression rules. Returns a count of suppressed items for
    reporting transparency (never silently hide that suppression happened)."""
    if not rules:
        return 0

    suppressed_count = 0
    sus = findings.suspicious
    mb = findings.modbus

    def filt(items, category, src_idx=0, dst_idx=1):
        nonlocal suppressed_count
        kept = []
        for item in items:
            src, dst = item[src_idx], item[dst_idx]
            if is_suppressed(rules, src, dst, category):
                suppressed_count += 1
            else:
                kept.append(item)
        return kept

    sus["uncommon_port_connections"] = filt(sus["uncommon_port_connections"], "uncommon_port")
    sus["modbus_over_nonstandard_port"] = filt(sus["modbus_over_nonstandard_port"], "modbus_nonstandard_port")
    sus["malformed_packet_flags"] = filt(sus["malformed_packet_flags"], "malformed_packets")
    sus["ot_traffic_to_internet"] = filt(sus["ot_traffic_to_internet"], "ot_to_internet")

    # possible_port_scanners is a dict src -> targets; suppress whole source if matched with dst='*'
    kept_scanners = {}
    for src, targets in sus["possible_port_scanners"].items():
        if is_suppressed(rules, src, "*", "port_scanning"):
            suppressed_count += 1
        else:
            kept_scanners[src] = targets
    sus["possible_port_scanners"] = kept_scanners

    # long sessions keyed by "ip:port <-> ip:port" string -- suppress by parsing endpoints
    kept_sessions = {}
    for conv, total in sus["long_tcp_sessions_bytes_in_flight"].items():
        try:
            left, right = conv.split(" <-> ")
            src = left.split(":")[0]
            dst = right.split(":")[0]
        except ValueError:
            src, dst = "*", "*"
        if is_suppressed(rules, src, dst, "long_tcp_sessions"):
            suppressed_count += 1
        else:
            kept_sessions[conv] = total
    sus["long_tcp_sessions_bytes_in_flight"] = kept_sessions

    mb["write_single_coil_events"] = filt(mb["write_single_coil_events"], "modbus_write")
    mb["write_multiple_registers_events"] = filt(mb["write_multiple_registers_events"], "modbus_write")
    mb["device_identification_events"] = filt(mb["device_identification_events"], "modbus_device_id")

    return suppressed_count
