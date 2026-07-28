"""Baseline / diff support: compare a run's signature against a saved one."""


def diff_baseline(current_sig, baseline_sig):
    diff = {}
    diff["new_macs"] = sorted(set(current_sig["macs"]) - set(baseline_sig.get("macs", [])))

    cur_arp = current_sig["arp_pairs"]
    if cur_arp and isinstance(cur_arp[0], (list, tuple)):
        cur_arp_set = set(tuple(p) for p in cur_arp)
    else:
        cur_arp_set = set(cur_arp)
    base_arp = baseline_sig.get("arp_pairs", [])
    if base_arp and isinstance(base_arp[0], (list, tuple)):
        base_arp_set = set(tuple(p) for p in base_arp)
    else:
        base_arp_set = set(base_arp)
    diff["new_arp_pairs"] = sorted(cur_arp_set - base_arp_set)

    diff["new_high_order_ports"] = sorted(set(current_sig["high_order_ports"]) - set(baseline_sig.get("high_order_ports", [])))
    diff["new_modbus_conversations"] = sorted(set(current_sig["modbus_conversations"]) - set(baseline_sig.get("modbus_conversations", [])))
    diff["new_internet_destinations"] = sorted(set(current_sig["internet_destinations"]) - set(baseline_sig.get("internet_destinations", [])))

    baseline_other = baseline_sig.get("other_protocol_conversations", {})
    new_other = {}
    for proto, convs in current_sig["other_protocol_conversations"].items():
        new = sorted(set(convs) - set(baseline_other.get(proto, [])))
        if new:
            new_other[proto] = new
    diff["new_other_protocol_conversations"] = new_other
    return diff
