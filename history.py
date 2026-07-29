"""
Fenceline Cross-Reference (importable module)
================================================

Connects two tools that answer different questions:
  - Fenceline: "what's been disclosed" (CISA ICS advisories, enriched)
  - ot_pcap_triage: "what's actually on the wire"

Matches against Fenceline's confirmed real advisories.json schema:
    exec_headline, business_impact, sector, cve_ids, vendor, product,
    attack_ics_technique {id, name, url} | null, exploit_maturity,
    cvss_score, ot_risk_rating, ot_risk_rationale, patch_status,
    known_mitigation, mitigation_confidence, purdue_level_estimate,
    severity_tier, source_url

Two independent match signals, reported separately:
  1. ATT&CK technique match (strong) -- both tools tag MITRE ATT&CK for
     ICS techniques; a shared technique ID is a precise, non-keyword match.
  2. Protocol keyword match (broader) -- product/vendor/summary text
     matched against protocols actually observed in your traffic.
"""

ADVISORY_TEXT_FIELDS = ["exec_headline", "business_impact", "ot_risk_rationale", "product", "vendor", "sector"]

PROTOCOL_KEYWORDS = {
    "modbus": ["modbus"],
    "s7": ["s7", "s7comm", "step 7", "simatic"],
    "dnp3": ["dnp3"],
    "ethernet/ip": ["ethernet/ip", "ethernet-ip", "cip ", "common industrial protocol"],
    "profinet": ["profinet"],
    "bacnet": ["bacnet"],
    "iec 60870-5-104": ["iec 60870", "60870-5-104", "iec104"],
    "iec 61850": ["iec 61850", "goose", "sampled values", "mms"],
}

PCAP_TRIAGE_ATTACK_IDS = {"T0846", "T0855", "T0831", "T0869", "T0884", "T0888"}


def advisory_text(advisory):
    parts = []
    for field in ADVISORY_TEXT_FIELDS:
        val = advisory.get(field)
        if val:
            parts.append(str(val))
    return " ".join(parts).lower()


def advisory_label(advisory):
    cves = advisory.get("cve_ids") or []
    headline = advisory.get("exec_headline")
    if cves and headline:
        return f"{', '.join(cves)} -- {headline}"
    if headline:
        return headline
    if cves:
        return ", ".join(cves)
    return advisory.get("source_url") or "(unlabeled advisory)"


def observed_protocols(pcap_findings):
    observed = set()
    if pcap_findings.get("modbus", {}).get("conversations"):
        observed.add("modbus")
    for proto_name in pcap_findings.get("other_protocols", {}):
        name_lower = proto_name.lower()
        for key, keywords in PROTOCOL_KEYWORDS.items():
            if key in name_lower or any(kw in name_lower for kw in keywords):
                observed.add(key)
    return observed


def observed_attack_ids(pcap_findings):
    ids = set()
    sus = pcap_findings.get("suspicious", {})
    mb = pcap_findings.get("modbus", {})

    if sus.get("possible_port_scanners"):
        ids.add("T0846")
    if (mb.get("write_single_coil_events") or mb.get("write_multiple_registers_events")):
        ids.add("T0855")
        ids.add("T0831")
    if sus.get("modbus_over_nonstandard_port"):
        ids.add("T0869")
    if sus.get("long_tcp_sessions_bytes_in_flight") or sus.get("ot_traffic_to_internet"):
        ids.add("T0884")
    if mb.get("device_identification_events"):
        ids.add("T0888")
    return ids


def cross_reference(pcap_findings, advisories):
    observed_proto = observed_protocols(pcap_findings)
    observed_attack = observed_attack_ids(pcap_findings)

    technique_matches = []
    keyword_matches = []

    for advisory in advisories:
        technique = advisory.get("attack_ics_technique")
        if technique and technique.get("id") in observed_attack:
            technique_matches.append({
                "advisory": advisory_label(advisory),
                "matched_technique": technique,
                "severity_tier": advisory.get("severity_tier"),
                "ot_risk_rating": advisory.get("ot_risk_rating"),
                "known_mitigation": advisory.get("known_mitigation"),
                "mitigation_confidence": advisory.get("mitigation_confidence"),
            })
            continue

        text = advisory_text(advisory)
        hit_protocols = {key for key, kws in PROTOCOL_KEYWORDS.items()
                         if key in observed_proto and any(kw in text for kw in kws)}
        if hit_protocols:
            keyword_matches.append({
                "advisory": advisory_label(advisory),
                "matched_protocols": sorted(hit_protocols),
                "severity_tier": advisory.get("severity_tier"),
                "ot_risk_rating": advisory.get("ot_risk_rating"),
            })

    return {
        "protocols_observed_in_traffic": sorted(observed_proto),
        "attack_ids_observed_in_traffic": sorted(observed_attack),
        "advisories_checked": len(advisories),
        "technique_matches": technique_matches,
        "keyword_matches": keyword_matches,
    }


def render_crossref_markdown(result):
    md = ["## Related Disclosed Advisories (Fenceline Cross-Reference)\n"]
    md.append(f"Checked against {result['advisories_checked']} disclosed advisories from Fenceline.\n")

    md.append(f"### Technique Matches (strongest signal): {len(result['technique_matches'])}")
    if result["technique_matches"]:
        md.append("These map to the exact same MITRE ATT&CK for ICS technique this capture's traffic was flagged for.\n")
        for m in result["technique_matches"]:
            md.append(f"- **{m['advisory']}**")
            md.append(f"  - ATT&CK match: {m['matched_technique']['id']} {m['matched_technique']['name']}")
            md.append(f"  - Fenceline severity: {m['severity_tier']} (OT risk: {m['ot_risk_rating']})")
            md.append(f"  - Known mitigation ({m['mitigation_confidence']}): {m['known_mitigation']}")
    else:
        md.append("None.")

    md.append(f"\n### Protocol Keyword Matches (broader signal): {len(result['keyword_matches'])}")
    if result["keyword_matches"]:
        for m in result["keyword_matches"]:
            md.append(f"- **{m['advisory']}** \u2014 matched on {', '.join(m['matched_protocols'])} "
                     f"(severity {m['severity_tier']}, OT risk {m['ot_risk_rating']})")
    else:
        md.append("None.")

    md.append("\n*Technique matches are a precise, non-keyword match against MITRE ATT&CK for ICS. "
              "Protocol keyword matches are broader and mean the advisory concerns a protocol observed "
              "in your traffic, not that the specific device/version is confirmed present on your "
              "network -- treat both as prioritization signals, not confirmed exposure.*")
    return "\n".join(md)

