#!/usr/bin/env python3
"""
Fenceline Cross-Reference
==========================

Connects two tools that answer different questions:
  - Fenceline: "what's been disclosed" (CISA ICS advisories, enriched)
  - ot_pcap_triage: "what's actually on the wire" (this tool's JSON output)

This version matches against Fenceline's CONFIRMED real advisories.json
schema (verified against the actual Fenceline build, not assumed):

    exec_headline, business_impact, sector, cve_ids, vendor, product,
    attack_ics_technique {id, name, url} | null, exploit_maturity,
    cvss_score, ot_risk_rating, ot_risk_rationale, patch_status,
    known_mitigation, mitigation_confidence, purdue_level_estimate,
    severity_tier, source_url

Two independent match signals are checked, and reported separately:

  1. ATT&CK technique match (strong signal) -- both tools tag MITRE
     ATT&CK for ICS techniques. If Fenceline's attack_ics_technique.id
     for a disclosed CVE matches an ATT&CK ID this pcap-triage run
     actually flagged in your traffic (e.g. both say T0855), that's a
     precise, non-keyword-based match.
  2. Protocol keyword match (broader signal) -- searches product,
     vendor, exec_headline, business_impact, ot_risk_rationale, sector
     for protocol keywords tied to what was actually observed in your
     traffic. Looser than #1, but catches advisories that don't carry
     an ATT&CK tag at all.

Usage:
    python3 fenceline_crossref.py --pcap-findings report.json --advisories advisories.json
"""

import argparse
import json
import sys

# Real Fenceline fields worth keyword-searching for protocol/product mentions.
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

# The ATT&CK IDs ot_pcap_triage can tag, matching src/ot_pcap_triage/kb.py.
# Kept as a plain list here (not imported) so this script has no dependency
# on the package being installed -- only on its JSON output.
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
    """Reconstructs which ATT&CK IDs this pcap-triage run actually flagged,
    based on which finding categories fired (mirrors kb.py's mappings)."""
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
            continue  # don't double-report the same advisory under keyword match

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


def render_report(result):
    lines = ["# Fenceline Cross-Reference\n"]
    lines.append(f"**Protocols observed in your traffic:** "
                 f"{', '.join(result['protocols_observed_in_traffic']) or 'none detected'}")
    lines.append(f"**ATT&CK for ICS techniques observed in your traffic:** "
                 f"{', '.join(result['attack_ids_observed_in_traffic']) or 'none'}")
    lines.append(f"**Advisories checked:** {result['advisories_checked']}\n")

    lines.append(f"## Technique Matches (strongest signal): {len(result['technique_matches'])}\n")
    if result["technique_matches"]:
        lines.append("These disclosed advisories map to the exact same MITRE ATT&CK for ICS "
                     "technique that this capture's traffic was flagged for -- not just a keyword "
                     "match, a shared technique.\n")
        for m in result["technique_matches"]:
            lines.append(f"### {m['advisory']}")
            lines.append(f"- ATT&CK match: {m['matched_technique']['id']} {m['matched_technique']['name']}")
            lines.append(f"- Fenceline severity: {m['severity_tier']} (OT risk: {m['ot_risk_rating']})")
            lines.append(f"- Known mitigation ({m['mitigation_confidence']}): {m['known_mitigation']}")
            lines.append("")
    else:
        lines.append("None.\n")

    lines.append(f"## Protocol Keyword Matches (broader signal): {len(result['keyword_matches'])}\n")
    if result["keyword_matches"]:
        for m in result["keyword_matches"]:
            lines.append(f"### {m['advisory']}")
            lines.append(f"- Matched on protocol: {', '.join(m['matched_protocols'])}")
            lines.append(f"- Fenceline severity: {m['severity_tier']} (OT risk: {m['ot_risk_rating']})")
            lines.append("")
    else:
        lines.append("None.\n")

    lines.append("---")
    lines.append("*Technique matches are a precise, non-keyword match against MITRE ATT&CK for ICS. "
                 "Protocol keyword matches are broader and mean the advisory concerns a protocol "
                 "observed in your traffic, not that the specific device/version is confirmed present "
                 "on your network -- treat both as prioritization signals, not confirmed exposure.*")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Cross-reference pcap-triage findings against Fenceline advisories.")
    parser.add_argument("--pcap-findings", required=True, help="JSON output from ot_pcap_triage (--json)")
    parser.add_argument("--advisories", required=True, help="Fenceline data/advisories.json")
    parser.add_argument("--out", default=None, help="Markdown output path (default: prints to stdout)")
    args = parser.parse_args()

    with open(args.pcap_findings) as f:
        pcap_findings = json.load(f)
    with open(args.advisories) as f:
        advisories = json.load(f)
        if isinstance(advisories, dict):
            advisories = advisories.get("advisories", [])

    result = cross_reference(pcap_findings, advisories)
    report = render_report(result)

    if args.out:
        with open(args.out, "w") as f:
            f.write(report)
        print(f"[Cross-reference report written to {args.out}]", file=sys.stderr)
    else:
        print(report)


if __name__ == "__main__":
    main()

