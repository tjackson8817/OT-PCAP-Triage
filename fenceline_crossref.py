#!/usr/bin/env python3
"""
Standalone CLI for Fenceline cross-referencing. The actual logic lives in
ot_pcap_triage.fenceline (importable, and used automatically by the main
CLI's --fenceline-advisories flag). This script is for running the
cross-reference on its own, against already-generated files.

Usage:
    python3 fenceline_crossref.py --pcap-findings report.json --advisories advisories.json
"""

import argparse
import json
import sys

from ot_pcap_triage.fenceline import cross_reference, render_crossref_markdown


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
    report = "# Fenceline Cross-Reference\n\n" + render_crossref_markdown(result)

    if args.out:
        with open(args.out, "w") as f:
            f.write(report)
        print(f"[Cross-reference report written to {args.out}]", file=sys.stderr)
    else:
        print(report)


if __name__ == "__main__":
    main()
