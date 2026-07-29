#!/usr/bin/env python3
"""
OT PCAP Triage Tool -- CLI

Usage:
    ot-pcap-triage capture.pcap
    ot-pcap-triage capture.pcap --assets assets.csv --suppress suppressions.csv
    ot-pcap-triage capture.pcap --save-baseline baseline.json
    ot-pcap-triage capture.pcap --baseline baseline.json --history history.json
    ot-pcap-triage --batch /path/to/pcaps/ --out-dir reports/
"""

import argparse
import glob
import json
import os
import sys

from .detect import triage
from .assets import load_assets
from .suppress import load_suppressions, apply_suppressions
from .baseline import diff_baseline
from .history import append_history, render_trend_markdown
from .report_md import render_markdown, build_summary_rows, render_executive_summary
from .report_html import render_html
from .fenceline import cross_reference, render_crossref_markdown
from .exec_report import render_exec_html


def run_one(pcap_path, args, assets, suppressions):
    findings = triage(pcap_path, assets=assets)
    suppressed_count = apply_suppressions(findings, suppressions) if suppressions else 0

    baseline_diff = None
    if args.baseline:
        with open(args.baseline) as f:
            baseline_sig = json.load(f)
        baseline_diff = diff_baseline(findings.signature, baseline_sig)

    trend_md = None
    if args.history:
        summary_rows_preview = build_summary_rows(findings, assets)
        history = append_history(args.history, pcap_path, summary_rows_preview, findings.meta["total_packets"])
        trend_md = render_trend_markdown(history)

    crossref_result = None
    crossref_md = None
    if args.fenceline_advisories:
        payload = {
            "meta": findings.meta,
            "network_discovery": findings.network_discovery,
            "suspicious": findings.suspicious,
            "modbus": findings.modbus,
            "other_protocols": findings.other_protocols,
        }
        with open(args.fenceline_advisories) as f:
            advisories = json.load(f)
            if isinstance(advisories, dict):
                advisories = advisories.get("advisories", [])
        crossref_result = cross_reference(payload, advisories)
        crossref_md = render_crossref_markdown(crossref_result)

    report_md, summary_rows = render_markdown(
        findings, pcap_path, assets=assets, baseline_diff=baseline_diff,
        suppressed_count=suppressed_count, trend_md=trend_md, crossref_md=crossref_md,
    )

    if args.save_baseline:
        with open(args.save_baseline, "w") as f:
            json.dump(findings.signature, f, indent=2, default=str)

    return findings, report_md, summary_rows, baseline_diff, suppressed_count, crossref_result


def write_outputs(pcap_path, findings, report_md, summary_rows, baseline_diff,
                   suppressed_count, out_md, out_html=None, out_json=None, assets=None,
                   out_pdf=None, crossref_result=None, out_exec_pdf=None, exec_meta=None):
    with open(out_md, "w") as f:
        f.write(report_md)

    html_report = None
    if out_html or out_pdf:
        from .report_html import markdown_bold_to_html
        exec_text = render_executive_summary(summary_rows, pcap_path, suppressed_count)
        exec_lines = [l for l in exec_text.split("\n") if l.strip() and not l.strip().startswith("#")]
        exec_html_lines = "<br>".join(markdown_bold_to_html(l) for l in exec_lines)
        html_report = render_html(
            findings, pcap_path, summary_rows, assets=assets, baseline_diff=baseline_diff,
            suppressed_count=suppressed_count, exec_summary_text=exec_html_lines,
        )

    if out_html:
        with open(out_html, "w") as f:
            f.write(html_report)

    if out_pdf:
        from .pdf import html_to_pdf
        html_to_pdf(html_report, out_pdf)

    if out_json:
        payload = {
            "meta": findings.meta,
            "network_discovery": findings.network_discovery,
            "suspicious": findings.suspicious,
            "modbus": findings.modbus,
            "other_protocols": findings.other_protocols,
        }
        with open(out_json, "w") as f:
            json.dump(payload, f, indent=2, default=str)

    if out_exec_pdf:
        from .pdf import html_to_pdf
        payload = {
            "meta": findings.meta,
            "network_discovery": findings.network_discovery,
            "suspicious": findings.suspicious,
            "modbus": findings.modbus,
            "other_protocols": findings.other_protocols,
        }
        meta = exec_meta or {}
        exec_html = render_exec_html(
            payload,
            client=meta.get("client", "[Client Name]"),
            site=meta.get("site", "[Site / Scope]"),
            prepared_by=meta.get("prepared_by", "Thomas Jackson, Principal"),
            firm=meta.get("firm", "Sale Fish Marketing & Consulting"),
            crossref_result=crossref_result,
        )
        html_to_pdf(exec_html, out_exec_pdf)


def main():
    parser = argparse.ArgumentParser(description="Triage pcap(s) for OT/ICS security findings.")
    parser.add_argument("pcap", nargs="?", help="Path to .pcap or .pcapng file")
    parser.add_argument("--batch", default=None, help="Directory of pcaps to process; produces one report per file plus an aggregate summary")
    parser.add_argument("--out", default=None, help="Markdown report path (single-file mode; default: <pcap>.report.md)")
    parser.add_argument("--out-dir", default="reports", help="Output directory for --batch mode")
    parser.add_argument("--html", action="store_true", help="Also write an HTML report alongside the Markdown")
    parser.add_argument("--json", default=None, help="Optional path to also write raw findings as JSON (single-file mode)")
    parser.add_argument("--assets", default=None, help="Optional CSV (ip,role,name) of known assets for host annotation")
    parser.add_argument("--suppress", default=None, help="Optional CSV (src,dst,category) of previously-triaged findings to silence")
    parser.add_argument("--baseline", default=None, help="Optional prior baseline signature JSON to diff against")
    parser.add_argument("--save-baseline", default=None, help="Path to save this run's signature as a future baseline")
    parser.add_argument("--history", default=None, help="Optional path to a trend-history JSON file (appended to each run)")
    parser.add_argument("--fenceline-advisories", default=None, help="Optional Fenceline advisories.json -- automatically cross-references and adds a section to the report")
    parser.add_argument("--pdf", action="store_true", help="Also write a PDF version of the technical report (requires weasyprint)")
    parser.add_argument("--exec-pdf", default=None, help="Path to write a branded executive-summary PDF (requires weasyprint)")
    parser.add_argument("--client", default="[Client Name]", help="Client name for the executive PDF")
    parser.add_argument("--site", default="[Site / Scope]", help="Site/scope description for the executive PDF")
    parser.add_argument("--prepared-by", default="Thomas Jackson, Principal", help="Preparer name for the executive PDF")
    parser.add_argument("--firm", default="Sale Fish Marketing & Consulting", help="Firm name for the executive PDF")
    args = parser.parse_args()

    assets = load_assets(args.assets) if args.assets else None
    suppressions = load_suppressions(args.suppress) if args.suppress else None

    if args.batch:
        pcap_files = sorted(
            glob.glob(os.path.join(args.batch, "*.pcap")) +
            glob.glob(os.path.join(args.batch, "*.pcapng"))
        )
        if not pcap_files:
            print(f"No .pcap/.pcapng files found in {args.batch}", file=sys.stderr)
            sys.exit(1)

        os.makedirs(args.out_dir, exist_ok=True)
        aggregate = []
        for pcap_path in pcap_files:
            base = os.path.splitext(os.path.basename(pcap_path))[0]
            findings, report_md, summary_rows, baseline_diff, suppressed_count, crossref_result = run_one(
                pcap_path, args, assets, suppressions
            )
            out_md = os.path.join(args.out_dir, f"{base}.report.md")
            out_html = os.path.join(args.out_dir, f"{base}.report.html") if (args.html or args.pdf) else None
            out_json = os.path.join(args.out_dir, f"{base}.report.json") if args.json else None
            out_pdf = os.path.join(args.out_dir, f"{base}.report.pdf") if args.pdf else None
            write_outputs(pcap_path, findings, report_md, summary_rows, baseline_diff,
                          suppressed_count, out_md, out_html, out_json, assets=assets,
                          out_pdf=out_pdf, crossref_result=crossref_result)
            aggregate.append((pcap_path, summary_rows))
            print(f"[{base}] {len(summary_rows)} finding categories -> {out_md}", file=sys.stderr)

        agg_path = os.path.join(args.out_dir, "_aggregate_summary.md")
        with open(agg_path, "w") as f:
            f.write("# Batch Triage -- Aggregate Summary\n\n")
            f.write(f"Processed {len(pcap_files)} capture(s) from `{args.batch}`\n\n")
            f.write("| File | Critical | High | Medium | Low |\n|---|---|---|---|---|\n")
            for pcap_path, summary_rows in aggregate:
                counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                for sev, _title, cnt in summary_rows:
                    if sev in counts:
                        counts[sev] += cnt
                f.write(f"| {os.path.basename(pcap_path)} | {counts['CRITICAL']} | {counts['HIGH']} | "
                        f"{counts['MEDIUM']} | {counts['LOW']} |\n")
        print(f"\n[Aggregate summary written to {agg_path}]", file=sys.stderr)
        return

    if not args.pcap:
        parser.error("pcap is required unless --batch is used")

    findings, report_md, summary_rows, baseline_diff, suppressed_count, crossref_result = run_one(
        args.pcap, args, assets, suppressions
    )
    out_md = args.out or (args.pcap + ".report.md")
    out_html = (os.path.splitext(out_md)[0] + ".html") if (args.html or args.pdf) else None
    out_pdf = (os.path.splitext(out_md)[0] + ".pdf") if args.pdf else None
    exec_meta = {"client": args.client, "site": args.site, "prepared_by": args.prepared_by, "firm": args.firm}
    write_outputs(args.pcap, findings, report_md, summary_rows, baseline_diff,
                  suppressed_count, out_md, out_html, args.json, assets=assets,
                  out_pdf=out_pdf, crossref_result=crossref_result,
                  out_exec_pdf=args.exec_pdf, exec_meta=exec_meta)

    print(report_md)
    print(f"\n\n[Report written to {out_md}]", file=sys.stderr)
    if args.html:
        print(f"[HTML report written to {out_html}]", file=sys.stderr)
    if out_pdf:
        print(f"[PDF report written to {out_pdf}]", file=sys.stderr)
    if args.exec_pdf:
        print(f"[Executive PDF written to {args.exec_pdf}]", file=sys.stderr)
    if args.json:
        print(f"[JSON written to {args.json}]", file=sys.stderr)
    if args.save_baseline:
        print(f"[Baseline signature saved to {args.save_baseline}]", file=sys.stderr)


if __name__ == "__main__":
    main()
