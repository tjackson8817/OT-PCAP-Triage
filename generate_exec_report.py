#!/usr/bin/env python3
"""
Executive Report Generator
============================

Reads the JSON findings output from ot_pcap_triage (--json) and produces a
polished, non-technical .docx summary suitable for a client, board, or
executive audience -- separate from the full technical Markdown/HTML
report, which stays analyst-facing.

Usage:
    python3 generate_exec_report.py --json report.json --out exec_report.docx \\
        --client "Acme Manufacturing" --site "Plant 4 - Mixing Line" \\
        --prepared-by "Thomas Jackson, Principal" --firm "Sale Fish Marketing & Consulting"
"""

import argparse
import json
from datetime import datetime

from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

from ot_pcap_triage.kb import KB, SEVERITY_ORDER, summary_counts

ACCENT = RGBColor(0x1F, 0x3B, 0x57)
SEVERITY_COLORS_HEX = {
    "CRITICAL": "8B0000",
    "HIGH": "C0392B",
    "MEDIUM": "E67E22",
    "LOW": "B8960C",
    "INFO": "607D8B",
}


def shade_cell(cell, hex_color):
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:fill"), hex_color)
    cell._tc.get_or_add_tcPr().append(shd)


def set_cell_text(cell, text, bold=False, color=None, size=10, align=None):
    cell.text = ""
    p = cell.paragraphs[0]
    if align:
        p.alignment = align
    run = p.add_run(text)
    run.bold = bold
    run.font.size = Pt(size)
    if color:
        run.font.color.rgb = color


def build_summary_rows(findings, assets_provided):
    rows = [(KB[k]["severity"], KB[k]["title"], n)
            for k, n in summary_counts(findings["suspicious"], findings["modbus"], findings.get("control", {})) if n]
    rows.sort(key=lambda r: -SEVERITY_ORDER.index(r[0]))
    return rows


def generate(findings, out_path, client, site, prepared_by, firm):
    rows = build_summary_rows(findings, findings["meta"].get("assets_provided"))
    critical = sum(c for s, _, c in rows if s == "CRITICAL")
    high = sum(c for s, _, c in rows if s == "HIGH")

    doc = Document()
    section = doc.sections[0]
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)
    section.left_margin = Inches(0.9)
    section.right_margin = Inches(0.9)
    section.top_margin = Inches(0.8)
    section.bottom_margin = Inches(0.8)

    # ---- Cover / header block -------------------------------------------
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(firm)
    run.bold = True
    run.font.size = Pt(20)
    run.font.color.rgb = ACCENT

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("OT/ICS Network Security Assessment")
    run.italic = True
    run.font.size = Pt(13)

    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(18)
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("Executive Summary")
    run.bold = True
    run.font.size = Pt(26)

    info_table = doc.add_table(rows=3, cols=2)
    info_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    labels = [("Client", client), ("Site / Scope", site), ("Date", datetime.now().strftime("%B %d, %Y"))]
    for i, (label, value) in enumerate(labels):
        set_cell_text(info_table.cell(i, 0), label, bold=True, size=10)
        set_cell_text(info_table.cell(i, 1), value, size=10)
    for row in info_table.rows:
        for cell in row.cells:
            cell.width = Inches(2.8)

    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # ---- Executive summary narrative -------------------------------------
    h = doc.add_heading("Summary", level=1)
    h.runs[0].font.color.rgb = ACCENT

    total_events = sum(c for _, _, c in rows)
    if critical:
        urgency = f"{critical} Critical-severity finding(s) warrant review within the next business day."
    elif high:
        urgency = f"No Critical findings, but {high} High-severity finding(s) should be reviewed this week."
    elif rows:
        urgency = "No Critical or High-severity findings. Lower urgency, but findings below are still worth a look."
    else:
        urgency = "No findings were triggered against current detection thresholds during this assessment window."

    summary_text = (
        f"This assessment analyzed {findings['meta']['total_packets']:,} packets of network traffic "
        f"captured from the OT/ICS environment described above. Traffic was evaluated against "
        f"{len(rows)} categories of known industrial-network risk indicators, covering reconnaissance "
        f"activity, unauthorized control commands, protocol misuse, and traffic leaving the intended "
        f"network boundary. {total_events} individual events were flagged for review. {urgency}"
    )
    doc.add_paragraph(summary_text)

    if rows:
        top_sev, top_title, top_count = rows[0]
        p = doc.add_paragraph()
        run = p.add_run("Highest priority: ")
        run.bold = True
        p.add_run(f"{top_title} ({top_count} occurrence(s), severity {top_sev}).")

    # ---- Findings table ----------------------------------------------------
    h = doc.add_heading("Findings Overview", level=1)
    h.runs[0].font.color.rgb = ACCENT

    if rows:
        table = doc.add_table(rows=1 + len(rows), cols=3)
        table.style = "Light Grid Accent 1" if "Light Grid Accent 1" in [s.name for s in doc.styles] else None
        hdr = table.rows[0]
        for i, text in enumerate(["Severity", "Finding", "Count"]):
            set_cell_text(hdr.cells[i], text, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF), size=10)
            shade_cell(hdr.cells[i], "1F3B57")
        for r, (sev, title, count) in enumerate(rows, start=1):
            set_cell_text(table.cell(r, 0), sev, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF), size=10)
            shade_cell(table.cell(r, 0), SEVERITY_COLORS_HEX.get(sev, "607D8B"))
            set_cell_text(table.cell(r, 1), title, size=10)
            set_cell_text(table.cell(r, 2), str(count), size=10)
    else:
        doc.add_paragraph("No findings triggered against current thresholds.")

    # ---- Priority actions --------------------------------------------------
    h = doc.add_heading("Priority Actions", level=1)
    h.runs[0].font.color.rgb = ACCENT

    key_by_title = {v["title"]: k for k, v in KB.items()}
    shown = 0
    for sev, title, count in rows:
        if sev not in ("CRITICAL", "HIGH"):
            continue
        key = key_by_title.get(title)
        if not key:
            continue
        p = doc.add_paragraph(style="List Bullet")
        run = p.add_run(f"{title}: ")
        run.bold = True
        p.add_run(KB[key]["immediate"])
        shown += 1
    if not shown:
        doc.add_paragraph("No Critical or High-severity findings requiring immediate action at this time.")

    # ---- Footer note --------------------------------------------------------
    doc.add_paragraph()
    p = doc.add_paragraph()
    run = p.add_run(
        "Full technical detail -- including packet-level evidence, MITRE ATT&CK for ICS "
        "mapping, and complete remediation guidance for every finding -- is provided in the "
        "accompanying technical report."
    )
    run.italic = True
    run.font.size = Pt(9)
    run.font.color.rgb = RGBColor(0x55, 0x55, 0x55)

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(f"Prepared by {prepared_by}")
    run.font.size = Pt(9)
    run.italic = True

    doc.save(out_path)


def main():
    parser = argparse.ArgumentParser(description="Generate a branded executive .docx summary from pcap-triage JSON findings.")
    parser.add_argument("--json", required=True, help="ot_pcap_triage JSON findings file (--json output)")
    parser.add_argument("--out", default="exec_report.docx")
    parser.add_argument("--client", default="[Client Name]")
    parser.add_argument("--site", default="[Site / Scope]")
    parser.add_argument("--prepared-by", default="Thomas Jackson, Principal")
    parser.add_argument("--firm", default="Sale Fish Marketing & Consulting")
    args = parser.parse_args()

    with open(args.json) as f:
        findings = json.load(f)

    generate(findings, args.out, args.client, args.site, args.prepared_by, args.firm)
    print(f"[Executive report written to {args.out}]")


if __name__ == "__main__":
    main()
