"""Executive report, rendered as branded HTML for PDF conversion via
weasyprint. This mirrors generate_exec_report.py's content (which produces
a .docx via python-docx) but doesn't require LibreOffice to get to PDF --
important for environments like Colab that don't have it installed."""

import html as _html
from datetime import datetime

from .kb import KB, SEVERITY_ORDER, summary_counts
from .report_html import SEVERITY_COLORS

ACCENT = "1F3B57"

CSS = """
body { font-family: Georgia, 'Times New Roman', serif; max-width: 800px; margin: 0 auto; padding: 2rem; color: #1a1a1a; }
.firm { text-align: center; font-family: Arial, sans-serif; font-weight: bold; font-size: 26px; color: %(accent)s; margin-bottom: 2px; }
.tagline { text-align: center; font-family: Arial, sans-serif; font-style: italic; font-size: 15px; color: #555; margin-bottom: 24px; }
.title { text-align: center; font-family: Arial, sans-serif; font-weight: bold; font-size: 30px; margin: 30px 0 20px 0; }
table.info { margin: 0 auto 24px auto; }
table.info td { padding: 4px 14px; font-size: 14px; }
table.info td.label { font-weight: bold; font-family: Arial, sans-serif; }
h2 { font-family: Arial, sans-serif; color: %(accent)s; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 30px; }
table.findings { width: 100%%; border-collapse: collapse; margin: 12px 0; font-family: Arial, sans-serif; font-size: 13px; }
table.findings th { background: %(accent)s; color: white; text-align: left; padding: 6px 10px; }
table.findings td { border: 1px solid #ddd; padding: 6px 10px; }
.sev { color: white; padding: 2px 10px; border-radius: 8px; font-weight: bold; font-size: 12px; }
ul.actions li { margin-bottom: 10px; font-size: 14px; }
.footnote { font-family: Arial, sans-serif; font-size: 11px; color: #666; font-style: italic; margin-top: 30px; }
.preparedby { text-align: center; font-family: Arial, sans-serif; font-size: 12px; font-style: italic; margin-top: 20px; }
""" % {"accent": ACCENT}


def e(s):
    return _html.escape(str(s))


def sev_badge(sev):
    color = SEVERITY_COLORS.get(sev, "#607d8b")
    return f'<span class="sev" style="background:{color}">{e(sev)}</span>'


def build_summary_rows(findings):
    rows = [(KB[k]["severity"], KB[k]["title"], n)
            for k, n in summary_counts(findings["suspicious"], findings["modbus"], findings.get("control", {})) if n]
    rows.sort(key=lambda r: -SEVERITY_ORDER.index(r[0]))
    return rows


def render_exec_html(findings, client="[Client Name]", site="[Site / Scope]",
                      prepared_by="Thomas Jackson, Principal", firm="Sale Fish Marketing & Consulting",
                      crossref_result=None):
    rows = build_summary_rows(findings)
    critical = sum(c for s, _, c in rows if s == "CRITICAL")
    high = sum(c for s, _, c in rows if s == "HIGH")
    total_events = sum(c for _, _, c in rows)

    if critical:
        urgency = f"{critical} Critical-severity finding(s) warrant review within the next business day."
    elif high:
        urgency = f"No Critical findings, but {high} High-severity finding(s) should be reviewed this week."
    elif rows:
        urgency = "No Critical or High-severity findings. Lower urgency, but findings below are still worth a look."
    else:
        urgency = "No findings were triggered against current detection thresholds during this assessment window."

    parts = [f"<!DOCTYPE html><html><head><meta charset='utf-8'><style>{CSS}</style></head><body>"]
    parts.append(f"<div class='firm'>{e(firm)}</div>")
    parts.append("<div class='tagline'>OT/ICS Network Security Assessment</div>")
    parts.append("<div class='title'>Executive Summary</div>")

    parts.append("<table class='info'>")
    parts.append(f"<tr><td class='label'>Client</td><td>{e(client)}</td></tr>")
    parts.append(f"<tr><td class='label'>Site / Scope</td><td>{e(site)}</td></tr>")
    parts.append(f"<tr><td class='label'>Date</td><td>{e(datetime.now().strftime('%B %d, %Y'))}</td></tr>")
    parts.append("</table>")

    parts.append("<h2>Summary</h2>")
    parts.append(f"<p>This assessment analyzed {findings['meta']['total_packets']:,} packets of network "
                 f"traffic captured from the OT/ICS environment described above. Traffic was evaluated "
                 f"against {len(rows)} categories of known industrial-network risk indicators, covering "
                 f"reconnaissance activity, unauthorized control commands, protocol misuse, and traffic "
                 f"leaving the intended network boundary. {total_events} individual events were flagged "
                 f"for review. {e(urgency)}</p>")

    if rows:
        top_sev, top_title, top_count = rows[0]
        parts.append(f"<p><strong>Highest priority:</strong> {e(top_title)} "
                     f"({top_count} occurrence(s), severity {top_sev}).</p>")

    parts.append("<h2>Findings Overview</h2>")
    if rows:
        parts.append("<table class='findings'><tr><th>Severity</th><th>Finding</th><th>Count</th></tr>")
        for sev, title, count in rows:
            parts.append(f"<tr><td>{sev_badge(sev)}</td><td>{e(title)}</td><td>{e(count)}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p>No findings triggered against current thresholds.</p>")

    parts.append("<h2>Priority Actions</h2>")
    key_by_title = {v["title"]: k for k, v in KB.items()}
    shown = 0
    parts.append("<ul class='actions'>")
    for sev, title, count in rows:
        if sev not in ("CRITICAL", "HIGH"):
            continue
        key = key_by_title.get(title)
        if not key:
            continue
        parts.append(f"<li><strong>{e(title)}:</strong> {e(KB[key]['immediate'])}</li>")
        shown += 1
    if not shown:
        parts.append("<li>No Critical or High-severity findings requiring immediate action at this time.</li>")
    parts.append("</ul>")

    if crossref_result is not None:
        parts.append("<h2>Related Disclosed Advisories</h2>")
        tm = crossref_result.get("technique_matches", [])
        km = crossref_result.get("keyword_matches", [])
        if tm or km:
            parts.append(f"<p>{len(tm)} advisory(ies) matched on the same MITRE ATT&CK technique observed "
                         f"in this traffic; {len(km)} more matched on protocol relevance.</p>")
            parts.append("<ul class='actions'>")
            for m in tm:
                parts.append(f"<li><strong>{e(m['advisory'])}</strong> \u2014 same technique as observed traffic "
                             f"({e(m['matched_technique']['id'])}); Fenceline severity: {e(m['severity_tier'])}</li>")
            for m in km:
                parts.append(f"<li><strong>{e(m['advisory'])}</strong> \u2014 protocol relevance "
                             f"({e(', '.join(m['matched_protocols']))}); Fenceline severity: {e(m['severity_tier'])}</li>")
            parts.append("</ul>")
        else:
            parts.append("<p>No disclosed advisories in the provided set matched this capture's traffic.</p>")

    parts.append("<p class='footnote'>Full technical detail -- including packet-level evidence, MITRE "
                 "ATT&CK for ICS mapping, and complete remediation guidance for every finding -- is "
                 "provided in the accompanying technical report.</p>")
    parts.append(f"<p class='preparedby'>Prepared by {e(prepared_by)}</p>")
    parts.append("</body></html>")
    return "".join(parts)
