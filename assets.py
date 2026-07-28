"""
Trend history: appends a small per-run record (timestamp, source file,
finding counts by severity) to a JSON list, so repeated runs against the
same environment (e.g. a weekly export from a span port) show whether
things are getting better or worse over time.
"""

import json
import os
from datetime import datetime, timezone


def compute_severity_counts(summary_rows):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for sev, _title, cnt in summary_rows:
        counts[sev] = counts.get(sev, 0) + cnt
    return counts


def append_history(history_path, source_file, summary_rows, total_packets):
    history = []
    if os.path.exists(history_path):
        with open(history_path) as f:
            history = json.load(f)

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_file": source_file,
        "total_packets": total_packets,
        "severity_counts": compute_severity_counts(summary_rows),
    }
    history.append(record)

    with open(history_path, "w") as f:
        json.dump(history, f, indent=2)

    return history


def render_trend_markdown(history):
    if len(history) < 2:
        return None

    md = ["## Trend (this environment, over time)\n"]
    md.append("| Run | Critical | High | Medium | Low |")
    md.append("|---|---|---|---|---|")
    for rec in history[-10:]:
        sc = rec["severity_counts"]
        md.append(f"| {rec['timestamp'][:19]} | {sc.get('CRITICAL',0)} | {sc.get('HIGH',0)} | "
                   f"{sc.get('MEDIUM',0)} | {sc.get('LOW',0)} |")

    first, last = history[0]["severity_counts"], history[-1]["severity_counts"]
    crit_delta = last.get("CRITICAL", 0) - first.get("CRITICAL", 0)
    high_delta = last.get("HIGH", 0) - first.get("HIGH", 0)
    direction = "up" if (crit_delta + high_delta) > 0 else ("down" if (crit_delta + high_delta) < 0 else "flat")
    md.append(f"\nCritical+High findings are trending **{direction}** "
               f"across {len(history)} recorded run(s) for this source.")
    return "\n".join(md)
