# OT PCAP Triage Tool (v2.1)

Triages OT/ICS packet captures against the same checks as the "Wireshark
for OT Cybersecurity" filter cheat sheet, then adds severity ratings,
mitigation/remediation guidance, MITRE ATT&CK for ICS tagging, known-asset
context, suppressions, baseline/diff comparison, batch processing, and
trend history across runs.

## Install

```bash
# Straight from GitHub (this is what the Colab notebooks do)
pip install "ot-pcap-triage @ git+https://github.com/tjackson8817/OT-PCAP-Triage.git"
# ...with PDF output
pip install "ot-pcap-triage[pdf] @ git+https://github.com/tjackson8817/OT-PCAP-Triage.git"

# Or from a local copy of this repo
pip install -e .
```

## Try it in Google Colab

- `Try_OT_PCAP_Triage.ipynb` -- upload a capture, get the report.
- `Try_OT_PCAP_Triage_Full.ipynb` -- every option: assets, suppressions,
  baseline, executive PDF and the Fenceline cross-reference.

## Quick start

```bash
# Basic run
ot-pcap-triage capture.pcap

# With known-asset context + previously-triaged findings suppressed
ot-pcap-triage capture.pcap --assets assets.csv --suppress suppressions.csv

# Also produce a color-coded HTML report
ot-pcap-triage capture.pcap --html

# Save this run as a baseline, then compare a later capture against it
ot-pcap-triage capture.pcap --save-baseline baseline.json
ot-pcap-triage capture2.pcap --baseline baseline.json

# Track trend across repeated runs against the same environment
ot-pcap-triage capture.pcap --history history.json

# Process a whole folder of captures at once
ot-pcap-triage --batch /path/to/pcaps/ --out-dir reports/ --html
```

(If you didn't `pip install -e .`, run as `python3 -m ot_pcap_triage.cli ...` instead.)

## What's new in v2.1 (November 2026)

- **Control commands on every OT protocol, not just Modbus:** DNP3
  Select/Operate/Direct Operate, IEC 104 command ASDUs, EtherNet/IP CIP
  tag writes, S7 variable writes, BACnet WriteProperty.
- **New findings:** device restart / STOP commands (S7 STOP/START, DNP3
  cold/warm restart, Modbus Restart Communications, BACnet
  ReinitializeDevice, IEC 104 reset process), program / logic downloads,
  and GOOSE spoofing (one control block published from two MAC addresses).
- **Modbus writes counted correctly:** FC 6 Write Single Register and the
  other write codes are now included, and the PLC's echoed reply is no
  longer counted as a second write.
- **Much less noise:** uncommon ports are listed once per client, server
  and port (not per packet) and ignore return traffic and known OT ports;
  ordinary ACKs are no longer "malformed"; long-lived OT polling sessions
  are no longer "possible tunnels."
- **Internet traffic shows direction** (inbound/outbound), and broadcast,
  multicast and link-local addresses are no longer mistaken for the
  internet.
- **ATT&CK IDs updated** to the October 2026 release (v19): T0855 and
  T0856 are now T1692.001 and T1692.002.

## What's new in v2

| Feature | What it does |
|---|---|
| **Executive Summary** | Plain-English "what happened / how urgent / look at this first" block at the top of every report |
| **Severity ratings** | Info/Low/Medium/High/Critical per finding, sorted worst-first in a summary table |
| **Mitigation & remediation** | Each finding category includes why it matters, immediate action, longer-term remediation, and a standard reference (NIST SP 800-82 Rev.3 / IEC 62443-3-3) |
| **MITRE ATT&CK for ICS tagging** | Verified against attack.mitre.org; each mapping is labeled "confirmed" or "suggested," and left blank where no defensible mapping exists |
| **Asset context (`--assets`)** | CSV of known hosts; unrecognized hosts issuing Modbus write commands automatically escalate that finding's severity |
| **Suppressions (`--suppress`)** | CSV allowlist (src, dst, category) to silence findings you've already triaged as benign -- suppressed counts are always shown, never silently hidden |
| **Baseline / diff** | `--save-baseline` then `--baseline` on a later run surfaces only what's *new* since a known-good capture |
| **Trend history (`--history`)** | Appends each run's severity counts to a JSON history file and renders a trend table + direction ("up"/"down"/"flat") |
| **Batch mode (`--batch`)** | Process a whole directory of captures; per-file reports plus one aggregate summary table |
| **HTML report (`--html`)** | Same content as the Markdown report, with color-coded severity badges |
| **PDF report (`--pdf`)** | Same content as the HTML report, converted to a standalone PDF via weasyprint -- `pip install -e ".[pdf]"` to enable |
| **Executive PDF (`--exec-pdf path.pdf`)** | A separate, branded, non-technical PDF summary (findings table, priority actions) for a client/board audience -- pass `--client`, `--site`, `--prepared-by`, `--firm` to customize |
| **Automatic Fenceline cross-reference (`--fenceline-advisories`)** | Point at a Fenceline advisories.json and both the technical report *and* the executive PDF automatically include a "Related Disclosed Advisories" section -- no separate manual step required |
| **New protocols** | IEC 60870-5-104 (port 2404), IEC 61850 GOOSE (EtherType 0x88B8) and Sampled Values (0x88BA), alongside the original Modbus/S7/DNP3/EtherNet-IP/Profinet/BACnet |
| **Fenceline cross-reference module** | `ot_pcap_triage.fenceline` (also usable standalone via `fenceline_crossref.py`) matches disclosed advisories against protocols *and* MITRE ATT&CK techniques actually observed in your traffic -- schema-verified against Fenceline's real advisories.json |

## Package layout

```
src/ot_pcap_triage/
  detect.py       -- packet parsing and finding detection
  kb.py           -- severity levels, mitigation/remediation, ATT&CK tags
  assets.py       -- known-asset loading and host annotation
  suppress.py     -- suppression/allowlist filtering
  baseline.py     -- baseline signature diffing
  history.py      -- trend history across repeated runs
  report_md.py    -- Markdown rendering (incl. executive summary)
  report_html.py  -- HTML rendering with severity color-coding
  exec_report.py  -- branded executive-summary HTML/PDF
  fenceline.py    -- Fenceline advisory cross-reference
  pdf.py          -- HTML-to-PDF via weasyprint
  cli.py          -- command-line entrypoint (single-file and --batch)
tests/            -- pytest suite using self-contained synthetic captures
fenceline_crossref.py
assets_template.csv
suppressions_template.csv
```

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

22 tests, all passing, covering: Modbus write detection and MBAP parsing,
severity escalation with/without asset context, port scanning, OT-to-
internet detection (and non-detection on private traffic), the two new
protocols (IEC 60870-5-104, IEC 61850 GOOSE), ARP handling, baseline diffing
(against itself and against a different capture), and suppression rules
(specific match, wildcard match, wildcard non-match, no-op with no rules),
plus v2.1 checks for FC 6 writes, echo de-duplication, S7 STOP detection,
broadcast/multicast handling and plain ACKs.

Additionally validated end-to-end against real public ICS sample captures
(Modbus/TCP, BACnet/IP, DNP3, Profinet RT) -- e.g. against a real
Modbus/TCP capture the tool correctly recovered actual function codes
(Read Coils, Write Multiple Registers, etc.) straight out of the MBAP
header, and batch mode was run across three real captures producing a
correct aggregate table.

## MITRE ATT&CK for ICS mapping notes

Each ATT&CK tag in `kb.py` was checked against attack.mitre.org and
secondary sources rather than pulled from memory:

IDs follow the October 2026 ATT&CK for ICS release (v19).

- **T0846.001 Remote System Discovery: Port Scan** (confirmed) -- port scanning
- **T1692.001 Unauthorized Message: Command Message** (confirmed; formerly
  T0855) -- Modbus writes and DNP3 / IEC 104 / CIP / S7 / BACnet control
  commands
- **T0816 Device Restart/Shutdown** (confirmed) and **T0858 Change
  Operating Mode** (suggested) -- restart and STOP/START commands
- **T0843 Program Download** (confirmed) -- S7 program/block download
- **T1692.002 Unauthorized Message: Reporting Message** (suggested;
  formerly T0856) -- one GOOSE control block from more than one MAC
- **T0883 Internet Accessible Device** (suggested) -- OT traffic to or
  from a public address
- **T0831 Manipulation of Control** (suggested) -- downstream consequence
  of unauthorized writes
- **T0869 Standard Application Layer Protocol** (suggested) -- Modbus on
  a non-standard port
- **T0884 Connection Proxy** (suggested) -- long tunneling sessions / OT
  traffic reaching the internet
- **T0888 Remote System Information Discovery** (suggested) -- Modbus
  Device Identification requests

"Uncommon port connections" and "malformed packets" carry **no ATT&CK
tag** -- there's no single defensible technique mapping for these general
anomaly indicators, and the report says so explicitly rather than forcing
a guess.

## Notes and limitations

- **Heuristic, not authoritative.** Thresholds (port-scan count, bytes
  in-flight for "long session," etc.) are defaults in `detect.py` -- tune
  them for your environment.
- **"Malformed packet" detection is simplified** -- undersized IP
  packets and impossible TCP flag combinations (NULL, SYN+FIN, XMAS, PSH
  with no data), not Wireshark's full stream-reassembly-based analysis.
- **Control-command decoding covers the common function codes** only;
  vendor-specific commands are not decoded.
- **"OT/ICS communication with Internet" will flag lab/test captures**
  that use public-looking IP ranges for convenience -- that's the filter
  working as intended; use judgment on capture provenance.
- **Remediation guidance is general best practice**, not a tailored
  assessment of your specific environment.
- **Fenceline integration is now schema-verified**, not assumed. `fenceline_crossref.py`
  checks against Fenceline's confirmed real advisories.json fields (exec_headline,
  business_impact, sector, cve_ids, vendor, product, attack_ics_technique,
  exploit_maturity, cvss_score, ot_risk_rating, ot_risk_rationale, patch_status,
  known_mitigation, mitigation_confidence, purdue_level_estimate, severity_tier,
  source_url). It checks two independent signals: a precise MITRE ATT&CK for ICS
  technique-ID match (both tools tag the same taxonomy) and a broader protocol
  keyword match. Validated against a realistic multi-advisory fixture covering
  both match types plus a correctly-excluded unrelated advisory.
- Only inspects packets scapy can parse; corrupted/truncated captures may
  under-report.

## Where this fits

Fenceline tells you what's been *disclosed*. This tool tells you what's
actually *happening on the wire*, with the same severity/ATT&CK/mitigation
discipline -- confirmed vs. suggested, never a guessed mapping presented
as fact.
