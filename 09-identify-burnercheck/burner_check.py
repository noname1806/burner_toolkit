"""
BurnerCheck - forensic triage console for burner / second-number app phone numbers.

Two independent provenance signals are read for every number:
  * Registry  : offline NPA-NXX -> carrier lookup (public NANPA CO-Code file)
  * Live      : real-time line-type + carrier (Twilio Lookup v2)
The console loads a ground-truth corpus of app-provisioned numbers on startup,
summarises the measurement, and lets an examiner triage a single number.

Twilio and python-dotenv are optional: without credentials the console still
runs and serves the corpus + analytics; only the live single-number lookup for
numbers outside the corpus is disabled.
"""
import csv
import re
import json
import os
from collections import Counter
from datetime import datetime

from flask import Flask, render_template_string, request, jsonify

# ---- optional dependencies (graceful) -------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

try:
    from twilio.rest import Client
except Exception:
    Client = None

app = Flask(__name__)

ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
CSV_FILE = "CoCodeAssignment_Utilized_AllStates_Public.txt"
CORPUS_FILE = "hushed_2ndline_lookups.json"     # 2,508 ground-truth numbers
SESSION_FILE = "burnercheck_session.json"       # new live lookups (kept separate)

client = None
if Client and ACCOUNT_SID and AUTH_TOKEN:
    try:
        client = Client(ACCOUNT_SID, AUTH_TOKEN)
    except Exception:
        client = None
LIVE_ENABLED = client is not None

BURNER_KEYWORDS = ["BANDWIDTH", "ONVOY", "LEVEL 3", "VONAGE", "TELNYX", "COMMIO",
                   "PINGER", "TEXTNOW", "GOOGLE", "PEERLESS", "SVR", "CLEC"]
REAL_KEYWORDS = ["WIRELESS", "T-MOBILE", "PCS", "CELLCO", "AT&T", "BELL", "VERIZON"]

APP_DISPLAY = {"burner": "Burner", "2ndline": "2ndLine", "textme": "TextMe",
               "hushed": "Hushed", "textfree": "TextFree"}
APP_ORDER = ["burner", "2ndline", "textme", "hushed", "textfree"]
MNO_TOKENS = ["T-MOBILE", "VERIZON", "AT&T", "METRO", "US CELLULAR", "CELLCO"]
CARRIER_ROWS = ["Onvoy / Sinch", "AdHoc / Bandwidth", "Talktone", "Bandwidth.com CLEC",
                "GoTextMe", "Onvoy Spectrum", "AffinityClick", "MNO", "Other"]


# ---------------------------------------------------------------- data model
def load_json(path):
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_session(rows):
    with open(SESSION_FILE, "w") as f:
        json.dump(rows, f, indent=2)


def all_records():
    """Corpus (read-only) + any live lookups from this session."""
    return load_json(CORPUS_FILE) + load_json(SESSION_FILE)


def norm_carrier(name):
    c = (name or "").upper()
    if "ONVOY SPECTRUM" in c:
        return "Onvoy Spectrum"
    if "GOTEXTME" in c:
        return "GoTextMe"
    if "AFFINITYCLICK" in c:
        return "AffinityClick"
    if "TALKTONE" in c:
        return "Talktone"
    if "ADHOC" in c:
        return "AdHoc / Bandwidth"
    if "BANDWIDTH.COM" in c:
        return "Bandwidth.com CLEC"
    if "ONVOY" in c or "SINCH" in c:
        return "Onvoy / Sinch"
    if any(m in c for m in MNO_TOKENS):
        return "MNO"
    return "Other"


def is_mno(name):
    return any(m in (name or "").upper() for m in MNO_TOKENS)


def pct(a, b):
    return round(100.0 * a / b, 1) if b else 0.0


def compute_analytics(records):
    recs = [r for r in records if r.get("source_app")]
    total = len(recs)
    empty = {"total": 0}
    if total == 0:
        return empty

    def live_voip(r):
        return r.get("twilio_line_type") == "nonFixedVoip"

    def prefix_voip(r):
        return r.get("csv_classification") == "BURNER/VoIP"

    by_app = {}
    for r in recs:
        by_app.setdefault(r["source_app"], []).append(r)

    per_app = []
    for a in APP_ORDER:
        g = by_app.get(a)
        if not g:
            continue
        n = len(g)
        car = Counter(norm_carrier(r.get("twilio_carrier")) for r in g)
        shares = [v / n for v in car.values()]
        per_app.append({
            "app": APP_DISPLAY.get(a, a), "raw": a, "n": n,
            "linetype_cov": pct(sum(live_voip(r) for r in g), n),
            "prefix_cov": pct(sum(prefix_voip(r) for r in g), n),
            "hhi": round(sum(s * s for s in shares), 2),
            "top_carrier": car.most_common(1)[0][0],
        })
    per_app_by_cov = sorted(per_app, key=lambda x: -x["linetype_cov"])

    lt = Counter(r.get("twilio_line_type") for r in recs)
    mob = [r for r in recs if r.get("twilio_line_type") == "mobile"]
    mob_mno = sum(is_mno(r.get("twilio_carrier")) for r in mob)

    both = sum(prefix_voip(r) and live_voip(r) for r in recs)
    p_only = sum(prefix_voip(r) and not live_voip(r) for r in recs)
    l_only = sum((not prefix_voip(r)) and live_voip(r) for r in recs)
    neither = sum((not prefix_voip(r)) and (not live_voip(r)) for r in recs)
    looks_mobile = sum(r.get("csv_classification") == "REAL/Mobile" and live_voip(r) for r in recs)

    # fingerprint matrix: carrier row -> per app within-app %
    fp_rows = []
    for cname in CARRIER_ROWS:
        cells = []
        any_cell = False
        for a in APP_ORDER:
            g = by_app.get(a, [])
            n = len(g)
            cnt = sum(1 for r in g if norm_carrier(r.get("twilio_carrier")) == cname)
            if cnt:
                any_cell = True
            cells.append({"app": APP_DISPLAY.get(a, a), "count": cnt, "pct": pct(cnt, n)})
        if any_cell:
            fp_rows.append({"carrier": cname, "cells": cells})

    return {
        "total": total,
        "apps_shown": [APP_DISPLAY.get(a, a) for a in APP_ORDER if a in by_app],
        "overall": {
            "linetype_cov": pct(sum(live_voip(r) for r in recs), total),
            "prefix_cov": pct(sum(prefix_voip(r) for r in recs), total),
            "agreement": pct(both + neither, total),
        },
        "per_app": per_app,
        "per_app_by_cov": per_app_by_cov,
        "line_types": {"nonFixedVoip": lt.get("nonFixedVoip", 0),
                       "mobile": lt.get("mobile", 0),
                       "fixedVoip": lt.get("fixedVoip", 0),
                       "other": total - lt.get("nonFixedVoip", 0) - lt.get("mobile", 0) - lt.get("fixedVoip", 0)},
        "mobile_mask": {"total": len(mob), "mno": mob_mno,
                        "wholesale": len(mob) - mob_mno,
                        "pct_wholesale": pct(len(mob) - mob_mno, len(mob))},
        "agreement_cells": {"both": both, "prefix_only": p_only,
                            "live_only": l_only, "neither": neither},
        "discordance": {"count": l_only + p_only, "portability": neither and l_only,
                        "prefix_stale": sum((not prefix_voip(r)) and live_voip(r) for r in recs),
                        "looks_mobile": looks_mobile,
                        "pct": pct(sum((not prefix_voip(r)) and live_voip(r) for r in recs), total)},
        "fingerprint": {"apps": [APP_DISPLAY.get(a, a) for a in APP_ORDER if a in by_app],
                        "rows": fp_rows},
        "geo": {"area_codes": len(set(r.get("area_code") for r in recs if r.get("area_code"))),
                "states": len(set(r.get("region_state") for r in recs if r.get("region_state")))},
        "live_enabled": LIVE_ENABLED,
    }


def hero_example(records):
    """A number whose registry reading and live reading disagree (the hook)."""
    for r in records:
        if r.get("csv_classification") == "REAL/Mobile" and r.get("twilio_line_type") == "nonFixedVoip":
            return r
    return records[0] if records else None


# ---------------------------------------------------------------- lookups
def analyze_with_csv(phone_number):
    clean = re.sub(r"\D", "", phone_number)
    if len(clean) < 10:
        return {"success": False, "message": "Enter at least 10 digits."}
    npa_nxx = f"{clean[:3]}-{clean[3:6]}"
    try:
        with open(CSV_FILE, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f, delimiter="\t")
            reader.fieldnames = [n.strip() for n in reader.fieldnames]
            for row in reader:
                if not row.get("NPA-NXX") or not row.get("Company"):
                    continue
                if row["NPA-NXX"].strip() == npa_nxx:
                    company = row["Company"].strip().upper()
                    if any(k in company for k in BURNER_KEYWORDS):
                        cls = "BURNER/VoIP"
                    elif any(k in company for k in REAL_KEYWORDS):
                        cls = "REAL/Mobile"
                    else:
                        cls = "LANDLINE/Regional"
                    return {"success": True, "npa_nxx": npa_nxx, "provider": company,
                            "classification": cls}
            return {"success": False, "message": f"NPA-NXX {npa_nxx} not found in registry."}
    except FileNotFoundError:
        return {"success": False, "message": "Registry file not available."}
    except Exception as e:
        return {"success": False, "message": f"Registry error: {e}"}


def analyze_with_twilio(phone_number):
    if client is None:
        return {"success": False, "message": "Live lookup unavailable (no Twilio credentials)."}
    try:
        clean = re.sub(r"\D", "", phone_number)
        formatted = f"+1{clean[:10]}"
        lookup = client.lookups.v2.phone_numbers(formatted).fetch(fields="line_type_intelligence")
        d = lookup.line_type_intelligence or {}
        line_type = d.get("type")
        return {"success": True, "carrier": d.get("carrier_name"), "line_type": line_type,
                "formatted_number": formatted}
    except Exception as e:
        return {"success": False, "message": f"Live lookup error: {e}"}


def verdict_for(line_type, carrier):
    """Human verdict + semantic class from the live reading."""
    if line_type == "nonFixedVoip":
        return ("Second-number VoIP line", "flag")
    if line_type == "mobile":
        if is_mno(carrier):
            return ("Genuine mobile-operator line", "ok")
        return ("Presents as mobile, wholesale carrier", "warn")
    if line_type == "fixedVoip":
        return ("Fixed VoIP line", "warn")
    return (line_type or "Unknown", "muted")


def fmt_number(s):
    d = re.sub(r"\D", "", s or "")
    if len(d) == 11 and d[0] == "1":
        d = d[1:]
    if len(d) == 10:
        return f"({d[:3]}) {d[3:6]}-{d[6:]}"
    return s


# ---------------------------------------------------------------- template
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BurnerCheck — forensic number triage</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --ink:#15202b; --paper:#e7ecf1; --surface:#ffffff; --surface-2:#f3f6f9;
  --line:#d2dbe4; --line-strong:#b7c3cf; --muted:#5c6b7a; --faint:#8b98a5;
  --live:#0e7f8c; --live-soft:#d7edef; --registry:#6d4aa7; --registry-soft:#e7e0f3;
  --flag:#c6531b; --flag-soft:#f6e2d6; --ok:#1f7a4d; --ok-soft:#dcefe4;
  --warn:#b7791f; --warn-soft:#f5e9d2;
  --shadow:0 1px 2px rgba(21,32,43,.05),0 8px 24px rgba(21,32,43,.06);
  --font-sans:'IBM Plex Sans',system-ui,-apple-system,Segoe UI,sans-serif;
  --font-mono:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
}
*{margin:0;padding:0;box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{font-family:var(--font-sans);background:var(--paper);color:var(--ink);
  line-height:1.55;font-size:15px;
  background-image:radial-gradient(circle at 1px 1px,rgba(21,32,43,.05) 1px,transparent 0);
  background-size:22px 22px;}
.wrap{max-width:1160px;margin:0 auto;padding:28px 24px 80px}
.mono{font-family:var(--font-mono);font-feature-settings:"tnum" 1}
a{color:var(--live);text-decoration:none}

/* header */
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;
  padding-bottom:18px;border-bottom:1.5px solid var(--ink);margin-bottom:26px}
.brand{display:flex;align-items:center;gap:12px}
.glyph{width:34px;height:34px;flex:none;border:1.5px solid var(--ink);border-radius:8px;
  display:grid;place-items:center;background:var(--surface)}
.glyph i{display:block;width:14px;height:14px;border-radius:50%;
  border:2px solid var(--live);border-right-color:var(--registry);border-bottom-color:var(--registry);
  transform:rotate(-30deg)}
.brand h1{font-size:20px;font-weight:700;letter-spacing:-.02em}
.brand .sub{font-size:12.5px;color:var(--muted);margin-top:1px}
.top .meta{text-align:right;font-size:12px;color:var(--muted)}
.top .meta b{font-family:var(--font-mono);color:var(--ink);font-weight:600}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:600;
  padding:3px 9px;border-radius:999px;border:1px solid var(--line-strong);
  background:var(--surface);color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.pill .dot{width:6px;height:6px;border-radius:50%;background:var(--ok)}
.pill.off .dot{background:var(--faint)}

/* section scaffolding */
.eyebrow{font-family:var(--font-mono);font-size:11px;font-weight:600;letter-spacing:.14em;
  text-transform:uppercase;color:var(--registry);margin-bottom:8px}
.sec{margin-top:40px}
.sec-head{margin-bottom:16px}
.sec-head h2{font-size:19px;font-weight:600;letter-spacing:-.01em}
.sec-head p{font-size:13.5px;color:var(--muted);margin-top:3px;max-width:70ch}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}

/* ---- READER (hero) ---- */
.reader{padding:22px 22px 24px}
.reader .lede{font-size:13.5px;color:var(--muted);margin-bottom:16px;max-width:74ch}
.reader .lede b{color:var(--ink);font-weight:600}
.qform{display:flex;gap:10px;flex-wrap:wrap}
.qform input{flex:1;min-width:220px;font-family:var(--font-mono);font-size:16px;
  padding:13px 15px;border:1.5px solid var(--line-strong);border-radius:10px;background:var(--surface-2);
  color:var(--ink);letter-spacing:.02em}
.qform input:focus{outline:none;border-color:var(--live);background:#fff;
  box-shadow:0 0 0 4px var(--live-soft)}
.qform button{font-family:var(--font-sans);font-size:14px;font-weight:600;color:#fff;
  background:var(--ink);border:none;border-radius:10px;padding:0 26px;cursor:pointer;
  transition:transform .08s ease,background .15s ease}
.qform button:hover{background:#0c1620}
.qform button:active{transform:translateY(1px)}
.qform button:disabled{background:var(--faint);cursor:not-allowed}

.readout{margin-top:20px;display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:720px){.readout{grid-template-columns:1fr}}
.lane{border:1px solid var(--line);border-radius:12px;padding:14px 15px;background:var(--surface-2);
  position:relative;overflow:hidden}
.lane::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px}
.lane.registry::before{background:var(--registry)}
.lane.live::before{background:var(--live)}
.lane .tag{font-family:var(--font-mono);font-size:10.5px;font-weight:600;letter-spacing:.1em;
  text-transform:uppercase;display:flex;align-items:center;gap:7px;margin-bottom:10px}
.lane.registry .tag{color:var(--registry)}
.lane.live .tag{color:var(--live)}
.lane .tag .src{color:var(--faint);font-weight:500;letter-spacing:.02em;text-transform:none}
.lane .val{font-family:var(--font-mono);font-size:17px;font-weight:600;letter-spacing:-.01em}
.lane .desc{font-size:12.5px;color:var(--muted);margin-top:3px;min-height:1.2em}
.lane.scan .val,.lane.scan .desc{opacity:.35}
.lane.scan::after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(14,127,140,.14),transparent);
  animation:scan 1.05s linear infinite}
@keyframes scan{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}

.verdict{margin-top:14px;display:flex;align-items:center;gap:14px;flex-wrap:wrap;
  padding:14px 16px;border-radius:12px;border:1px solid var(--line);background:var(--surface-2)}
.verdict .num{font-family:var(--font-mono);font-size:15px;font-weight:600}
.chip{display:inline-flex;align-items:center;gap:7px;font-size:13px;font-weight:600;
  padding:6px 12px;border-radius:999px;border:1px solid transparent}
.chip .d{width:8px;height:8px;border-radius:50%}
.chip.flag{background:var(--flag-soft);color:var(--flag);border-color:#e9c3ac}.chip.flag .d{background:var(--flag)}
.chip.ok{background:var(--ok-soft);color:var(--ok);border-color:#bfe0cd}.chip.ok .d{background:var(--ok)}
.chip.warn{background:var(--warn-soft);color:var(--warn);border-color:#e8d3a6}.chip.warn .d{background:var(--warn)}
.chip.muted{background:var(--surface);color:var(--muted);border-color:var(--line-strong)}.chip.muted .d{background:var(--faint)}
.agree{font-size:12.5px;font-weight:600;display:inline-flex;align-items:center;gap:7px}
.agree.disagree{color:var(--flag)} .agree.match{color:var(--ok)}
.agree .ic{font-family:var(--font-mono)}
.provenance{margin-left:auto;font-size:12px;color:var(--faint)}

/* ---- readout strip (stats) ---- */
.strip{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:22px}
@media(max-width:860px){.strip{grid-template-columns:1fr 1fr}}
.stat{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:15px 16px}
.stat .k{font-family:var(--font-mono);font-size:11px;color:var(--muted);letter-spacing:.02em;
  text-transform:uppercase;display:block;margin-bottom:8px;min-height:2.4em}
.stat .v{font-family:var(--font-mono);font-size:30px;font-weight:600;letter-spacing:-.02em;line-height:1}
.stat .v small{font-size:16px;color:var(--faint);font-weight:500}
.stat .c{font-size:12px;color:var(--faint);margin-top:6px}

/* ---- findings ---- */
.grid2{display:grid;grid-template-columns:1.15fr .85fr;gap:20px}
@media(max-width:900px){.grid2{grid-template-columns:1fr}}
.panel{padding:20px}
.panel h3{font-size:14px;font-weight:600;margin-bottom:3px}
.panel .note{font-size:12.5px;color:var(--muted);margin-bottom:16px}

/* coverage bars */
.bars{display:flex;flex-direction:column;gap:13px}
.bar-row{display:grid;grid-template-columns:76px 1fr 52px;align-items:center;gap:12px}
.bar-row .lbl{font-size:13px;font-weight:600}
.bar-row .lbl small{display:block;font-family:var(--font-mono);font-size:10.5px;color:var(--faint);font-weight:400}
.track{height:22px;background:var(--surface-2);border-radius:6px;overflow:hidden;border:1px solid var(--line)}
.fill{height:100%;border-radius:5px 0 0 5px;background:var(--live);
  display:flex;align-items:center;transition:width .9s cubic-bezier(.22,1,.36,1)}
.fill.low{background:var(--flag)} .fill.mid{background:var(--warn)}
.bar-row .pctv{font-family:var(--font-mono);font-size:13px;font-weight:600;text-align:right}
.ghost{position:relative}
.ghost .g{position:absolute;top:0;height:100%;width:2px;background:var(--registry);opacity:.65}

/* split bars (line-type / mask / agreement) */
.split{display:flex;height:30px;border-radius:8px;overflow:hidden;border:1px solid var(--line)}
.split span{display:flex;align-items:center;justify-content:center;font-family:var(--font-mono);
  font-size:11px;font-weight:600;color:#fff;min-width:0;overflow:hidden;white-space:nowrap}
.legend{display:flex;flex-wrap:wrap;gap:14px;margin-top:12px;font-size:12px;color:var(--muted)}
.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:-1px}
.kv{display:flex;justify-content:space-between;font-size:13px;padding:7px 0;border-bottom:1px dashed var(--line)}
.kv:last-child{border-bottom:none}
.kv .mono{font-weight:600}

/* fingerprint heatmap */
.fp{overflow-x:auto}
.fp table{border-collapse:collapse;width:100%;font-size:12px}
.fp th{font-weight:600;text-align:center;padding:8px 6px;color:var(--muted);
  font-family:var(--font-mono);font-size:11px;white-space:nowrap}
.fp th.rowlab,.fp td.rowlab{text-align:left;color:var(--ink);font-family:var(--font-sans);
  font-weight:500;white-space:nowrap;padding-right:12px}
.fp td{padding:0;text-align:center}
.fp .cell{margin:2px;height:34px;border-radius:6px;display:flex;flex-direction:column;
  align-items:center;justify-content:center;line-height:1.05}
.fp .cell .n{font-family:var(--font-mono);font-weight:600;font-size:12px}
.fp .cell .p{font-family:var(--font-mono);font-size:9.5px;opacity:.8}

/* ---- explorer ---- */
.filters{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.filters input,.filters select{font-family:var(--font-sans);font-size:13px;padding:9px 11px;
  border:1px solid var(--line-strong);border-radius:9px;background:var(--surface);color:var(--ink)}
.filters input{flex:1;min-width:200px;font-family:var(--font-mono)}
.filters input:focus,.filters select:focus{outline:none;border-color:var(--live);box-shadow:0 0 0 3px var(--live-soft)}
.filters .count{margin-left:auto;font-size:12.5px;color:var(--muted);font-family:var(--font-mono)}
.tbl-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px}
table.rec{width:100%;border-collapse:collapse;font-size:13px}
table.rec th{position:sticky;top:0;background:var(--surface-2);text-align:left;font-weight:600;
  font-size:11px;letter-spacing:.03em;text-transform:uppercase;color:var(--muted);
  padding:11px 14px;border-bottom:1px solid var(--line)}
table.rec td{padding:11px 14px;border-bottom:1px solid var(--line);white-space:nowrap}
table.rec tr:last-child td{border-bottom:none}
table.rec tr:hover td{background:var(--surface-2)}
.tnum{font-family:var(--font-mono);font-weight:600}
.tag2{display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;
  border:1px solid var(--line-strong);background:var(--surface);color:var(--muted);font-family:var(--font-mono)}
.lt{font-family:var(--font-mono);font-size:12px;font-weight:600}
.lt.voip{color:var(--flag)} .lt.mobile{color:var(--warn)} .lt.fixed{color:var(--registry)}
.dis{font-family:var(--font-mono);font-size:11px;font-weight:600}
.dis.y{color:var(--flag)} .dis.n{color:var(--ok)}
.pager{display:flex;gap:8px;align-items:center;justify-content:center;margin-top:16px;font-size:13px}
.pager button{font-family:var(--font-mono);font-size:12px;padding:7px 13px;border:1px solid var(--line-strong);
  background:var(--surface);border-radius:8px;cursor:pointer;color:var(--ink)}
.pager button:disabled{opacity:.4;cursor:not-allowed}
.pager .pg{color:var(--muted);font-family:var(--font-mono)}

.foot{margin-top:48px;padding-top:18px;border-top:1px solid var(--line);
  font-size:12px;color:var(--faint);display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}
.foot .mono{color:var(--muted)}

@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<div class="wrap">

  <header class="top">
    <div class="brand">
      <span class="glyph"><i></i></span>
      <div>
        <h1>BurnerCheck</h1>
        <div class="sub">Forensic triage for burner &amp; second-number app numbers</div>
      </div>
    </div>
    <div class="meta">
      <div><b id="m-total">—</b> ground-truth numbers &middot; <b id="m-apps">—</b> apps loaded</div>
      <div style="margin-top:7px">
        <span class="pill {{ 'off' if not live_enabled else '' }}"><span class="dot"></span>{{ 'Live lookup online' if live_enabled else 'Live lookup offline' }}</span>
      </div>
    </div>
  </header>

  <!-- READER -->
  <div class="eyebrow">Single-number triage</div>
  <section class="card reader">
    <p class="lede">Every number is read through <b>two independent signals</b>. The
      <b style="color:var(--registry)">Registry</b> lane resolves the number block offline against the public
      carrier assignment file; the <b style="color:var(--live)">Live</b> lane returns the current line type and
      carrier. Where the two disagree, the number was usually ported, which is the signature of a second-number line
      that looks ordinary on paper.</p>
    <form class="qform" id="qform" autocomplete="off">
      <input id="q" class="mono" placeholder="Enter a phone number, e.g. (609) 490-8198" value="{{ hero_num }}">
      <button id="qbtn" type="submit">Read number</button>
    </form>

    <div class="readout">
      <div class="lane registry" id="lane-reg">
        <div class="tag">Registry <span class="src">// offline NPA-NXX</span></div>
        <div class="val" id="reg-val">—</div>
        <div class="desc" id="reg-desc"></div>
      </div>
      <div class="lane live" id="lane-live">
        <div class="tag">Live <span class="src">// line-type lookup</span></div>
        <div class="val" id="live-val">—</div>
        <div class="desc" id="live-desc"></div>
      </div>
    </div>

    <div class="verdict" id="verdict">
      <span class="num" id="v-num"></span>
      <span class="chip muted" id="v-chip"><span class="d"></span><span id="v-chip-t">—</span></span>
      <span class="agree" id="v-agree"></span>
      <span class="provenance" id="v-prov"></span>
    </div>
  </section>

  <!-- STRIP -->
  <div class="strip">
    <div class="stat"><span class="k">Corpus</span>
      <div class="v" id="s-corpus">—</div><div class="c" id="s-corpus-c">across five apps</div></div>
    <div class="stat"><span class="k">Live rule catches</span>
      <div class="v" id="s-cov">—<small>%</small></div><div class="c">flagged nonFixedVoip</div></div>
    <div class="stat"><span class="k">“Mobile” that is really wholesale VoIP</span>
      <div class="v" id="s-mask">—<small>%</small></div><div class="c" id="s-mask-c"></div></div>
    <div class="stat"><span class="k">Registry &amp; live disagree</span>
      <div class="v" id="s-dis">—<small>%</small></div><div class="c">two signals split</div></div>
  </div>

  <!-- FINDINGS -->
  <section class="sec">
    <div class="sec-head">
      <div class="eyebrow">What the corpus shows</div>
      <h2>Identification depends on the service, not the number</h2>
      <p>The live line-type rule is close to conclusive for some apps and useless for others. Concentration on a single
        wholesale carrier is what decides it.</p>
    </div>

    <div class="grid2">
      <div class="card panel">
        <h3>Line-type coverage by app</h3>
        <div class="note">Share of each app's numbers the <span style="color:var(--live);font-weight:600">live</span>
          rule flags as VoIP. The <span style="color:var(--registry);font-weight:600">violet mark</span> is the offline
          registry's coverage of the same app.</div>
        <div class="bars" id="cov-bars"></div>
      </div>

      <div class="card panel">
        <h3>The “mobile” mask</h3>
        <div class="note">Line types returned across the corpus, and what actually sits behind a
          <span class="mono" style="font-weight:600">mobile</span> label.</div>
        <div style="margin-bottom:6px;font-family:var(--font-mono);font-size:11px;color:var(--muted)">LINE TYPES RETURNED</div>
        <div class="split" id="lt-split"></div>
        <div class="legend" id="lt-legend"></div>
        <div style="margin:18px 0 6px;font-family:var(--font-mono);font-size:11px;color:var(--muted)">CARRIER BEHIND “MOBILE”</div>
        <div class="split" id="mask-split"></div>
        <div class="legend" id="mask-legend"></div>
      </div>
    </div>

    <div class="grid2" style="margin-top:20px">
      <div class="card panel">
        <h3>Carrier fingerprint</h3>
        <div class="note">Within-app share on each wholesale carrier. Each app draws from its own set; the shared
          <span class="mono" style="font-weight:600">Onvoy Spectrum</span> row is where the mobile mask lives.</div>
        <div class="fp" id="fp"></div>
      </div>

      <div class="card panel">
        <h3>Two signals, one verdict</h3>
        <div class="note">How often the registry and live readings agree, and how each unique catch is distributed.
          Neither signal alone is enough.</div>
        <div class="split" id="agree-split"></div>
        <div class="legend" id="agree-legend"></div>
        <div style="margin-top:16px">
          <div class="kv"><span>Both signals flag VoIP</span><span class="mono" id="a-both">—</span></div>
          <div class="kv"><span>Live only <span style="color:var(--faint)">(registry missed)</span></span><span class="mono" id="a-live">—</span></div>
          <div class="kv"><span>Registry only <span style="color:var(--faint)">(live missed)</span></span><span class="mono" id="a-reg">—</span></div>
          <div class="kv"><span>Flagged by neither</span><span class="mono" id="a-none">—</span></div>
        </div>
      </div>
    </div>
  </section>

  <!-- EXPLORER -->
  <section class="sec">
    <div class="sec-head">
      <div class="eyebrow">Corpus explorer</div>
      <h2>Every number, both readings</h2>
      <p>Filter the ground-truth corpus. “Disagree” marks numbers where the registry and live signals give different
        verdicts, the population an offline-only check would misread.</p>
    </div>
    <div class="card panel">
      <div class="filters">
        <input id="f-search" placeholder="Search number or carrier…">
        <select id="f-app"><option value="">All apps</option></select>
        <select id="f-lt">
          <option value="">All line types</option>
          <option value="nonFixedVoip">nonFixedVoip</option>
          <option value="mobile">mobile</option>
          <option value="fixedVoip">fixedVoip</option>
        </select>
        <select id="f-dis">
          <option value="">Agreement: any</option>
          <option value="y">Signals disagree</option>
          <option value="n">Signals agree</option>
        </select>
        <span class="count" id="f-count">—</span>
      </div>
      <div class="tbl-wrap">
        <table class="rec">
          <thead><tr>
            <th>Number</th><th>App (truth)</th><th>Live line type</th><th>Carrier</th>
            <th>Registry class</th><th>Signals</th>
          </tr></thead>
          <tbody id="rec-body"></tbody>
        </table>
      </div>
      <div class="pager">
        <button id="pg-prev">‹ Prev</button>
        <span class="pg" id="pg-info">—</span>
        <button id="pg-next">Next ›</button>
      </div>
    </div>
  </section>

  <div class="foot">
    <span>BurnerCheck &middot; research artifact. Readings are provenance signals, not identity attribution.</span>
    <span class="mono">Registry: public NANPA CO-Code file &nbsp;·&nbsp; Live: Twilio Lookup v2</span>
  </div>
</div>

<script>
const ANALYTICS = {{ analytics_json|safe }};
let RECORDS = [];

const $ = s => document.querySelector(s);
const money = n => n.toLocaleString();
const covClass = v => v >= 80 ? '' : (v >= 40 ? 'mid' : 'low');

/* ---------- header + strip ---------- */
function paintHeader(){
  $('#m-total').textContent = money(ANALYTICS.total);
  $('#m-apps').textContent = ANALYTICS.apps_shown.length;
  $('#s-corpus').textContent = money(ANALYTICS.total);
  $('#s-corpus-c').textContent = 'across ' + ANALYTICS.apps_shown.length + ' apps';
  $('#s-cov').innerHTML = ANALYTICS.overall.linetype_cov + '<small>%</small>';
  $('#s-mask').innerHTML = ANALYTICS.mobile_mask.pct_wholesale + '<small>%</small>';
  $('#s-mask-c').textContent = ANALYTICS.mobile_mask.wholesale + ' of ' + ANALYTICS.mobile_mask.total + ' mobile-labeled';
  $('#s-dis').innerHTML = (100 - ANALYTICS.overall.agreement).toFixed(1) + '<small>%</small>';
}

/* ---------- coverage bars ---------- */
function paintBars(){
  const host = $('#cov-bars');
  host.innerHTML = ANALYTICS.per_app_by_cov.map(a => `
    <div class="bar-row">
      <div class="lbl">${a.app}<small>n=${a.n}</small></div>
      <div class="track ghost">
        <div class="fill ${covClass(a.linetype_cov)}" style="width:${a.linetype_cov}%"></div>
        <div class="g" style="left:${a.prefix_cov}%" title="registry ${a.prefix_cov}%"></div>
      </div>
      <div class="pctv">${a.linetype_cov}%</div>
    </div>`).join('');
}

/* ---------- line-type + mask splits ---------- */
function seg(w, color, label){ return `<span style="width:${w}%;background:${color}" title="${label}">${w>=9?label:''}</span>`; }
function paintMask(){
  const lt = ANALYTICS.line_types, t = ANALYTICS.total;
  const p = n => +(100*n/t).toFixed(1);
  $('#lt-split').innerHTML =
    seg(p(lt.nonFixedVoip),'var(--flag)', lt.nonFixedVoip) +
    seg(p(lt.mobile),'var(--warn)', lt.mobile) +
    seg(p(lt.fixedVoip+lt.other),'var(--registry)', lt.fixedVoip+lt.other);
  $('#lt-legend').innerHTML =
    `<span><i style="background:var(--flag)"></i>nonFixedVoip · ${money(lt.nonFixedVoip)}</span>
     <span><i style="background:var(--warn)"></i>mobile · ${money(lt.mobile)}</span>
     <span><i style="background:var(--registry)"></i>fixedVoip/other · ${money(lt.fixedVoip+lt.other)}</span>`;

  const m = ANALYTICS.mobile_mask;
  const pw = m.total ? +(100*m.wholesale/m.total).toFixed(1) : 0;
  const pm = m.total ? +(100*m.mno/m.total).toFixed(1) : 0;
  $('#mask-split').innerHTML =
    seg(pw,'var(--flag)', m.wholesale + ' wholesale VoIP') +
    seg(pm,'var(--ok)', m.mno + ' MNO');
  $('#mask-legend').innerHTML =
    `<span><i style="background:var(--flag)"></i>wholesale VoIP · ${m.wholesale} (${m.pct_wholesale}%)</span>
     <span><i style="background:var(--ok)"></i>real mobile operator · ${m.mno}</span>`;
}

/* ---------- fingerprint heatmap ---------- */
function shade(pct){
  // light -> deep teal
  const t = Math.max(0, Math.min(1, pct/100));
  const lo=[243,246,249], hi=[14,127,140];
  const c = lo.map((v,i)=>Math.round(v+(hi[i]-v)*t));
  return `rgb(${c[0]},${c[1]},${c[2]})`;
}
function paintFingerprint(){
  const fp = ANALYTICS.fingerprint;
  let h = '<table><thead><tr><th class="rowlab"></th>' +
    fp.apps.map(a=>`<th>${a}</th>`).join('') + '</tr></thead><tbody>';
  fp.rows.forEach(row=>{
    h += `<tr><td class="rowlab">${row.carrier}</td>`;
    row.cells.forEach(c=>{
      if(c.count===0){ h += `<td><div class="cell" style="background:var(--surface-2)"></div></td>`; }
      else{
        const tc = c.pct>55 ? '#fff' : 'var(--ink)';
        h += `<td><div class="cell" style="background:${shade(c.pct)};color:${tc}">
          <span class="n">${c.count}</span><span class="p">${c.pct}%</span></div></td>`;
      }
    });
    h += '</tr>';
  });
  h += '</tbody></table>';
  $('#fp').innerHTML = h;
}

/* ---------- agreement ---------- */
function paintAgreement(){
  const a = ANALYTICS.agreement_cells, t = ANALYTICS.total;
  const p = n => +(100*n/t).toFixed(1);
  $('#agree-split').innerHTML =
    seg(p(a.both),'var(--live)', a.both) +
    seg(p(a.live_only),'#4bb3bd', a.live_only) +
    seg(p(a.prefix_only),'var(--registry)', a.prefix_only) +
    seg(p(a.neither),'var(--faint)', a.neither);
  $('#agree-legend').innerHTML =
    `<span><i style="background:var(--live)"></i>both</span>
     <span><i style="background:#4bb3bd"></i>live only</span>
     <span><i style="background:var(--registry)"></i>registry only</span>
     <span><i style="background:var(--faint)"></i>neither</span>`;
  $('#a-both').textContent = money(a.both);
  $('#a-live').textContent = money(a.live_only);
  $('#a-reg').textContent  = money(a.prefix_only);
  $('#a-none').textContent = money(a.neither);
}

/* ---------- reader ---------- */
function renderReading(d){
  const reg = $('#lane-reg'), live = $('#lane-live');
  reg.classList.remove('scan'); live.classList.remove('scan');
  if(!d.success){
    $('#reg-val').textContent='—'; $('#reg-desc').textContent='';
    $('#live-val').textContent='—'; $('#live-desc').textContent = d.message || 'No reading.';
    setChip('muted','No reading'); $('#v-num').textContent=''; $('#v-agree').textContent='';
    $('#v-prov').textContent=''; return;
  }
  $('#v-num').textContent = d.formatted_display || '';
  $('#reg-val').textContent = d.registry_class || 'not found';
  $('#reg-desc').textContent = d.registry_provider ? d.registry_provider : (d.registry_msg||'');
  $('#live-val').textContent = d.line_type || 'unknown';
  $('#live-desc').textContent = d.carrier || (d.live_msg||'');
  setChip(d.verdict_class, d.verdict);
  const ag = $('#v-agree');
  if(d.agree === null || d.agree === undefined){ ag.textContent=''; }
  else if(d.agree){ ag.className='agree match'; ag.innerHTML='<span class="ic">=</span> signals agree'; }
  else { ag.className='agree disagree'; ag.innerHTML='<span class="ic">&ne;</span> signals disagree · likely ported'; }
  $('#v-prov').textContent = d.provenance || '';
}
function setChip(cls, text){
  const c = $('#v-chip'); c.className = 'chip ' + (cls||'muted');
  $('#v-chip-t').textContent = text || '—';
}
async function readNumber(num){
  const btn = $('#qbtn'); btn.disabled = true; btn.textContent = 'Reading…';
  $('#lane-reg').classList.add('scan'); $('#lane-live').classList.add('scan');
  try{
    const r = await fetch('/analyze',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({phone_number:num})});
    renderReading(await r.json());
  }catch(e){
    renderReading({success:false,message:'Request failed. Check the console is running.'});
  }finally{ btn.disabled=false; btn.textContent='Read number'; }
}
$('#qform').addEventListener('submit', e=>{ e.preventDefault();
  const v=$('#q').value.trim(); if(v) readNumber(v); });

/* ---------- explorer ---------- */
const PAGE=40; let page=0, filtered=[];
function ltClass(t){ return t==='nonFixedVoip'?'voip':(t==='mobile'?'mobile':'fixed'); }
function disagree(r){
  const live = r.twilio_line_type==='nonFixedVoip';
  const reg = r.csv_classification==='BURNER/VoIP';
  return live!==reg;
}
function applyFilters(){
  const q=$('#f-search').value.trim().toLowerCase();
  const app=$('#f-app').value, lt=$('#f-lt').value, dis=$('#f-dis').value;
  filtered = RECORDS.filter(r=>{
    if(app && r.source_app!==app) return false;
    if(lt && r.twilio_line_type!==lt) return false;
    if(dis){ const d=disagree(r); if(dis==='y'&&!d)return false; if(dis==='n'&&d)return false; }
    if(q){ const hay=((r.phone_number||'')+' '+(r.twilio_carrier||'')).toLowerCase();
      if(!hay.includes(q)) return false; }
    return true;
  });
  page=0; renderTable();
}
function renderTable(){
  const total=filtered.length, pages=Math.max(1,Math.ceil(total/PAGE));
  if(page>=pages) page=pages-1;
  const rows=filtered.slice(page*PAGE,(page+1)*PAGE);
  $('#rec-body').innerHTML = rows.map(r=>{
    const d=disagree(r);
    return `<tr>
      <td class="tnum">${fmtNum(r.phone_number)}</td>
      <td><span class="tag2">${(ANALYTICS.appmap&&ANALYTICS.appmap[r.source_app])||r.source_app}</span></td>
      <td><span class="lt ${ltClass(r.twilio_line_type)}">${r.twilio_line_type||'—'}</span></td>
      <td class="mono" style="font-size:12px">${r.twilio_carrier||'—'}</td>
      <td style="font-size:12px;color:var(--muted)">${r.csv_classification||'—'}</td>
      <td><span class="dis ${d?'y':'n'}">${d?'≠ disagree':'= agree'}</span></td>
    </tr>`;
  }).join('') || `<tr><td colspan="6" style="text-align:center;color:var(--faint);padding:26px">No numbers match.</td></tr>`;
  $('#f-count').textContent = money(total)+' / '+money(RECORDS.length);
  $('#pg-info').textContent = `page ${page+1} of ${pages}`;
  $('#pg-prev').disabled = page<=0; $('#pg-next').disabled = page>=pages-1;
}
function fmtNum(s){ const d=(s||'').replace(/\D/g,''); const x=d.length===11&&d[0]==='1'?d.slice(1):d;
  return x.length===10?`(${x.slice(0,3)}) ${x.slice(3,6)}-${x.slice(6)}`:(s||'—'); }
$('#pg-prev').onclick=()=>{ if(page>0){page--;renderTable();} };
$('#pg-next').onclick=()=>{ page++; renderTable(); };
['#f-search','#f-app','#f-lt','#f-dis'].forEach(s=>{
  const el=$(s); el.addEventListener(s==='#f-search'?'input':'change', applyFilters);
});

/* ---------- boot ---------- */
function fillAppFilter(){
  const sel=$('#f-app');
  ANALYTICS.per_app.forEach(a=>{
    const o=document.createElement('option'); o.value=a.raw; o.textContent=`${a.app} (${a.n})`; sel.appendChild(o);
  });
}
async function boot(){
  paintHeader(); paintBars(); paintMask(); paintFingerprint(); paintAgreement(); fillAppFilter();
  // pre-read the hero number so the reader is populated on load
  const hero = $('#q').value.trim(); if(hero) readNumber(hero);
  try{
    const r = await fetch('/records'); const j = await r.json(); RECORDS = j.records||[];
  }catch(e){ RECORDS=[]; }
  applyFilters();
}
boot();
</script>
</body>
</html>"""


# ---------------------------------------------------------------- routes
@app.route("/")
def index():
    records = all_records()
    analytics = compute_analytics(records)
    analytics["appmap"] = APP_DISPLAY
    hero = hero_example(records)
    hero_num = fmt_number(hero["phone_number"]) if hero else ""
    return render_template_string(
        HTML_TEMPLATE,
        analytics_json=json.dumps(analytics),
        hero_num=hero_num,
        live_enabled=LIVE_ENABLED,
    )


@app.route("/records")
def records():
    rows = [r for r in all_records() if r.get("source_app")]
    slim = [{
        "phone_number": r.get("phone_number"),
        "source_app": r.get("source_app"),
        "twilio_line_type": r.get("twilio_line_type"),
        "twilio_carrier": r.get("twilio_carrier"),
        "csv_classification": r.get("csv_classification"),
    } for r in rows]
    return jsonify({"records": slim})


@app.route("/analytics")
def analytics():
    return jsonify(compute_analytics(all_records()))


def _reading_from_record(r):
    line_type = r.get("twilio_line_type")
    carrier = r.get("twilio_carrier")
    reg_cls = r.get("csv_classification")
    verdict, vclass = verdict_for(line_type, carrier)
    live_voip = line_type == "nonFixedVoip"
    reg_voip = reg_cls == "BURNER/VoIP"
    return {
        "success": True,
        "formatted_display": fmt_number(r.get("phone_number")),
        "registry_class": reg_cls,
        "registry_provider": r.get("csv_provider"),
        "line_type": line_type,
        "carrier": carrier,
        "verdict": verdict,
        "verdict_class": vclass,
        "agree": (live_voip == reg_voip),
        "provenance": "from corpus · " + APP_DISPLAY.get(r.get("source_app"), r.get("source_app", "")),
    }


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json or {}
    phone_number = (data.get("phone_number") or "").strip()
    if not phone_number:
        return jsonify({"success": False, "message": "Enter a phone number."})

    clean = re.sub(r"\D", "", phone_number)
    key = "+1" + clean[-10:] if len(clean) >= 10 else phone_number

    # 1) corpus first (offline, instant, ground truth)
    for r in all_records():
        if r.get("phone_number") == key or re.sub(r"\D", "", r.get("phone_number", ""))[-10:] == clean[-10:]:
            if r.get("source_app"):
                return jsonify(_reading_from_record(r))

    # 2) live lookup for numbers outside the corpus
    csv_r = analyze_with_csv(phone_number)
    tw_r = analyze_with_twilio(phone_number)

    if not tw_r["success"]:
        # still return the registry reading if we have it
        if csv_r.get("success"):
            return jsonify({
                "success": True,
                "formatted_display": fmt_number(phone_number),
                "registry_class": csv_r["classification"],
                "registry_provider": csv_r["provider"],
                "line_type": None, "carrier": None,
                "live_msg": tw_r["message"],
                "verdict": "Live reading unavailable", "verdict_class": "muted",
                "agree": None, "provenance": "registry only",
            })
        return jsonify({"success": False, "message": tw_r["message"]})

    line_type = tw_r["line_type"]
    carrier = tw_r["carrier"]
    verdict, vclass = verdict_for(line_type, carrier)
    reg_cls = csv_r.get("classification")
    live_voip = line_type == "nonFixedVoip"
    reg_voip = reg_cls == "BURNER/VoIP"

    record = {
        "phone_number": tw_r["formatted_number"],
        "timestamp": datetime.now().isoformat(),
        "source_app": "session",
        "csv_npa_nxx": csv_r.get("npa_nxx", "N/A"),
        "csv_provider": csv_r.get("provider", "N/A"),
        "csv_classification": reg_cls or "N/A",
        "twilio_carrier": carrier,
        "twilio_line_type": line_type,
        "is_burner": live_voip,
    }
    session = load_json(SESSION_FILE)
    session.append(record)
    save_session(session)

    return jsonify({
        "success": True,
        "formatted_display": fmt_number(tw_r["formatted_number"]),
        "registry_class": reg_cls or (csv_r.get("message") if not csv_r.get("success") else None),
        "registry_provider": csv_r.get("provider"),
        "registry_msg": csv_r.get("message") if not csv_r.get("success") else None,
        "line_type": line_type, "carrier": carrier,
        "verdict": verdict, "verdict_class": vclass,
        "agree": (live_voip == reg_voip) if reg_cls else None,
        "provenance": "live lookup",
    })


if __name__ == "__main__":
    print(f"BurnerCheck: loaded {len(all_records())} records; live lookup {'ON' if LIVE_ENABLED else 'OFF'}")
    app.run(debug=True, host="0.0.0.0", port=5000)
