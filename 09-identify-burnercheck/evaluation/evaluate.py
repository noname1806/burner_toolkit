#!/usr/bin/env python3
"""
Reproducible ground-truth evaluation for BurnerCheck.

Scores three line-type classifiers over a labeled corpus of phone numbers:
  1. CSV / NANPA prefix  -- NPA-NXX block owner matched against VoIP/CLEC keywords
  2. Twilio line-type    -- line_type == 'nonFixedVoip'  (BurnerCheck's actual decision)
  3. Naive fusion        -- CSV OR Twilio  (illustrates why fusion is NOT used)

Ground truth is assigned by PROVENANCE, independent of the classifiers:
  * positives  = numbers we issued from the apps (Burner=100, Hushed=75, 2ndLine=50)
  * negatives  = known conventional numbers (real mobile / landline / fixed-VoIP)

Inputs:
  ../twilio_lookup_results.jsonl                     (Twilio Lookup v2 output, one JSON/line)
  CoCodeAssignment_Utilized_AllStates_Public.txt     (NANPA Co Code export; not bundled -- see README)

Outputs (written next to this script):
  labeled_dataset.json       every number with source, ground truth, and each classifier's prediction
  confusion_matrices.json    TP/FP/TN/FN + precision/recall/specificity/accuracy/F1 per classifier
"""
import json, csv, re, os, sys
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
# Prefer the copy bundled next to this script; fall back to the repo root.
LOOKUPS = os.path.join(HERE, "twilio_lookup_results.jsonl")
if not os.path.exists(LOOKUPS):
    LOOKUPS = os.path.join(HERE, "..", "twilio_lookup_results.jsonl")
# NANPA export is large and licensed separately; point NANPA_CSV at your local copy.
NANPA_CSV = os.environ.get("NANPA_CSV", os.path.join(HERE, "CoCodeAssignment_Utilized_AllStates_Public.txt"))

BURNER_KW = ["BANDWIDTH","ONVOY","LEVEL 3","VONAGE","TELNYX","COMMIO",
             "PINGER","TEXTNOW","GOOGLE","PEERLESS","SVR","CLEC"]

# Provenance labels for the app-issued positives, in collection order (checked_at ascending)
# among the nonFixedVoip lookups. Counts are the researcher's registration records.
APP_SPANS = [("Burner", 0, 100), ("Hushed", 100, 175), ("2ndLine", 175, 225)]


def load_prefix_map(path):
    m = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        rdr = csv.DictReader(f, delimiter="\t")
        rdr.fieldnames = [c.strip() for c in rdr.fieldnames]
        for row in rdr:
            k = (row.get("NPA-NXX") or "").strip()
            c = (row.get("Company") or "").strip().upper()
            if k and c and k not in m:
                m[k] = c
    return m


def csv_pred(e164, prefix):
    d = re.sub(r"\D", "", e164)
    d = d[1:] if len(d) == 11 and d[0] == "1" else d
    key = f"{d[:3]}-{d[3:6]}"
    comp = prefix.get(key)
    if comp is None:
        return None, None
    return (any(k in comp for k in BURNER_KW)), comp


def matrix(rows, pred_key):
    tp = fp = tn = fn = skip = 0
    for r in rows:
        gt, p = r["ground_truth_burner"], r[pred_key]
        if gt is None or p is None:
            skip += 1; continue
        if gt and p: tp += 1
        elif gt and not p: fn += 1
        elif not gt and p: fp += 1
        else: tn += 1
    n = tp + fp + tn + fn
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    spec = tn / (tn + fp) if tn + fp else 0.0
    acc = (tp + tn) / n if n else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return dict(TP=tp, FP=fp, TN=tn, FN=fn, skipped=skip, n=n,
                precision=round(prec, 3), recall=round(rec, 3),
                specificity=round(spec, 3), accuracy=round(acc, 3), f1=round(f1, 3))


def main():
    if not os.path.exists(NANPA_CSV):
        sys.exit(f"NANPA export not found at {NANPA_CSV}\n"
                 f"Download the NANPA Co Code assignment file and set NANPA_CSV=<path>.")
    prefix = load_prefix_map(NANPA_CSV)

    allrows = [json.loads(l) for l in open(LOOKUPS, encoding="utf-8") if l.strip()]
    nf = sorted([r for r in allrows if r.get("line_type") == "nonFixedVoip"],
                key=lambda r: r["checked_at"])
    if len(nf) != 225:
        print(f"WARNING: expected 225 nonFixedVoip app-issued numbers, found {len(nf)}", file=sys.stderr)
    appmap = {}
    for app, a, b in APP_SPANS:
        for i in range(a, b):
            appmap[nf[i]["e164"]] = app

    labeled = []
    for r in allrows:
        e, lt = r["e164"], r.get("line_type")
        if not r.get("lookup_success") or lt is None:
            gt, src = None, None
        elif e in appmap:
            gt, src = True, appmap[e]
        else:
            gt, src = False, "conventional"
        tw = (lt == "nonFixedVoip")
        cp, comp = csv_pred(e, prefix)
        labeled.append(OrderedDict([
            ("e164", e), ("source", src), ("ground_truth_burner", gt),
            ("collected_date", r["checked_at"][:10]),
            ("twilio_line_type", lt), ("twilio_pred", tw),
            ("csv_prefix_company", comp), ("csv_pred", cp),
            ("combined_pred", (tw or cp) if cp is not None else tw),
        ]))

    json.dump(labeled, open(os.path.join(HERE, "labeled_dataset.json"), "w", encoding="utf-8"), indent=2)

    res = {}
    for key, name in [("csv_pred", "CSV / NANPA prefix"),
                      ("twilio_pred", "Twilio line-type (tool decision)"),
                      ("combined_pred", "Naive fusion (CSV OR Twilio)")]:
        res[name] = matrix(labeled, key)
    json.dump(res, open(os.path.join(HERE, "confusion_matrices.json"), "w", encoding="utf-8"), indent=2)

    pos = sum(1 for r in labeled if r["ground_truth_burner"] is True)
    neg = sum(1 for r in labeled if r["ground_truth_burner"] is False)
    uns = sum(1 for r in labeled if r["ground_truth_burner"] is None)
    print(f"labeled corpus: {pos} app-issued positives, {neg} conventional negatives, {uns} unscoreable")
    for name, m in res.items():
        print(f"\n{name}")
        print(f"  TP={m['TP']} FP={m['FP']} TN={m['TN']} FN={m['FN']} (skipped {m['skipped']})")
        print(f"  precision={m['precision']} recall={m['recall']} "
              f"specificity={m['specificity']} accuracy={m['accuracy']} f1={m['f1']}")


if __name__ == "__main__":
    main()
