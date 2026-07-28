import os, re, csv, json, sys, time
import burner_check as bc   # provides client, analyze_with_twilio, BURNER_KEYWORDS, REAL_KEYWORDS

HERE = os.path.dirname(os.path.abspath(__file__))
NANPA = os.path.join(HERE, "CoCodeAssignment_Utilized_AllStates_Public.txt")
OUT = r"C:/Phd/Research/Burner-Paper/hushed_2ndline_lookups.json"
SOURCES = [
    ("hushed",  r"C:/Phd/Research/Burner-Paper/hushed_numbers/hushed_burner_numbers.csv"),
    ("2ndline", r"C:/Phd/Research/Burner-Paper/dingtone_numbers/dingtone_burner_numbers.csv"),
    ("burner",  r"C:/Phd/Research/Burner-Paper/burner_app_numbers/burner_numbers.csv"),
    ("textme",  r"C:/Phd/Research/Burner-Paper/text_me_numbers/textme_numbers.csv"),
    ("textfree", r"C:/Phd/Research/Burner-Paper/text_free_numbers/textfree_numbers.csv"),
]
LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else None  # for a small test

def nat10(pn):
    d = re.sub(r"\D", "", pn)
    return d[-10:]

def prefix(pn):
    n = nat10(pn)
    return f"{n[:3]}-{n[3:6]}"

# ---- load inputs ----
inputs = []  # (source, row)
for src, path in SOURCES:
    for r in csv.DictReader(open(path, encoding="utf-8")):
        inputs.append((src, r))
if LIMIT:
    # take a few from each source
    inputs = inputs[:LIMIT] + [x for x in inputs if x[0] == "2ndline"][:LIMIT]

needed = {prefix(r["phone_number"]) for _, r in inputs}
print(f"{len(inputs)} numbers, {len(needed)} distinct prefixes", flush=True)

# ---- NANPA index (first occurrence company per needed prefix) ----
idx = {}
with open(NANPA, encoding="utf-8") as f:
    rd = csv.DictReader(f, delimiter="\t")
    rd.fieldnames = [n.strip() for n in rd.fieldnames]
    for row in rd:
        k = (row.get("NPA-NXX") or "").strip()
        if k in needed and k not in idx:
            comp = (row.get("Company") or "").strip().upper()
            if comp:
                idx[k] = comp
        if len(idx) == len(needed):
            break
print(f"NANPA matched {len(idx)}/{len(needed)} prefixes", flush=True)

def csv_classify(pn):
    npx = prefix(pn)
    comp = idx.get(npx)
    if not comp:
        return npx, "N/A", "N/A"
    for k in bc.BURNER_KEYWORDS:
        if k in comp:
            return npx, comp, "BURNER/VoIP"
    for k in bc.REAL_KEYWORDS:
        if k in comp:
            return npx, comp, "REAL/Mobile"
    return npx, comp, "LANDLINE/Regional"

# ---- resume: skip ONLY successful lookups; re-run failures + unprocessed ----
by_key = {}
if os.path.exists(OUT):
    try:
        for rr in json.load(open(OUT, encoding="utf-8")):
            by_key[(rr["source_app"], rr["phone_number"])] = rr
    except Exception:
        by_key = {}
done = {k for k, v in by_key.items() if v.get("twilio_success")}
print(f"loaded {len(by_key)} records; {len(done)} already successful (skip); re-running the rest", flush=True)

def save():
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(list(by_key.values()), f, indent=2)
    os.replace(tmp, OUT)

n = 0
for src, r in inputs:
    nat = nat10(r["phone_number"])
    key = (src, "+1" + nat)
    if key in done:
        continue
    # Twilio (pass national 10-digit so its +1 formatting is correct)
    tw = bc.analyze_with_twilio(nat)
    for _ in range(2):
        if tw.get("success"):
            break
        time.sleep(2)
        tw = bc.analyze_with_twilio(nat)
    npx, comp, ccls = csv_classify(nat)
    rec = {
        "source_app": src,
        "phone_number": "+1" + nat,
        "area_code": r.get("area_code", nat[:3]),
        "region_state": r.get("region_state", ""),
        "twilio_success": tw.get("success", False),
        "twilio_carrier": tw.get("carrier"),
        "twilio_line_type": tw.get("line_type"),
        "twilio_classification": tw.get("classification"),
        "twilio_error": tw.get("message") if not tw.get("success") else None,
        "csv_npa_nxx": npx,
        "csv_provider": comp,
        "csv_classification": ccls,
        "is_burner": tw.get("is_burner", None),
    }
    by_key[key] = rec
    n += 1
    if n % 10 == 0:
        save()
        ok = sum(1 for x in by_key.values() if x.get("twilio_success"))
        print(f"  processed {n} this run; total records={len(by_key)}; successful={ok}", flush=True)
    time.sleep(0.1)

save()
vals = list(by_key.values())
h = sum(1 for x in vals if x["source_app"] == "hushed")
d = sum(1 for x in vals if x["source_app"] == "2ndline")
ok = sum(1 for x in vals if x.get("twilio_success"))
print(f"DONE: {len(vals)} records ({ok} successful) -> {OUT}  (hushed={h}, 2ndline={d})", flush=True)
