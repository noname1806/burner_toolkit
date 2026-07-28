# BurnerCheck — ground-truth evaluation

This directory contains the labeled dataset and reproducible evaluation used to assess
second-line/VoIP number identification. It exists to make every accuracy claim in the paper
checkable against released data.

## Ground truth (assigned by provenance, not by the classifier)

| Class | n | How the label was established |
|-------|---|-------------------------------|
| **Positives — app-issued** | 225 | Numbers we registered from the apps: **Burner (100)**, **Hushed (75)**, **2ndLine (50)**. |
| **Negatives — conventional** | 372 | Known real numbers: real mobile (117), landline (86), fixed-VoIP home/business (169). |
| Unscoreable | 14 | Twilio Lookup returned an error / no line type; excluded from scoring. |
| **Total looked up** | 611 | |

Labels are assigned from **how each number was obtained**, independently of what any
classifier outputs. The positive set is listed, in collection order, in
`groundtruth_app_numbers.json`; every number in the full corpus (with its label and each
classifier's prediction) is in `labeled_dataset.json`.

### On the app boundaries
The Twilio lookups were run in collection order (`checked_at` ascending). The
**Hushed → 2ndLine** boundary coincides with a **7-day gap** in the log (the 2ndLine batch
was collected a week later, on 2026-03-31), which a reviewer can verify from the
`collected_date` field. The Burner → Hushed boundary (index 100) falls inside one continuous
collection session and reflects our registration records. Counts are 100 / 75 / 50 per those
records; note the last Hushed number was looked up in the later session.

## Classifiers compared

1. **CSV / NANPA prefix** — the naive/prior approach: map the number's NPA-NXX block to its
   assigned carrier (NANPA Co Code export) and flag VoIP/CLEC keywords.
2. **Twilio line-type** — BurnerCheck's actual decision: flag `line_type == nonFixedVoip`
   from Twilio Lookup v2 Line Type Intelligence (portability-aware).
3. **Naive fusion (CSV OR Twilio)** — flag if *either* fires; included to show why the tool
   does **not** fuse this way.

## Results (597 scoreable numbers)

| Classifier | Precision | Recall | Specificity | Accuracy | F1 |
|---|---|---|---|---|---|
| CSV / NANPA prefix          | 0.324 | 0.293 | 0.629 | 0.503 | 0.308 |
| Twilio line-type (tool)     | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| Naive fusion (CSV OR Twilio)| 0.620 | 1.000 | 0.629 | 0.769 | 0.765 |

### What the numbers mean
- **Prefix-only identification is unreliable (F1 = 0.31, accuracy ≈ chance).** 159 app-issued
  numbers sit in blocks whose registered owner looks like a conventional carrier
  (e.g. a Burner line in a *VoiceStream/BellSouth* block); 138 conventional numbers sit in
  blocks owned by carriers on the VoIP keyword list (e.g. a real landline in a *Level 3*
  block). Number portability and CLEC block reassignment break the block-owner assumption.
- **Portability-aware line-type separates the classes on this corpus** (all 225 app-issued
  numbers resolve to `nonFixedVoip`; no conventional number does). This is why BurnerCheck
  decides on Twilio's line type.
- **Fusing by OR *degrades* precision (1.00 → 0.62)** by importing the prefix method's false
  positives. This is the empirical reason the tool uses the NANPA prefix only as
  **corroborating provenance context**, not as a fused vote in the decision.

### Scope and honest bounds
- The Twilio row is a **near-upper bound**, not a standalone headline: the positive class
  comprises three apps that all issue `nonFixedVoip` numbers. Apps that issue numbers typed
  as `fixedVoip` (e.g. TextFree) or resold `mobile` would evade a `nonFixedVoip`-only rule
  and are **not** represented in this labeled set — that evasion case is discussed as a
  limitation in the paper, not scored here.
- **US/NANP only.** NANPA covers country code +1; Twilio line-type coverage/accuracy varies
  by jurisdiction.

## Reproduce

```bash
# Twilio Lookup output is bundled (twilio_lookup_results.jsonl).
# The NANPA Co Code export is large/licensed and is NOT bundled — download it and point to it:
NANPA_CSV=/path/to/CoCodeAssignment_Utilized_AllStates_Public.txt python evaluate.py
```

Regenerates `labeled_dataset.json` and `confusion_matrices.json` and prints the table above.

## Files
- `groundtruth_app_numbers.json` — the 225 app-issued positives, labeled by source app.
- `labeled_dataset.json` — all 611 numbers: source, ground truth, and every classifier's prediction.
- `confusion_matrices.json` — TP/FP/TN/FN + metrics per classifier.
- `twilio_lookup_results.jsonl` — raw Twilio Lookup v2 output, one JSON object per line.
- `evaluate.py` — reproducible scoring script.
