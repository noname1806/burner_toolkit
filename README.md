# Burner Forensics Toolkit

An open, layer-structured toolkit for the forensic analysis of Android second-number
("burner") apps, spanning the **device → network → cloud** evidence path. It accompanies the
paper *"Not All 'Burners' Burn: Device and Cloud Forensics of Android Burner Apps."*

Each numbered folder is one stage of the workflow. Every tool emits a hashed artifact and was
validated on live data, so each claim in the paper maps to a runnable tool.

> **Scope.** The **acquisition and analysis** stages are automated and reproducible.
> **Installing an app and using it** (registration, messaging, deletion, number burn) is
> *analyst-driven* through a deterministic UI helper  it is **not** a fully automated
> install-to-acquisition robot. The toolkit does **not** defeat PairIP-class hardening; where a
> stage is infeasible it names the blocking mechanism rather than inferring an app property.

## Workflow order
``
        ┌─────────────┐
        │ 01 hardening │  static triage: what is feasible on this app?
        └──────┬──────┘
   DEVICE ─────┼───────────────────────────────────────────────
        ┌──────▼──────┐   ┌────────────┐   ┌────────────────┐
        │ 02 acquire   │──▶│ 03 db-diff │──▶│ 04 decrypt     │
        │ (hashed)     │   │ before/aft │   │ (Hushed key)   │
        └──────────────┘   └────────────┘   └───────┬────────┘
        ┌──────────────┐   ┌────────────┐   ┌────────▼───────┐
        │ 06 extract   │   │ 05 carve   │◀──│ (decrypted DB) │
        │ prefs/tokens │   │ deleted    │   └────────────────┘
        └──────────────┘   └────────────┘
   NETWORK ────────────────────────────────────────────────────
        ┌──────────────────────────────┐
        │ 07 network-capture (below TLS)│
        └──────────────────────────────┘
   CLOUD ──────────────────────────────────────────────────────
        ┌──────────────────────────────┐   ┌────────────────────┐
        │ 08 cloud-client (BFCC)        │   │ 09 identify        │
        │ token-scoped, read-only       │   │ (BurnerCheck)      │
        └──────────────────────────────┘   └────────────────────┘
   SUPPORT ────────────────────────────────────────────────────
        10 ui-helper (drive app actions)   11 orchestrator (run automatable stages)

        ``

| # | Folder | Layer | What it does |
|---|--------|-------|--------------|
| 01 | `01-hardening-scan` | triage | Static scan of an APK/bundle: PairIP, Play Integrity, App Check, FingerprintJS, TLS pinning, SQLCipher, and backend hosts. Tells you what is feasible. |
| 02 | `02-acquire` | device | Force-stop, on-device per-file SHA-256 manifest, and a hashed logical acquisition (`tar`) of `/data/data/<pkg>`. |
| 03 | `03-db-diff` | device | Per-table rowcount diff between two captures → which rows an action *created* or *removed*; flags encrypted DBs. |
| 04 | `04-decrypt-hushed` | device | Derives the Hushed database key from the installation UUID and decrypts the SQLCipher store (nothing hardcoded). |
| 05 | `05-carve-deleted` | device | Carves deleted records from raw SQLCipher pages / freelist to test secure-delete behavior. |
| 06 | `06-extract-prefs` | device | Dumps Android encrypted shared-preferences (e.g., tokens) at runtime via Frida. |
| 07 | `07-network-capture` | network | Frida `SSL_read`/`SSL_write` hook: reads plaintext **beneath** certificate pinning. |
| 08 | `08-cloud-client-bfcc` | cloud | **BFCC** — read-only-by-default token-scoped cloud acquisition with automatic SHA-256 + Merkle-root evidence manifests. *(has its own README)* |
| 09 | `09-identify-burnercheck` | identify | **BurnerCheck** — line-type/prefix number classification with a labeled ground-truth evaluation. *(has its own README + `evaluation/`)* |
| 10 | `10-ui-helper` | support | Deterministic `uiautomator` helper to drive per-action app usage (taps hit real element centers). |
| 11 | `11-orchestrator` | support | Runs the automatable stages end-to-end (01→02→03) and emits a per-app report + outcome-schema template. |

## Install

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: . .venv/Scripts/Activate.ps1
pip install -r requirements.txt
```

**External requirements** (not pip-installable):
- **Android Platform Tools** (`adb`) on `PATH`.
- A **rooted** device/emulator with **Magisk** (for `su`-based acquisition) and **frida-server**
  running on-device (for stages 06 and 07).
- For 09, a **Twilio** account (Lookup v2) and the NANPA Co Code export (see that folder's README).

## Quick start

```bash
# Triage + automated device stages on an installed app:
python 11-orchestrator/analyze.py --pkg com.hushed.release --apk path/to/hushed.apk

# Per action (register / send / delete / burn): drive it, then capture before & after:
python 10-ui-helper/ui.py dump                 # find the control to tap
bash   02-acquire/capture.sh com.hushed.release before_delete
#   ... perform the action in the app ...
bash   02-acquire/capture.sh com.hushed.release after_delete
python 03-db-diff/dbdiff.py <before_capture> <after_capture>
```

## Reproducibility & claim-to-tool mapping

Every finding in the paper is backed by a released tool: Hushed decryption (04), secure-delete
result (05 + 03), TLS-below-pinning API mapping (07), token-scoped cloud acquisition (08), and
the line-type identification confusion matrix (09/`evaluation/`, reproducible via `evaluate.py`).

## Lawful use & ethics

For research and lawful, authorized investigations only. Use only with accounts and devices you
are authorized to access. Cloud stages replay device-recovered credentials and may exceed a
device-only warrant; BFCC defaults to read-only and records operator/case/mode in every manifest.
The identification method is bounded to the North American Numbering Plan (`+1`).

## License

Add a `LICENSE` file (MIT / Apache-2.0 / BSD-3-Clause) before public release.
