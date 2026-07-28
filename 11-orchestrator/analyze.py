#!/usr/bin/env python3
"""Orchestrator for the second-number app forensic workflow.

Runs the automatable stages end-to-end on any installed Android package and emits
a per-app report (markdown + JSON) plus an outcome-schema template for the analyst
to complete. Ties together the single-purpose tools in this directory.

    python tools/analyze.py --pkg com.hushed.release [--apk apk/hushed.apk] [--out out/]

Automatable here:  static hardening scan (if --apk), hashed baseline acquisition,
                   database inventory + encryption detection.
Interactive (guided, not run here): per-action before/after captures (drive with
                   ui.py), TLS-below-pinning capture (net_capture.py), cloud replay.
No overclaim: the tool reports what it observed and names what it could not reach.
"""
import argparse, subprocess, os, sys, json, tarfile, hashlib, re, glob

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ["MSYS_NO_PATHCONV"] = "1"


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, shell=isinstance(cmd, str))


def db_is_encrypted(head: bytes) -> bool:
    # plaintext SQLite files start with this magic; SQLCipher replaces it with salt
    return not head.startswith(b"SQLite format 3\x00")


def inventory_dbs(tar_path):
    dbs = []
    with tarfile.open(tar_path) as t:
        for m in t.getmembers():
            if m.isfile() and m.name.endswith((".db", ".sqlite", ".sqlite3")):
                head = t.extractfile(m).read(16)
                dbs.append({"path": m.name.lstrip("./"), "size": m.size,
                            "encrypted": db_is_encrypted(head)})
    return dbs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pkg", required=True)
    ap.add_argument("--apk", help="APK/bundle for the static hardening scan")
    ap.add_argument("--out", default=os.path.join(HERE, "..", "reports"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    report = {"package": args.pkg, "hardening": None, "acquisition": None, "databases": []}

    # 1) static hardening scan
    if args.apk and os.path.exists(args.apk):
        print(f"[1/3] hardening scan: {args.apk}")
        r = run([sys.executable, os.path.join(HERE, "hardening_scan.py"), args.apk])
        report["hardening"] = r.stdout
        print(r.stdout)

    # 2) hashed baseline acquisition (device layer)
    print(f"[2/3] baseline acquisition: {args.pkg}")
    r = run(["bash", os.path.join(HERE, "capture.sh"), args.pkg, "orch_baseline"])
    print(r.stdout.strip() or r.stderr.strip())
    tars = sorted(glob.glob(os.path.join(HERE, "..", "captures", args.pkg, "orch_baseline_*", "appdata.tar")))
    if tars:
        tar = tars[-1]
        h = hashlib.sha256(open(tar, "rb").read()).hexdigest()
        report["acquisition"] = {"tar": os.path.relpath(tar), "sha256": h}
        # 3) database inventory
        print("[3/3] database inventory")
        report["databases"] = inventory_dbs(tar)
        for d in report["databases"]:
            flag = "ENCRYPTED" if d["encrypted"] else "plaintext"
            print(f"    {flag:<10} {d['path']} ({d['size']} B)")
    else:
        print("    (no acquisition tar found; is the app installed and device rooted?)")

    # write reports
    base = os.path.join(args.out, args.pkg.replace(".", "_"))
    json.dump(report, open(base + ".json", "w"), indent=2)
    with open(base + ".md", "w", encoding="utf-8") as f:
        f.write(f"# Forensic workflow report: {args.pkg}\n\n")
        if report["acquisition"]:
            f.write(f"- Acquisition: `{report['acquisition']['tar']}`  "
                    f"(SHA-256 `{report['acquisition']['sha256'][:16]}...`)\n")
        enc = [d for d in report["databases"] if d["encrypted"]]
        f.write(f"- Databases: {len(report['databases'])} "
                f"({len(enc)} encrypted, {len(report['databases'])-len(enc)} plaintext)\n")
        for d in report["databases"]:
            f.write(f"  - {'ENCRYPTED' if d['encrypted'] else 'plaintext'}: `{d['path']}`\n")
        f.write("\n## Outcome-schema template (complete per action)\n\n")
        f.write("| action | device (created/persist/removed) | network | cloud |\n")
        f.write("|---|---|---|---|\n")
        for a in ("register", "obtain number", "send SMS", "receive SMS",
                  "delete message", "delete thread", "burn number", "logout"):
            f.write(f"| {a} |  |  |  |\n")
        f.write("\n## Next (interactive) steps\n")
        f.write("1. For each action: `ui.py` to drive it, `capture.sh` before/after, "
                "`dbdiff.py` (decrypt first with the app's key-derivation plugin if encrypted).\n")
        f.write("2. Network: `net_capture.py <pkg>` to map the API beneath pinning.\n")
        f.write("3. Cloud: replay the recovered credential read-only; log every request.\n")
        if report["hardening"] and "NOT FEASIBLE" in report["hardening"]:
            f.write("\n> Note: hardening detected — record blocked observations as "
                    "△ (not feasible) with the named mechanism.\n")
    print(f"\n[*] report written: {base}.md / .json")


if __name__ == "__main__":
    main()
