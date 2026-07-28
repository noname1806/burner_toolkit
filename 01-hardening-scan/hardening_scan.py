#!/usr/bin/env python3
"""Static hardening + backend-surface scanner for an Android APK / app bundle.

Generalises the per-app hardening characterisation used in this study: given an
APK (or an .xapk/.apkm bundle), it reports which anti-analysis mechanisms are
present and enumerates the backend/cloud hosts the app talks to. This is the
"network layer, static half" of the workflow and the input to the outcome-schema
\notfeasible cells (a blocked observation is labelled with the mechanism found here).

    python tools/hardening_scan.py <app.apk | bundle.xapk>

No claim of completeness: absence of a marker is not proof the protection is
absent (it may be renamed/packed); presence is a lower bound.
"""
import sys, os, re, zipfile

# marker -> (human name, dex byte-substrings to count)
MARKERS = {
    "PairIP (VM code protection)":        [b"com/pairip", b"VMRunner", b"pairip"],
    "Play licensing / integrity check":   [b"licensecheck", b"LicenseClient"],
    "Play Integrity API":                 [b"PlayIntegrity", b"IntegrityManager", b"integrityToken"],
    "DroidGuard (SafetyNet/Integrity)":   [b"DroidGuard"],
    "Firebase App Check (attestation)":   [b"firebaseappcheck", b"AppCheck"],
    "FingerprintJS (device fingerprint)": [b"fpjs", b"fingerprintjs"],
    "TLS certificate pinning":            [b"CertificatePinner", b"checkServerTrusted", b"pinning"],
    "Anti-Frida / debugger checks":       [b"frida", b"debugger", b"ptrace"],
    "SQLCipher (encrypted DB)":           [b"net/sqlcipher", b"SupportFactory"],
}

HOST_RE = re.compile(rb"https?://([a-z0-9.\-]+\.(?:com|net|io|co|org|cloud|app))")
FIRST_PARTY_HINTS = re.compile(rb"api|prod|backend|gateway|auth|voip|sip|twilio|bandwidth|firebase|amazonaws")


def collect_dex(path):
    """Return concatenated DEX bytes and the manifest, from an APK or a bundle."""
    dex, manifest = b"", b""
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        inner_apks = [n for n in names if n.endswith(".apk")]
        if inner_apks:  # .xapk / .apkm bundle: read the base apk
            base = min(inner_apks, key=len)
            return collect_dex_from_bytes(z.read(base))
        for n in names:
            if n.endswith(".dex"):
                dex += z.read(n)
            elif n == "AndroidManifest.xml":
                manifest = z.read(n)
    return dex, manifest


def collect_dex_from_bytes(apk_bytes):
    import io
    dex, manifest = b"", b""
    with zipfile.ZipFile(io.BytesIO(apk_bytes)) as z:
        for n in z.namelist():
            if n.endswith(".dex"):
                dex += z.read(n)
            elif n == "AndroidManifest.xml":
                manifest = z.read(n)
    return dex, manifest


def main():
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(1)
    path = sys.argv[1]
    dex, manifest = collect_dex(path)
    blob = dex + manifest
    print(f"# hardening scan: {os.path.basename(path)}  ({len(dex)//1024} KB DEX)\n")

    print("## anti-analysis / hardening markers")
    found_any = False
    for name, subs in MARKERS.items():
        hits = {s.decode(errors='replace'): blob.count(s) for s in subs if blob.count(s)}
        if hits:
            found_any = True
            total = sum(hits.values())
            print(f"  [x] {name:<38} (x{total}: {', '.join(f'{k}:{v}' for k,v in hits.items())})")
        else:
            print(f"  [ ] {name}")
    if not found_any:
        print("  (no markers matched; app may be unhardened or heavily renamed)")

    print("\n## backend / cloud hosts (first-party-looking first)")
    hosts = sorted(set(HOST_RE.findall(blob)))
    fp = [h for h in hosts if FIRST_PARTY_HINTS.search(h)]
    other = [h for h in hosts if h not in fp]
    for h in fp[:30]:
        print("  *", h.decode())
    if other:
        print(f"  ... plus {len(other)} more hosts (ad/analytics/CDN); {len(hosts)} total")

    print("\n## outcome-schema hint")
    has = lambda n: any(blob.count(s) for s in MARKERS[n])
    pairip = has("PairIP (VM code protection)")
    attest = has("Play Integrity API") or has("DroidGuard (SafetyNet/Integrity)")
    if pairip:
        print("  PairIP VM protection present -> the app may refuse to launch under a "
              "rooted/emulated/instrumented runtime; if it crashes, record the blocked "
              "device/network/cloud observations as \\notfeasible (mechanism: PairIP).")
    elif attest:
        print("  Play Integrity / DroidGuard present but no PairIP VM: local device and "
              "network instrumentation are usually still possible (e.g. Hushed runs and "
              "was intercepted); attestation mainly gates SERVER-SIDE acceptance, which "
              "can block cloud replay. Verify each layer at runtime before labelling.")
    else:
        print("  No VM/attestation hardening detected; device + network layers expected "
              "to be reachable (verify at runtime).")


if __name__ == "__main__":
    main()
