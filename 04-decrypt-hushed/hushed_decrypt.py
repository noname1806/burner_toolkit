#!/usr/bin/env python3
"""Reproduce Hushed's offline database key derivation and decrypt hushed-encrypted.db.

Fully offline, no network. Demonstrates the reverse-engineered key-derivation:
  installation UUID  (shared_prefs/com.hushed.release_preferences.xml, key
                      KEY_DB_INFO_STORE)
  + package id       ("com.hushed.release")
  -> SHA-1           (first 16 bytes)
  -> (byte % 94) + 33 per byte  -> 16-char ASCII-printable SQLCipher passphrase

Usage:
    python tools/hushed_decrypt.py <capture appdata.tar> [out_plaintext.db]

Writes a decrypted plaintext copy (default: alongside the tar as
hushed-decrypted.db) so dbdiff.py can diff Hushed across actions, and prints
the exact SQLCipher parameters + per-table row counts.
"""
import sys, os, re, tarfile, tempfile, hashlib
import sqlcipher3

PKG = "com.hushed.release"
PREFS_MEMBER_HINT = "com.hushed.release_preferences.xml"
UUID_KEY = "KEY_DB_INFO_STORE"
ENC_DB_MEMBER = "./databases/hushed-encrypted.db"


def read_uuid_from_tar(tar):
    """Extract the installation UUID (KEY_DB_INFO_STORE) from captured prefs."""
    with tarfile.open(tar) as t:
        for m in t.getmembers():
            if m.isfile() and PREFS_MEMBER_HINT in m.name:
                xml = t.extractfile(m).read().decode("utf-8", "replace")
                mobj = re.search(
                    rf'<string name="{UUID_KEY}">([0-9a-fA-F-]{{36}})</string>', xml)
                if mobj:
                    return mobj.group(1)
    raise SystemExit(f"UUID key {UUID_KEY} not found in {PREFS_MEMBER_HINT}")


def derive_password(uuid):
    digest = hashlib.sha1((uuid + PKG).encode("utf-8")).digest()
    return "".join(chr((digest[i] & 0xFF) % 94 + 33) for i in range(16))


def extract_member(tar, member, dest):
    with tarfile.open(tar) as t:
        with t.extractfile(t.getmember(member)) as s, open(dest, "wb") as o:
            o.write(s.read())


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    tar = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(tar), "hushed-decrypted.db")

    uuid = read_uuid_from_tar(tar)
    pw = derive_password(uuid)
    print(f"installation UUID : {uuid}   (KEY_DB_INFO_STORE)")
    print(f"derived passphrase: {pw!r}")

    tmp = tempfile.mkdtemp()
    enc = os.path.join(tmp, "enc.db")
    extract_member(tar, ENC_DB_MEMBER, enc)

    con = sqlcipher3.connect(enc)
    cur = con.cursor()
    cur.execute(f"PRAGMA key = '{pw.replace(chr(39), chr(39)*2)}'")
    cur.execute("SELECT count(*) FROM sqlite_master")  # forces key check
    cur.fetchone()

    # record the exact cipher parameters (the concrete RE detail reviewers wanted)
    print("\nSQLCipher parameters:")
    for p in ("cipher_version", "cipher_page_size", "kdf_iter",
              "cipher_kdf_algorithm", "cipher_hmac_algorithm"):
        try:
            cur.execute(f"PRAGMA {p}")
            print(f"  {p:<22} = {cur.fetchone()[0]}")
        except Exception:
            pass

    # export a plaintext copy
    if os.path.exists(out):
        os.remove(out)
    eout = out.replace("'", "''")
    cur.execute(f"ATTACH DATABASE '{eout}' AS plaintext KEY ''")
    cur.execute("SELECT sqlcipher_export('plaintext')")
    cur.execute("DETACH DATABASE plaintext")

    cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [r[0] for r in cur.fetchall()]
    print(f"\nDecrypted {len(tables)} tables -> {out}")
    print(f"  {'table':<26} {'rows':>8}")
    for tb in tables:
        try:
            cur.execute(f'SELECT COUNT(*) FROM "{tb}"')
            print(f"  {tb:<26} {cur.fetchone()[0]:>8}")
        except Exception as e:
            print(f"  {tb:<26} {'?':>8}  ({e})")
    con.close()


if __name__ == "__main__":
    main()
