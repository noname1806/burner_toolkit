#!/usr/bin/env python3
"""Raw-page carver for SQLCipher-4 databases (freelist / unallocated residue).

`sqlcipher_export` repacks a DB and destroys deleted-record residue. This tool
instead decrypts every physical 4096-byte page in place (AES-256-CBC with the
per-page IV) WITHOUT repacking, so records that were deleted from live tables but
still linger in freeblocks / freelist / unallocated pages become recoverable.

SQLCipher 4 format: salt = first 16 file bytes; key = PBKDF2-HMAC-SHA512(pass,
salt, 256000, 32B); each page = [ciphertext][IV 16B][HMAC-SHA512 64B] (reserve 80),
page 1 ciphertext starts after the 16-byte salt.

Usage:
    python tools/sqlcipher_carve.py <capture appdata.tar> [needle]
Derives the Hushed passphrase from the capture's prefs automatically.
"""
import sys, os, re, tarfile, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PAGE = 4096
RESERVE = 80          # SQLCipher4: IV(16) + HMAC-SHA512(64)
ENC_DB = "./databases/hushed-encrypted.db"
PKG = "com.hushed.release"


def passphrase_from_tar(tar):
    with tarfile.open(tar) as t:
        for m in t.getmembers():
            if m.isfile() and "com.hushed.release_preferences.xml" in m.name:
                xml = t.extractfile(m).read().decode("utf-8", "replace")
                mm = re.search(r'<string name="KEY_DB_INFO_STORE">([0-9a-fA-F-]{36})</string>', xml)
                if mm:
                    uuid = mm.group(1)
                    d = hashlib.sha1((uuid + PKG).encode()).digest()
                    return "".join(chr((d[i] & 0xFF) % 94 + 33) for i in range(16)).encode()
    raise SystemExit("could not derive passphrase from capture prefs")


def read_enc_db(tar):
    with tarfile.open(tar) as t:
        return t.extractfile(t.getmember(ENC_DB)).read()


def decrypt_all_pages(raw, passphrase, reserve=RESERVE):
    salt = raw[:16]
    key = hashlib.pbkdf2_hmac("sha512", passphrase, salt, 256000, dklen=32)
    npages = len(raw) // PAGE
    pages = []
    for i in range(npages):
        pg = raw[i * PAGE:(i + 1) * PAGE]
        start = 16 if i == 0 else 0
        iv = pg[PAGE - reserve: PAGE - reserve + 16]
        ct = pg[start: PAGE - reserve]
        ct = ct[: len(ct) // 16 * 16]
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        pages.append(dec.update(ct) + dec.finalize())
    return pages


def printable_runs(b, minlen=4):
    return re.findall(rb"[\x20-\x7e]{%d,}" % minlen, b)


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    tar = sys.argv[1]
    needle = sys.argv[2].encode() if len(sys.argv) > 2 else None

    raw = read_enc_db(tar)
    pw = passphrase_from_tar(tar)
    pages = decrypt_all_pages(raw, pw)
    blob = b"".join(pages)

    # validate decryption against known live markers
    markers = [b"events", b"conversations", b"accounts", b"Hello abdur"]
    ok = [m for m in markers if m in blob]
    print(f"pages decrypted : {len(pages)}  ({len(raw)} bytes)")
    print(f"decrypt validated by live markers: {[m.decode() for m in ok]}")
    if len(ok) < 2:
        print("!! decryption looks wrong (markers missing) — check reserve/passphrase")
        return

    if needle:
        print(f"\n=== carving for {needle!r} ===")
        hits = [i for i, p in enumerate(pages) if needle in p]
        if hits:
            for i in hits:
                ctx = pages[i]
                idx = ctx.find(needle)
                snippet = ctx[max(0, idx - 40):idx + len(needle) + 40]
                runs = b" | ".join(printable_runs(snippet)[:6]).decode("ascii", "replace")
                print(f"  RECOVERED on physical page {i+1}: ...{runs}...")
            print(f"\n>>> {needle.decode()!r} carved from {len(hits)} page(s) of the "
                  f"ENCRYPTED db despite being hard-deleted from the live table.")
        else:
            print("  needle not found in any decrypted page (fully overwritten/absent)")


if __name__ == "__main__":
    main()
