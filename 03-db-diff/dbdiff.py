#!/usr/bin/env python3
"""Diff SQLite databases between two logical-acquisition captures.

Fills the action-matrix cells: for each action, what rows were CREATED,
what REMOVED, what PERSISTS on device.

Usage:
    python tools/dbdiff.py <before.tar> <after.tar>
    python tools/dbdiff.py captures/com.hushed.release/A00_clean_*/appdata.tar \
                           captures/com.hushed.release/A10_burn_*/appdata.tar

Encrypted DBs (e.g. Hushed SQLCipher hushed.db) can't be opened by stdlib
sqlite3; they are listed as [encrypted/unreadable] so you know to decrypt
first with the derived key. Plaintext DBs (Burner, TextMe, 2ndLine) diff directly.
"""
import sys, os, tarfile, tempfile, sqlite3, re

DB_SUFFIXES = (".db", ".sqlite", ".sqlite3")


def extract_dbs(tar_path, dest):
    """Extract only SQLite DB members to dest, with Windows-safe filenames.

    Returns {logical_relpath: safe_local_path}. Avoids full extraction, which
    fails on Windows for app files containing ':' (e.g. Firebase prefs).
    """
    out = {}
    with tarfile.open(tar_path) as t:
        for m in t.getmembers():
            if m.isfile() and m.name.endswith(DB_SUFFIXES):
                rel = m.name.lstrip("./")
                safe = re.sub(r'[<>:"/\\|?*]', "_", rel)
                local = os.path.join(dest, safe)
                with t.extractfile(m) as src, open(local, "wb") as dst:
                    dst.write(src.read())
                out[rel] = local
    return out


def table_counts(db_path):
    """Return {table: rowcount} or None if the DB is not readable (encrypted)."""
    con = None
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        counts = {}
        for tb in tables:
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{tb}"')
                counts[tb] = cur.fetchone()[0]
            except sqlite3.DatabaseError:
                counts[tb] = None
        return counts
    except sqlite3.DatabaseError:
        return None
    finally:
        if con is not None:
            con.close()


def rel(root, p):
    return os.path.relpath(p, root)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    before_tar, after_tar = sys.argv[1], sys.argv[2]

    with tempfile.TemporaryDirectory() as bdir, tempfile.TemporaryDirectory() as adir:
        bdbs = extract_dbs(before_tar, bdir)
        adbs = extract_dbs(after_tar, adir)

        before = {name: table_counts(path) for name, path in bdbs.items()}
        after = {name: table_counts(path) for name, path in adbs.items()}

        all_dbs = sorted(set(before) | set(after))
        print(f"\n=== DB DIFF ===\nbefore: {before_tar}\nafter : {after_tar}\n")

        for db in all_dbs:
            b, a = before.get(db), after.get(db)
            if b is None and a is None:
                print(f"[encrypted/unreadable] {db}  (decrypt with derived key to diff)")
                continue
            if db not in before:
                print(f"[DB CREATED] {db}")
            elif db not in after:
                print(f"[DB REMOVED] {db}")
            b = b or {}
            a = a or {}
            tables = sorted(set(b) | set(a))
            rows = []
            for tb in tables:
                bc, ac = b.get(tb), a.get(tb)
                if bc != ac:
                    delta = ""
                    if isinstance(bc, int) and isinstance(ac, int):
                        d = ac - bc
                        delta = f"{'+' if d >= 0 else ''}{d}"
                    rows.append((tb, bc, ac, delta))
            if rows:
                print(f"\n{db}")
                print(f"  {'table':<32} {'before':>8} {'after':>8} {'delta':>8}")
                for tb, bc, ac, delta in rows:
                    print(f"  {tb:<32} {str(bc):>8} {str(ac):>8} {delta:>8}")
        print()


if __name__ == "__main__":
    main()
