#!/usr/bin/env python3
"""Dump Android EncryptedSharedPreferences (androidx.security) at runtime via Frida.

Spawns the target app, hooks the encrypted-prefs getters, and prints/records the
decrypted key/value pairs — surfacing token-looking values (auth/jwt/bearer/session).
The Frida hook (dump_esp.js) is loaded from this script's own folder.

    python esp_dump.py <package> [seconds]
Writes esp_dump.txt in the current directory.
"""
import frida, sys, time, re, os

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = sys.argv[1] if len(sys.argv) > 1 else "com.hushed.release"
SECS = int(sys.argv[2]) if len(sys.argv) > 2 else 18
hits = []


def on(msg, data):
    if msg["type"] == "send":
        p = msg["payload"]
        if p.get("t") == "log":
            print("[frida]", p["m"])
        elif p.get("t") == "esp":
            hits.append((p["tag"], p["k"], p["v"]))
            print(f"[{p['tag']}] {p['k']} = {p['v'][:90]}")
    elif msg["type"] == "error":
        print("[err]", msg.get("description"))


dev = frida.get_usb_device()
pid = dev.spawn([PKG])
s = dev.attach(pid)
sc = s.create_script(open(os.path.join(HERE, "dump_esp.js")).read())
sc.on("message", on)
sc.load()
dev.resume(pid)
time.sleep(SECS)

with open("esp_dump.txt", "w", encoding="utf-8") as f:
    for tag, k, v in hits:
        f.write(f"{tag}\t{k}\t{v}\n")
print(f"\n[*] {len(hits)} pref values dumped -> esp_dump.txt")
tokish = [(k, v) for _, k, v in hits
          if re.search(r'(token|auth|jwt|bearer|access|session|key)', k, re.I) or v.startswith("ey")]
print(f"[*] token-looking keys: {[k for k, _ in tokish]}")
s.detach()
