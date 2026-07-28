#!/usr/bin/env python3
"""Spawn Hushed, hook TLS below pinning, capture the bearer token + /items traffic.

Proves token-scoped cloud acquisition: extract the Authorization bearer token and
observe whether the Hushed cloud still returns a message that was secure-deleted
on device.

    python tools/ssl_capture.py [seconds]
"""
import frida, sys, time, re, os

PKG = "com.hushed.release"
SECS = int(sys.argv[1]) if len(sys.argv) > 1 else 45
TARGET_ID = b"69366edabf5da3292886ab73"       # the secure-deleted message
TARGET_TXT = b"Text me some reply"
HOSTS = (b"hushed.com", b"googleapis.com")

out_stream, in_stream = bytearray(), bytearray()
req_lines, tokens = [], []


def on_message(msg, data):
    if msg["type"] != "send" or data is None:
        if msg["type"] == "send" and msg["payload"].get("dir") == "log":
            print("[frida]", msg["payload"]["msg"])
        elif msg["type"] == "error":
            print("[frida-error]", msg.get("description"))
        return
    d = msg["payload"]["dir"]
    (out_stream if d == "out" else in_stream).extend(data)
    # capture request lines + auth headers from outgoing frames
    if d == "out" and (b"HTTP/1" in data or b"Authorization" in data):
        try:
            head = data.split(b"\r\n\r\n", 1)[0].decode("latin1")
        except Exception:
            return
        first = head.split("\r\n")[0]
        host = ""
        for ln in head.split("\r\n"):
            if ln.lower().startswith("host:"):
                host = ln.split(":", 1)[1].strip()
            m = re.match(r"authorization:\s*(.+)", ln, re.I)
            if m:
                tokens.append(m.group(1).strip())
        if any(h in host.encode() for h in HOSTS) or "/v1/users" in first:
            req_lines.append(f"{first}   [Host: {host}]")


def main():
    device = frida.get_usb_device()
    print(f"[*] spawning {PKG} ...")
    pid = device.spawn([PKG])
    session = device.attach(pid)
    script = session.create_script(open("frida/ssl_hook.js").read())
    script.on("message", on_message)
    script.load()
    device.resume(pid)

    # let it cold-start & sync, then drive navigation to force an /items fetch
    time.sleep(13)
    os.system("adb shell input tap 493 396")   # number card -> messages (hits /items)
    time.sleep(5)
    # pull-to-refresh the messages list a few times to force server item sync
    for _ in range(3):
        os.system("adb shell input swipe 540 500 540 1400 300")
        time.sleep(3)
    os.system("adb shell input tap 589 888")    # open a thread
    time.sleep(3)
    os.system("adb shell input swipe 540 700 540 1500 300")   # refresh inside thread
    print(f"[*] capturing for {SECS}s ...")
    time.sleep(SECS)

    print("\n===== authenticated requests seen =====")
    for r in dict.fromkeys(req_lines):
        print("  ", r)

    uniq = list(dict.fromkeys(tokens))
    print(f"\n===== bearer tokens captured: {len(uniq)} =====")
    for t in uniq[:3]:
        print("  ", t[:80], "...")
    if uniq:
        open("frida/token.txt", "w").write(uniq[0])
        print("[*] saved frida/token.txt")

    print("\n===== cloud retention check (incoming stream) =====")
    print(f"  captured IN={len(in_stream)}B  OUT={len(out_stream)}B")
    for label, needle in (("message id", TARGET_ID), ("message text", TARGET_TXT)):
        present = needle in in_stream
        print(f"  secure-deleted {label} present in cloud response: "
              f"{'YES — recovered from cloud' if present else 'no'}")
    open("frida/in.bin", "wb").write(bytes(in_stream))
    open("frida/out.bin", "wb").write(bytes(out_stream))
    print("[*] saved frida/in.bin, frida/out.bin for offline analysis")

    # did ANY hushed.com API request happen? show request lines + header names
    print("\n===== hushed.com requests in outgoing stream =====")
    reqs = re.findall(rb"(?:GET|POST|PUT|DELETE|PATCH) [^\r\n]+HTTP/1\.[01]\r\n(?:[^\r\n]+\r\n)*",
                      bytes(out_stream))
    seen = set()
    for req in reqs:
        if b"hushed" in req.lower():
            line0 = req.split(b"\r\n")[0].decode("latin1")
            hdrs = [h.split(b":")[0].decode("latin1") for h in req.split(b"\r\n")[1:] if b":" in h]
            key = line0
            if key in seen:
                continue
            seen.add(key)
            print("  ", line0)
            print("      headers:", ", ".join(hdrs))
    if not seen:
        print("  (none — app made no Hushed API call in this window)")
    session.detach()


if __name__ == "__main__":
    main()
