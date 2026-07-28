#!/usr/bin/env python3
"""Generic TLS-below-pinning capture: spawn any app, hook BoringSSL, map its
network + cloud API surface. Defeats certificate pinning by reading plaintext at
SSL_read/SSL_write (Conscrypt libjavacrypto.so + libssl.so).

    python net_capture.py <package> [seconds]
Saves <pkg>_out.bin / <pkg>_in.bin in the current directory and prints unique
HTTP requests + auth headers. The Frida hook (ssl_hook.js) is loaded from this
script's own folder, so it runs from anywhere.
"""
import frida, sys, time, re, os

os.environ["MSYS_NO_PATHCONV"] = "1"
HERE = os.path.dirname(os.path.abspath(__file__))
PKG = sys.argv[1]
SECS = int(sys.argv[2]) if len(sys.argv) > 2 else 40
TAPS = sys.argv[3] if len(sys.argv) > 3 else ""   # optional "x,y;x,y;..." nav script

out_stream, in_stream = bytearray(), bytearray()


def on(msg, data):
    if msg["type"] == "error":
        print("[err]", msg.get("description")); return
    if msg["type"] != "send":
        return
    p = msg["payload"]
    if p.get("dir") == "log":
        print("[frida]", p.get("msg")); return
    if data is None:
        return
    (out_stream if p["dir"] == "out" else in_stream).extend(data)


def main():
    dev = frida.get_usb_device()
    print(f"[*] spawning {PKG}")
    pid = dev.spawn([PKG])
    s = dev.attach(pid)
    sc = s.create_script(open(os.path.join(HERE, "ssl_hook.js")).read())
    sc.on("message", on)
    sc.load()
    dev.resume(pid)

    time.sleep(12)                       # splash + cold start
    for step in [t for t in TAPS.split(";") if t]:
        x, y = step.split(",")
        os.system(f"adb shell input tap {x} {y}")
        time.sleep(4)
    # generic refresh
    os.system("adb shell input swipe 540 700 540 1500 300")
    print(f"[*] capturing {SECS}s ...")
    time.sleep(SECS)

    open(f"{PKG}_out.bin", "wb").write(bytes(out_stream))
    open(f"{PKG}_in.bin", "wb").write(bytes(in_stream))
    print(f"\n[*] IN={len(in_stream)}B OUT={len(out_stream)}B saved")

    # parse unique HTTP requests (method + path + Host) and auth headers
    reqs = re.findall(rb"(?:GET|POST|PUT|DELETE|PATCH) [^\r\n]+ HTTP/1\.[01]\r\n(?:[^\r\n]+\r\n)*",
                      bytes(out_stream))
    seen, auths = {}, set()
    for req in reqs:
        lines = req.split(b"\r\n")
        line0 = lines[0].decode("latin1")
        host = ""
        for ln in lines[1:]:
            low = ln.lower()
            if low.startswith(b"host:"):
                host = ln.split(b":", 1)[1].strip().decode("latin1")
            if low.startswith((b"authorization:", b"x-auth", b"token", b"cookie:", b"sessionid")):
                auths.add(ln.decode("latin1")[:100])
        method_path = line0.rsplit(" ", 1)[0]
        seen[f"{host}  {method_path}"] = seen.get(f"{host}  {method_path}", 0) + 1

    print(f"\n===== unique HTTP requests ({len(seen)}) =====")
    for k, c in sorted(seen.items()):
        print(f"  x{c:<3} {k}")
    print(f"\n===== auth/token headers ({len(auths)}) =====")
    for a in list(auths)[:12]:
        print("  ", a)
    s.detach()


if __name__ == "__main__":
    main()
