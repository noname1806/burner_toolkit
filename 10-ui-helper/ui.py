#!/usr/bin/env python3
"""Deterministic UI helper for driving app experiments via uiautomator.

  python tools/ui.py dump           # list text/clickable nodes with tap coords
  python tools/ui.py tapback        # press BACK
Parses the uiautomator hierarchy so taps hit real element centers, not guesses.
"""
import subprocess, sys, re, xml.etree.ElementTree as ET, os

os.environ["MSYS_NO_PATHCONV"] = "1"


def adb(*args, binary=False):
    return subprocess.run(["adb", *args], capture_output=True).stdout


def dump():
    adb("shell", "uiautomator", "dump", "/sdcard/ui.xml")
    xml = adb("exec-out", "cat", "/sdcard/ui.xml").decode("utf-8", "replace")
    # exec-out is text here (xml) but strip stray CRs just in case
    xml = xml.replace("\r", "")
    root = ET.fromstring(xml)
    rows = []
    for n in root.iter("node"):
        text = n.attrib.get("text", "").strip()
        desc = n.attrib.get("content-desc", "").strip()
        clk = n.attrib.get("clickable", "false")
        rid = n.attrib.get("resource-id", "")
        b = n.attrib.get("bounds", "")
        if not (text or desc):
            continue
        m = re.findall(r"\[(\d+),(\d+)\]", b)
        if len(m) != 2:
            continue
        (x1, y1), (x2, y2) = (int(m[0][0]), int(m[0][1])), (int(m[1][0]), int(m[1][1]))
        cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
        rows.append((cy, cx, clk, text or desc, rid.split("/")[-1]))
    rows.sort()
    for cy, cx, clk, label, rid in rows:
        flag = "TAP" if clk == "true" else "   "
        print(f"{flag} ({cx:>4},{cy:>4})  {label[:52]:<52} {rid}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "dump"
    if cmd == "dump":
        dump()
    elif cmd == "tapback":
        adb("shell", "input", "keyevent", "KEYCODE_BACK")
