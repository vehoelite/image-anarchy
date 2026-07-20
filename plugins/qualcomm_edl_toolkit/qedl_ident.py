"""Standalone EDL ident helper. Prints one JSON line with serial/hwid/pkhash.
Run by EdlWorker as: <python> qedl_ident.py  (with the vendored edl/ on sys.path)."""
import json
import os
import sys


def _add_edl_to_path():
    here = os.path.dirname(os.path.abspath(__file__))
    for c in (os.path.join(here, "edl"), os.path.join(here, "edl", "edl")):
        if os.path.isfile(os.path.join(c, "edl.py")):
            sys.path.insert(0, c)
            return True
    return False


def main():
    res = {"ok": False, "serial": "", "hwid": "", "pkhash": "",
           "secureboot": False, "error": ""}
    if not _add_edl_to_path():
        res["error"] = "vendored edl/ not found"
        print(json.dumps(res)); return
    try:
        import logging
        from edlclient.Library.Connection.usblib import usb_class
        from edlclient.Library.sahara import sahara
        cdc = usb_class(portconfig=[[0x05c6, 0x9008, -1]], loglevel=logging.WARNING)
        if not cdc.connect():
            res["error"] = "no 9008 device (bind WinUSB / enter EDL)"
            print(json.dumps(res)); return
        sah = sahara(cdc, loglevel=logging.WARNING)
        conn = sah.connect()
        if conn.get("mode") != "sahara":
            res["error"] = f"unexpected mode: {conn.get('mode')}"
            print(json.dumps(res)); return
        data = conn.get("data")
        version = getattr(data, "version_min", 1) if data is not None else 1
        sah.cmd_info(version=version)
        pk = (sah.pkhash or "")
        res.update({
            "ok": True,
            "serial": hex(sah.serial) if isinstance(sah.serial, int) else str(sah.serial or ""),
            "hwid": (sah.hwidstr or "").lower() or (hex(sah.hwid) if isinstance(sah.hwid, int) else str(sah.hwid or "")),
            "pkhash": pk.lower(),
            "secureboot": bool(pk) and set(pk.replace("0x", "")) != {"0"},
        })
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
    print(json.dumps(res))


if __name__ == "__main__":
    main()
