"""Path resolution for the Qualcomm EDL Toolkit (prefers the plugin's own files)."""
import os
import sys

_ADB_NAME = "adb.exe" if os.name == "nt" else "adb"
_LIBUSB_NAME = "libusb-1.0.dll" if os.name == "nt" else "libusb-1.0.so"


def plugin_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _app_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    # plugins/<id>/ -> repo root is two levels up
    return os.path.dirname(os.path.dirname(plugin_dir()))


def get_edl_dir():
    candidates = [
        os.path.join(plugin_dir(), "edl"),
        os.path.join(plugin_dir(), "edl", "edl"),
        os.path.join(_app_dir(), "edl"),
    ]
    for c in candidates:
        if os.path.isfile(os.path.join(c, "edl.py")):
            return c
    return None


def get_adb():
    candidates = [
        os.path.join(plugin_dir(), _ADB_NAME),                          # own bundled copy first
        os.path.join(_app_dir(), "plugins", "adb_toolkit", _ADB_NAME),  # ADB plugin fallback
        os.path.join(_app_dir(), "platform-tools", _ADB_NAME),          # app platform-tools
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def get_libusb():
    candidates = [
        os.path.join(plugin_dir(), _LIBUSB_NAME),
        os.path.join(_app_dir(), _LIBUSB_NAME),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None
