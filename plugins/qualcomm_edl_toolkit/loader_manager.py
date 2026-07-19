"""Firehose loader indexing and HWID/PK-hash auto-matching."""
import os
import re
import shutil

_NAME_RE = re.compile(r"^([0-9a-fA-F]{16})_([0-9a-fA-F]{16})_", re.ASCII)
_LOADER_EXTS = (".bin", ".elf", ".mbn")


def parse_loader_name(name: str):
    m = _NAME_RE.match(name)
    if not m:
        return None
    return {"hwid": m.group(1).lower(), "pkhash": m.group(2).lower()}


def index_loaders(dirs):
    out = []
    for d in dirs:
        if not d or not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                if not f.lower().endswith(_LOADER_EXTS):
                    continue
                parsed = parse_loader_name(f)
                if parsed is None:
                    continue
                parsed = dict(parsed)
                parsed["path"] = os.path.join(root, f)
                parsed["name"] = f
                out.append(parsed)
    return out


def match(loaders, hwid_hex, pkhash_hex):
    hwid = (hwid_hex or "").lower()
    pk16 = (pkhash_hex or "").lower()[:16]
    exact, hwid_only = [], []
    for ld in loaders:
        if ld["hwid"] != hwid:
            continue
        if ld["pkhash"] == pk16:
            exact.append(ld)
        else:
            hwid_only.append(ld)
    return exact + hwid_only


def import_byo(src_path: str, dest_dir: str) -> str:
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, os.path.basename(src_path))
    shutil.copy2(src_path, dest)
    return dest
