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
    """Rank loaders for a device by (HWID, PK-hash). Tiers, best first:

      1. exact  — same HWID *and* same PK-hash (right SoC + right signing key).
      2. pkhash — same PK-hash only (same signing key → the loader is ACCEPTED by
                  secure boot; the SoC may differ, so the right-SoC one among these
                  is what actually runs — e.g. an LG 8998 device matches every
                  LG-signed loader here regardless of the HWID string in the name).
      3. hwid   — same HWID, different key (right SoC, wrong key: rejected on a
                  secure-boot device, but valid on a non-secure device).

    A loader appears only in its highest tier. Without the pkhash tier, a device
    whose HWID string doesn't literally equal any loader's HWID (common: HWID is
    reported as the JTAG msm_id while loaders are named with the HW_ID1 form)
    would wrongly show "no loader" despite same-key loaders being present.
    """
    hwid = (hwid_hex or "").lower()
    pk16 = (pkhash_hex or "").lower()[:16]
    exact, pk_only, hwid_only = [], [], []
    for ld in loaders:
        h_match = bool(hwid) and ld["hwid"] == hwid
        p_match = bool(pk16) and ld["pkhash"] == pk16
        if h_match and p_match:
            exact.append(ld)
        elif p_match:
            pk_only.append(ld)
        elif h_match:
            hwid_only.append(ld)
    return exact + pk_only + hwid_only


def import_byo(src_path: str, dest_dir: str) -> str:
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, os.path.basename(src_path))
    shutil.copy2(src_path, dest)
    return dest
