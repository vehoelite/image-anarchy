"""Pure device_info (devinfo partition) parse/patch for Qualcomm LK bootloaders.

No I/O and no PyQt — unit-testable. The live read/write of the devinfo partition
is done by the EDL worker via edl.py; this module only understands the byte layout
so the "unlock" logic can be tested without hardware.

Layout (Qualcomm Little Kernel, bengal/khaje `app/aboot/aboot.c`):

    struct device_info {
        u8   magic[13];          // "ANDROID-BOOT!"
        bool is_unlocked;        // 13
        bool is_tampered;        // 14
        bool is_unlock_critical; // 15
        bool charger_screen_enabled; // 16
        char display_panel[64];
        char bootloader_version[64];
        char radio_version[64];
        bool verity_mode;
    };

We locate the struct by searching for MAGIC anywhere in the partition blob (the
struct is not always at offset 0), then apply the flag offsets relative to it.
"""

MAGIC = b"ANDROID-BOOT!"          # DEVICE_MAGIC, DEVICE_MAGIC_SIZE = 13

# Byte offsets of the bool flags, relative to the start of MAGIC.
OFF_IS_UNLOCKED = 13
OFF_IS_TAMPERED = 14
OFF_IS_UNLOCK_CRITICAL = 15
OFF_CHARGER_SCREEN = 16


def find_magic(data: bytes) -> int:
    """Offset of the device_info magic in the blob, or -1 if absent."""
    return (data or b"").find(MAGIC)


def read_state(data: bytes) -> dict:
    """Parse the unlock-relevant flags. `found` is False if the magic is missing
    (wrong partition / unexpected layout — caller must NOT write in that case)."""
    i = find_magic(data)
    if i < 0:
        return {"found": False, "offset": -1}
    return {
        "found": True,
        "offset": i,
        "is_unlocked": data[i + OFF_IS_UNLOCKED],
        "is_tampered": data[i + OFF_IS_TAMPERED],
        "is_unlock_critical": data[i + OFF_IS_UNLOCK_CRITICAL],
        "charger_screen_enabled": data[i + OFF_CHARGER_SCREEN],
    }


def _set_flags(data: bytes, unlocked: int, unlock_critical: int) -> bytes:
    i = find_magic(data)
    if i < 0:
        raise ValueError(
            "device_info magic 'ANDROID-BOOT!' not found — wrong partition or layout?")
    b = bytearray(data)
    b[i + OFF_IS_UNLOCKED] = 1 if unlocked else 0
    b[i + OFF_IS_UNLOCK_CRITICAL] = 1 if unlock_critical else 0
    return bytes(b)


def patch_unlock(data: bytes) -> bytes:
    """Copy with is_unlocked = is_unlock_critical = 1 (bootloader unlocked)."""
    return _set_flags(data, 1, 1)


def patch_relock(data: bytes) -> bytes:
    """Copy with is_unlocked = is_unlock_critical = 0 (re-locked) — reversibility."""
    return _set_flags(data, 0, 0)


def diff(before: bytes, after: bytes) -> list:
    """List of (offset, old, new) byte changes — for auditing/logging a patch."""
    n = min(len(before), len(after))
    out = [(k, before[k], after[k]) for k in range(n) if before[k] != after[k]]
    if len(before) != len(after):
        out.append(("len", len(before), len(after)))
    return out
