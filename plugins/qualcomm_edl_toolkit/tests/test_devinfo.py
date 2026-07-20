import pytest

from plugins.qualcomm_edl_toolkit import devinfo


def _blob(is_unlocked=0, is_tampered=0, is_unlock_critical=0, charger=1,
          pad_before=0x20, total=0x1000):
    """Synthesize a devinfo partition: leading pad, the struct, trailing zero-fill."""
    body = bytearray(devinfo.MAGIC)
    body += bytes([is_unlocked, is_tampered, is_unlock_critical, charger])
    body += b"\x00" * 64 * 3  # panel + bootloader + radio versions
    body += b"\x01"           # verity_mode
    return b"\xff" * pad_before + bytes(body) + b"\x00" * (total - pad_before - len(body))


def test_find_magic_at_offset():
    data = _blob(pad_before=0x30)
    assert devinfo.find_magic(data) == 0x30


def test_find_magic_absent():
    assert devinfo.find_magic(b"\x00" * 256) == -1


def test_read_state_locked():
    st = devinfo.read_state(_blob(is_unlocked=0, is_unlock_critical=0))
    assert st["found"] and st["is_unlocked"] == 0 and st["is_unlock_critical"] == 0


def test_read_state_already_unlocked():
    st = devinfo.read_state(_blob(is_unlocked=1, is_unlock_critical=1))
    assert st["is_unlocked"] == 1 and st["is_unlock_critical"] == 1


def test_read_state_not_found():
    assert devinfo.read_state(b"\x00" * 128) == {"found": False, "offset": -1}


def test_patch_unlock_sets_both_flags_only():
    data = _blob(is_unlocked=0, is_unlock_critical=0, is_tampered=1)
    out = devinfo.patch_unlock(data)
    st = devinfo.read_state(out)
    assert st["is_unlocked"] == 1 and st["is_unlock_critical"] == 1
    # untouched fields preserved, length unchanged
    assert st["is_tampered"] == 1
    assert len(out) == len(data)
    # exactly the two flag bytes changed
    changes = {o for o, _, _ in devinfo.diff(data, out)}
    assert changes == {devinfo.find_magic(data) + devinfo.OFF_IS_UNLOCKED,
                       devinfo.find_magic(data) + devinfo.OFF_IS_UNLOCK_CRITICAL}


def test_patch_relock_clears_flags():
    data = _blob(is_unlocked=1, is_unlock_critical=1)
    st = devinfo.read_state(devinfo.patch_relock(data))
    assert st["is_unlocked"] == 0 and st["is_unlock_critical"] == 0


def test_patch_unlock_idempotent_when_already_unlocked():
    data = _blob(is_unlocked=1, is_unlock_critical=1)
    assert devinfo.diff(data, devinfo.patch_unlock(data)) == []


def test_patch_raises_without_magic():
    with pytest.raises(ValueError):
        devinfo.patch_unlock(b"\x00" * 256)


def test_diff_reports_offsets():
    a = _blob(is_unlocked=0)
    b = devinfo.patch_unlock(a)
    d = devinfo.diff(a, b)
    off = devinfo.find_magic(a) + devinfo.OFF_IS_UNLOCKED
    assert (off, 0, 1) in d
