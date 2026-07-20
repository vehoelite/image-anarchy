# Qualcomm EDL Toolkit — Phase 2 (devinfo OEM-Unlock) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to finish/validate this plan. Steps use checkbox (`- [ ]`) syntax. **Most of Phase 2 is already built** (see "Status" below) — the remaining work is live validation, gated on sourcing a signed loader.

**Goal:** From a device in EDL (9008) with a matched Firehose loader, read the `devinfo` partition, flip the bootloader unlock flags (`is_unlocked` / `is_unlock_critical`), write it back, verify on-device, and reset — giving a working OEM/bootloader unlock on devices whose fastboot unlock commands are stripped. Fully reversible (Re-lock). Owner-device only.

**Why this exists:** On khaje/bengal devices like the onn 8Core, `fastboot flashing unlock` / `oem unlock` are stripped from the bootloader, and the developer-options OEM-unlock toggle is hidden (`sys.oem_unlock_allowed` blank). The unlock state actually lives in the `devinfo` partition's `device_info` struct (confirmed via `fastboot oem device-info`). Writing that struct directly over Firehose is the only remaining unlock path.

## Status (as of 2026-07-20)

**BUILT + unit-tested (committed):**
- `devinfo.py` — pure `device_info` parse/patch (`find_magic`, `read_state`, `patch_unlock`, `patch_relock`, `diff`). 10 tests in `tests/test_devinfo.py`.
- `plugin.py` — `EdlWorker._devinfo()` op (read | unlock | relock), reusable `_pump()` + `_edl()` helpers, `devinfo_state` signal, **Unlock tab** (state readout + Read/Unlock/Re-lock buttons, confirm dialog + factory-reset warning). Read→patch→write→**verify-before-reset**→reset, with an automatic original-devinfo backup to `plugins/qualcomm_edl_toolkit/backups/`.

**BLOCKED (live path):** requires a Firehose loader signed for PK-hash `ec15a291…` (onn/khaje). No public loader matches; secure boot is enforced (loader upload is rejected → clean stop). The entire code path above is therefore **dead until a loader is imported** — every entry point guards on a matched loader.

## Global Constraints

- Same as Phase 1: Qt threading rules (no parent to QThread; UI only via signals; `deleteLater()` on finish); loader filename convention `<HWID16>_<PKHASH16>_<suffix>.(bin|elf|mbn)`.
- Reference device: onn 8Core — MSM-ID `001b80e1` (khaje/SM6225), Serial `0x60B4DF14`, PK-hash `ec15a2914a2b435a…`, devinfo = mmcblk0p73 (eMMC, LUN 0, ~4 KiB).
- Dev test interpreter: `.venv\Scripts\python.exe` (pytest; **no PyQt6** — GUI is validated by `py_compile` + running IA, not by importing plugin.py in the venv).
- **Safety is non-negotiable:** always back up original devinfo first; never reset unless the readback verifies the intended flag; abort if the `ANDROID-BOOT!` magic is absent (unexpected layout); expect and warn about userdata factory-reset on the lock-state transition.
- No secure-boot bypass, no FRP. Owner-device only.

---

## device_info byte layout (the crux)

Search the partition blob for `MAGIC = b"ANDROID-BOOT!"` (13 bytes); the struct is not guaranteed at offset 0. Flags are at fixed offsets **relative to the magic**:

| Offset (rel) | Field | Unlock value |
|---|---|---|
| +13 | `is_unlocked` | `1` |
| +14 | `is_tampered` | (left as-is) |
| +15 | `is_unlock_critical` | `1` |
| +16 | `charger_screen_enabled` | (left as-is) |

`patch_unlock` sets **only** +13 and +15 to `1` (a two-byte change — verified by `diff()` in tests). `patch_relock` clears them. All other bytes are preserved byte-for-byte.

## Live flow (EdlWorker `_devinfo`, per invocation)

```
edl.py r devinfo  <tmp>            # 1st call: sahara → upload loader → firehose → read
  → devinfo.read_state(tmp)        #   confirm magic; log current flags; back up original
  → (read)  stop here, report state
  → (unlock/relock) devinfo.patch_*(data) → <patched>
edl.py w devinfo  <patched>        # 2nd call: edl.py re-detects firehose mode (no re-sahara)
edl.py r devinfo  <verify>         # 3rd call: read back
  → verify is_unlocked == want; if not → ABORT, do NOT reset
edl.py reset                       # only after verify passes
```

`edl.py` handles the "already in firehose" case (edl.py:367 branches on `mode == "firehose"`), so read/write/reset as separate subprocess calls is safe — no repeated Sahara handshake.

---

## Remaining Tasks

- [ ] **T1 — Source a signed loader.** Obtain a Firehose programmer signed for HWID `001b80e1…` + PK-hash `ec15a291…` (same-ODM Tinno/khaje device, or onn-signed). Import via the Loaders tab; confirm it auto-matches (green). Until then T2–T5 cannot run.
- [ ] **T2 — Live read.** With the matched loader: Unlock tab → **📖 Read devinfo**. Expect `is_unlocked=0` (matches `fastboot oem device-info` on the locked device). Confirm the magic is found and a backup lands in `backups/`. This validates the read/parse path with zero risk.
- [ ] **T3 — Verify struct offsets on real data.** Inspect the backed-up `devinfo_*.bin`: confirm `ANDROID-BOOT!` present and byte +13 == 0 on the locked device. If the real layout differs (some bengal builds vary), adjust `devinfo.py` offsets + tests before any write.
- [ ] **T4 — Live unlock.** **🔓 Unlock** → confirm dialog → write → **on-device verify** flips `is_unlocked` to 1 → reset. Reboot; check `fastboot oem device-info` / `fastboot flashing get_unlock_ability` reports unlocked. Expect a factory-reset on first boot.
- [ ] **T5 — Reversibility.** **🔒 Re-lock** restores `is_unlocked=0`; verify device returns to locked. Confirms the backup/restore story and the owner-device ethos.
- [ ] **T6 — Docs/memory.** Record the confirmed loader source + any offset corrections in `[[onn8core-edl-unlock]]`; update the plugin `description.html` with the Unlock tab; note the once-per-device factory-reset behavior in the PR.

## Risks / Open Questions

- **Loader is the only blocker.** Everything else is built and unit-tested.
- **Struct drift:** if a future device uses a different `device_info` layout, the magic-search + `read_state` guard prevents a blind write (aborts on magic-not-found), but T3 must confirm offsets before T4.
- **AVB / rollback:** flipping devinfo to unlocked should make the bootloader skip verification and allow fastboot flashing; on first unlocked boot Android wipes userdata (security). This is expected, not a bug — warn the user (dialog already does).
- **Verify-before-reset** guarantees we never reboot into an unknown state; a failed verify leaves devinfo as-written but does not reset, so the user can re-read and decide.
