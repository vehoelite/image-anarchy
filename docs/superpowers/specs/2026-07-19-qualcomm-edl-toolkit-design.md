# Qualcomm EDL Toolkit — Plugin Design Spec

**Date:** 2026-07-19
**Status:** Approved design, pre-implementation
**Plugin id:** `qualcomm_edl_toolkit`

## 1. Goal

Give Image Anarchy first-class **Qualcomm EDL (Emergency Download / 9008) compatibility** — a
built-in, QPST-class communication suite. It connects to any Qualcomm device in EDL, identifies it
via Sahara, uploads a Firehose loader, and performs partition operations, with a headline
**OEM-unlock** capability (patch `devinfo`). Built as a standard Image Anarchy plugin alongside
MTK Toolkit / Fastboot Toolkit / ADB Toolkit.

The design was validated end-to-end against a real device (Walmart **onn 8Core**, SoC khaje /
SM6225) — see [[onn8core-edl-unlock]]. Every step below has been exercised by hand with the
`edlclient` engine.

## 2. Context / proven facts

- EDL entry works via `adb reboot edl` → 9008 (VID 05C6 / PID 9008). No test points required on the
  reference device.
- Sahara **command mode** yields Serial, MSM HWID, and 96-char OEM PK-hash without a loader.
- Firehose loader upload transport works; secure-boot devices reject wrong-key loaders at signature
  validation (whole image uploaded, then USB drop) — must be reported clearly, not as a timeout.
- Windows requires the 9008 interface bound to **WinUSB/libusb** (Zadig today). Engine =
  `edlclient` (bkerler/edl), pure-Python (pyusb/pyserial/pycryptodome), runs on the app's Python.
- Loader-less Sahara probes can leave the PBL stuck; a real EDL re-entry (reset → `adb reboot edl`)
  clears it. The plugin must avoid unnecessary loader-less probes and guide recovery.

## 3. Plugin packaging (follows existing convention)

Mirror `mtk_toolkit`, which vendors its engine via `git_clone` + `requirements`.

**`manifest.json`** (provisional — deps/setup finalized during build, per owner):
```json
{
    "id": "qualcomm_edl_toolkit",
    "name": "Qualcomm EDL Toolkit",
    "version": "0.1.0",
    "description": "QPST-class Qualcomm EDL suite: WinUSB auto-bind, EDL entry, Sahara auto-ident (chip/PK-hash/HWID/serial), Firehose loader match/upload, partition read/write/erase, GPT browser, and OEM unlock via devinfo patch. Powered by edlclient.",
    "author": "Image Anarchy Team",
    "icon": "🔌",
    "license_type": "free",
    "website": "https://github.com/bkerler/edl",
    "support_url": "https://github.com/vehoelite/image-anarchy/issues",
    "min_version": "3.0",
    "git_clone": { "repo": "https://github.com/bkerler/edl.git", "target": "edl" },
    "requirements": ["wheel","setuptools","pyusb","pyserial","docopt","pycryptodome","pycryptodomex","colorama","lxml","requests","capstone","keystone-engine"],
    "bundled_binaries": [
        "https://imageanarchy.com/platform-tools/adb.exe",
        "https://imageanarchy.com/platform-tools/AdbWinApi.dll",
        "https://imageanarchy.com/platform-tools/AdbWinUsbApi.dll",
        "https://imageanarchy.com/platform-tools/libwinpthread-1.dll"
    ],
    "setup_commands": [],
    "enabled": true,
    "remote_capable": false
}
```
**Self-contained `adb`:** the plugin bundles its **own** `adb.exe` + `AdbWinApi.dll` +
`AdbWinUsbApi.dll` + `libwinpthread-1.dll` (same set/hosting as `adb_toolkit`/`fastboot_toolkit`/
`iaabs`). This keeps it independent of the ADB plugin being installed and gives it a working `adb`
when remote capabilities are later enabled. `edl_paths.get_adb()` resolves the plugin's own copy
first, then app/other-plugin copies as fallback.

Open packaging items (deferred to build, per owner): whether edlclient needs `pip install -e .`
in `setup_commands`; hosting `libusb-1.0.dll` and the WinUSB driver package under `bundled_binaries`
(imageanarchy.com/platform-tools/ like the other plugins); bundling a starter loader collection vs.
downloading on demand; flipping `remote_capable` to `true` once USB-over-remote is designed.
`capstone`/`keystone-engine` are optional (edl prints "missing (optional)") — include only if needed.

**Files:** `manifest.json`, `plugin.py`, `description.html`, vendored `edl/` (via git_clone),
bundled `adb.exe` + 3 ADB DLLs, `libusb-1.0.dll`, WinUSB driver package.

## 4. Module boundaries (each independently understandable/testable)

| Module | Does | Depends on |
|---|---|---|
| `edl_engine.py` — `EdlWorker(QThread)` | Thin API over edlclient (`connect`, `identify`, `upload_loader`, firehose `read/write/erase/printgpt`). One op per run; emits `log(str)`, `progress(cur,total)`, `ident(dict)`, `finished(ok,payload)`. All device I/O off the UI thread. | edlclient (`edl/`), engine-dir resolver |
| `driver_manager.py` | Detect the 9008's bound driver; **auto-bind WinUSB** (bundled inf + `pnputil`/libusbK) — built-in Zadig replacement. Detect/verify state; guide if it fails. | Windows PnP, bundled driver |
| `loader_manager.py` | Index loaders `HWID`/`pkhash` → file; **auto-match** to the connected device; bring-your-own import; browse/import a collection. | filesystem, ident dict |
| `edl_paths.py` | `get_edl_dir()` (prioritize plugin dir, like `get_mtkclient_dir()`), adb path, libusb path, sys.path insertion. | — |
| `plugin.py` | `Plugin` class (`get_name/get_icon/get_description/get_version/get_author`, `create_widget(parent_window)`, `on_load/on_unload`) + `PluginWidget(QWidget)` with the tabbed UI. | all of the above |

Threading follows the repo rules: no `QTimer.singleShot(0, …)` from background threads; UI updates
only via `pyqtSignal`; `deleteLater()` + null-out on worker finish; never pass parent to `QThread`.

## 5. UI (QPST-like tabs, anarchy-themed)

- **Device** — "💥 Reboot to EDL" (adb), 9008 detection, driver-state banner + one-click **Bind
  WinUSB**, Sahara **ident readout** (chip / full PK-hash / HWID / serial / secure-boot state).
- **Loaders** — auto-match indicator (matched file or "no match — provide loader"), BYO loader
  picker, collection browser/import.
- **Partitions** — GPT browser; read/dump (P2); write/erase/flash (P3). Dry-run gate on writes.
- **Unlock** — `devinfo` read + `is_unlocked`/`is_unlock_critical` patch, with explicit
  secure-boot-enforced detection and a clear "need OEM-signed loader for PK-hash X" message (P2).
- **Log** — live engine log + export.

## 6. Data flow

UI action → `EdlWorker` (QThread) → edlclient (Sahara/Firehose) → device; results/log/progress
returned via `pyqtSignal` to the UI. Ident results populate the Device tab and feed
`loader_manager` auto-match. Loader upload success transitions the UI into "firehose connected",
enabling partition/unlock actions.

## 7. Phasing

- **Phase 1 — EDL comms foundation (this spec's implementation target):** driver auto-bind → EDL
  entry → Sahara auto-ident → loader match/BYO → upload → firehose handshake, live log. Deliverable:
  connect to any Qualcomm 9008, identify it, load a firehose, confirm firehose comms. Everything we
  proved by hand, productized.
- **Phase 2 — Read + Unlock:** printgpt/GPT browser, partition read/dump/backup, `devinfo`
  OEM-unlock.
- **Phase 3 — Full QPST parity:** partition write/erase/flash, restore, peek/poke, reset,
  NV/EFS browse.

## 8. Error handling (from validated lessons)

- **Secure-boot rejection:** detect the upload → drop pattern and report "loader signature rejected;
  device enforces secure boot, need loader signed for PK-hash `<hash>`" — never a bare timeout.
- **Stuck Sahara:** avoid needless loader-less probes; on a hung handshake, instruct reset → re-enter
  EDL rather than silently retrying.
- **Driver not bound:** detect and offer one-click bind before any op.
- **Per-op timeouts** with cancel; worker cleanup on cancel.

## 9. Testing

- Real onn 8Core validates: EDL entry, Sahara ident, loader auto-match, and the loader-reject path
  (secure-boot messaging).
- Unit tests: `loader_manager` HWID/pkhash matching against the collections; `edl_paths` resolver;
  ident parser on captured Sahara bytes.
- **Dry-run gate** on all write operations until Phase 3 sign-off.

## 10. Non-goals

- No secure-boot bypass / exploit development. The onn 8Core specifically stays blocked until an
  OEM-signed khaje loader is sourced; the plugin is *ready* for it, not a cracker of it.
- No FRP / Google-account bypass. Owner-device bootloader unlock only.
