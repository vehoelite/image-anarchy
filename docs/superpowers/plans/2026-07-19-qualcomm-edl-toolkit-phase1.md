# Qualcomm EDL Toolkit — Phase 1 (Comms Foundation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a loadable Image Anarchy plugin that connects to any Qualcomm device in EDL (9008), auto-identifies it via Sahara (serial/HWID/PK-hash/secure-boot), auto-matches or accepts a Firehose loader, uploads it, and reports firehose handshake — all with a live log.

**Architecture:** New plugin `plugins/qualcomm_edl_toolkit/` mirroring `mtk_toolkit` (engine vendored via `git_clone` of `bkerler/edl` → `edl/`). Pure-logic modules (`edl_paths`, `loader_manager`, `driver_manager`) are unit-tested; device I/O runs off-UI-thread in an `EdlWorker(QThread)` that subprocess-drives the vendored `edl.py` and a bundled `qedl_ident.py` helper, emitting Qt signals. UI is a `PluginWidget` with Device / Loaders / Log tabs.

**Tech Stack:** Python 3, PyQt6, `edlclient` (bkerler/edl: pyusb, pyserial, pycryptodome), bundled `adb.exe`, Windows `pnputil` for WinUSB bind.

## Global Constraints

- Plugin id `qualcomm_edl_toolkit`; manifest carries all 15 required fields in order (id, name, version, description, author, icon, license_type, website, support_url, min_version, git_clone, requirements, bundled_binaries, setup_commands, enabled) — see `C:\Users\jacob\image-anarchy\CLAUDE.md`.
- Qt threading rules: never pass parent to `QThread`; UI updates only via `pyqtSignal` (never `QTimer.singleShot(0, …)` from a bg thread); call `deleteLater()` and null-out the worker on finish.
- Loader filename convention: `<HWID 16 hex>_<PKHASH 16 hex>_<suffix>.(bin|elf|mbn)` (e.g. `001b80e102e80000_8b2d1c830d9d8576_fhprg.bin`). HWID field = 8-byte MSM HW id; first 8 bytes of PK-hash form the pkhash field.
- Reference device (for manual verification): onn 8Core — MSM-ID `001b80e1` (khaje/SM6225), Serial `0x60B4DF14`, PK-hash `ec15a2914a2b435a…` (secure boot enforced; loader upload will be rejected — that rejection path is a valid Phase 1 test).
- Dev test interpreter: `C:\Users\jacob\image-anarchy\.venv\Scripts\python.exe` (has pytest-installable env). Runtime interpreter is Image Anarchy's bundled Python.
- No secure-boot bypass, no FRP. Owner-device only.

---

## File Structure

```
plugins/qualcomm_edl_toolkit/
  manifest.json          # 15-field manifest, git_clone edl, requirements
  plugin.py              # Plugin class + PluginWidget (Device/Loaders/Log tabs) + EdlWorker
  edl_paths.py           # path resolvers (plugin dir, edl dir, adb, libusb)
  loader_manager.py      # loader index + HWID/pkhash auto-match + BYO import
  driver_manager.py      # Windows WinUSB detection + bind
  qedl_ident.py          # bundled subprocess helper: prints JSON ident via edlclient
  description.html       # plugin description
  loaders/               # starter/BYO loader collection (created empty w/ .keep)
  tests/
    test_edl_paths.py
    test_loader_manager.py
    test_driver_manager.py
    test_ident.py
  edl/                   # vendored at install via git_clone (NOT committed)
```

---

### Task 1: Plugin scaffold (loads in Image Anarchy)

**Files:**
- Create: `plugins/qualcomm_edl_toolkit/manifest.json`
- Create: `plugins/qualcomm_edl_toolkit/plugin.py`
- Create: `plugins/qualcomm_edl_toolkit/description.html`
- Create: `plugins/qualcomm_edl_toolkit/loaders/.keep`

**Interfaces:**
- Produces: `class Plugin` with `get_name()->str`, `get_icon()->str`, `get_description()->str`, `get_version()->str`, `get_author()->str`, `create_widget(parent_window)->QWidget`, `on_load()`, `on_unload()`; module-level `manifest=None` set by loader.

- [ ] **Step 1: Write `manifest.json`** (exact 15 fields, in order)

```json
{
    "id": "qualcomm_edl_toolkit",
    "name": "Qualcomm EDL Toolkit",
    "version": "0.1.0",
    "description": "QPST-class Qualcomm EDL suite: WinUSB auto-bind, EDL entry, Sahara auto-ident (chip/PK-hash/HWID/serial), Firehose loader match/upload, and (later) partition R/W + OEM unlock. Powered by edlclient.",
    "author": "Image Anarchy Team",
    "icon": "🔌",
    "license_type": "free",
    "website": "https://github.com/bkerler/edl",
    "support_url": "https://github.com/vehoelite/image-anarchy/issues",
    "min_version": "3.0",
    "git_clone": { "repo": "https://github.com/bkerler/edl.git", "target": "edl" },
    "requirements": ["wheel","setuptools","pyusb","pyserial","docopt","pycryptodome","pycryptodomex","colorama","lxml","requests"],
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

- [ ] **Step 2: Write minimal `plugin.py`** (loads without the engine present)

```python
"""Qualcomm EDL Toolkit — Image Anarchy plugin (Phase 1: comms foundation)."""
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel

manifest = None  # set by PluginManager


class PluginWidget(QWidget):
    def __init__(self, parent_window=None):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("🔌 Qualcomm EDL Toolkit — loading…"))


class Plugin:
    manifest = None

    def get_name(self) -> str:
        return self.manifest.name if self.manifest else "Qualcomm EDL Toolkit"

    def get_icon(self) -> str:
        return self.manifest.icon if self.manifest else "🔌"

    def get_description(self) -> str:
        return self.manifest.description if self.manifest else ""

    def get_version(self) -> str:
        return self.manifest.version if self.manifest else "0.1.0"

    def get_author(self) -> str:
        return self.manifest.author if self.manifest else "Image Anarchy Team"

    def create_widget(self, parent_window) -> QWidget:
        return PluginWidget(parent_window)

    def on_load(self):
        pass

    def on_unload(self):
        pass
```

- [ ] **Step 3: Write `description.html`** (short, anarchy-themed)

```html
<h2>🔌 Qualcomm EDL Toolkit</h2>
<p>Talk to Qualcomm devices in Emergency Download (9008) mode. Auto-bind WinUSB,
enter EDL, identify the chip over Sahara, match and upload a Firehose loader.
Owner-device tool — break the chains on hardware you own.</p>
```

- [ ] **Step 4: Create `loaders/.keep`** (empty file so the dir ships)

Run: `printf '' > plugins/qualcomm_edl_toolkit/loaders/.keep`

- [ ] **Step 5: Manually verify the plugin loads**

Launch Image Anarchy (or the dev entrypoint) and confirm "Qualcomm EDL Toolkit" appears in the plugins list with the 🔌 icon and its widget shows the placeholder label. If it does not appear, check `plugins/plugins_config.json` and the manifest field order per `CLAUDE.md`.
Expected: plugin listed and selectable, no load error in console.

- [ ] **Step 6: Commit**

```bash
git add plugins/qualcomm_edl_toolkit/manifest.json plugins/qualcomm_edl_toolkit/plugin.py plugins/qualcomm_edl_toolkit/description.html plugins/qualcomm_edl_toolkit/loaders/.keep
git commit -m "feat(qedl): scaffold Qualcomm EDL Toolkit plugin"
```

---

### Task 2: `edl_paths.py` — path resolvers

**Files:**
- Create: `plugins/qualcomm_edl_toolkit/edl_paths.py`
- Test: `plugins/qualcomm_edl_toolkit/tests/test_edl_paths.py`

**Interfaces:**
- Produces: `plugin_dir() -> str`, `get_edl_dir() -> str|None` (dir containing `edl.py`), `get_adb() -> str|None`, `get_libusb() -> str|None`. All return absolute paths or None; `get_edl_dir` prefers the plugin's own `edl/`.

- [ ] **Step 1: Write the failing test**

```python
import os
from plugins.qualcomm_edl_toolkit import edl_paths

def test_plugin_dir_is_this_package(tmp_path):
    d = edl_paths.plugin_dir()
    assert os.path.isdir(d)
    assert d.endswith("qualcomm_edl_toolkit")

def test_get_edl_dir_prefers_plugin_edl(monkeypatch, tmp_path):
    fake_plugin = tmp_path / "qualcomm_edl_toolkit"
    (fake_plugin / "edl").mkdir(parents=True)
    (fake_plugin / "edl" / "edl.py").write_text("# edl")
    monkeypatch.setattr(edl_paths, "plugin_dir", lambda: str(fake_plugin))
    assert edl_paths.get_edl_dir() == str(fake_plugin / "edl")

def test_get_adb_prefers_bundled(monkeypatch, tmp_path):
    fake_plugin = tmp_path / "qualcomm_edl_toolkit"
    fake_plugin.mkdir(parents=True)
    (fake_plugin / "adb.exe").write_text("x")
    monkeypatch.setattr(edl_paths, "plugin_dir", lambda: str(fake_plugin))
    assert edl_paths.get_adb() == str(fake_plugin / "adb.exe")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `C:\Users\jacob\image-anarchy\.venv\Scripts\python.exe -m pytest plugins/qualcomm_edl_toolkit/tests/test_edl_paths.py -v`
Expected: FAIL (module/functions not defined).

- [ ] **Step 3: Write `edl_paths.py`**

```python
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
        os.path.join(plugin_dir(), _ADB_NAME),                         # own bundled copy first
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `C:\Users\jacob\image-anarchy\.venv\Scripts\python.exe -m pytest plugins/qualcomm_edl_toolkit/tests/test_edl_paths.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add plugins/qualcomm_edl_toolkit/edl_paths.py plugins/qualcomm_edl_toolkit/tests/test_edl_paths.py
git commit -m "feat(qedl): path resolvers (edl dir, bundled adb, libusb)"
```

---

### Task 3: `loader_manager.py` — loader index + auto-match

**Files:**
- Create: `plugins/qualcomm_edl_toolkit/loader_manager.py`
- Test: `plugins/qualcomm_edl_toolkit/tests/test_loader_manager.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `parse_loader_name(name) -> dict|None` with keys `hwid`, `pkhash`, `path`(set by caller); `index_loaders(dirs) -> list[dict]`; `match(loaders, hwid_hex, pkhash_hex) -> list[dict]` ranked (exact hwid+pkhash first, then hwid-only); `import_byo(src_path, dest_dir) -> str`.
- `hwid_hex`/`pkhash_hex` are lowercase hex strings (hwid 16 chars, pkhash ≥16 chars; match uses first 16 of pkhash).

- [ ] **Step 1: Write the failing test**

```python
import os
from plugins.qualcomm_edl_toolkit import loader_manager as lm

def test_parse_loader_name_valid():
    r = lm.parse_loader_name("001b80e102e80000_8b2d1c830d9d8576_fhprg.bin")
    assert r["hwid"] == "001b80e102e80000"
    assert r["pkhash"] == "8b2d1c830d9d8576"

def test_parse_loader_name_invalid():
    assert lm.parse_loader_name("prog_firehose_ddr.elf") is None

def test_index_and_match(tmp_path):
    for n in ["001b80e102e80000_8b2d1c830d9d8576_fhprg.bin",
              "001b80e100000000_503b13f78c1e5374_fhprg.bin",
              "0009b0e100000000_deadbeef00000000_fhprg.bin"]:
        (tmp_path / n).write_text("ELF")
    loaders = lm.index_loaders([str(tmp_path)])
    assert len(loaders) == 3
    # exact hwid+pkhash beats hwid-only
    ranked = lm.match(loaders, "001b80e102e80000", "8b2d1c830d9d8576ffff")
    assert ranked[0]["pkhash"] == "8b2d1c830d9d8576"
    # hwid-only matches when pkhash differs
    ranked2 = lm.match(loaders, "001b80e102e80000", "ec15a2914a2b435a")
    assert all(x["hwid"] == "001b80e102e80000" for x in ranked2)
    assert len(ranked2) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `C:\Users\jacob\image-anarchy\.venv\Scripts\python.exe -m pytest plugins/qualcomm_edl_toolkit/tests/test_loader_manager.py -v`
Expected: FAIL (module not defined).

- [ ] **Step 3: Write `loader_manager.py`**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `C:\Users\jacob\image-anarchy\.venv\Scripts\python.exe -m pytest plugins/qualcomm_edl_toolkit/tests/test_loader_manager.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add plugins/qualcomm_edl_toolkit/loader_manager.py plugins/qualcomm_edl_toolkit/tests/test_loader_manager.py
git commit -m "feat(qedl): loader indexing + HWID/pkhash auto-match"
```

---

### Task 4: `driver_manager.py` — WinUSB detection + bind

**Files:**
- Create: `plugins/qualcomm_edl_toolkit/driver_manager.py`
- Test: `plugins/qualcomm_edl_toolkit/tests/test_driver_manager.py`

**Interfaces:**
- Produces: `parse_9008_state(pnp_lines: list[str]) -> dict` → `{present: bool, winusb: bool, instance_id: str|None}`; `is_ready() -> dict` (runs PnP query on Windows, returns same shape; non-Windows → present False); `bind_winusb(instance_id: str) -> tuple[bool,str]` (Windows only; drives `pnputil`/bundled inf).
- Detection is parsed from lines shaped `"<Status>|<Service>|<InstanceId>"` (one device per line), so it is testable without hardware.

- [ ] **Step 1: Write the failing test**

```python
from plugins.qualcomm_edl_toolkit import driver_manager as dm

def test_parse_present_winusb():
    lines = ["OK|WinUSB|USB\\VID_05C6&PID_9008\\9&abc&0&1"]
    st = dm.parse_9008_state(lines)
    assert st["present"] and st["winusb"]
    assert st["instance_id"].endswith("0&1")

def test_parse_present_not_winusb():
    lines = ["OK|usbser|USB\\VID_05C6&PID_9008\\9&abc&0&1"]
    st = dm.parse_9008_state(lines)
    assert st["present"] and not st["winusb"]

def test_parse_absent():
    st = dm.parse_9008_state(["OK|WinUSB|USB\\VID_1234&PID_5678\\x"])
    assert not st["present"] and st["instance_id"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `C:\Users\jacob\image-anarchy\.venv\Scripts\python.exe -m pytest plugins/qualcomm_edl_toolkit/tests/test_driver_manager.py -v`
Expected: FAIL (module not defined).

- [ ] **Step 3: Write `driver_manager.py`**

```python
"""Windows WinUSB detection + bind for the Qualcomm 9008 interface."""
import os
import subprocess

VID_PID = "VID_05C6&PID_9008"
_PS_QUERY = (
    "Get-PnpDevice -PresentOnly | "
    "Where-Object { $_.InstanceId -match 'VID_05C6&PID_9008' } | "
    "ForEach-Object { "
    "$svc = ($_ | Get-PnpDeviceProperty -KeyName 'DEVPKEY_Device_Service').Data; "
    "\"$($_.Status)|$svc|$($_.InstanceId)\" }"
)


def parse_9008_state(pnp_lines):
    for raw in pnp_lines:
        line = (raw or "").strip()
        if VID_PID not in line:
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        status, service, instance_id = parts[0], parts[1], parts[2]
        return {
            "present": True,
            "winusb": service.strip().lower() == "winusb",
            "instance_id": instance_id.strip(),
        }
    return {"present": False, "winusb": False, "instance_id": None}


def is_ready():
    if os.name != "nt":
        return {"present": False, "winusb": False, "instance_id": None}
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", _PS_QUERY],
            capture_output=True, text=True, timeout=20,
        )
        return parse_9008_state(out.stdout.splitlines())
    except Exception:
        return {"present": False, "winusb": False, "instance_id": None}


def bind_winusb(instance_id: str):
    """Bind WinUSB to the 9008 interface using the bundled inf via pnputil.
    Returns (ok, message). Windows only. Requires the bundled winusb inf in plugin_dir()."""
    if os.name != "nt":
        return (False, "WinUSB bind is Windows-only")
    from . import edl_paths
    inf = os.path.join(edl_paths.plugin_dir(), "drivers", "winusb_9008.inf")
    if not os.path.isfile(inf):
        return (False, "Bundled WinUSB inf not found (drivers/winusb_9008.inf)")
    try:
        r = subprocess.run(
            ["pnputil", "/add-driver", inf, "/install"],
            capture_output=True, text=True, timeout=60,
        )
        ok = r.returncode == 0
        return (ok, (r.stdout + r.stderr).strip())
    except Exception as e:
        return (False, str(e))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `C:\Users\jacob\image-anarchy\.venv\Scripts\python.exe -m pytest plugins/qualcomm_edl_toolkit/tests/test_driver_manager.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add plugins/qualcomm_edl_toolkit/driver_manager.py plugins/qualcomm_edl_toolkit/tests/test_driver_manager.py
git commit -m "feat(qedl): WinUSB 9008 detection + bind"
```

> **Note for implementer:** sourcing/generating `drivers/winusb_9008.inf` (a generic WinUSB inf targeting `USB\VID_05C6&PID_9008`) is a packaging step done during integration; `bind_winusb` already degrades gracefully when it is absent. The detection path (`parse_9008_state`/`is_ready`) is fully functional without it.

---

### Task 5: `qedl_ident.py` helper + ident parsing

**Files:**
- Create: `plugins/qualcomm_edl_toolkit/qedl_ident.py`
- Create (parse helper): add `parse_ident_json(text) -> dict` to `loader_manager.py` is wrong home; put it in a new `ident.py`.
- Create: `plugins/qualcomm_edl_toolkit/ident.py`
- Test: `plugins/qualcomm_edl_toolkit/tests/test_ident.py`

**Interfaces:**
- `qedl_ident.py` is a standalone script run via the engine's Python: prints one JSON line `{"ok":bool,"serial":str,"hwid":str,"pkhash":str,"secureboot":bool,"error":str}` then exits. It imports `edlclient` from the vendored `edl/`.
- `ident.py` produces `parse_ident_json(text: str) -> dict` returning the same keys with safe defaults; `secureboot` True when `pkhash` is non-empty and not all zeros.

- [ ] **Step 1: Write the failing test for the parser**

```python
from plugins.qualcomm_edl_toolkit import ident

def test_parse_ok():
    line = '{"ok":true,"serial":"0x60b4df14","hwid":"001b80e102350305","pkhash":"ec15a2914a2b435a","secureboot":true,"error":""}'
    r = ident.parse_ident_json("noise\n" + line + "\nmore")
    assert r["ok"] and r["serial"] == "0x60b4df14"
    assert r["hwid"] == "001b80e102350305"
    assert r["secureboot"] is True

def test_parse_zero_pkhash_not_secureboot():
    line = '{"ok":true,"serial":"0x1","hwid":"0009b0e100000000","pkhash":"0000000000000000","secureboot":false,"error":""}'
    assert ident.parse_ident_json(line)["secureboot"] is False

def test_parse_garbage():
    r = ident.parse_ident_json("no json here")
    assert r["ok"] is False and r["error"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `C:\Users\jacob\image-anarchy\.venv\Scripts\python.exe -m pytest plugins/qualcomm_edl_toolkit/tests/test_ident.py -v`
Expected: FAIL (module not defined).

- [ ] **Step 3: Write `ident.py`**

```python
"""Parse the JSON emitted by qedl_ident.py."""
import json
import re

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def _is_zero_hash(pk: str) -> bool:
    pk = (pk or "").replace("0x", "").strip().lower()
    return pk == "" or set(pk) <= {"0"}


def parse_ident_json(text: str) -> dict:
    default = {"ok": False, "serial": "", "hwid": "", "pkhash": "",
               "secureboot": False, "error": ""}
    m = _JSON_RE.search(text or "")
    if not m:
        default["error"] = "no ident JSON in output"
        return default
    try:
        data = json.loads(m.group(0))
    except Exception as e:
        default["error"] = f"bad ident JSON: {e}"
        return default
    out = dict(default)
    out.update({k: data.get(k, default[k]) for k in default})
    if "secureboot" not in data:
        out["secureboot"] = not _is_zero_hash(out["pkhash"])
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `C:\Users\jacob\image-anarchy\.venv\Scripts\python.exe -m pytest plugins/qualcomm_edl_toolkit/tests/test_ident.py -v`
Expected: 3 passed.

- [ ] **Step 5: Write `qedl_ident.py`** (standalone helper; uses vendored edlclient)

```python
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
        from edlclient.Library.usblib import usb_class
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
        version = conn.get("data").version_min if conn.get("data") else 1
        sah.cmd_info(version=version)
        pk = (sah.pkhash or "")
        res.update({
            "ok": True,
            "serial": hex(sah.serial) if isinstance(sah.serial, int) else str(sah.serial or ""),
            "hwid": (sah.hwidstr or "").lower() or (hex(sah.hwid) if isinstance(sah.hwid, int) else str(sah.hwid or "")),
            "pkhash": pk.lower(),
            "secureboot": bool(pk) and set(pk.replace('0x', '')) != {"0"},
        })
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
    print(json.dumps(res))


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Manually verify the helper against the device** (onn 8Core in EDL, WinUSB bound)

Run: `C:\Users\jacob\image-anarchy\.venv\Scripts\python.exe plugins/qualcomm_edl_toolkit/qedl_ident.py`
Expected: JSON line with `"serial":"0x60b4df14"`, hwid containing `1b80e1`, pkhash starting `ec15a291`, `"secureboot":true`. (If the PBL is in a stuck state, force-reset the tablet and `adb reboot edl` first.)

- [ ] **Step 7: Commit**

```bash
git add plugins/qualcomm_edl_toolkit/ident.py plugins/qualcomm_edl_toolkit/qedl_ident.py plugins/qualcomm_edl_toolkit/tests/test_ident.py
git commit -m "feat(qedl): Sahara ident helper + JSON parser"
```

---

### Task 6: `EdlWorker` engine (QThread) inside `plugin.py`

**Files:**
- Modify: `plugins/qualcomm_edl_toolkit/plugin.py` (add `EdlWorker`)

**Interfaces:**
- Consumes: `edl_paths.get_edl_dir/get_adb`, `ident.parse_ident_json`, `driver_manager.is_ready`.
- Produces: `class EdlWorker(QThread)` with signals `log = pyqtSignal(str)`, `progress = pyqtSignal(int, int)`, `ident_ready = pyqtSignal(dict)`, `finished_op = pyqtSignal(bool, str)`; constructor `EdlWorker(op: str, params: dict)` where `op ∈ {"enter_edl","identify","upload_loader"}`; `run()` dispatches.

- [ ] **Step 1: Add `EdlWorker` to `plugin.py`** (imports at top, class below `manifest`)

```python
import os
import subprocess
import sys
from PyQt6.QtCore import QThread, pyqtSignal
from . import edl_paths, ident, driver_manager


class EdlWorker(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    ident_ready = pyqtSignal(dict)
    finished_op = pyqtSignal(bool, str)

    def __init__(self, op: str, params: dict = None):
        super().__init__()  # never pass parent
        self.op = op
        self.params = params or {}

    def _python(self) -> str:
        return sys.executable

    def run(self):
        try:
            if self.op == "enter_edl":
                self._enter_edl()
            elif self.op == "identify":
                self._identify()
            elif self.op == "upload_loader":
                self._upload_loader()
            else:
                self.finished_op.emit(False, f"unknown op {self.op}")
        except Exception as e:
            self.log.emit(f"❌ {type(e).__name__}: {e}")
            self.finished_op.emit(False, str(e))

    def _enter_edl(self):
        adb = edl_paths.get_adb()
        if not adb:
            self.finished_op.emit(False, "adb not found"); return
        self.log.emit("💥 Rebooting device to EDL (9008)…")
        subprocess.run([adb, "reboot", "edl"], capture_output=True, text=True, timeout=20)
        self.finished_op.emit(True, "Sent reboot to EDL. Waiting for 9008…")

    def _identify(self):
        st = driver_manager.is_ready()
        if not st["present"]:
            self.finished_op.emit(False, "No 9008 device present"); return
        if os.name == "nt" and not st["winusb"]:
            self.finished_op.emit(False, "9008 present but not on WinUSB — bind driver first"); return
        helper = os.path.join(edl_paths.plugin_dir(), "qedl_ident.py")
        self.log.emit("🔎 Reading Sahara identity…")
        r = subprocess.run([self._python(), helper], capture_output=True, text=True, timeout=60)
        info = ident.parse_ident_json(r.stdout + r.stderr)
        if not info["ok"]:
            self.finished_op.emit(False, info["error"] or "ident failed"); return
        self.log.emit(f"✅ Serial {info['serial']}  HWID {info['hwid']}")
        self.log.emit(f"   PK-hash {info['pkhash'][:16]}…  secure-boot={info['secureboot']}")
        self.ident_ready.emit(info)
        self.finished_op.emit(True, "Identified")

    def _upload_loader(self):
        edl_dir = edl_paths.get_edl_dir()
        loader = self.params.get("loader")
        if not edl_dir:
            self.finished_op.emit(False, "vendored edl/ not found"); return
        if not loader or not os.path.isfile(loader):
            self.finished_op.emit(False, "no loader selected"); return
        self.log.emit(f"⬆️  Uploading loader {os.path.basename(loader)} …")
        proc = subprocess.Popen(
            [self._python(), os.path.join(edl_dir, "edl.py"),
             "printgpt", f"--loader={loader}", "--memory=eMMC", "--lun=0"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=edl_dir,
        )
        dropped = False
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                self.log.emit(line)
            if "No such device" in line or "Pipe error" in line:
                dropped = True
        proc.wait()
        if dropped:
            self.finished_op.emit(
                False,
                "Loader rejected — device dropped during read. Secure boot is enforced; "
                "you need a Firehose loader signed for this device's PK-hash.")
        else:
            self.finished_op.emit(True, "Firehose loader accepted")
```

- [ ] **Step 2: Smoke-test import** (no device needed)

Run: `C:\Users\jacob\image-anarchy\.venv\Scripts\python.exe -c "import importlib.util,sys; sys.path.insert(0,'plugins'); import qualcomm_edl_toolkit.plugin as p; print('EdlWorker' in dir(p))"`
Expected: prints `True`.

- [ ] **Step 3: Commit**

```bash
git add plugins/qualcomm_edl_toolkit/plugin.py
git commit -m "feat(qedl): EdlWorker engine (enter EDL, identify, upload loader)"
```

---

### Task 7: `PluginWidget` UI (Device / Loaders / Log tabs) + wiring

**Files:**
- Modify: `plugins/qualcomm_edl_toolkit/plugin.py` (replace placeholder `PluginWidget`)

**Interfaces:**
- Consumes: `EdlWorker` signals; `loader_manager.index_loaders/match/import_byo`; `driver_manager.is_ready/bind_winusb`; `edl_paths.plugin_dir`.
- Produces: functional `PluginWidget(parent_window)` with tabs and a live log; auto-matches loaders on `ident_ready`.

- [ ] **Step 1: Replace `PluginWidget`** with the tabbed UI

```python
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QGroupBox, QLabel,
    QPushButton, QTextEdit, QFormLayout, QFileDialog, QListWidget
)


class PluginWidget(QWidget):
    def __init__(self, parent_window=None):
        super().__init__()
        self.parent_window = parent_window
        self.worker = None
        self.current_ident = None

        root = QVBoxLayout(self)
        self.tabs = QTabWidget()
        root.addWidget(self.tabs)

        # --- Device tab ---
        dev = QWidget(); dl = QVBoxLayout(dev)
        row = QHBoxLayout()
        self.btn_edl = QPushButton("💥 Reboot to EDL")
        self.btn_bind = QPushButton("🔧 Bind WinUSB")
        self.btn_ident = QPushButton("🔎 Identify")
        for b in (self.btn_edl, self.btn_bind, self.btn_ident):
            row.addWidget(b)
        dl.addLayout(row)
        self.driver_lbl = QLabel("Driver: unknown")
        dl.addWidget(self.driver_lbl)
        box = QGroupBox("Device (Sahara)"); form = QFormLayout(box)
        self.lbl_serial = QLabel("—"); self.lbl_hwid = QLabel("—")
        self.lbl_pk = QLabel("—"); self.lbl_sb = QLabel("—")
        form.addRow("Serial:", self.lbl_serial)
        form.addRow("HWID:", self.lbl_hwid)
        form.addRow("PK-hash:", self.lbl_pk)
        form.addRow("Secure boot:", self.lbl_sb)
        dl.addWidget(box); dl.addStretch()
        self.tabs.addTab(dev, "Device")

        # --- Loaders tab ---
        ld = QWidget(); ll = QVBoxLayout(ld)
        self.match_lbl = QLabel("No device identified yet.")
        ll.addWidget(self.match_lbl)
        self.loader_list = QListWidget(); ll.addWidget(self.loader_list)
        lr = QHBoxLayout()
        self.btn_import = QPushButton("📥 Import Loader…")
        self.btn_upload = QPushButton("⬆️ Upload Selected")
        lr.addWidget(self.btn_import); lr.addWidget(self.btn_upload)
        ll.addLayout(lr)
        self.tabs.addTab(ld, "Loaders")

        # --- Log tab ---
        lg = QWidget(); gl = QVBoxLayout(lg)
        self.logbox = QTextEdit(); self.logbox.setReadOnly(True)
        gl.addWidget(self.logbox)
        self.tabs.addTab(lg, "Log")

        self.btn_edl.clicked.connect(lambda: self._run("enter_edl"))
        self.btn_ident.clicked.connect(lambda: self._run("identify"))
        self.btn_bind.clicked.connect(self._bind)
        self.btn_import.clicked.connect(self._import_loader)
        self.btn_upload.clicked.connect(self._upload_selected)

        self._refresh_driver()
        self._refresh_loaders([])

    # --- helpers ---
    def _log(self, msg):
        self.logbox.append(msg)

    def _refresh_driver(self):
        st = driver_manager.is_ready()
        if not st["present"]:
            self.driver_lbl.setText("Driver: no 9008 device present")
        elif st["winusb"]:
            self.driver_lbl.setText("Driver: ✅ WinUSB bound")
        else:
            self.driver_lbl.setText("Driver: ⚠️ 9008 present, NOT WinUSB — bind it")

    def _refresh_loaders(self, ranked):
        self.loader_list.clear()
        base = [os.path.join(edl_paths.plugin_dir(), "loaders")]
        allld = loader_manager.index_loaders(base)
        show = ranked if ranked else allld
        for ld in show:
            self.loader_list.addItem(f"{ld['name']}   [{ld['hwid']} / {ld['pkhash']}]")
        self._loaders_cache = show

    def _run(self, op, params=None):
        if self.worker is not None:
            self._log("⏳ Busy…"); return
        self.worker = EdlWorker(op, params)
        self.worker.log.connect(self._log)
        self.worker.ident_ready.connect(self._on_ident)
        self.worker.finished_op.connect(self._on_finished)
        self.worker.start()

    def _on_finished(self, ok, msg):
        self._log(("✅ " if ok else "❌ ") + msg)
        self._refresh_driver()
        if self.worker:
            self.worker.deleteLater()
            self.worker = None

    def _on_ident(self, info):
        self.current_ident = info
        self.lbl_serial.setText(info["serial"] or "—")
        self.lbl_hwid.setText(info["hwid"] or "—")
        self.lbl_pk.setText((info["pkhash"] or "—"))
        self.lbl_sb.setText("yes" if info["secureboot"] else "no")
        base = [os.path.join(edl_paths.plugin_dir(), "loaders")]
        ranked = loader_manager.match(loader_manager.index_loaders(base),
                                      info["hwid"], info["pkhash"])
        if ranked:
            self.match_lbl.setText(f"✅ {len(ranked)} candidate loader(s) matched.")
        else:
            self.match_lbl.setText(
                f"⚠️ No loader for PK-hash {info['pkhash'][:16]}… — import a signed loader.")
        self._refresh_loaders(ranked)

    def _bind(self):
        st = driver_manager.is_ready()
        if not st["present"]:
            self._log("No 9008 device to bind."); return
        ok, msg = driver_manager.bind_winusb(st["instance_id"])
        self._log(("✅ " if ok else "❌ ") + "WinUSB bind: " + msg)
        self._refresh_driver()

    def _import_loader(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Firehose loader", "",
                                              "Loaders (*.bin *.elf *.mbn)")
        if not path:
            return
        dest = loader_manager.import_byo(path, os.path.join(edl_paths.plugin_dir(), "loaders"))
        self._log(f"📥 Imported {os.path.basename(dest)}")
        ranked = loader_manager.match(
            loader_manager.index_loaders([os.path.join(edl_paths.plugin_dir(), "loaders")]),
            self.current_ident["hwid"] if self.current_ident else "",
            self.current_ident["pkhash"] if self.current_ident else "")
        self._refresh_loaders(ranked)

    def _upload_selected(self):
        idx = self.loader_list.currentRow()
        if idx < 0 or idx >= len(getattr(self, "_loaders_cache", [])):
            self._log("Select a loader first."); return
        loader = self._loaders_cache[idx]["path"]
        self._run("upload_loader", {"loader": loader})
```

- [ ] **Step 2: Smoke-test widget construction** (offscreen Qt, no device)

Run:
```
QT_QPA_PLATFORM=offscreen C:\Users\jacob\image-anarchy\.venv\Scripts\python.exe -c "import sys; sys.path.insert(0,'plugins'); from PyQt6.QtWidgets import QApplication; import qualcomm_edl_toolkit.plugin as p; app=QApplication([]); w=p.PluginWidget(); print('tabs', w.tabs.count())"
```
Expected: prints `tabs 3` with no exception.

- [ ] **Step 3: Manual end-to-end verification** (onn 8Core)

1. Load the plugin in Image Anarchy; open Qualcomm EDL Toolkit.
2. With the device in Android + USB debugging, click **Reboot to EDL** → device enumerates 9008.
3. If driver banner shows "NOT WinUSB", click **Bind WinUSB** (or run the plugin as admin) until it shows ✅.
4. Click **Identify** → Device tab fills in Serial `0x60b4df14`, HWID `…1b80e1…`, PK-hash `ec15a291…`, Secure boot `yes`; Loaders tab shows "No loader for PK-hash ec15a291…".
5. Import the Moto G52 khaje loader and **Upload Selected** → Log streams the upload and ends with the secure-boot rejection message (expected for onn).

Expected: each step behaves as described; no UI freeze (all work off-thread); rejection reported clearly, not as a hang.

- [ ] **Step 4: Commit**

```bash
git add plugins/qualcomm_edl_toolkit/plugin.py
git commit -m "feat(qedl): Device/Loaders/Log UI with auto-match + live log"
```

---

## Self-Review

- **Spec coverage:** Phase-1 items from the spec — driver auto-bind (Task 4/7), EDL entry (Task 6/7), Sahara auto-ident (Task 5/6/7), loader match/BYO (Task 3/7), loader upload + firehose handshake/rejection (Task 6/7), live log (Task 7), packaging/manifest with bundled adb (Task 1). Partition R/W, GPT browser, and `devinfo` OEM-unlock are correctly **out of scope** (Phase 2/3).
- **Placeholders:** none — every code step has full code; the only deferred artifact is `drivers/winusb_9008.inf` (a packaging asset) and `bind_winusb` degrades gracefully without it, with an explicit implementer note.
- **Type consistency:** ident dict keys (`ok/serial/hwid/pkhash/secureboot/error`) are identical across `qedl_ident.py`, `ident.parse_ident_json`, `EdlWorker._identify`, and `PluginWidget._on_ident`. Loader dict keys (`hwid/pkhash/path/name`) consistent across `loader_manager` and UI. `EdlWorker` signal names (`log/progress/ident_ready/finished_op`) match every connection in `PluginWidget`.

## Implementation Findings (2026-07-19, validated on onn 8Core)

- **Plugin loads, "Reboot to EDL" (adb) works live** in Image Anarchy. Detection correctly reports
  driver state. All 13 unit tests green.
- **Serial mode rejected.** edl `--serial --portname=COMxx` over Qualcomm's `qcusbser` COM port
  reaches "Mode detected: sahara" but the initial Sahara HELLO comes back empty/mis-framed, so
  command-mode identity reads never complete (hangs). Over **WinUSB**, the same reads succeed
  cleanly. Conclusion: WinUSB is required; serial is not a viable substitute for this device.
- **WinUSB auto-bind needs libwdi, not pnputil.** `pnputil /add-driver <unsigned>.inf /install`
  is rejected ("does not contain digital signature information"), and Qualcomm's signed `qcusbser`
  out-ranks a generic WinUSB inf on re-enumeration. The robust one-click bind must bundle **libwdi
  (`wdi-simple.exe`)** — the self-signing + force-install engine Zadig uses. Until then,
  `bind_winusb` short-circuits when already bound and otherwise returns actionable Zadig guidance.
  **→ Phase 1.1 task: bundle libwdi and drive it from `driver_manager.bind_winusb`.**

## Notes for Phase 2/3

Phase 2 adds `printgpt`/GPT browser + partition read/dump + `devinfo` OEM-unlock (`is_unlocked`/`is_unlock_critical`) once a loader that authenticates is available. Phase 3 adds write/erase/flash/restore + peek/poke behind a dry-run gate. The onn 8Core stays blocked until an OEM-signed khaje loader is sourced — the plugin is ready for it.
