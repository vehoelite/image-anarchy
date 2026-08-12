# Dump Surgeon Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "🔪 Dump Surgeon" tab to Image Anarchy with four offline MTK/eMMC dump-repair tools (trim partition, build EMI header, un-mangle CRLF, inspect dump).

**Architecture:** Pure-Python logic lives in a new sibling module `mtk_dump_tools.py` (no Qt, unit-tested). `image_anarchy.py` imports it and adds one top-level tab containing an inner `QTabWidget` of four tools; multi-GB ops run in a `QThread` worker that reports via `pyqtSignal`.

**Tech Stack:** Python 3 stdlib (`struct`/`int.from_bytes`, `hashlib`, `os`), PyQt6 (existing), `unittest` (stdlib) for tests.

## Global Constraints

- No new third-party dependencies — stdlib only in `mtk_dump_tools.py`.
- `mtk_dump_tools.py` MUST NOT import PyQt/GUI — keep it pure so tests run without Qt.
- All tools are offline file operations — no device/USB/network I/O.
- Never overwrite the input file; outputs go to new paths.
- Test interpreter on this machine: `./python_embedded/python.exe` (fallback: `./mtkclient-2.1.2/venv/Scripts/python.exe`). Referred to below as `PY`.
- Work happens on branch `feature/dump-surgeon` (already created; spec + .gitattributes already committed).

---

## File Structure

- Create: `mtk_dump_tools.py` — `MtkDumpTools` class (4 static methods), pure logic.
- Create: `tests/test_mtk_dump_tools.py` — unittest suite with synthetic fixtures.
- Modify: `image_anarchy.py` — import `MtkDumpTools`, add `_DumpSurgeonWorker(QThread)`, add `create_dump_surgeon_tab()`, register tab via `addTab`.

---

### Task 1: `unmangle_crlf` — lossless LF↔CRLF repair

**Files:**
- Create: `mtk_dump_tools.py`
- Test: `tests/test_mtk_dump_tools.py`

**Interfaces:**
- Produces: `MtkDumpTools.unmangle_crlf(data: bytes) -> tuple[bytes, dict]`. Report keys: `mangled: bool`, `crlf_ratio: float`, `bytes_removed: int`, `size_before: int`, `size_after: int`, `aligned_before: bool`, `aligned_after: bool`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_mtk_dump_tools.py
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mtk_dump_tools import MtkDumpTools


class TestUnmangleCrlf(unittest.TestCase):
    def test_roundtrip_recovers_original(self):
        original = bytes(range(256)) * 400  # contains many 0x0a bytes
        mangled = original.replace(b"\x0a", b"\x0d\x0a")  # insert CR before each LF
        recovered, rep = MtkDumpTools.unmangle_crlf(mangled)
        self.assertEqual(recovered, original)
        self.assertTrue(rep["mangled"])
        self.assertEqual(rep["bytes_removed"], original.count(b"\x0a"))
        self.assertEqual(rep["size_after"], len(original))

    def test_clean_binary_not_flagged(self):
        clean = bytes([0xAB, 0xCD] * 5000)  # no 0x0a at all
        recovered, rep = MtkDumpTools.unmangle_crlf(clean)
        self.assertEqual(recovered, clean)
        self.assertFalse(rep["mangled"])
        self.assertEqual(rep["bytes_removed"], 0)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./python_embedded/python.exe tests/test_mtk_dump_tools.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mtk_dump_tools'`

- [ ] **Step 3: Write minimal implementation**

```python
# mtk_dump_tools.py
"""Dump Surgeon — offline MTK/eMMC dump repair & inspection (pure stdlib, no Qt)."""
import hashlib


class MtkDumpTools:
    BLOADER = b"MTK_BLOADER_INFO_v"

    @staticmethod
    def unmangle_crlf(data):
        data = bytes(data)
        sample = data[: 1 << 20]
        lf = sample.count(b"\x0a")
        crlf = sample.count(b"\x0d\x0a")
        ratio = (crlf / lf) if lf else 0.0
        recovered = data.replace(b"\x0d\x0a", b"\x0a")
        report = {
            "mangled": lf > 0 and ratio >= 0.98,
            "crlf_ratio": round(ratio, 4),
            "bytes_removed": len(data) - len(recovered),
            "size_before": len(data),
            "size_after": len(recovered),
            "aligned_before": len(data) % 512 == 0,
            "aligned_after": len(recovered) % 512 == 0,
        }
        return recovered, report
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./python_embedded/python.exe tests/test_mtk_dump_tools.py -v`
Expected: PASS (2 tests in TestUnmangleCrlf)

- [ ] **Step 5: Commit**

```bash
git add mtk_dump_tools.py tests/test_mtk_dump_tools.py
git commit -m "feat(dump-surgeon): lossless CRLF un-mangle with detection"
```

---

### Task 2: `trim_partition` — strip padding / trim to size

**Files:**
- Modify: `mtk_dump_tools.py`
- Test: `tests/test_mtk_dump_tools.py`

**Interfaces:**
- Produces: `MtkDumpTools.trim_partition(data: bytes, target_size: int | None = None) -> tuple[bytes, dict]`. Auto mode report keys: `mode="auto"`, `size_before`, `size_after`, `bytes_removed`, `content_end`, `padding_byte`, `sector_aligned`. Explicit mode keys: `mode="explicit"`, `size_before`, `size_after`, `bytes_removed`, `cut_real_content: bool`.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_mtk_dump_tools.py
class TestTrimPartition(unittest.TestCase):
    def test_auto_strips_padding_to_sector(self):
        data = b"REALDATA" + b"\xff" * 2000  # 8 + 2000 = 2008 bytes
        trimmed, rep = MtkDumpTools.trim_partition(data)
        self.assertEqual(rep["mode"], "auto")
        self.assertEqual(rep["content_end"], 8)
        self.assertEqual(len(trimmed), 512)          # 8 rounded up to next 512
        self.assertTrue(rep["sector_aligned"])
        self.assertEqual(trimmed[:8], b"REALDATA")

    def test_explicit_size_flags_content_cut(self):
        data = b"ABCD" + b"\xff" * 4
        trimmed, rep = MtkDumpTools.trim_partition(data, target_size=4)
        self.assertEqual(trimmed, b"ABCD")
        self.assertFalse(rep["cut_real_content"])
        trimmed2, rep2 = MtkDumpTools.trim_partition(b"ABCDEF", target_size=3)
        self.assertEqual(trimmed2, b"ABC")
        self.assertTrue(rep2["cut_real_content"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./python_embedded/python.exe tests/test_mtk_dump_tools.py -v`
Expected: FAIL — `AttributeError: type object 'MtkDumpTools' has no attribute 'trim_partition'`

- [ ] **Step 3: Write minimal implementation**

```python
# add method to MtkDumpTools in mtk_dump_tools.py
    @staticmethod
    def trim_partition(data, target_size=None):
        data = bytes(data)
        if target_size is not None:
            trimmed = data[:target_size]
            cut = (target_size < len(data)
                   and any(b not in (0x00, 0xFF) for b in data[target_size:]))
            return trimmed, {
                "mode": "explicit", "size_before": len(data),
                "size_after": len(trimmed), "bytes_removed": len(data) - len(trimmed),
                "cut_real_content": cut,
            }
        last = len(data) - 1
        while last >= 0 and data[last] in (0x00, 0xFF):
            last -= 1
        content_end = last + 1
        sector = 512
        size = ((content_end + sector - 1) // sector) * sector
        size = min(size, len(data))
        trimmed = data[:size]
        pad = data[content_end] if content_end < len(data) else None
        return trimmed, {
            "mode": "auto", "size_before": len(data), "size_after": len(trimmed),
            "bytes_removed": len(data) - len(trimmed), "content_end": content_end,
            "padding_byte": (f"0x{pad:02x}" if pad is not None else None),
            "sector_aligned": len(trimmed) % 512 == 0,
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./python_embedded/python.exe tests/test_mtk_dump_tools.py -v`
Expected: PASS (all TestTrimPartition + prior tests)

- [ ] **Step 5: Commit**

```bash
git add mtk_dump_tools.py tests/test_mtk_dump_tools.py
git commit -m "feat(dump-surgeon): trim partition (auto-padding + explicit size)"
```

---

### Task 3: `build_emi` — extract mtkclient-ready EMI block

**Files:**
- Modify: `mtk_dump_tools.py`
- Test: `tests/test_mtk_dump_tools.py`

**Interfaces:**
- Produces: `MtkDumpTools.build_emi(data: bytes) -> tuple[bytes | None, dict]`. Success report keys: `ok=True`, `version: str`, `emi_offset: int`, `emi_length: int`, `length_field_offset: int`, `parses: bool`. Failure: `ok=False`, `reason: str`, optional `version`.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_mtk_dump_tools.py
import struct

def _make_preloader(version=b"38", emi_len=600, pre=64):
    head = b"MTK_BLOADER_INFO_v" + version + b"\x00\x00"
    block = head + b"\xAA" * (emi_len - len(head))     # payload won't collide with length value
    assert len(block) == emi_len
    return b"\x00" * pre + block + struct.pack("<I", emi_len) + b"\x00" * 32

class TestBuildEmi(unittest.TestCase):
    def test_extracts_block_and_version(self):
        data = _make_preloader(emi_len=600, pre=64)
        emi, rep = MtkDumpTools.build_emi(data)
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["version"], "38")
        self.assertEqual(rep["emi_length"], 600)
        self.assertTrue(rep["parses"])
        self.assertTrue(emi.startswith(b"MTK_BLOADER_INFO_v38"))

    def test_no_marker_returns_none(self):
        emi, rep = MtkDumpTools.build_emi(b"\x00" * 4096)
        self.assertIsNone(emi)
        self.assertFalse(rep["ok"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./python_embedded/python.exe tests/test_mtk_dump_tools.py -v`
Expected: FAIL — `AttributeError: ... has no attribute 'build_emi'`

- [ ] **Step 3: Write minimal implementation**

```python
# add method to MtkDumpTools in mtk_dump_tools.py
    @staticmethod
    def build_emi(data):
        data = bytes(data)
        bld = MtkDumpTools.BLOADER
        b = data.find(bld)
        if b == -1:
            return None, {"ok": False, "reason": "no MTK_BLOADER_INFO_v marker found"}
        ver = data[b + len(bld): b + len(bld) + 2].rstrip(b"\x00").decode("latin1", "replace")
        found = None
        for p in range(b + 0x200, min(b + 0x4000, len(data) - 4)):
            if int.from_bytes(data[p:p + 4], "little") == (p - b):
                found = p
                break
        if found is None:
            return None, {"ok": False, "reason": "no EMI length field found after marker", "version": ver}
        block = data[b:found]
        return block, {
            "ok": True, "version": ver, "emi_offset": b, "emi_length": len(block),
            "length_field_offset": found, "parses": block.startswith(bld),
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./python_embedded/python.exe tests/test_mtk_dump_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add mtk_dump_tools.py tests/test_mtk_dump_tools.py
git commit -m "feat(dump-surgeon): build mtkclient-ready EMI block from preloader"
```

---

### Task 4: `inspect_dump` — verdict + report

**Files:**
- Modify: `mtk_dump_tools.py`
- Test: `tests/test_mtk_dump_tools.py`

**Interfaces:**
- Consumes: `build_emi`, `unmangle_crlf` (same class).
- Produces: `MtkDumpTools.inspect_dump(data: bytes) -> dict`. Keys: `size`, `aligned_512`, `aligned_4k`, `all_zero`, `nonzero_bytes`, `sha256`, `head_magic` (str|None), `bloader_version` (str|None), `has_emi` (bool), `emi_length` (int, optional), `crlf_mangled` (bool), `verdict` (str), `summary` (str).

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_mtk_dump_tools.py
class TestInspectDump(unittest.TestCase):
    def test_wiped_detected(self):
        rep = MtkDumpTools.inspect_dump(b"\x00" * 4096)
        self.assertTrue(rep["all_zero"])
        self.assertEqual(rep["verdict"], "wiped (all zeros)")

    def test_mangled_detected(self):
        original = bytes(range(256)) * 400
        mangled = original.replace(b"\x0a", b"\x0d\x0a")
        rep = MtkDumpTools.inspect_dump(mangled)
        self.assertTrue(rep["crlf_mangled"])
        self.assertEqual(rep["verdict"], "crlf-mangled")

    def test_clean_preloader_reports_emi(self):
        data = _make_preloader(emi_len=600, pre=64)
        # pad to a 512 boundary so it isn't flagged oversized/odd
        data = data + b"\xff" * (512 - (len(data) % 512))
        rep = MtkDumpTools.inspect_dump(data)
        self.assertTrue(rep["has_emi"])
        self.assertEqual(rep["bloader_version"], "38")
        self.assertFalse(rep["crlf_mangled"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./python_embedded/python.exe tests/test_mtk_dump_tools.py -v`
Expected: FAIL — `AttributeError: ... has no attribute 'inspect_dump'`

- [ ] **Step 3: Write minimal implementation**

```python
# add method to MtkDumpTools in mtk_dump_tools.py
    @staticmethod
    def inspect_dump(data):
        data = bytes(data)
        n = len(data)
        nz = n - data.count(0)
        rep = {
            "size": n, "aligned_512": n % 512 == 0, "aligned_4k": n % 4096 == 0,
            "all_zero": nz == 0, "nonzero_bytes": nz,
            "sha256": hashlib.sha256(data).hexdigest(),
            "head_magic": None, "bloader_version": None, "has_emi": False,
            "crlf_mangled": False,
        }
        if data[:9] == b"EMMC_BOOT":
            rep["head_magic"] = "EMMC_BOOT"
        elif data[:4] == b"\x4d\x4d\x4d\x01":
            rep["head_magic"] = "GFH(MMM)"
        elif data[:9] == b"FILE_INFO":
            rep["head_magic"] = "FILE_INFO"
        emi, emi_rep = MtkDumpTools.build_emi(data)
        if emi is not None:
            rep["has_emi"] = True
            rep["bloader_version"] = emi_rep.get("version")
            rep["emi_length"] = emi_rep.get("emi_length")
        _, cr = MtkDumpTools.unmangle_crlf(data)
        rep["crlf_mangled"] = cr["mangled"]
        if rep["all_zero"]:
            verdict = "wiped (all zeros)"
        elif rep["crlf_mangled"]:
            verdict = "crlf-mangled"
        elif not rep["aligned_512"]:
            verdict = "oversized/odd (footer or padding)"
        else:
            verdict = "clean"
        rep["verdict"] = verdict
        rep["summary"] = (
            f"{n} bytes, verdict={verdict}"
            + (f", bloader v{rep['bloader_version']}" if rep["bloader_version"] else "")
        )
        return rep
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./python_embedded/python.exe tests/test_mtk_dump_tools.py -v`
Expected: PASS (all suites)

- [ ] **Step 5: Commit**

```bash
git add mtk_dump_tools.py tests/test_mtk_dump_tools.py
git commit -m "feat(dump-surgeon): inspect_dump report + verdict"
```

---

### Task 5: Wire the "🔪 Dump Surgeon" tab into the app

**Files:**
- Modify: `image_anarchy.py` (import near top of module; add `_DumpSurgeonWorker` near other `QThread` subclasses; add `create_dump_surgeon_tab` method in `ImageAnarchyGUI`; register the tab right after the Scatter Gen tab at `image_anarchy.py:15480`).

**Interfaces:**
- Consumes: `MtkDumpTools` (all four methods).
- Produces: a new tab; no programmatic consumers. Verified by smoke test.

- [ ] **Step 1: Add the import**

Near the top-level imports of `image_anarchy.py` (after the stdlib imports block), add:

```python
from mtk_dump_tools import MtkDumpTools
```

- [ ] **Step 2: Add the background worker**

Add this class at module scope (place it just before `class ImageAnarchyGUI`):

```python
class _DumpSurgeonWorker(QThread):
    """Runs a Dump Surgeon op on a large file off the UI thread."""
    finished_ok = pyqtSignal(bytes, dict)   # output bytes, report
    failed = pyqtSignal(str)

    def __init__(self, op, in_path, target_size=None):
        super().__init__()
        self.op = op            # "unmangle" or "trim"
        self.in_path = in_path
        self.target_size = target_size

    def run(self):
        try:
            with open(self.in_path, "rb") as f:
                data = f.read()
            if self.op == "unmangle":
                out, rep = MtkDumpTools.unmangle_crlf(data)
            elif self.op == "trim":
                out, rep = MtkDumpTools.trim_partition(data, self.target_size)
            else:
                raise ValueError(f"unknown op {self.op}")
            self.finished_ok.emit(out, rep)
        except Exception as e:  # noqa: BLE001 - surface any failure to UI
            self.failed.emit(str(e))
```

- [ ] **Step 3: Add the tab builder method**

Add this method inside `class ImageAnarchyGUI` (place near the other `create_*_tab`/tab helpers). It builds the tab and stores it on `self.dump_surgeon_tab`:

```python
    def create_dump_surgeon_tab(self):
        from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                                     QLineEdit, QPushButton, QTextEdit, QTabWidget,
                                     QFileDialog, QSpinBox, QGroupBox, QFormLayout)
        tab = QWidget()
        root = QVBoxLayout(tab)
        root.addWidget(QLabel("🔪 Dump Surgeon — offline MTK/eMMC dump repair (Ⓐ break the chains)"))
        inner = QTabWidget()
        self.dsurg_report = QTextEdit(); self.dsurg_report.setReadOnly(True)

        def report(d):
            self.dsurg_report.append("\n".join(f"  {k}: {v}" for k, v in d.items()))
            self.dsurg_report.append("─" * 40)

        def pick_in(line):
            p, _ = QFileDialog.getOpenFileName(self, "Select dump file", "",
                                               "Dumps (*.img *.bin);;All Files (*.*)")
            if p:
                line.setText(p)

        def out_path(in_path, suffix):
            base, ext = os.path.splitext(in_path)
            return f"{base}{suffix}{ext or '.bin'}"

        # --- Inspector ---
        insp = QWidget(); il = QVBoxLayout(insp)
        self.dsurg_insp_in = QLineEdit(); insp_btn = QPushButton("Browse")
        insp_btn.clicked.connect(lambda: pick_in(self.dsurg_insp_in))
        run_insp = QPushButton("🔍 Inspect")
        def do_inspect():
            p = self.dsurg_insp_in.text().strip()
            if not os.path.isfile(p):
                report({"error": "file not found"}); return
            with open(p, "rb") as f:
                report(MtkDumpTools.inspect_dump(f.read()))
        run_insp.clicked.connect(do_inspect)
        row = QHBoxLayout(); row.addWidget(self.dsurg_insp_in); row.addWidget(insp_btn)
        il.addLayout(row); il.addWidget(run_insp); il.addStretch()
        inner.addTab(insp, "🔍 Inspect")

        # --- EMI Builder ---
        emi = QWidget(); el = QVBoxLayout(emi)
        self.dsurg_emi_in = QLineEdit(); emi_btn = QPushButton("Browse")
        emi_btn.clicked.connect(lambda: pick_in(self.dsurg_emi_in))
        run_emi = QPushButton("⚡ Build EMI")
        def do_emi():
            p = self.dsurg_emi_in.text().strip()
            if not os.path.isfile(p):
                report({"error": "file not found"}); return
            with open(p, "rb") as f:
                block, rep = MtkDumpTools.build_emi(f.read())
            if block is None:
                report(rep); return
            outp = out_path(p, "_emi")
            with open(outp, "wb") as f:
                f.write(block)
            rep["written"] = outp
            report(rep)
        run_emi.clicked.connect(do_emi)
        row = QHBoxLayout(); row.addWidget(self.dsurg_emi_in); row.addWidget(emi_btn)
        el.addLayout(row); el.addWidget(run_emi); el.addStretch()
        inner.addTab(emi, "⚡ EMI Builder")

        # --- Trim ---
        trim = QWidget(); tl = QVBoxLayout(trim)
        self.dsurg_trim_in = QLineEdit(); trim_btn = QPushButton("Browse")
        trim_btn.clicked.connect(lambda: pick_in(self.dsurg_trim_in))
        self.dsurg_trim_size = QSpinBox(); self.dsurg_trim_size.setMaximum(2_000_000_000)
        self.dsurg_trim_size.setSpecialValueText("auto (strip padding)")
        run_trim = QPushButton("✂️ Trim")
        def do_trim():
            p = self.dsurg_trim_in.text().strip()
            if not os.path.isfile(p):
                report({"error": "file not found"}); return
            size = self.dsurg_trim_size.value() or None
            self._dsurg_worker = _DumpSurgeonWorker("trim", p, size)
            self._dsurg_worker.finished_ok.connect(lambda out, rep, ip=p: self._dsurg_save(out, rep, ip, "_trimmed"))
            self._dsurg_worker.failed.connect(lambda m: report({"error": m}))
            self._dsurg_worker.start()
        run_trim.clicked.connect(do_trim)
        row = QHBoxLayout(); row.addWidget(self.dsurg_trim_in); row.addWidget(trim_btn)
        tl.addLayout(row)
        form = QFormLayout(); form.addRow("Target size (bytes):", self.dsurg_trim_size)
        tl.addLayout(form); tl.addWidget(run_trim); tl.addStretch()
        inner.addTab(trim, "✂️ Trim")

        # --- Un-mangle ---
        unm = QWidget(); ul = QVBoxLayout(unm)
        self.dsurg_unm_in = QLineEdit(); unm_btn = QPushButton("Browse")
        unm_btn.clicked.connect(lambda: pick_in(self.dsurg_unm_in))
        run_unm = QPushButton("🩹 Un-mangle CRLF")
        def do_unm():
            p = self.dsurg_unm_in.text().strip()
            if not os.path.isfile(p):
                report({"error": "file not found"}); return
            self._dsurg_worker = _DumpSurgeonWorker("unmangle", p)
            self._dsurg_worker.finished_ok.connect(lambda out, rep, ip=p: self._dsurg_save(out, rep, ip, "_recovered"))
            self._dsurg_worker.failed.connect(lambda m: report({"error": m}))
            self._dsurg_worker.start()
        run_unm.clicked.connect(do_unm)
        row = QHBoxLayout(); row.addWidget(self.dsurg_unm_in); row.addWidget(unm_btn)
        ul.addLayout(row); ul.addWidget(run_unm); ul.addStretch()
        inner.addTab(unm, "🩹 Un-mangle")

        root.addWidget(inner)
        root.addWidget(QLabel("Report:"))
        root.addWidget(self.dsurg_report)
        self.dump_surgeon_tab = tab
        return tab

    def _dsurg_save(self, out_bytes, report_dict, in_path, suffix):
        base, ext = os.path.splitext(in_path)
        outp = f"{base}{suffix}{ext or '.bin'}"
        with open(outp, "wb") as f:
            f.write(out_bytes)
        report_dict["written"] = outp
        self.dsurg_report.append("\n".join(f"  {k}: {v}" for k, v in report_dict.items()))
        self.dsurg_report.append("─" * 40)
```

- [ ] **Step 4: Register the tab**

At `image_anarchy.py:15480`, immediately after the line:

```python
            self.tab_widget.addTab(scatter_tab, "📄 Scatter Gen")
```

add:

```python
            self.tab_widget.addTab(self.create_dump_surgeon_tab(), "🔪 Dump Surgeon")
```

- [ ] **Step 5: Smoke test (manual)**

Run the app: `./python_embedded/python.exe image_anarchy.py`
Verify:
1. App launches without error and a "🔪 Dump Surgeon" tab is present.
2. **Inspect**: pick `mtkclient-2.1.2/../../hotspot/sspm_a/sspm_a.img` → report shows a verdict + size.
3. **EMI Builder**: pick `hotspot/preloader_a/preloader_a.bin` → writes `..._emi.bin`, report `ok: True, version: 38`.
4. **Un-mangle**: pick `hotspot/mmcblk0boot0/mmcblk0boot0.bin` → writes `..._recovered.bin`, report `mangled: True`, and `aligned_after: True`.
5. **Trim**: pick any oversized dump with `auto` → writes `..._trimmed.bin` smaller than input.

- [ ] **Step 6: Commit**

```bash
git add image_anarchy.py
git commit -m "feat(dump-surgeon): add Dump Surgeon tab (inspect/EMI/trim/un-mangle)"
```

---

## Self-Review

- **Spec coverage:** trim ✅ Task 2; EMI builder ✅ Task 3; CRLF un-mangle ✅ Task 1; inspector ✅ Task 4; single tab + inner QTabWidget ✅ Task 5; QThread for large ops ✅ Task 5 (`_DumpSurgeonWorker`); no new deps ✅ (stdlib only); never overwrite input ✅ (suffix outputs). 
- **Placeholder scan:** none — every step has concrete code/commands.
- **Type consistency:** method names/return shapes (`unmangle_crlf`, `trim_partition`, `build_emi`, `inspect_dump`) are consistent between definitions (Tasks 1-4) and consumers (`inspect_dump`, Task 5 worker/UI).
- **Note:** spec said the logic class could sit "near AndroidImageExtractor" in `image_anarchy.py`; plan puts it in a sibling `mtk_dump_tools.py` instead — a deliberate improvement so the logic is unit-testable without importing PyQt/the monolith. Captured here so it's not mistaken for drift.
