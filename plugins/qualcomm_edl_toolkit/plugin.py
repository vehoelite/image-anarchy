"""Qualcomm EDL Toolkit — Image Anarchy plugin (Phase 1: comms foundation)."""
import os
import subprocess
import sys

import tempfile
import time

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QGroupBox, QLabel,
    QPushButton, QTextEdit, QFormLayout, QFileDialog, QListWidget, QMessageBox,
    QComboBox
)
from PyQt6.QtCore import QThread, pyqtSignal

# Sibling imports must work both as a package (tests import
# `qualcomm_edl_toolkit.plugin`) and as a top-level module (Image Anarchy loads
# plugin.py via importlib.spec_from_file_location, without a package context and
# without the plugin dir on sys.path).
try:
    from . import edl_paths, ident, driver_manager, loader_manager, edl_util, devinfo
except ImportError:  # pragma: no cover - runtime top-level context
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import edl_paths
    import ident
    import driver_manager
    import loader_manager
    import edl_util
    import devinfo

manifest = None  # set by PluginManager


class EdlWorker(QThread):
    """Runs one EDL operation off the UI thread; talks to the UI via signals."""
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    ident_ready = pyqtSignal(dict)
    devinfo_state = pyqtSignal(dict)
    finished_op = pyqtSignal(bool, str)

    def __init__(self, op: str, params: dict = None):
        super().__init__()  # never pass parent to a QThread
        self.op = op
        self.params = params or {}
        self._proc = None
        self._cancel = False

    def _python(self) -> str:
        return sys.executable

    def cancel(self):
        """Request cancellation and kill any running subprocess."""
        self._cancel = True
        self._terminate_proc()

    def _terminate_proc(self):
        p = self._proc
        if p and p.poll() is None:
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    def run(self):
        try:
            if self.op == "enter_edl":
                self._enter_edl()
            elif self.op == "identify":
                self._identify()
            elif self.op == "upload_loader":
                self._upload_loader()
            elif self.op == "devinfo":
                self._devinfo()
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
        mem = self.params.get("memory", "eMMC")
        self.log.emit(f"⬆️  Uploading loader {os.path.basename(loader)} ({mem}) …")
        dropped, _ = self._edl(edl_dir, ["printgpt"], loader=loader, memory=mem, lun=0)
        if self._cancel:
            self.finished_op.emit(False, "Cancelled")
        elif dropped:
            self.finished_op.emit(
                False,
                "Loader rejected — device dropped during read. Secure boot is enforced; "
                "you need a Firehose loader signed for this device's PK-hash.")
        else:
            self.finished_op.emit(True, "Firehose loader accepted")

    def _pump(self, proc):
        """Forward proc stdout to the log; stop early if the device drops off the bus.
        Returns True if a drop was detected (rejected/unsigned loader spews an otherwise
        infinite USBError stream). Shared by every edl.py invocation."""
        dropped = False
        drop_streak = 0
        MAX_DROP_LINES = 3   # after this many consecutive drop lines, the device is gone
        for line in proc.stdout:
            if self._cancel:
                break
            line = line.rstrip()
            if edl_util.is_drop_line(line):
                dropped = True
                drop_streak += 1
                if drop_streak <= MAX_DROP_LINES:
                    self.log.emit(line)
                elif drop_streak == MAX_DROP_LINES + 1:
                    self.log.emit("… device dropped off USB — stopping (suppressing repeated errors)")
                    break  # do NOT keep reading the infinite USBError stream
            else:
                drop_streak = 0
                if line:
                    self.log.emit(line)
        self._terminate_proc()
        return dropped

    def _edl(self, edl_dir, args, loader=None, memory=None, lun=None):
        """Run one edl.py subcommand, pumping its output. Returns (dropped, returncode).
        A second/third edl.py call re-detects firehose mode (edl.py handles an
        already-loaded device), so read→write→reset works as separate invocations.
        `memory` is 'eMMC'/'ufs'/'nand' (omit for non-storage cmds like reset).
        `lun` is omitted for partition-name reads so edl.py scans all LUNs to find
        the partition (UFS devinfo lives on a non-zero LUN, e.g. LUN 4 on LG 8998)."""
        cmd = [self._python(), os.path.join(edl_dir, "edl.py"), *args]
        if loader:
            cmd.append(f"--loader={loader}")
        if memory:
            cmd.append(f"--memory={memory}")
        if lun is not None:
            cmd.append(f"--lun={lun}")
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=edl_dir)
        dropped = self._pump(self._proc)
        return dropped, self._proc.poll()

    def _devinfo(self):
        """Read (and optionally patch) the devinfo partition to flip the bootloader
        unlock flags. action = read | unlock | relock. Requires a matched loader."""
        edl_dir = edl_paths.get_edl_dir()
        loader = self.params.get("loader")
        action = self.params.get("action", "read")
        mem = self.params.get("memory", "eMMC")
        if not edl_dir:
            self.finished_op.emit(False, "vendored edl/ not found"); return
        if not loader or not os.path.isfile(loader):
            self.finished_op.emit(False, "No matched loader — import/select one first"); return

        tmp = os.path.join(tempfile.gettempdir(), "ia_devinfo_read.bin")
        self.log.emit(f"📖 Reading devinfo ({mem}) …")
        dropped, _ = self._edl(edl_dir, ["r", "devinfo", tmp], loader=loader, memory=mem)
        if self._cancel:
            self.finished_op.emit(False, "Cancelled"); return
        if dropped:
            self.finished_op.emit(
                False, "Loader rejected (secure boot) — need a loader signed for this PK-hash."); return
        if not os.path.isfile(tmp) or os.path.getsize(tmp) == 0:
            self.finished_op.emit(False, "devinfo read failed (no data)"); return

        with open(tmp, "rb") as f:
            data = f.read()
        st = devinfo.read_state(data)
        if not st["found"]:
            self.finished_op.emit(
                False, "device_info magic not found — unexpected layout, aborting (nothing written)."); return
        self.log.emit(f"   is_unlocked={st['is_unlocked']}  is_unlock_critical="
                      f"{st['is_unlock_critical']}  tampered={st['is_tampered']}")

        # Always back up the original before any write.
        bdir = os.path.join(edl_paths.plugin_dir(), "backups")
        os.makedirs(bdir, exist_ok=True)
        bpath = os.path.join(bdir, f"devinfo_{int(time.time())}.bin")
        with open(bpath, "wb") as f:
            f.write(data)
        self.log.emit(f"   🗄  backed up original → {os.path.relpath(bpath, edl_paths.plugin_dir())}")
        self.devinfo_state.emit({**st, "action": action})

        if action == "read":
            self.finished_op.emit(True, f"devinfo read (unlocked={st['is_unlocked']})"); return

        patched = devinfo.patch_unlock(data) if action == "unlock" else devinfo.patch_relock(data)
        changes = devinfo.diff(data, patched)
        if not changes:
            self.finished_op.emit(True, "devinfo already in requested state (no change)"); return
        self.log.emit("   ✏  " + ", ".join(f"@{o}:{a}→{n}" for o, a, n in changes))

        ppath = os.path.join(tempfile.gettempdir(), "ia_devinfo_patched.bin")
        with open(ppath, "wb") as f:
            f.write(patched)
        self.log.emit("💾 Writing patched devinfo …")
        dropped, _ = self._edl(edl_dir, ["w", "devinfo", ppath], loader=loader, memory=mem)
        if dropped:
            self.finished_op.emit(
                False, "Device dropped during write — state uncertain. Re-read devinfo before rebooting."); return

        # Verify by reading it back BEFORE we reset.
        self.log.emit("🔁 Verifying …")
        vtmp = os.path.join(tempfile.gettempdir(), "ia_devinfo_verify.bin")
        self._edl(edl_dir, ["r", "devinfo", vtmp], loader=loader, memory=mem)
        vst = devinfo.read_state(open(vtmp, "rb").read()) if os.path.isfile(vtmp) else {"found": False}
        want = 1 if action == "unlock" else 0
        if vst.get("found") and vst.get("is_unlocked") == want:
            self.devinfo_state.emit({**vst, "action": action})
            self.log.emit("✅ Verified on-device.")
            self._edl(edl_dir, ["reset"], loader=loader)
            verb = "UNLOCKED" if action == "unlock" else "re-locked"
            self.finished_op.emit(
                True, f"devinfo {verb} + reset sent. Device may factory-reset on first boot.")
        else:
            self.finished_op.emit(
                False, "Write did not verify — devinfo unchanged or layout mismatch. NOT rebooting.")


class PluginWidget(QWidget):
    def __init__(self, parent_window=None):
        super().__init__()
        self.parent_window = parent_window
        self.worker = None
        self.current_ident = None
        self._loaders_cache = []

        root = QVBoxLayout(self)
        self.tabs = QTabWidget()
        root.addWidget(self.tabs)

        # --- Device tab ---
        dev = QWidget(); dl = QVBoxLayout(dev)
        row = QHBoxLayout()
        self.btn_edl = QPushButton("💥 Reboot to EDL")
        self.btn_bind = QPushButton("🔧 Bind WinUSB")
        self.btn_ident = QPushButton("🔎 Identify")
        self.btn_stop = QPushButton("🛑 Stop")
        self.btn_stop.setEnabled(False)
        for b in (self.btn_edl, self.btn_bind, self.btn_ident, self.btn_stop):
            row.addWidget(b)
        dl.addLayout(row)
        self._action_buttons = [self.btn_edl, self.btn_bind, self.btn_ident]
        self.driver_lbl = QLabel("Driver: unknown")
        dl.addWidget(self.driver_lbl)
        srow = QHBoxLayout()
        srow.addWidget(QLabel("Storage:"))
        self.mem_combo = QComboBox()
        self.mem_combo.addItems(["eMMC", "ufs"])  # UFS devices (e.g. LG 8998) store devinfo on a non-zero LUN
        srow.addWidget(self.mem_combo)
        srow.addStretch()
        dl.addLayout(srow)
        box = QGroupBox("Device (Sahara)"); form = QFormLayout(box)
        self.lbl_serial = QLabel("—"); self.lbl_hwid = QLabel("—")
        self.lbl_pk = QLabel("—"); self.lbl_sb = QLabel("—")
        self.lbl_pk.setWordWrap(True)
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

        # --- Unlock tab (devinfo OEM-unlock) ---
        un = QWidget(); ul = QVBoxLayout(un)
        warn = QLabel(
            "⚠️  Writes the <b>devinfo</b> partition to flip the bootloader unlock "
            "flags — for <b>devices you own</b>. The device will likely "
            "<b>factory-reset</b> on first boot. The original devinfo is backed up first. "
            "Requires a Firehose loader matched to this device's PK-hash.")
        warn.setWordWrap(True)
        ul.addWidget(warn)
        ubox = QGroupBox("devinfo state"); uform = QFormLayout(ubox)
        self.lbl_unlocked = QLabel("—"); self.lbl_ucrit = QLabel("—"); self.lbl_tamper = QLabel("—")
        uform.addRow("is_unlocked:", self.lbl_unlocked)
        uform.addRow("is_unlock_critical:", self.lbl_ucrit)
        uform.addRow("is_tampered:", self.lbl_tamper)
        ul.addWidget(ubox)
        ur = QHBoxLayout()
        self.btn_read_devinfo = QPushButton("📖 Read devinfo")
        self.btn_unlock = QPushButton("🔓 Unlock")
        self.btn_relock = QPushButton("🔒 Re-lock")
        for b in (self.btn_read_devinfo, self.btn_unlock, self.btn_relock):
            ur.addWidget(b)
        ul.addLayout(ur); ul.addStretch()
        self.tabs.addTab(un, "Unlock")

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
        self.btn_stop.clicked.connect(self._stop)
        self.btn_read_devinfo.clicked.connect(lambda: self._devinfo_action("read"))
        self.btn_unlock.clicked.connect(lambda: self._devinfo_action("unlock"))
        self.btn_relock.clicked.connect(lambda: self._devinfo_action("relock"))
        self._action_buttons += [self.btn_import, self.btn_upload,
                                 self.btn_read_devinfo, self.btn_unlock, self.btn_relock]

        self._refresh_driver()
        self._refresh_loaders([])

    def _loaders_dir(self):
        return os.path.join(edl_paths.plugin_dir(), "loaders")

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
        allld = loader_manager.index_loaders([self._loaders_dir()])
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
        self.worker.devinfo_state.connect(self._on_devinfo_state)
        self.worker.finished_op.connect(self._on_finished)
        self._set_busy(True)
        self.worker.start()

    def _set_busy(self, busy):
        for b in self._action_buttons:
            b.setEnabled(not busy)
        self.btn_stop.setEnabled(busy)

    def _stop(self):
        if self.worker is not None:
            self._log("🛑 Stopping…")
            self.worker.cancel()

    def _on_finished(self, ok, msg):
        self._log(("✅ " if ok else "❌ ") + msg)
        self._refresh_driver()
        self._set_busy(False)
        if self.worker:
            self.worker.deleteLater()
            self.worker = None

    def _on_ident(self, info):
        self.current_ident = info
        self.lbl_serial.setText(info["serial"] or "—")
        self.lbl_hwid.setText(info["hwid"] or "—")
        self.lbl_pk.setText(info["pkhash"] or "—")
        self.lbl_sb.setText("yes" if info["secureboot"] else "no")
        ranked = loader_manager.match(
            loader_manager.index_loaders([self._loaders_dir()]),
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
        dest = loader_manager.import_byo(path, self._loaders_dir())
        self._log(f"📥 Imported {os.path.basename(dest)}")
        hwid = self.current_ident["hwid"] if self.current_ident else ""
        pk = self.current_ident["pkhash"] if self.current_ident else ""
        ranked = loader_manager.match(
            loader_manager.index_loaders([self._loaders_dir()]), hwid, pk)
        self._refresh_loaders(ranked)

    def _memory(self):
        return self.mem_combo.currentText()

    def _upload_selected(self):
        loader = self._selected_loader_path()
        if not loader:
            self._log("Select a loader first."); return
        self._run("upload_loader", {"loader": loader, "memory": self._memory()})

    def _selected_loader_path(self):
        """The highlighted loader, or the single best match if none is highlighted."""
        idx = self.loader_list.currentRow()
        if 0 <= idx < len(self._loaders_cache):
            return self._loaders_cache[idx]["path"]
        if len(self._loaders_cache) == 1:
            return self._loaders_cache[0]["path"]
        return None

    def _on_devinfo_state(self, st):
        self.lbl_unlocked.setText(str(st.get("is_unlocked", "—")))
        self.lbl_ucrit.setText(str(st.get("is_unlock_critical", "—")))
        self.lbl_tamper.setText(str(st.get("is_tampered", "—")))

    def _devinfo_action(self, action):
        loader = self._selected_loader_path()
        if not loader:
            self._log("Select a matched loader on the Loaders tab first."); return
        if action in ("unlock", "relock"):
            verb = "UNLOCK" if action == "unlock" else "RE-LOCK"
            ans = QMessageBox.warning(
                self, f"{verb} bootloader?",
                f"This writes the devinfo partition to {verb} the bootloader.\n\n"
                "• Owner device only.\n"
                "• The device will likely FACTORY-RESET on first boot.\n"
                "• A backup of the original devinfo is saved first.\n"
                "• The change is verified on-device before reboot.\n\nContinue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if ans != QMessageBox.StandardButton.Yes:
                self._log("Cancelled."); return
        self.tabs.setCurrentIndex(self.tabs.count() - 1)  # show Log
        self._run("devinfo", {"loader": loader, "action": action, "memory": self._memory()})


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
