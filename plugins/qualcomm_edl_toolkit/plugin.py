"""Qualcomm EDL Toolkit — Image Anarchy plugin (Phase 1: comms foundation)."""
import os
import subprocess
import sys

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt6.QtCore import QThread, pyqtSignal

# Sibling imports must work both as a package (tests import
# `qualcomm_edl_toolkit.plugin`) and as a top-level module (Image Anarchy loads
# plugin.py via importlib.spec_from_file_location, without a package context and
# without the plugin dir on sys.path).
try:
    from . import edl_paths, ident, driver_manager, loader_manager
except ImportError:  # pragma: no cover - runtime top-level context
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import edl_paths
    import ident
    import driver_manager
    import loader_manager

manifest = None  # set by PluginManager


class EdlWorker(QThread):
    """Runs one EDL operation off the UI thread; talks to the UI via signals."""
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    ident_ready = pyqtSignal(dict)
    finished_op = pyqtSignal(bool, str)

    def __init__(self, op: str, params: dict = None):
        super().__init__()  # never pass parent to a QThread
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
