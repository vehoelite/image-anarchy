"""
MTK Toolkit Plugin for Image Anarchy

Advanced MediaTek device toolkit including:
- BROM Mode Detection & Exploitation
- Flash Read (Partitions & Full ROM)
- Flash Write (Partitions & Full ROM)
- Erase Partitions
- Unlock/Lock Bootloader
- FRP/Factory Reset Protection Bypass
- RPMB Key Extraction
- Preloader Dumping
- DA (Download Agent) Operations
- Device Information
- Partition Table Management

Uses mtkclient Python library directly (not CLI) for persistent connection.
"""

import os
import sys
import subprocess
import shutil
import json
import threading
import time
import logging
import faulthandler
import struct
import re
from typing import Optional, List, Dict, Tuple, Any
from datetime import datetime
from pathlib import Path
from unittest import mock

# Enable faulthandler to catch segfaults and low-level crashes
faulthandler.enable()

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QComboBox,
    QPushButton, QLineEdit, QTextEdit, QListWidget, QListWidgetItem,
    QProgressBar, QFileDialog, QMessageBox, QAbstractItemView, QTabWidget,
    QFormLayout, QCheckBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QRadioButton, QButtonGroup, QScrollArea, QFrame, QSplitter,
    QGridLayout, QSpinBox, QStackedWidget, QToolButton, QSizePolicy,
    QPlainTextEdit, QApplication, QInputDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QPropertyAnimation, QEasingCurve, QObject, pyqtSlot
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon, QPixmap, QPainter, QBrush, QPen


# ═══════════════════════════════════════════════════════════════════════════════
# MTK Client Library Integration
# ═══════════════════════════════════════════════════════════════════════════════

def get_plugin_dir() -> str:
    """Get the plugin directory (where this plugin.py file is located)."""
    return os.path.dirname(os.path.abspath(__file__))


def get_app_dir() -> str:
    """Get the application directory."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def get_drivers_dir() -> str:
    """Get the drivers directory."""
    return os.path.join(get_app_dir(), "drivers")


def get_mtkclient_dir() -> Optional[str]:
    """Find the mtkclient installation directory. Prioritizes plugin directory."""
    plugin_dir = get_plugin_dir()
    app_dir = get_app_dir()
    
    possible_dirs = [
        # Plugin directory first (bundled with plugin - preferred!)
        os.path.join(plugin_dir, "mtkclient"),
        # Check for mtkclient nested inside (common structure)
        os.path.join(plugin_dir, "mtkclient", "mtkclient"),
        # Then app directory
        os.path.join(app_dir, "mtkclient"),
        os.path.join(app_dir, "mtkclient", "mtkclient"),
        # System-wide installations
        r"C:\mtkclient",
        r"C:\mtkclient\mtkclient",
        os.path.expanduser("~/mtkclient"),
        os.path.expanduser("~/mtkclient/mtkclient"),
        os.path.expanduser("~/.local/share/mtkclient"),
        "/opt/mtkclient",
    ]
    
    for dir_path in possible_dirs:
        if not dir_path:
            continue
        # Check for mtk.py (CLI entry) or Library folder (library mode)
        mtk_py = os.path.join(dir_path, "mtk.py")
        library_dir = os.path.join(dir_path, "Library")
        mtkclient_pkg = os.path.join(dir_path, "mtkclient")
        
        if os.path.isfile(mtk_py):
            return dir_path
        # Also check if this IS the mtkclient package folder (has Library inside)
        if os.path.isdir(library_dir):
            return dir_path
        # Or if it contains the mtkclient package
        if os.path.isdir(mtkclient_pkg) and os.path.isdir(os.path.join(mtkclient_pkg, "Library")):
            return dir_path
    
    return None


def setup_mtkclient_path():
    """Add mtkclient to Python path for library imports."""
    mtk_dir = get_mtkclient_dir()
    if mtk_dir:
        # Add the mtkclient directory itself
        if mtk_dir not in sys.path:
            sys.path.insert(0, mtk_dir)
        # Also add parent if mtkclient is a package inside
        parent_dir = os.path.dirname(mtk_dir)
        if parent_dir and parent_dir not in sys.path:
            # Only add if it contains an mtkclient folder
            if os.path.isdir(os.path.join(parent_dir, "mtkclient")):
                sys.path.insert(0, parent_dir)
    return mtk_dir


# ═══════════════════════════════════════════════════════════════════════════════
# PySide6 → PyQt6 Complete Shim
# mtkclient uses PySide6, but Image Anarchy uses PyQt6.
# We inject fake PySide6 modules that redirect to PyQt6 to avoid DLL conflicts.
# This MUST happen BEFORE any mtkclient imports.
# ═══════════════════════════════════════════════════════════════════════════════

def _install_pyside6_shim():
    """
    Install a complete PySide6 shim that redirects all imports to PyQt6.
    This prevents PySide6 DLLs from loading and conflicting with PyQt6.
    """
    import types
    
    # Check if PySide6 is already loaded (would be a problem)
    if 'PySide6.QtCore' in sys.modules and not hasattr(sys.modules['PySide6.QtCore'], '_is_shim'):
        # Real PySide6 already loaded - shim may not work
        return False
    
    # Import PyQt6 components we'll redirect to
    from PyQt6 import QtCore as PyQt6_QtCore
    from PyQt6 import QtGui as PyQt6_QtGui
    from PyQt6 import QtWidgets as PyQt6_QtWidgets
    
    # ─────────────────────────────────────────────────────────────────────────
    # Create fake PySide6 package
    # ─────────────────────────────────────────────────────────────────────────
    pyside6_pkg = types.ModuleType('PySide6')
    pyside6_pkg.__path__ = []
    pyside6_pkg.__package__ = 'PySide6'
    pyside6_pkg._is_shim = True
    
    # ─────────────────────────────────────────────────────────────────────────
    # PySide6.QtCore shim
    # Key differences: Signal→pyqtSignal, Slot→pyqtSlot, Property→pyqtProperty
    # ─────────────────────────────────────────────────────────────────────────
    qtcore_shim = types.ModuleType('PySide6.QtCore')
    qtcore_shim.__package__ = 'PySide6'
    qtcore_shim._is_shim = True
    
    # Copy everything from PyQt6.QtCore
    for name in dir(PyQt6_QtCore):
        if not name.startswith('_'):
            setattr(qtcore_shim, name, getattr(PyQt6_QtCore, name))
    
    # PySide6 naming → PyQt6 naming
    qtcore_shim.Signal = PyQt6_QtCore.pyqtSignal
    qtcore_shim.Slot = PyQt6_QtCore.pyqtSlot
    qtcore_shim.Property = PyQt6_QtCore.pyqtProperty
    
    # QObject with PySide6-compatible tr() method
    class QObject_Shim(PyQt6_QtCore.QObject):
        """QObject with PySide6-compatible static tr() method."""
        @staticmethod
        def tr(text, *args, **kwargs):
            return text
    
    qtcore_shim.QObject = QObject_Shim
    
    # ─────────────────────────────────────────────────────────────────────────
    # PySide6.QtGui shim
    # ─────────────────────────────────────────────────────────────────────────
    qtgui_shim = types.ModuleType('PySide6.QtGui')
    qtgui_shim.__package__ = 'PySide6'
    qtgui_shim._is_shim = True
    
    for name in dir(PyQt6_QtGui):
        if not name.startswith('_'):
            setattr(qtgui_shim, name, getattr(PyQt6_QtGui, name))
    
    # QAction moved from QtWidgets to QtGui in Qt6
    if hasattr(PyQt6_QtGui, 'QAction'):
        qtgui_shim.QAction = PyQt6_QtGui.QAction
    
    # ─────────────────────────────────────────────────────────────────────────
    # PySide6.QtWidgets shim
    # ─────────────────────────────────────────────────────────────────────────
    qtwidgets_shim = types.ModuleType('PySide6.QtWidgets')
    qtwidgets_shim.__package__ = 'PySide6'
    qtwidgets_shim._is_shim = True
    
    for name in dir(PyQt6_QtWidgets):
        if not name.startswith('_'):
            setattr(qtwidgets_shim, name, getattr(PyQt6_QtWidgets, name))
    
    # ─────────────────────────────────────────────────────────────────────────
    # Register all shim modules
    # ─────────────────────────────────────────────────────────────────────────
    sys.modules['PySide6'] = pyside6_pkg
    sys.modules['PySide6.QtCore'] = qtcore_shim
    sys.modules['PySide6.QtGui'] = qtgui_shim
    sys.modules['PySide6.QtWidgets'] = qtwidgets_shim
    
    # Also set as attributes on the package
    pyside6_pkg.QtCore = qtcore_shim
    pyside6_pkg.QtGui = qtgui_shim
    pyside6_pkg.QtWidgets = qtwidgets_shim
    
    return True

# Install the shim immediately when this module loads
_shim_installed = _install_pyside6_shim()


# ═══════════════════════════════════════════════════════════════════════════════
# FUSE shim — prevent OSError crash when libfuse is missing
# ═══════════════════════════════════════════════════════════════════════════════
# Official mtkclient's mtkdafs.py does `from fuse import Operations, LoggingMixIn`
# which crashes with OSError (not ImportError) when fusepy is installed but the
# system libfuse library is missing. The upstream code only catches ImportError,
# so the OSError kills the entire mtkclient import chain even though FUSE is only
# used for one optional feature (filesystem mounting).
#
# We can't modify the official mtkclient files, so we pre-test the fuse import
# and install a stub module if it fails, allowing everything else to work.
def _install_fuse_shim():
    """Install a stub 'fuse' module if the real one can't load (missing libfuse)."""
    try:
        import fuse  # noqa: F401 — test if it loads without OSError
        return False  # Real fuse works fine, no shim needed
    except (ImportError, OSError):
        pass

    # Create stub classes that mtkclient expects
    fuse_shim = types.ModuleType('fuse')
    fuse_shim.__package__ = 'fuse'
    fuse_shim._is_shim = True

    class _StubOperations:
        """Stub base class so MtkDaFS(LoggingMixIn, Operations) doesn't crash."""
        pass

    class _StubLoggingMixIn:
        """Stub base class for FUSE logging mixin."""
        pass

    fuse_shim.Operations = _StubOperations
    fuse_shim.LoggingMixIn = _StubLoggingMixIn
    fuse_shim.FUSE = None  # mtk_da_handler checks `if FUSE is not None`

    sys.modules['fuse'] = fuse_shim
    return True

_fuse_shimmed = _install_fuse_shim()


# ═══════════════════════════════════════════════════════════════════════════════
# Now safe to import mtkclient
# ═══════════════════════════════════════════════════════════════════════════════
_mtkclient_available = False
_mtkclient_error = None

try:
    setup_mtkclient_path()
    from mtkclient.Library.mtk_class import Mtk
    from mtkclient.Library.DA.mtk_da_handler import DaHandler
    from mtkclient.Library.Partitions.gpt import GptSettings
    from mtkclient.config.mtk_config import MtkConfig
    from mtkclient.Library.meta import META
    _mtkclient_available = True
except ImportError as e:
    _mtkclient_error = f"Import error: {e}"
except Exception as e:
    _mtkclient_error = f"Error: {e}"


def find_mtk_client() -> Optional[str]:
    """Find mtkclient (mtk.py or mtk executable). Prioritizes plugin directory."""
    plugin_dir = get_plugin_dir()
    
    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        app_dir = os.path.dirname(sys.executable)
    else:
        meipass = None
        app_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    possible_paths = []
    
    # Plugin directory first (preferred location for self-contained plugin)
    possible_paths.extend([
        os.path.join(plugin_dir, "mtkclient", "mtk.py"),
    ])
    
    # Check common locations for cloned mtkclient
    if meipass:
        possible_paths.extend([
            os.path.join(meipass, "mtkclient", "mtk.py"),
            os.path.join(meipass, "mtk.py"),
        ])
    
    possible_paths.extend([
        # App directory (where Image Anarchy is)
        os.path.join(app_dir, "mtkclient", "mtk.py"),
        os.path.join(app_dir, "mtk.py"),
        # Common Windows locations
        r"C:\mtkclient\mtk.py",
        # User home
        os.path.expanduser("~/mtkclient/mtk.py"),
        os.path.expanduser("~/.local/share/mtkclient/mtk.py"),
        # Linux common
        "/opt/mtkclient/mtk.py",
    ])
    
    # Check for mtk.py files
    for path in possible_paths:
        if path and os.path.isfile(path):
            return path
    
    # Check if mtk is in PATH (rare, but possible)
    mtk_in_path = shutil.which("mtk")
    if mtk_in_path:
        return mtk_in_path
    
    return None


def run_mtk_command(args: List[str], callback=None, cwd: str = None) -> Tuple[bool, str]:
    """Run MTK command and return (success, output). No timeout - waits for completion."""
    mtk_path = find_mtk_client()
    if not mtk_path:
        return False, "MTKClient not found. Please clone it from: git clone https://github.com/bkerler/mtkclient.git"
    
    # Get working directory (mtkclient folder)
    if cwd is None:
        mtk_dir = get_mtkclient_dir()
        if mtk_dir:
            cwd = mtk_dir
    
    # Build command
    if mtk_path.endswith('.py'):
        cmd = [sys.executable, mtk_path] + args
    elif " -m " in mtk_path:
        parts = mtk_path.split()
        cmd = parts + args
    else:
        cmd = [mtk_path] + args
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=cwd,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )
        
        # Store process globally so it can be killed if needed
        global _current_mtk_process
        _current_mtk_process = process
        
        output_lines = []
        
        for line in iter(process.stdout.readline, ''):
            output_lines.append(line)
            if callback:
                callback(line)
        
        process.wait()
        _current_mtk_process = None
        output = ''.join(output_lines)
        success = process.returncode == 0 or "Done" in output or "success" in output.lower()
        return success, output
        
    except Exception as e:
        _current_mtk_process = None
        return False, str(e)

# Global process reference for cancellation
_current_mtk_process = None

def kill_mtk_process():
    """Kill any running MTK process."""
    global _current_mtk_process
    if _current_mtk_process:
        try:
            _current_mtk_process.terminate()
            _current_mtk_process.kill()
            _current_mtk_process = None
            return True
        except:
            pass
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING BRIDGE - Capture mtkclient logs and forward to UI
# ═══════════════════════════════════════════════════════════════════════════════

class MtkLoggingHandler(logging.Handler):
    """Custom logging handler that forwards mtkclient logs to Qt signals."""
    
    def __init__(self, emit_func):
        super().__init__()
        self.emit_func = emit_func
        # Format without timestamp since UI adds its own
        self.setFormatter(logging.Formatter('%(name)s - %(message)s'))
    
    def emit(self, record):
        try:
            msg = self.format(record)
            # Clean up ANSI escape codes that mtkclient uses
            msg = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            # Filter out empty or whitespace-only messages
            if msg.strip():
                self.emit_func(msg)
        except Exception:
            pass  # Don't let logging errors crash the app


class StdoutCapture:
    """Captures stdout and forwards to a callback while preserving original output."""
    
    def __init__(self, emit_func, original_stdout):
        self.emit_func = emit_func
        self.original_stdout = original_stdout
        self.buffer = ""
        self._encoding = getattr(original_stdout, 'encoding', 'utf-8') or 'utf-8'
    
    @property
    def encoding(self):
        return self._encoding
    
    def write(self, text):
        # Always write to original stdout
        if self.original_stdout:
            try:
                self.original_stdout.write(text)
            except Exception:
                pass
        
        # Buffer and emit complete lines
        self.buffer += text
        while '\n' in self.buffer:
            line, self.buffer = self.buffer.split('\n', 1)
            line = line.strip()
            if line:
                # Clean ANSI codes
                line = re.sub(r'\x1b\[[0-9;]*m', '', line)
                if line:
                    try:
                        self.emit_func(f"[stdout] {line}")
                    except Exception:
                        pass
    
    def flush(self):
        if self.original_stdout:
            try:
                self.original_stdout.flush()
            except Exception:
                pass
    
    def fileno(self):
        if self.original_stdout and hasattr(self.original_stdout, 'fileno'):
            return self.original_stdout.fileno()
        return -1
    
    def isatty(self):
        if self.original_stdout and hasattr(self.original_stdout, 'isatty'):
            return self.original_stdout.isatty()
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# MTK Device Handler (Persistent Connection - like original GUI)
# ═══════════════════════════════════════════════════════════════════════════════

class MtkDeviceHandler(QObject):
    """
    Handles persistent MTK device connection using mtkclient library directly.
    This mirrors the DeviceHandler from the original mtk_gui.py to maintain
    connection state across multiple operations.
    """
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    status_signal = pyqtSignal(str)
    connected_signal = pyqtSignal(bool)
    partitions_signal = pyqtSignal(list)
    device_info_signal = pyqtSignal(dict)
    mode_changed_signal = pyqtSignal(str)  # Emits current mode when it changes
    
    # Define which operations work in which modes
    # Modes: BROM, Preloader, DA, META, ADV_META
    # All DA-based operations (partition r/w, IMEI, modem, NVRAM, etc.)
    _DA_OPS = {
        'read_partition', 'write_partition', 'erase_partition',
        'get_gpt', 'dump_brom', 'dump_preloader',
        'unlock_bootloader', 'lock_bootloader', 'erase_frp',
        'read_full_flash', 'write_full_flash',
        'dump_seccfg', 'reset_seccfg', 'patch_vbmeta',
        'get_rpmb', 'read_rpmb', 'write_rpmb', 'erase_rpmb', 'auth_rpmb',
        'read_efuses', 'memory_dump',
        'read_imei', 'write_imei', 'patch_modem',
        'backup_nvram', 'restore_nvram',
        'backup_modem', 'restore_modem',
        'check_network_lock', 'remove_network_lock', 'scan_sml_data',
        'read_chip_id', 'read_me_id', 'read_soc_id', 'read_full_hw_info',
        'check_sbc_status', 'check_daa_status',
        'switch_mode', 'set_meta_mode',
    }
    
    # BROM-specific operations (exploits, raw memory access)
    _BROM_OPS = {
        'run_kamakiri', 'run_amonet', 'run_carbonara', 'load_custom_payload',
        'peek_memory', 'poke_memory',
    }
    
    # META-specific operations (AT commands over serial - real META protocol)
    _META_AT_OPS = {
        'meta_read_imei', 'meta_write_imei',
        'meta_check_network_lock', 'meta_remove_network_lock',
        'meta_unlock_network', 'meta_try_engineering_codes',
        'meta_at_command',
    }
    
    MODE_CAPABILITIES = {
        'BROM': _DA_OPS | _BROM_OPS,
        'Preloader': _DA_OPS - {'dump_brom', 'get_rpmb', 'read_efuses', 'memory_dump'},
        'DA': _DA_OPS,
        'META': _META_AT_OPS | {
            'read_imei', 'write_imei', 'patch_modem',
            'backup_nvram', 'restore_nvram',
            'backup_modem', 'restore_modem',
            'check_network_lock', 'remove_network_lock',
            'read_chip_id', 'read_me_id', 'read_soc_id', 'read_full_hw_info',
            'switch_mode',
        },
        'ADV_META': _META_AT_OPS | _DA_OPS | _BROM_OPS,
        'Disconnected': set(),  # Nothing works when disconnected
    }
    
    def __init__(self, parent=None, preloader: str = None, loader: str = None):
        super().__init__(parent)
        self.mtk = None
        self.da_handler = None
        self.connected = False
        self.partitions = []
        self.device_info = {}
        self.preloader = preloader
        self.loader = loader
        self._lock = threading.Lock()
        self._logging_handler = None
        self._stdout_capture = None
        self._original_stdout = None
        self.current_mode = "Disconnected"  # Track current mode
        self.meta_connected = False  # Track META mode connection
        self.meta_serial = None  # Serial port for META AT commands
        
        # Output directory for operations
        self.output_dir = os.getcwd()
        
        # Setup logging bridge to capture mtkclient logs
        self._setup_logging_bridge()
    
    def _setup_logging_bridge(self):
        """Setup custom logging handler to capture mtkclient logs."""
        try:
            # Create custom handler that forwards to our signal
            self._logging_handler = MtkLoggingHandler(self._emit_log)
            self._logging_handler.setLevel(logging.DEBUG)  # Capture all levels
            
            # mtkclient uses many different logger names - capture them all via root
            # Known mtkclient loggers: GCpu, Dxcc, Sej, Cqdma, HwCrypto, Exploitation, usb, etc.
            root_logger = logging.getLogger()
            
            # Remove existing handlers to prevent duplicate stdout output
            # (mtkclient adds its own stream handlers)
            for handler in root_logger.handlers[:]:
                if isinstance(handler, logging.StreamHandler):
                    # Keep our custom handler, remove others
                    if not isinstance(handler, MtkLoggingHandler):
                        root_logger.removeHandler(handler)
            
            root_logger.addHandler(self._logging_handler)
            root_logger.setLevel(logging.DEBUG)
            
            # Also explicitly add to common mtkclient loggers
            mtkclient_loggers = [
                'mtkclient', 'Preloader', 'DA', 'META', 'Port', 'Config',
                'GCpu', 'Dxcc', 'Sej', 'Cqdma', 'HwCrypto', 'Exploitation',
                'usb', 'usb.core', 'LibUsb1Backend', 'PLTools', 'DAXFlash'
            ]
            for logger_name in mtkclient_loggers:
                logger = logging.getLogger(logger_name)
                # Remove any stream handlers on this logger too
                for handler in logger.handlers[:]:
                    if isinstance(handler, logging.StreamHandler) and not isinstance(handler, MtkLoggingHandler):
                        logger.removeHandler(handler)
                logger.addHandler(self._logging_handler)
                logger.setLevel(logging.DEBUG)
            
            # Also capture stdout since mtkclient uses print() in some places
            # and modifies sys.stdout during import
            self._original_stdout = sys.stdout
            self._stdout_capture = StdoutCapture(self._emit_log, self._original_stdout)
            sys.stdout = self._stdout_capture
            
            self._emit_log("✅ Logging bridge initialized")
        except Exception:
            pass  # Logging bridge setup failed silently
    
    def _emit_log(self, message: str):
        """Thread-safe log emission - Qt signals are inherently thread-safe."""
        try:
            self.log_signal.emit(str(message))
        except Exception:
            pass  # Ignore emission errors
    
    def _emit_progress(self, value: int):
        """Thread-safe progress emission."""
        try:
            self.progress_signal.emit(int(value))
        except Exception:
            pass
    
    def _emit_status(self, message: str):
        """Thread-safe status emission."""
        try:
            self.status_signal.emit(str(message))
        except Exception:
            pass
    
    def set_mode(self, mode: str):
        """Set the current device mode and emit signal."""
        old_mode = self.current_mode
        self.current_mode = mode
        if old_mode != mode:
            self._emit_log(f"🔄 Mode changed: {old_mode} → {mode}")
            try:
                self.mode_changed_signal.emit(mode)
            except Exception:
                pass
    
    def is_operation_allowed(self, operation: str) -> bool:
        """Check if an operation is allowed in the current mode."""
        allowed_ops = self.MODE_CAPABILITIES.get(self.current_mode, set())
        return operation in allowed_ops
    
    def get_allowed_operations(self) -> set:
        """Get the set of allowed operations for current mode."""
        return self.MODE_CAPABILITIES.get(self.current_mode, set())
    
    def _thread_safe_log_callback(self, message):
        """Thread-safe wrapper for mtkclient log callbacks."""
        try:
            if hasattr(message, 'emit'):
                # It's a signal, convert to string call
                self._emit_log(str(message))
            else:
                self._emit_log(str(message))
        except Exception:
            pass  # Ignore logging errors to prevent cascade
    
    def _thread_safe_progress_callback(self, value):
        """Thread-safe wrapper for mtkclient progress callbacks."""
        try:
            self._emit_progress(int(value))
        except Exception:
            pass
    
    def _thread_safe_status_callback(self, message):
        """Thread-safe wrapper for mtkclient status callbacks."""
        try:
            self._emit_status(str(message))
        except Exception:
            pass
    
    def is_library_available(self) -> bool:
        """Check if mtkclient library is available."""
        return _mtkclient_available
    
    def get_library_error(self) -> str:
        """Get the library import error if any."""
        return _mtkclient_error or "Unknown error"
    
    def initialize(self) -> bool:
        """Initialize the MTK config and classes."""
        if not _mtkclient_available:
            self._emit_log(f"❌ mtkclient library not available: {_mtkclient_error}")
            return False
        
        try:
            self._emit_log("🔧 Initializing MTK configuration...")
            
            # Create thread-safe callback wrapper class
            class ThreadSafeSignalWrapper:
                """Wraps Qt signals for thread-safe emission from mtkclient threads."""
                def __init__(self, handler, emit_func):
                    self._handler = handler
                    self._emit_func = emit_func
                
                def emit(self, *args):
                    try:
                        self._emit_func(*args)
                    except Exception:
                        pass  # Ignore errors to prevent crashes
            
            # Create config with thread-safe wrappers
            config = MtkConfig(
                loglevel=logging.INFO,
                gui=ThreadSafeSignalWrapper(self, self._emit_log),
                guiprogress=ThreadSafeSignalWrapper(self, self._emit_progress),
                update_status_text=ThreadSafeSignalWrapper(self, self._emit_status)
            )
            
            # Set GPT settings
            config.gpt_settings = GptSettings(
                gpt_num_part_entries='0',
                gpt_part_entry_size='0',
                gpt_part_entry_start_lba='0'
            )
            
            config.reconnect = True
            config.uartloglevel = 2
            config.loader = self.loader
            config.preloader = self.preloader
            config.write_preloader_to_file = False
            
            # Create MTK class
            self.mtk = Mtk(config=config, loglevel=logging.INFO)
            
            # Create DA handler
            self.da_handler = DaHandler(self.mtk, logging.INFO)
            
            self._emit_log("✅ MTK configuration initialized")
            return True
            
        except Exception as e:
            self._emit_log(f"❌ Failed to initialize: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def connect_device(self, directory: str = ".") -> bool:
        """
        Connect to MTK device and configure DA.
        This is equivalent to configure_da() in the original.
        """
        if not self.mtk or not self.da_handler:
            if not self.initialize():
                return False
        
        try:
            self._emit_log("━" * 45)
            self._emit_log("🔌 CONNECTING TO DEVICE...")
            self._emit_log("━" * 45)
            self._emit_log("💡 Device must be in BROM or Preloader mode")
            self._emit_log("💡 Hold Volume buttons while connecting USB")
            
            # Configure DA (this does the actual connection)
            self.mtk = self.da_handler.configure_da(self.mtk, directory)
            
            if self.mtk is not None:
                self.connected = True
                
                # Get device info
                self.device_info = {
                    'chipset': str(self.mtk.config.chipconfig.name),
                    'description': str(self.mtk.config.chipconfig.description),
                    'hw_code': hex(self.mtk.config.hwcode) if self.mtk.config.hwcode else 'Unknown',
                    'is_brom': self.mtk.config.is_brom,
                }
                
                # Determine and set the current mode
                if self.mtk.config.is_brom:
                    self.device_info['boot_mode'] = "BROM Mode"
                    self.set_mode("BROM")
                elif self.mtk.config.chipconfig.damode:
                    self.device_info['boot_mode'] = "DA Mode"
                    self.set_mode("DA")
                else:
                    self.device_info['boot_mode'] = "Preloader Mode"
                    self.set_mode("Preloader")
                
                self._emit_log("━" * 45)
                self._emit_log(f"🔥 DEVICE CONNECTED!")
                self._emit_log(f"📱 Chipset: {self.device_info['chipset']}")
                self._emit_log(f"📱 Mode: {self.device_info['boot_mode']}")
                self._emit_log(f"📱 HW Code: {self.device_info['hw_code']}")
                self._emit_log("━" * 45)
                
                # Direct signal emission - Qt handles thread safety
                try:
                    self.connected_signal.emit(True)
                    self.device_info_signal.emit(self.device_info)
                except Exception:
                    pass
                return True
            else:
                self._emit_log("❌ Failed to connect - configure_da returned None")
                self._emit_log("💡 Make sure device is in BROM/Preloader mode")
                self.connected = False
                self.set_mode("Disconnected")
                try:
                    self.connected_signal.emit(False)
                except Exception:
                    pass
                return False
                
        except Exception as e:
            self._emit_log(f"❌ Connection error: {e}")
            import traceback
            traceback.print_exc()
            self.connected = False
            self.set_mode("Disconnected")
            try:
                self.connected_signal.emit(False)
            except Exception:
                pass
            return False
    
    def get_gpt(self) -> Tuple[Optional[bytes], Optional[Any]]:
        """Get GPT data and partition table."""
        if not self.connected or not self.mtk:
            self._emit_log("❌ Device not connected")
            return None, None
        
        try:
            self._emit_log("📋 Reading GPT partition table...")
            data, guid_gpt = self.mtk.daloader.get_gpt()
            
            if guid_gpt is None:
                self._emit_log("❌ Error reading GPT")
                return data, None
            
            # Parse partitions
            self.partitions = []
            for partition in guid_gpt.partentries:
                part_info = {
                    'name': partition.name,
                    'sector': partition.sector,
                    'sectors': partition.sectors,
                    'size': partition.sectors * guid_gpt.sectorsize,
                    'flags': partition.flags,
                }
                self.partitions.append(part_info)
            
            self._emit_log(f"✅ Found {len(self.partitions)} partitions")
            self.partitions_signal.emit(self.partitions)
            
            return data, guid_gpt
            
        except Exception as e:
            self._emit_log(f"❌ Error reading GPT: {e}")
            return None, None
    
    def partition_exists(self, partition_name: str) -> bool:
        """Check if a partition exists in the GPT."""
        if not self.partitions:
            return True  # Assume it exists if we don't have partition list
        for part in self.partitions:
            if part.get('name', '').lower() == partition_name.lower():
                return True
        return False
    
    def read_partition(self, partition_name: str, output_file: str, 
                       offset: int = None, length: int = None,
                       silent_fail: bool = False) -> bool:
        """Read a partition to file.
        
        Args:
            partition_name: Name of the partition to read
            output_file: Path to save the partition image
            offset: Optional offset in bytes
            length: Optional length in bytes
            silent_fail: If True, don't log failure message (used for A/B fallback)
        """
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log(f"📥 Reading partition: {partition_name}")
            
            # Create mock variables with ALL fields explicitly set (not Mock defaults)
            variables = mock.Mock()
            variables.partitionname = partition_name
            variables.filename = output_file
            variables.parttype = None  # Explicitly None
            variables.offset = offset  # None or int
            variables.length = length  # None or int
            
            # Use handle_da_cmds like original GUI
            result = self.da_handler.handle_da_cmds(self.mtk, "r", variables)
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                size = os.path.getsize(output_file)
                self._emit_log(f"✅ Saved: {output_file} ({size / (1024*1024):.1f} MB)")
                return True
            else:
                if not silent_fail:
                    self._emit_log(f"❌ Failed to read partition {partition_name}")
                return False
                
        except Exception as e:
            error_str = str(e)
            if not silent_fail:
                self._emit_log(f"❌ Error reading partition: {e}")
                
                # Detect if device has booted to Android
                if "Input/Output Error" in error_str or "USBError" in error_str:
                    self._emit_log("")
                    self._emit_log("⚠️ USB communication lost!")
                    self._emit_log("💡 The device may have booted to Android")
                    self._emit_log("💡 To re-enter flash mode:")
                    self._emit_log("   1. Power off completely (hold power 10s)")
                    self._emit_log("   2. Hold Vol Down + Vol Up")
                    self._emit_log("   3. Connect USB while holding buttons")
                    self._emit_log("   4. Click 'Check Device' when detected")
                    self._emit_log("")
                    # Mark as disconnected
                    self.connected = False
                    try:
                        self.connected_signal.emit(False)
                    except:
                        pass
            return False
    
    def write_partition(self, partition_name: str, input_file: str) -> bool:
        """Write a file to partition."""
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log(f"📤 Writing partition: {partition_name}")
            
            variables = mock.Mock()
            variables.partitionname = partition_name
            variables.filename = input_file
            variables.parttype = None
            
            self.da_handler.handle_da_cmds(self.mtk, "w", variables)
            
            self._emit_log(f"✅ Written: {partition_name}")
            return True
            
        except Exception as e:
            self._emit_log(f"❌ Error writing partition: {e}")
            return False
    
    def erase_partition(self, partition_name: str) -> bool:
        """Erase a partition."""
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log(f"🗑️ Erasing partition: {partition_name}")
            
            variables = mock.Mock()
            variables.partitionname = partition_name
            variables.parttype = None
            
            self.da_handler.handle_da_cmds(self.mtk, "e", variables)
            
            self._emit_log(f"✅ Erased: {partition_name}")
            return True
            
        except Exception as e:
            self._emit_log(f"❌ Error erasing partition: {e}")
            return False
    
    def read_flash(self, output_file: str, parttype: str = "user") -> bool:
        """Read full flash to file."""
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log(f"📥 Reading full flash ({parttype})...")
            
            # Create variables object with ALL required fields explicitly set
            variables = mock.Mock()
            variables.filename = output_file
            variables.parttype = parttype
            variables.offset = None  # Must be explicitly None, not Mock
            variables.length = None  # Must be explicitly None, not Mock
            
            self.da_handler.handle_da_cmds(self.mtk, "rf", variables)
            
            if os.path.exists(output_file):
                size = os.path.getsize(output_file)
                self._emit_log(f"✅ Saved: {output_file} ({size / (1024*1024*1024):.2f} GB)")
                return True
            return False
            
        except Exception as e:
            self._emit_log(f"❌ Error reading flash: {e}")
            return False
    
    def unlock_bootloader(self) -> bool:
        """Unlock bootloader via seccfg."""
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log("🔓 Unlocking bootloader...")
            
            variables = mock.Mock()
            variables.parttype = None
            
            self.da_handler.handle_da_cmds(self.mtk, "da seccfg unlock", variables)
            
            self._emit_log("✅ Bootloader unlock command sent")
            return True
            
        except Exception as e:
            self._emit_log(f"❌ Error unlocking: {e}")
            return False
    
    def lock_bootloader(self) -> bool:
        """Lock bootloader via seccfg."""
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log("🔒 Locking bootloader...")
            
            variables = mock.Mock()
            variables.parttype = None
            
            self.da_handler.handle_da_cmds(self.mtk, "da seccfg lock", variables)
            
            self._emit_log("✅ Bootloader lock command sent")
            return True
            
        except Exception as e:
            self._emit_log(f"❌ Error locking: {e}")
            return False
    
    def dump_preloader(self, output_file: str) -> bool:
        """Dump preloader from device."""
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log("📥 Dumping preloader...")
            
            variables = mock.Mock()
            variables.partitionname = "preloader"
            variables.filename = output_file
            variables.parttype = "boot2"
            
            self.da_handler.handle_da_cmds(self.mtk, "r", variables)
            
            if os.path.exists(output_file):
                size = os.path.getsize(output_file)
                self._emit_log(f"✅ Preloader saved: {output_file} ({size // 1024} KB)")
                return True
            return False
            
        except Exception as e:
            self._emit_log(f"❌ Error dumping preloader: {e}")
            return False
    
    def dump_brom(self, output_file: str) -> bool:
        """Dump Boot ROM."""
        if not self.connected:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log("📥 Dumping Boot ROM...")
            
            # BROM dump typically uses mtk.dumpbrom() method
            if hasattr(self.mtk, 'dumpbrom'):
                self.mtk.dumpbrom(output_file)
            else:
                # Fallback - some MTK devices use preloader read with brom parttype
                variables = mock.Mock()
                variables.filename = output_file
                self.da_handler.handle_da_cmds(self.mtk, "dumpbrom", variables)
            
            if os.path.exists(output_file):
                size = os.path.getsize(output_file)
                self._emit_log(f"✅ BROM saved: {output_file} ({size // 1024} KB)")
                return True
            return False
            
        except Exception as e:
            self._emit_log(f"❌ Error dumping BROM: {e}")
            return False
    
    def write_flash(self, input_file: str, parttype: str = "user") -> bool:
        """Write full flash from file."""
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log(f"📤 Writing full flash from: {input_file}")
            
            # Explicitly set all fields to avoid Mock returning Mock
            variables = mock.Mock()
            variables.filename = input_file
            variables.parttype = parttype if parttype else "user"
            
            self.da_handler.handle_da_cmds(self.mtk, "wf", variables)
            
            self._emit_log("✅ Flash written successfully")
            return True
            
        except Exception as e:
            self._emit_log(f"❌ Error writing flash: {e}")
            return False
    
    def generate_keys(self, output_dir: str) -> bool:
        """Generate hardware keys."""
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log("🔑 Generating hardware keys...")
            
            # Set hwparam_path for key generation
            self.mtk.config.hwparam_path = output_dir
            
            variables = mock.Mock()
            variables.directory = output_dir
            
            self.da_handler.handle_da_cmds(self.mtk, "da keys", variables)
            
            self._emit_log(f"✅ Keys saved to: {output_dir}")
            return True
            
        except Exception as e:
            self._emit_log(f"❌ Error generating keys: {e}")
            return False
    
    # ═══════════════════════════════════════════════════════════════════════════
    # NEW v2.1.2 Features - Image Anarchy Style! 
    # ═══════════════════════════════════════════════════════════════════════════
    
    def patch_vbmeta(self, mode: int = 3) -> bool:
        """
        Patch vbmeta partition to disable verification/verity.
        
        Uses da_handler.da_vbmeta() directly (from mtkclient 2.1.2).
        
        Args:
            mode: 0=locked, 1=disable_verity, 2=disable_verification, 3=disable_both
        """
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        mode_names = {
            0: "LOCKED (re-enable security)",
            1: "DISABLE VERITY",
            2: "DISABLE VERIFICATION", 
            3: "DISABLE BOTH (full freedom)"
        }
        
        try:
            self._emit_log(f"⚡ Patching vbmeta: {mode_names.get(mode, 'Unknown')}")
            
            # Use da_vbmeta directly - it handles read, patch, and write internally
            # The method reads vbmeta, patches byte 0x78 with mode flags, and writes back
            self.da_handler.da_vbmeta(vbmode=mode, display=True)
            
            self._emit_log("━" * 45)
            self._emit_log("✅ vbmeta patched - YOUR device, YOUR rules!")
            return True
            
        except Exception as e:
            self._emit_log(f"❌ Error patching vbmeta: {e}")
            import traceback
            self._emit_log(traceback.format_exc())
            return False
            return False
    
    def read_imei(self) -> Optional[List[str]]:
        """
        Read and decrypt IMEI values from device.
        Returns list of valid IMEI strings.
        
        Multi-strategy decryption:
        1. Hardware SEJ crypto via DA (device-specific OTP key)
        2. Software AES-ECB with multiple vendor key seeds
        3. Software RC4 with multiple vendor key seeds
        4. Raw unencrypted BCD (some budget devices)
        
        Uses direct nvdata partition reading and decryption (from mtkclient 2.1.2).
        """
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return None
        
        try:
            self._emit_log("📱 Reading device IMEI values...")
            self._emit_log("━" * 50)
            
            # Import the crypto functions from mtkclient
            try:
                from mtkclient.Library.mtk_crypto import (
                    calc_checksum, decode_imei, is_luhn_valid, decrypt_cssd,
                    SST_Get_NVRAM_SW_Key, decrypt_nvitem, decrypt_nvitem_rc4,
                    verify_checksum, nvram_keys
                )
                from mtkclient.Library.utils import find_binary
            except ImportError as e:
                self._emit_log(f"❌ Failed to import mtkclient crypto: {e}")
                return None
            
            # Read nvdata partition directly
            self._emit_log("📥 Reading nvdata partition...")
            nvdata = self.da_handler.da_read_partition(partitionname="nvdata", display=False)
            
            if not nvdata or nvdata == b"":
                self._emit_log("❌ Failed to read nvdata partition")
                return None
            
            self._emit_log(f"✅ Read {len(nvdata)} bytes from nvdata")
            
            imei_list = []
            
            # Find IMEI data marker: "LDI\x00" + LID 0xEF10 (standard IMEI NVRAM item)
            # Full 9-byte marker: 4C444900 10EF 0A00 0A
            #   "LDI\x00" magic + LID 0xEF10 (LE) + items=0x000A (10 slots) + size starts with 0x0A
            IMEI_MARKER = b"\x4C\x44\x49\x00\x10\xEF\x0A\x00\x0A"
            pos = find_binary(nvdata, IMEI_MARKER)
            
            if pos is None or pos == -1:
                # Primary marker not found — scan for LDI headers with IMEI-like properties
                # IMEI items have: LID=0xEF10, items=1-10, itemsize=0x0A-0x24
                self._emit_log("⚠️ Standard IMEI marker not found, scanning LDI headers...")
                ldi_magic = b"\x4C\x44\x49\x00"  # "LDI\x00"
                scan_pos = 0
                while scan_pos < len(nvdata) - 0x40:
                    scan_pos = nvdata.find(ldi_magic, scan_pos)
                    if scan_pos == -1:
                        break
                    # Parse this LDI header
                    try:
                        scan_lid = int.from_bytes(nvdata[scan_pos+4:scan_pos+6], 'little')
                        scan_items = int.from_bytes(nvdata[scan_pos+6:scan_pos+8], 'little')
                        scan_size = int.from_bytes(nvdata[scan_pos+8:scan_pos+0xC], 'little')
                        # LID 0xEF10 is the IMEI item — accept close matches too
                        # (some devices use 0xEF10, others might use nearby LIDs)
                        if scan_lid == 0xEF10 and 1 <= scan_items <= 10 and 0x0A <= scan_size <= 0x24:
                            self._emit_log(f"🔍 Found IMEI LDI (partial marker) at 0x{scan_pos:X}")
                            pos = scan_pos
                            break
                    except:
                        pass
                    scan_pos += 4
            
            if pos is not None and pos != -1:
                self._emit_log(f"🔍 Found IMEI data at offset 0x{pos:X}")
                
                nvitem_data = nvdata[pos:pos + 0x180]
                
                # Parse the LDI header
                lid = int.from_bytes(nvitem_data[4:6], 'little')
                items = int.from_bytes(nvitem_data[6:8], 'little')
                itemsize = int.from_bytes(nvitem_data[8:0xC], 'little')
                attr = int.from_bytes(nvitem_data[0xC:0x10], 'little')
                
                self._emit_log(f"   LID: 0x{lid:04X}, Items: {items}, Size: 0x{itemsize:X}")
                self._emit_log(f"   Attributes: 0x{attr:04X}", )
                
                is_sw_encrypted = bool(attr & 0x8)    # CONFIDENTIAL = SW AES
                is_hw_encrypted = bool(attr & 0x20)    # MSP = HW AES (SEJ)
                
                if is_hw_encrypted:
                    self._emit_log("   🔐 HW encrypted (SEJ)")
                elif is_sw_encrypted:
                    self._emit_log("   🔐 SW encrypted (AES)")
                else:
                    self._emit_log("   🔓 Unencrypted (or unknown)")
                
                encrypted_data = nvitem_data[0x40:]
                self._emit_log(f"   Raw data (first 64 bytes): {encrypted_data[:64].hex()}")
                
                # ══════════════════════════════════════════════════
                # STRATEGY 1: Hardware SEJ crypto via DA
                # This is the gold standard — uses device OTP key
                # ══════════════════════════════════════════════════
                result = None
                decrypt_method = None
                
                try:
                    seed = bytes.fromhex("3132616263646566")  # "12abcdef" 
                    aeskey = bytes.fromhex("0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000")
                    
                    if hasattr(self.mtk, 'daloader') and hasattr(self.mtk.daloader, 'nvitem'):
                        self._emit_log("🔑 Trying HW SEJ decryption via DA (10s timeout)...")
                        
                        # Run nvitem() in a thread with timeout — it hangs on some devices
                        # where the DA doesn't support custom_sej_hw
                        import concurrent.futures
                        hw_result = None
                        
                        def _hw_decrypt():
                            return self.mtk.daloader.nvitem(
                                data=nvitem_data,
                                encrypt=False,
                                otp=self.mtk.config.get_otp() if hasattr(self.mtk.config, 'get_otp') else None,
                                seed=seed,
                                aeskey=aeskey,
                                display=False
                            )
                        
                        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                            future = executor.submit(_hw_decrypt)
                            try:
                                hw_result = future.result(timeout=10)
                            except concurrent.futures.TimeoutError:
                                self._emit_log("   ⏱️ HW SEJ timed out (DA doesn't support it on this device)")
                                hw_result = None
                        
                        if hw_result and hw_result != b"":
                            # Validate: does this produce valid IMEIs?
                            test_imeis = self._try_extract_imeis(hw_result, decode_imei, calc_checksum, is_luhn_valid)
                            if test_imeis:
                                result = hw_result
                                decrypt_method = "HW SEJ"
                                self._emit_log(f"   ✅ HW SEJ decryption produced {len(test_imeis)} valid IMEI(s)")
                            else:
                                self._emit_log("   ⚠️ HW SEJ returned data but no valid IMEIs")
                                self._emit_log(f"   Decrypted (first 64): {hw_result[:64].hex()}")
                except Exception as e:
                    self._emit_log(f"   ⚠️ HW SEJ unavailable: {e}")
                
                # ══════════════════════════════════════════════════
                # STRATEGY 2: Software AES-ECB with vendor key seeds
                # Different manufacturers use different key seeds
                # ══════════════════════════════════════════════════
                if result is None:
                    self._emit_log("🔑 Trying software AES decryption with vendor keys...")
                    
                    vendor_keys = {
                        "MTK Standard": nvram_keys.get("mtk", bytes.fromhex("0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000")),
                        "BLU/MTKv2": nvram_keys.get("mtkv2", bytes.fromhex("425431988FD5AFE5EA6ACD443F382EFEFB6124B5814C376B759F21B484213B8F")),
                        "Samsung": nvram_keys.get("samsung", bytes.fromhex("C1A2B1D9B1DDC1F621436F6E666964656E7469616C53414D53554E4700000000")),
                    }
                    
                    from Cryptodome.Cipher import AES as AES_Cipher
                    
                    for key_name, key_seed in vendor_keys.items():
                        try:
                            nvramkey = SST_Get_NVRAM_SW_Key(key_seed, 0x10)
                            sw_result = bytearray()
                            
                            nvitemsize = 0x20
                            num_items = len(encrypted_data) // nvitemsize
                            
                            for x in range(num_items):
                                chunk = encrypted_data[x * nvitemsize:(x + 1) * nvitemsize]
                                dec_chunk = AES_Cipher.new(nvramkey, AES_Cipher.MODE_ECB).decrypt(bytes(chunk))
                                sw_result.extend(dec_chunk)
                            
                            test_imeis = self._try_extract_imeis(bytes(sw_result), decode_imei, calc_checksum, is_luhn_valid)
                            if test_imeis:
                                result = bytes(sw_result)
                                decrypt_method = f"SW AES ({key_name})"
                                self._emit_log(f"   ✅ {key_name} key: {len(test_imeis)} valid IMEI(s)!")
                                break
                            else:
                                self._emit_log(f"   ❌ {key_name} key: no valid IMEIs")
                        except Exception as e:
                            self._emit_log(f"   ❌ {key_name} error: {e}")
                
                # ══════════════════════════════════════════════════
                # STRATEGY 3: Software RC4 decryption
                # Some older MTK devices use RC4 instead of AES
                # ══════════════════════════════════════════════════
                if result is None:
                    self._emit_log("🔑 Trying RC4 decryption...")
                    
                    for key_name, key_seed in vendor_keys.items():
                        try:
                            rc4_result = decrypt_nvitem_rc4(bytes(encrypted_data), key=key_seed)
                            if rc4_result:
                                test_imeis = self._try_extract_imeis(rc4_result, decode_imei, calc_checksum, is_luhn_valid)
                                if test_imeis:
                                    result = rc4_result
                                    decrypt_method = f"RC4 ({key_name})"
                                    self._emit_log(f"   ✅ RC4 {key_name}: {len(test_imeis)} valid IMEI(s)!")
                                    break
                                else:
                                    self._emit_log(f"   ❌ RC4 {key_name}: no valid IMEIs")
                        except Exception as e:
                            self._emit_log(f"   ❌ RC4 {key_name}: {e}")
                
                # ══════════════════════════════════════════════════
                # STRATEGY 4: Direct unencrypted BCD
                # Some very budget devices don't encrypt at all
                # ══════════════════════════════════════════════════
                if result is None:
                    self._emit_log("🔑 Trying raw unencrypted extraction...")
                    test_imeis = self._try_extract_imeis(bytes(encrypted_data), decode_imei, calc_checksum, is_luhn_valid)
                    if test_imeis:
                        result = bytes(encrypted_data)
                        decrypt_method = "Unencrypted"
                        self._emit_log(f"   ✅ Raw data: {len(test_imeis)} valid IMEI(s)")
                    else:
                        self._emit_log("   ❌ Raw data: no valid IMEIs either")
                
                # ══════════════════════════════════════════════════
                # Extract the validated IMEIs from the winning method
                # ══════════════════════════════════════════════════
                if result is not None:
                    self._emit_log("")
                    self._emit_log(f"🔓 Decryption method: {decrypt_method}")
                    imei_list = self._try_extract_imeis(result, decode_imei, calc_checksum, is_luhn_valid, verbose=True)
                else:
                    self._emit_log("")
                    self._emit_log("━" * 50)
                    self._emit_log("⚠️ ALL decryption methods failed!")
                    self._emit_log("")
                    self._emit_log("💡 This device uses a key we don't have yet.")
                    self._emit_log("   The IMEI data IS there, but we can't decrypt it.")
                    self._emit_log("")
                    self._emit_log("📋 DIAGNOSTIC DATA (share for analysis):")
                    self._emit_log(f"   Attr: 0x{attr:04X} LID: 0x{lid:04X}")
                    self._emit_log(f"   HW Code: {hex(self.mtk.config.hwcode) if hasattr(self.mtk.config, 'hwcode') else 'unknown'}")
                    self._emit_log(f"   Encrypted (hex): {encrypted_data[:0x40].hex()}")
                    self._emit_log("━" * 50)
            else:
                self._emit_log("⚠️ IMEI marker (LID 0xEF10) not found in nvdata")
                self._emit_log("")
                self._emit_log("💡 This device stores IMEI data differently.")
                self._emit_log("   The IMEI is encrypted in NVRAM and we don't have")
                self._emit_log("   the correct LID or encryption key for this device.")
                self._emit_log("")
                self._emit_log("🔧 Use META mode → AT+EGMR reads IMEI directly")
                self._emit_log("   (same path as dialing *#06# — always works)")
            
            # ══════════════════════════════════════════════════════
            # CSSD data (Xiaomi-style device info, may contain IMEI)
            # ══════════════════════════════════════════════════════
            cssd_pos = nvdata.find(b"devPubKeyModulus")
            if cssd_pos != -1:
                self._emit_log(f"🔍 Found CSSD data at offset 0x{cssd_pos:X}")
                try:
                    cssd_data = nvdata[cssd_pos - 0x40:cssd_pos - 0x40 + 0x1048]
                    content = decrypt_cssd(data=cssd_data).config
                    
                    self._emit_log("\n📋 CSSD Device Data:")
                    self._emit_log("━" * 30)
                    for field in content:
                        value = content[field]
                        self._emit_log(f"  {field}: {value}")
                        
                    # CSSD may contain IMEI directly
                    if 'imei_1' in content and content['imei_1']:
                        cssd_imei1 = content['imei_1']
                        if cssd_imei1 not in imei_list and cssd_imei1.replace('0', '') != '':
                            self._emit_log(f"📱 IMEI1 from CSSD: \"{cssd_imei1}\"")
                            imei_list.insert(0, cssd_imei1)
                    if 'imei_2' in content and content['imei_2']:
                        cssd_imei2 = content['imei_2']
                        if cssd_imei2 not in imei_list and cssd_imei2.replace('0', '') != '':
                            self._emit_log(f"📱 IMEI2 from CSSD: \"{cssd_imei2}\"")
                            imei_list.append(cssd_imei2)
                except Exception as e:
                    self._emit_log(f"⚠️ CSSD decryption failed: {e}")
            
            if imei_list:
                self._emit_log("━" * 50)
                self._emit_log(f"✅ Found {len(imei_list)} IMEI value(s)")
                return imei_list
            else:
                self._emit_log("━" * 50)
                self._emit_log("⚠️ No valid IMEI values found")
                self._emit_log("")
                self._emit_log("💡 Possible reasons:")
                self._emit_log("   1. Device uses unique HW encryption key (most common)")
                self._emit_log("   2. IMEI was erased or never programmed")
                self._emit_log("   3. Different NVRAM storage format")
                self._emit_log("")
                self._emit_log("🔧 Next steps:")
                self._emit_log("   • Try META mode — AT+EGMR reads IMEI directly")
                self._emit_log("   • Try 'Generate Keys' first (needed for HW crypto)")
                self._emit_log("   • Check diagnostic data above for analysis")
                return []
            
        except Exception as e:
            self._emit_log(f"❌ Error reading IMEI: {e}")
            import traceback
            self._emit_log(traceback.format_exc())
            return None
    
    @staticmethod
    def _is_plausible_imei(imei: str) -> bool:
        """
        Check if an IMEI string looks like a real IMEI (beyond just Luhn).
        
        Rejects:
        - Mostly zeros (encrypted data decoded as BCD often produces this)
        - Invalid TAC prefixes (00, 0000xxxx patterns)
        - Low entropy (same digit repeated)
        """
        if len(imei) < 14:
            return False
        
        digits = imei[:14]
        
        # Count zero digits — real IMEIs rarely have more than 2-3 zeros
        zero_count = digits.count('0')
        if zero_count > 6:  # More than ~40% zeros = garbage
            return False
        
        # TAC (first 8 digits) should not start with 00
        # Valid TACs start with reporting body ID (01-99)
        if digits[:2] == '00':
            return False
        
        # Reject 9010/9000 prefixes — common garbage from encrypted BCD
        if digits[:3] in ('900', '901', '902'):
            return False
        
        # Count unique digits — real IMEIs have reasonable entropy
        unique_digits = len(set(digits))
        if unique_digits < 3:  # e.g., "11111111111111" or "10101010101010"
            return False
        
        # Check that TAC has at least 4 unique digits
        tac = digits[:8]
        if len(set(tac)) < 3:
            return False
        
        return True
    
    def _try_extract_imeis(self, data: bytes, decode_imei, calc_checksum, is_luhn_valid, verbose: bool = False) -> List[str]:
        """
        Try to extract valid IMEI values from decrypted nvitem data.
        
        Each IMEI entry is 0x20 bytes. First 0xA bytes are BCD-encoded IMEI,
        next 8 bytes are MD5-based checksum.
        
        Requires BOTH checksum AND Luhn to pass (or checksum + plausible).
        Luhn alone is not sufficient — random data passes Luhn ~10% of the time.
        
        Returns list of valid IMEI strings.
        """
        imei_list = []
        nvitemsize = 0x20
        
        for i in range(min(len(data) // nvitemsize, 10)):
            entry = bytearray(data[i * nvitemsize:(i + 1) * nvitemsize])
            
            # Skip empty/invalid slots
            if entry[:0xA] == b"\xFF" * 0xA:
                continue
            if entry[:0xA] == b"\x00" * 0xA:
                continue
            
            try:
                imei = decode_imei(entry[:0xA])
                
                # Must be 14-15 digits
                if len(imei) < 14 or not imei[:14].isdigit():
                    continue
                
                # Reject all-zeros
                if imei.replace('0', '') == '':
                    if verbose:
                        self._emit_log(f"   ⚠️ Slot {i}: all zeros (empty/erased)")
                    continue
                
                # Plausibility check — reject garbage that happens to pass Luhn
                plausible = self._is_plausible_imei(imei)
                
                # Validate checksum (MD5-based)
                csum = calc_checksum(entry, 0xA)
                csum_valid = (csum == entry[0xA:0xA + 8])
                
                # Validate Luhn check digit
                luhn_valid = is_luhn_valid(imei)
                
                if csum_valid and luhn_valid and plausible:
                    if verbose:
                        self._emit_log(f"   📱 IMEI{i + 1}: \"{imei}\" ✅ (checksum OK, Luhn OK)")
                    imei_list.append(imei)
                elif csum_valid and plausible:
                    # Checksum is strong validation (MD5-based), accept even without Luhn
                    if verbose:
                        self._emit_log(f"   📱 IMEI{i + 1}: \"{imei}\" ⚠️ (checksum OK, Luhn fail)")
                    imei_list.append(imei)
                elif csum_valid and luhn_valid and not plausible:
                    # Both crypto checks pass but looks weird — still accept but warn
                    if verbose:
                        self._emit_log(f"   📱 IMEI{i + 1}: \"{imei}\" ⚠️ (valid but unusual format)")
                    imei_list.append(imei)
                else:
                    # Luhn alone is NOT sufficient — random data passes Luhn ~10% of the time
                    if verbose:
                        self._emit_log(f"   ❌ Slot {i}: \"{imei}\" (wrong key — checksum mismatch)")
            except Exception:
                continue
        
        return imei_list
    
    def write_imei(self, imei1: str, imei2: str = None, product: str = "thunder") -> bool:
        """
        Write IMEI values to device.
        
        YOUR device. YOUR identity. This is TRUE ownership.
        
        Uses direct nvdata partition reading/writing and encryption (from mtkclient 2.1.2).
        
        Args:
            imei1: Primary IMEI (14-15 digits, checksum auto-calculated)
            imei2: Secondary IMEI (optional, for dual-SIM devices)
            product: Product name for CSSD encryption (default: thunder)
        
        Returns:
            True on success
        
        WARNING: IMEI manipulation may be illegal in some jurisdictions.
                 This tool is for device recovery and legitimate repair only.
        """
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            # Import the crypto functions from mtkclient
            try:
                from mtkclient.Library.mtk_crypto import (
                    calc_checksum, encode_imei, make_luhn_checksum,
                    decrypt_cssd, create_cssd
                )
            except ImportError as e:
                self._emit_log(f"❌ Failed to import mtkclient crypto: {e}")
                return False
            
            # Validate and prepare IMEI(s)
            imei1 = imei1.strip()
            if not imei1.isdigit() or len(imei1) < 14 or len(imei1) > 15:
                self._emit_log(f"❌ Invalid IMEI1 format: must be 14-15 digits")
                return False
            
            imeis = [imei1]
            if imei2:
                imei2 = imei2.strip()
                if not imei2.isdigit() or len(imei2) < 14 or len(imei2) > 15:
                    self._emit_log(f"❌ Invalid IMEI2 format: must be 14-15 digits")
                    return False
                imeis.append(imei2)
            
            # Calculate Luhn checksums for all IMEIs
            for i in range(len(imeis)):
                preimei = imeis[i][:14] + "0"
                imeis[i] = preimei[:14] + str(make_luhn_checksum(preimei))
            
            self._emit_log("📱 IMEI WRITE - Reclaiming YOUR device identity!")
            self._emit_log(f"⚠️ Writing IMEI(s): {', '.join(imeis)}")
            self._emit_log("🏴 You bought it. You own it. Your identity, your rules.")
            
            # Read nvdata partition
            self._emit_log("📥 Reading nvdata partition...")
            nvdata = bytearray(self.da_handler.da_read_partition(partitionname="nvdata", display=False))
            
            if not nvdata or nvdata == b"":
                self._emit_log("❌ Failed to read nvdata partition")
                return False
            
            self._emit_log(f"✅ Read {len(nvdata)} bytes from nvdata")
            
            # Default crypto parameters
            seed = bytes.fromhex("3132616263646566")
            aeskey = bytes.fromhex("0102030405060708090A0B0C0D0E0F1011120B1415161718191A1B1C00000000")
            
            # Find and update all IMEI markers
            pos = 0
            imei_updated = False
            while True:
                pos = nvdata.find(b"\x4C\x44\x49\x00\x10\xEF\x0A\x00\x0A", pos + 1)
                if pos == -1:
                    break
                    
                self._emit_log(f"🔍 Found IMEI data at offset 0x{pos:X}")
                
                old_nvitem_data = nvdata[pos:pos + 0x180]
                nvitem_data = bytearray()
                
                # Encode each IMEI
                x = 0
                for imei in imeis:
                    data = encode_imei(imei) + b"\x00\x00"
                    csum = calc_checksum(data, 0xA)
                    encoded_imei = data + csum + b"\x00" * 0xE
                    nvitem_data.extend(encoded_imei)
                    x += 1
                
                # Fill remaining slots with empty entries
                for i in range(10 - x):
                    data = b"\xFF" * 0xA
                    csum = calc_checksum(data, 0xA)
                    encoded_imei = data + csum + b"\x00" * 0xE
                    nvitem_data.extend(encoded_imei)
                
                # Keep original header
                header = old_nvitem_data[:0x40]
                
                # Encrypt the nvitem data
                try:
                    result = self.mtk.daloader.nvitem(
                        data=header + bytes(nvitem_data),
                        encrypt=True,
                        otp=self.mtk.config.get_otp(),
                        seed=seed,
                        aeskey=aeskey,
                        display=False
                    )
                    nvitem = header + result
                    nvdata[pos:pos + 0x180] = nvitem
                    imei_updated = True
                    self._emit_log(f"✅ Encrypted and prepared IMEI data")
                except Exception as e:
                    self._emit_log(f"⚠️ NVITEM encryption failed: {e}")
            
            if not imei_updated:
                self._emit_log("❌ No IMEI markers found in nvdata")
                return False
            
            # Optionally update CSSD data (if we have keys - usually not available)
            cssd_pos = 0
            while True:
                cssd_pos = nvdata.find(b"devPubKeyModulus", cssd_pos + 1)
                if cssd_pos == -1:
                    break
                    
                try:
                    cssd_data = nvdata[cssd_pos - 0x40:cssd_pos - 0x40 + 0x1048]
                    content = decrypt_cssd(data=cssd_data).config
                    content["imei_1"] = imeis[0]
                    if len(imeis) > 1:
                        content["imei_2"] = imeis[1]
                    
                    # Only update CSSD if we have the required private keys
                    import os
                    if os.path.exists("private_2048.pem") and os.path.exists("private_1024.pem"):
                        self._emit_log("🔐 Updating CSSD data with private keys...")
                        new_cssd_data = create_cssd(content, product=product)
                        nvdata[cssd_pos - 0x40:cssd_pos - 0x40 + 0x1048] = new_cssd_data
                    else:
                        self._emit_log("ℹ️ CSSD update skipped (no private keys)")
                except Exception as e:
                    self._emit_log(f"⚠️ CSSD processing failed: {e}")
            
            # Write back to nvdata partition
            self._emit_log("📤 Writing nvdata partition...")
            if self.da_handler.da_write_partition(partitionname="nvdata", data=bytes(nvdata), display=False):
                self._emit_log("━" * 45)
                self._emit_log("✅ IMEI written successfully!")
                self._emit_log("🏴 Device identity restored to YOUR control!")
                return True
            else:
                self._emit_log("❌ Failed to write nvdata partition")
                return False
            
        except Exception as e:
            self._emit_log(f"❌ Error writing IMEI: {e}")
            import traceback
            self._emit_log(traceback.format_exc())
            return False
    
    def patch_modem(self) -> bool:
        """
        Patch modem firmware for IMEI operations.
        
        This patches md1img to allow IMEI changes on devices that
        normally block them. Required before IMEI write on many devices.
        
        Supported patches:
        - RSA modulus replacement (Xiaomi + generic MTK reference modems)
          Auto-generates RSA keypair if private_2048.pem doesn't exist
        - Realme devices (ARM instruction patch)
        - CPH1909 and similar (ARM instruction patch)
        - Generic SIM lock bypass (ARM Thumb2 instruction patterns)
        - SIMMELOCK data neutralization
        
        Returns:
            True on success
        """
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        import os
        import tempfile
        
        try:
            self._emit_log("📡 MODEM PATCHING - Breaking the carrier's chains!")
            self._emit_log("━" * 50)
            
            # Get current slot (A/B partitioning)
            slot = self.da_handler.get_current_slot() if hasattr(self.da_handler, 'get_current_slot') else ""
            partition_name = f"md1img{slot}"
            
            # Read md1img partition
            self._emit_log(f"📥 Reading {partition_name} partition...")
            md1img = self.da_handler.da_read_partition(partitionname=partition_name, display=False)
            
            if not md1img or md1img == b"":
                self._emit_log(f"❌ Failed to read {partition_name} partition")
                return False
            
            size_mb = len(md1img) / (1024 * 1024)
            self._emit_log(f"✅ Read {len(md1img)} bytes ({size_mb:.1f} MB) from {partition_name}")
            
            # ── Modem analysis ─────────────────────────────────────
            self._emit_log("")
            self._emit_log("🔬 MODEM ANALYSIS")
            self._emit_log("─" * 40)
            self._analyze_modem_image(md1img)
            
            # ── Auto-backup ────────────────────────────────────────
            backup_dir = os.path.join(self.output_dir if hasattr(self, 'output_dir') and self.output_dir else tempfile.gettempdir(), "modem_backup")
            os.makedirs(backup_dir, exist_ok=True)
            backup_path = os.path.join(backup_dir, f"{partition_name}_backup.bin")
            if os.path.exists(backup_path):
                self._emit_log(f"💾 Existing backup preserved: {backup_path}")
            else:
                try:
                    with open(backup_path, "wb") as f:
                        f.write(md1img)
                    self._emit_log(f"💾 Backup saved: {backup_path}")
                except Exception as e:
                    self._emit_log(f"⚠️ Backup failed: {e} (continuing anyway)")
            
            # ── Begin patching ─────────────────────────────────────
            self._emit_log("")
            self._emit_log("🔧 APPLYING PATCHES")
            self._emit_log("─" * 40)
            
            md1img = bytearray(md1img)
            patched = False
            patches_applied = []
            
            # ═══════════════════════════════════════════════════════
            # PATCH 1: RSA Modulus Replacement
            # Many MTK devices (Xiaomi, WIKO, Alcatel, etc.) use
            # a shared reference modem with the same RSA public key.
            # We replace it with OUR key so we control CSSD signing.
            # ═══════════════════════════════════════════════════════
            
            # Known RSA-2048 moduli found in MTK modem firmware
            # First 64 bytes used as search pattern, full 256 bytes replaced
            known_moduli = {
                "Xiaomi/MTK Reference": bytearray([
                    0xC0, 0x76, 0x21, 0xF1, 0x95, 0x51, 0x14, 0x2D, 0x3D, 0x5D, 0x9D, 0xD5, 0x14, 0x05, 0xD5, 0xD8,
                    0x34, 0x70, 0xD5, 0x41, 0x7E, 0x66, 0x1C, 0xB3, 0xF5, 0x47, 0x2D, 0x2E, 0x4A, 0x9A, 0xE5, 0x63,
                    0x45, 0xBF, 0x41, 0x87, 0x16, 0xFE, 0x7F, 0xB5, 0xA5, 0xC0, 0x41, 0x0E, 0x0F, 0xB1, 0x06, 0x72,
                    0x59, 0x23, 0x05, 0xAC, 0x46, 0xC1, 0xB8, 0x01, 0x24, 0x06, 0xDD, 0x02, 0x8B, 0xF6, 0x68, 0x7F,
                ]),
            }
            
            # Check if WE already patched this modem (our key is present)
            already_patched = False
            try:
                from Cryptodome.PublicKey import RSA as RSA_Check
                from Cryptodome.Util.number import long_to_bytes as ltb
                key_dir = os.path.dirname(os.path.abspath(__file__))
                our_key_path = os.path.join(key_dir, "private_2048.pem")
                if os.path.exists("private_2048.pem"):
                    our_key_path = "private_2048.pem"
                if os.path.exists(our_key_path):
                    our_key = RSA_Check.import_key(open(our_key_path, "r").read())
                    our_modulus = ltb(our_key.n, 256)
                    if md1img.find(our_modulus[:64]) != -1:
                        already_patched = True
                        self._emit_log("✅ OUR RSA key already present in modem — previously patched!")
            except Exception:
                pass
            
            modulus_found = False
            for vendor_name, modulus_prefix in known_moduli.items():
                idx = md1img.find(modulus_prefix)
                if idx != -1:
                    modulus_found = True
                    self._emit_log(f"🔍 Found {vendor_name} RSA modulus at offset 0x{idx:X}")
                    
                    try:
                        from Cryptodome.PublicKey import RSA
                        from Cryptodome.Util.number import long_to_bytes
                        
                        key_dir = os.path.dirname(os.path.abspath(__file__))
                        key_path_2048 = os.path.join(key_dir, "private_2048.pem")
                        key_path_1024 = os.path.join(key_dir, "private_1024.pem")
                        
                        # Also check CWD (mtkclient compat)
                        if os.path.exists("private_2048.pem"):
                            key_path_2048 = "private_2048.pem"
                        if os.path.exists("private_1024.pem"):
                            key_path_1024 = "private_1024.pem"
                        
                        if not os.path.exists(key_path_2048):
                            # ── Auto-generate RSA keypair ──────────────
                            self._emit_log("🔑 No private key found — generating RSA keypair...")
                            self._emit_log("   This lets YOU control IMEI signing on YOUR device")
                            
                            # Generate 2048-bit key
                            priv2048 = RSA.generate(2048)
                            with open(key_path_2048, "wb") as f:
                                f.write(priv2048.export_key("PEM"))
                            self._emit_log(f"   ✅ Saved: {key_path_2048}")
                            
                            # Generate 1024-bit key (needed for CSSD operations)
                            if not os.path.exists(key_path_1024):
                                priv1024 = RSA.generate(1024)
                                with open(key_path_1024, "wb") as f:
                                    f.write(priv1024.export_key("PEM"))
                                self._emit_log(f"   ✅ Saved: {key_path_1024}")
                        else:
                            self._emit_log(f"🔑 Using existing key: {key_path_2048}")
                            priv2048 = RSA.import_key(open(key_path_2048, "r").read())
                        
                        modulus_new = long_to_bytes(priv2048.n, 2048 // 8)
                        md1img[idx:idx + (2048 // 8)] = modulus_new
                        patched = True
                        patches_applied.append(f"RSA modulus ({vendor_name})")
                        self._emit_log(f"✅ Replaced {vendor_name} modulus with our key!")
                        self._emit_log("   🏴 YOUR key, YOUR modem, YOUR rules!")
                    except ImportError:
                        self._emit_log("⚠️ PyCryptodome not available — RSA patch skipped")
                        self._emit_log("   Install: pip install pycryptodome")
                    except Exception as e:
                        self._emit_log(f"⚠️ RSA patch failed: {e}")
                    break  # Only patch first modulus found
            
            # ═══════════════════════════════════════════════════════
            # PATCH 2: Realme instruction patch (no key needed)
            # ═══════════════════════════════════════════════════════
            realme_pattern = b"\xc5\x64\x02\x6a\x06\xd2\x00\x6a\x07\xd2\x04\x6a\x04\xd2\x08\xf0"
            idx = md1img.find(realme_pattern)
            if idx != -1:
                self._emit_log(f"🔍 Found Realme SIM check at offset 0x{idx:X}")
                md1img[idx:idx + 3] = b"\x20\xe8\x01"
                patched = True
                patches_applied.append("Realme SIM check bypass")
                self._emit_log("✅ Applied Realme modem patch")
            
            # ═══════════════════════════════════════════════════════
            # PATCH 3: CPH1909 instruction patch (no key needed)
            # ═══════════════════════════════════════════════════════
            cph1909_pattern = b"\x20\xe8\x01\x6a\xa0\xff\x30\x91\x20\xe8"
            idx = md1img.find(cph1909_pattern)
            if idx != -1:
                self._emit_log(f"🔍 Found CPH1909 pattern at offset 0x{idx:X}")
                md1img[idx:idx + 10] = b"\x01" + b"\x00" * 9
                patched = True
                patches_applied.append("CPH1909 bypass")
                self._emit_log("✅ Applied CPH1909 modem patch")
            
            # ═══════════════════════════════════════════════════════
            # PATCH 4: SIMMELOCK neutralization
            # Many MTK modems store SIM lock config as plaintext
            # strings in the modem image. We NOP out the markers.
            # ═══════════════════════════════════════════════════════
            simmelock_markers = [
                (b"SIMMELOCK_", "SIMMELOCK config"),
                (b"SML_LOCK_", "SML lock config"),
            ]
            
            for marker, name in simmelock_markers:
                count = 0
                search_start = 0
                while True:
                    idx = md1img.find(marker, search_start)
                    if idx == -1:
                        break
                    count += 1
                    search_start = idx + len(marker)
                if count > 0:
                    self._emit_log(f"🔍 Found {count}x {name} references in modem")
                    # Don't NOP these blindly — just report for now.
                    # The actual lock state is controlled by NVRAM, not code.
            
            # ═══════════════════════════════════════════════════════
            # PATCH 5: Generic ARM Thumb2 SIM lock check patterns
            # These patch conditional branches that check lock status
            # ═══════════════════════════════════════════════════════
            arm_patches = [
                # Pattern → Replacement, Description
                # CMP R0, #1; BNE → CMP R0, #1; NOP (skip lock check)
                (b"\x01\x28\x01\xd1", b"\x01\x28\x00\xbf", "SIM lock branch (CMP+BNE)"),
                # MOV.W R0, #1 (lock active) → MOV.W R0, #0 (lock inactive)
                (b"\x4f\xf0\x01\x00\x70\x47", b"\x4f\xf0\x00\x00\x70\x47", "SIM lock return=1 (MOV.W+BX LR)"),
                # CBNZ Rn, lock_handler → CBZ Rn (invert: treat locked as unlocked)
                # These are too generic to blindly patch — only log them
            ]
            
            for pattern, replacement, name in arm_patches:
                idx = md1img.find(pattern)
                if idx != -1:
                    self._emit_log(f"🔍 Found {name} at offset 0x{idx:X}")
                    md1img[idx:idx + len(replacement)] = replacement
                    patched = True
                    patches_applied.append(name)
                    self._emit_log(f"✅ Patched {name}")
            
            # ═══════════════════════════════════════════════════════
            # RESULTS
            # ═══════════════════════════════════════════════════════
            self._emit_log("")
            self._emit_log("━" * 50)
            
            if not patched:
                if already_patched:
                    self._emit_log("✅ RESULT: Modem already patched!")
                    self._emit_log("")
                    self._emit_log("   Our RSA key is already in the modem image.")
                    self._emit_log("   No need to patch again — you're good to go!")
                    self._emit_log("━" * 50)
                    return True
                
                self._emit_log("📋 RESULT: No applicable patches for this modem")
                self._emit_log("")
                self._emit_log("💡 This doesn't necessarily mean failure:")
                self._emit_log("   • Many generic devices don't need modem patching")
                self._emit_log("   • IMEI is stored in nvdata, not the modem image")
                self._emit_log("   • Try Read/Write IMEI directly — it may just work!")
                self._emit_log("")
                if not modulus_found:
                    self._emit_log("   No RSA modulus found = modem likely doesn't use")
                    self._emit_log("   Xiaomi-style CSSD signing. IMEI ops may work as-is.")
                self._emit_log("━" * 50)
                return False
            
            # Write back
            self._emit_log(f"📤 Writing patched {partition_name}...")
            self._emit_log(f"   Patches applied: {len(patches_applied)}")
            for p in patches_applied:
                self._emit_log(f"   • {p}")
            self._emit_log("")
            
            if self.da_handler.da_write_partition(partitionname=partition_name, data=bytes(md1img), display=False):
                self._emit_log("✅ Modem patched successfully!")
                self._emit_log("🏴 Carrier restrictions? What carrier restrictions?")
                self._emit_log("━" * 50)
                return True
            else:
                self._emit_log("❌ Failed to write patched modem")
                self._emit_log(f"💾 Original backup at: {backup_path}")
                return False
            
        except Exception as e:
            self._emit_log(f"❌ Error patching modem: {e}")
            import traceback
            self._emit_log(traceback.format_exc())
            return False
    
    def _analyze_modem_image(self, md1img: bytes):
        """Analyze modem image and report useful diagnostic info."""
        data = bytes(md1img)
        
        # Header / magic detection
        magic = data[:4]
        if magic == b"\x88\x16\x88\x58":
            self._emit_log("   Format: MTK modem image (standard header)")
        elif magic[:2] == b"\x4D\x44":
            self._emit_log("   Format: MD (Modem Data) image")
        else:
            self._emit_log(f"   Header: {magic.hex().upper()}")
        
        self._emit_log(f"   Size: {len(data):,} bytes ({len(data)/(1024*1024):.1f} MB)")
        
        # Vendor string detection
        vendor_strings = {
            b"XIAOMI": "Xiaomi",
            b"xiaomi": "Xiaomi",
            b"OPPO": "OPPO",
            b"REALME": "Realme",
            b"realme": "Realme",
            b"VIVO": "Vivo",
            b"SAMSUNG": "Samsung",
            b"WIKO": "WIKO",
            b"wiko": "WIKO",
            b"ALCATEL": "Alcatel",
            b"TINNO": "Tinno",        # WIKO's ODM
            b"tinno": "Tinno",
            b"TECNO": "TECNO",
            b"INFINIX": "Infinix",
            b"LENOVO": "Lenovo",
            b"MOTOROLA": "Motorola",
            b"nokia": "Nokia",
            b"NOKIA": "Nokia",
            b"ZTE": "ZTE",
            b"HUAWEI": "Huawei",
        }
        
        detected_vendors = set()
        for pattern, vendor in vendor_strings.items():
            if pattern in data:
                detected_vendors.add(vendor)
        
        if detected_vendors:
            self._emit_log(f"   Vendor hints: {', '.join(sorted(detected_vendors))}")
        else:
            self._emit_log("   Vendor: Unknown / Generic MTK")
        
        # SIM lock indicator scan
        lock_indicators = {
            b"SIMMELOCK": "SIMMELOCK",
            b"SIM_LOCK": "SIM_LOCK",
            b"NW_LOCK": "Network Lock",
            b"SP_LOCK": "SP Lock",
            b"CP_LOCK": "Corporate Lock",
            b"SML_LOCK": "SML Lock",
            b"NETWORK_LOCK": "Network Lock (alt)",
        }
        
        found_locks = []
        for pattern, name in lock_indicators.items():
            count = data.count(pattern)
            if count > 0:
                found_locks.append(f"{name} ({count}x)")
        
        if found_locks:
            self._emit_log(f"   Lock refs: {', '.join(found_locks)}")
        else:
            self._emit_log("   Lock refs: None found (good!)")
        
        # RSA modulus scan — look for high-entropy 256-byte aligned blocks
        # that could be RSA public keys
        rsa_candidates = 0
        known_xiaomi = bytearray([0xC0, 0x76, 0x21, 0xF1])
        pos = 0
        while pos < len(data) - 256:
            # Quick heuristic: RSA moduli have high byte values,
            # first byte is usually >= 0x80 (MSB set for 2048-bit)
            if data[pos] >= 0x80:
                block = data[pos:pos + 256]
                # Check entropy: RSA moduli should have no long zero runs
                zero_runs = block.count(b"\x00" * 8)
                unique_bytes = len(set(block))
                if zero_runs == 0 and unique_bytes > 200:
                    # Likely RSA modulus candidate
                    if block[:4] == bytes(known_xiaomi):
                        pos += 256
                        continue  # Already handled above
                    rsa_candidates += 1
                    if rsa_candidates <= 3:  # Don't spam
                        self._emit_log(f"   RSA candidate at 0x{pos:X}: {block[:8].hex()}...")
            pos += 256  # RSA moduli are 256-byte aligned in practice
        
        if rsa_candidates > 0:
            self._emit_log(f"   Total RSA-like blocks: {rsa_candidates}")
        
        # devPubKeyModulus check (CSSD-style signing in modem)
        if b"devPubKeyModulus" in data:
            idx = data.find(b"devPubKeyModulus")
            self._emit_log(f"   ⚡ CSSD signing data found at 0x{idx:X}")
            self._emit_log("   → This modem uses RSA-signed IMEI verification")
    
    def read_efuses(self) -> bool:
        """
        Read eFuse values from device.
        
        Uses direct memory peek to read eFuse registers (from mtkclient 2.1.2).
        """
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            # Import eFuse config from mtkclient
            try:
                from mtkclient.config.brom_config import Efuse
            except ImportError as e:
                self._emit_log(f"❌ Failed to import mtkclient Efuse config: {e}")
                return False
            
            self._emit_log("🔐 Reading eFuse values - OEM's dirty secrets exposed!")
            
            # Check if we have efuse address in chipconfig
            if not hasattr(self.mtk.config, 'chipconfig') or not self.mtk.config.chipconfig:
                self._emit_log("⚠️ Chip configuration not available")
                return False
            
            efuse_addr = getattr(self.mtk.config.chipconfig, 'efuse_addr', None)
            if efuse_addr is None:
                self._emit_log("⚠️ eFuse address not available for this chip")
                return False
            
            hwcode = self.mtk.config.hwcode
            self._emit_log(f"📍 eFuse base address: 0x{efuse_addr:08X}")
            self._emit_log(f"📱 Hardware code: 0x{hwcode:04X}")
            
            # Get eFuse configuration for this chip
            efuseconfig = Efuse(efuse_addr, hwcode)
            
            self._emit_log("━" * 45)
            self._emit_log("📋 eFuse Values:")
            self._emit_log("━" * 45)
            
            # Read each eFuse register
            for idx in range(len(efuseconfig.efuses)):
                addr = efuseconfig.efuses[idx]
                if addr < 0x1000:
                    # This is an offset value, not an address
                    data = int.to_bytes(addr, 4, 'little')
                else:
                    # Read the actual register
                    try:
                        data = bytearray(self.mtk.daloader.peek(addr=addr, length=4, registers=True))
                    except Exception as e:
                        self._emit_log(f"   eFuse[0x{idx:02X}]: Read failed ({e})")
                        continue
                
                self._emit_log(f"   eFuse[0x{idx:02X}] @ 0x{addr:08X}: {data.hex().upper()}")
            
            self._emit_log("━" * 45)
            self._emit_log("✅ eFuses dumped - knowledge is power!")
            return True
            
        except Exception as e:
            self._emit_log(f"❌ Error reading eFuses: {e}")
            import traceback
            self._emit_log(traceback.format_exc())
            return False
    
    def memory_dump(self, output_dir: str, dump_type: str = "full") -> bool:
        """
        Dump device memory.
        
        Uses da_peek directly to read memory regions (from mtkclient 2.1.2).
        
        Args:
            output_dir: Directory to save dumps
            dump_type: "full" (brom+dram+sram+efuse), "dram" (dram only)
        """
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            import os
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            self._emit_log(f"🧠 MEMORY EXTRACTION: {dump_type.upper()} dump starting...")
            self._emit_log("💀 This will extract the device's deepest secrets!")
            self._emit_log(f"📁 Output directory: {output_dir}")
            
            # Get memory region addresses from config or use defaults
            dramaddr = 0x40000000
            bromaddr = 0
            bromsize = 0x300000
            sramaddr = 0x300000
            sramsize = 0x11200000
            efuseaddr = 0x11C10000
            efusesize = 0x10000
            
            # Use config values if available
            if hasattr(self.mtk.config, 'dram') and self.mtk.config.dram:
                dramaddr = self.mtk.config.dram.base_address
            if hasattr(self.mtk.config, 'sram') and self.mtk.config.sram:
                sramaddr = self.mtk.config.sram.base_address
                sramsize = self.mtk.config.sram.size
            
            if dump_type == "dram":
                # DRAM only
                self._emit_log(f"📥 Dumping DRAM at 0x{dramaddr:X}, size 0x{0x100000000 - dramaddr:X}...")
                self.da_handler.da_peek(
                    addr=dramaddr,
                    length=0x100000000 - dramaddr,
                    filename=os.path.join(output_dir, f"dump_dram_{hex(dramaddr)}.bin"),
                    registers=False
                )
            else:
                # Full dump
                self._emit_log(f"📥 Dumping BROM at 0x{bromaddr:X}, size 0x{bromsize:X}...")
                self.da_handler.da_peek(
                    addr=bromaddr,
                    length=bromsize,
                    filename=os.path.join(output_dir, "dump_brom.bin"),
                    registers=True
                )
                
                self._emit_log(f"📥 Dumping DRAM at 0x{dramaddr:X}, size 0x{0x100000000 - dramaddr:X}...")
                self.da_handler.da_peek(
                    addr=dramaddr,
                    length=0x100000000 - dramaddr,
                    filename=os.path.join(output_dir, f"dump_dram_{hex(dramaddr)}.bin"),
                    registers=False
                )
                
                self._emit_log(f"📥 Dumping eFuse at 0x{efuseaddr:X}, size 0x{efusesize:X}...")
                self.da_handler.da_peek(
                    addr=efuseaddr,
                    length=efusesize,
                    filename=os.path.join(output_dir, "dump_efuse.bin"),
                    registers=True
                )
                
                self._emit_log(f"📥 Dumping SRAM at 0x{sramaddr:X}, size 0x{sramsize:X}...")
                self.da_handler.da_peek(
                    addr=sramaddr,
                    length=sramsize,
                    filename=os.path.join(output_dir, "dump_sram.bin"),
                    registers=False
                )
            
            self._emit_log("━" * 45)
            self._emit_log(f"✅ Memory dumped to: {output_dir}")
            self._emit_log("🏴 The device's memory is now in YOUR hands!")
            return True
            
        except Exception as e:
            self._emit_log(f"❌ Error during memory dump: {e}")
            import traceback
            self._emit_log(traceback.format_exc())
            return False
    
    def _send_da_shutdown(self, bootmode: int = 0, enablewdt: int = 0):
        """
        Send DA shutdown/reboot command directly via USB protocol.
        
        This bypasses daloader.shutdown() which calls port.close(reset=True)
        AFTER sending the command. That causes a fatal C-level access violation
        because the device physically disconnects before close() finishes.
        
        We send the same protocol bytes but skip the dangerous port.close(reset=True).
        
        Args:
            bootmode: 0=shutdown/poweroff, 1=home_screen/reboot, 2=fastboot
            enablewdt: 0=disable watchdog (clean shutdown), 1=enable watchdog
                       (auto-restart via watchdog reset after shutdown)
        """
        from struct import pack as _pack
        
        da = self.mtk.daloader.da  # The actual xflash/legacy DA object
        
        if hasattr(da, 'xsend') and hasattr(da, 'status'):
            # XFLASH DA protocol
            if da.xsend(da.cmd.SHUTDOWN):
                status = da.status()
                if status == 0:
                    hasflags = 1 if (bootmode != 0 or enablewdt) else 0
                    async_mode = 0
                    dl_bit = 0
                    dont_resetrtc = 0
                    leaveusb = 0
                    da.xsend(_pack("<IIIIIIII", hasflags, enablewdt, async_mode,
                                   bootmode, dl_bit, dont_resetrtc, leaveusb, 0))
                    try:
                        da.status()  # Read final status (may fail if device already reset)
                    except Exception:
                        pass
                else:
                    self._emit_log(f"⚠️ DA shutdown status: {status}")
        elif hasattr(da, 'usbwrite') and hasattr(da, 'Cmd'):
            # Legacy DA protocol: FINISH_CMD (0xD9) + bootmode
            da.usbwrite(da.Cmd.FINISH_CMD)
            try:
                ack = da.usbread(1)
                if ack and ack[0] == 0x5A:  # ACK
                    da.usbwrite(_pack(">I", bootmode))
                    try:
                        da.usbread(1)
                    except Exception:
                        pass
            except Exception:
                pass  # Device may have already disconnected
        else:
            # Unknown DA type - call shutdown as last resort
            self._emit_log("⚠️ Unknown DA type - using daloader.shutdown()")
            self.mtk.daloader.shutdown(bootmode=bootmode)
    
    def set_meta_mode(self, mode: str = "FASTBOOT") -> bool:
        """
        Switch device to specified boot mode.
        
        Handles the full transition from any connected state:
        - From DA mode: Uses DA shutdown to trigger reboot, then catches Preloader VCOM
        - From pure BROM (pre-DA): Uses watchdog reset, then catches Preloader VCOM
        
        The key insight: After connect_device(), the DA is loaded and running.
        You CANNOT use BROM-level commands (init_wdg, brom_register_access) on a
        DA connection. You MUST use the DA's own shutdown/reboot to trigger a reset,
        then catch the Preloader VCOM during the reboot sequence.
        
        For XFLASH DA: setmetamode("usb") sets a META boot flag, then shutdown
        triggers the reboot. The preloader sees the flag and enters VCOM mode.
        
        For all DA types: After shutdown(bootmode=1), META.init() polls for
        PID 0x2000 and performs the READY/mode handshake.
        
        Args:
            mode: Boot mode target (FASTBOOT, META, ADVMETA, FACTORY, SHUTDOWN, REBOOT, etc.)
        """
        if not self.connected or not self.mtk:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            # ═══════════════════════════════════════════════════════════════════
            # Handle DA-only meta port commands (only work in XFLASH DA mode)
            # These set meta port type, NOT boot mode
            # ═══════════════════════════════════════════════════════════════════
            if mode in ["off", "usb", "uart"]:
                if self.da_handler:
                    self._emit_log(f"🔄 Setting DA meta port mode: {mode}")
                    try:
                        if self.mtk.daloader.setmetamode(mode):
                            self._emit_log(f"✅ DA meta port set to {mode}")
                            return True
                        else:
                            self._emit_log("❌ setmetamode failed - device may not be in XFLASH mode")
                            return False
                    except Exception as e:
                        self._emit_log(f"❌ DA setmetamode error: {e}")
                        return False
                else:
                    self._emit_log("❌ DA handler not available for meta mode")
                    return False
            
            # ═══════════════════════════════════════════════════════════════════
            # Handle simple shutdown/reboot (no META handshake needed)
            # We send DA protocol bytes directly to avoid the fatal
            # port.close(reset=True) crash in daloader.shutdown()
            # ═══════════════════════════════════════════════════════════════════
            if mode in ("SHUTDOWN", "REBOOT"):
                bootmode_val = 0 if mode == "SHUTDOWN" else 1
                icon = "⏻" if mode == "SHUTDOWN" else "♻️"
                self._emit_log(f"{icon} Sending {mode.lower()} command...")
                try:
                    self._send_da_shutdown(bootmode_val)
                    if mode == "SHUTDOWN":
                        self._emit_log("✅ Shutdown sent - disconnect USB to power off")
                    else:
                        self._emit_log("✅ Reboot triggered!")
                except Exception as e:
                    self._emit_log(f"⚠️ {mode} error: {e}")
                # Close port safely
                try:
                    if hasattr(self.mtk, 'port') and self.mtk.port:
                        self.mtk.port.close(reset=False)
                except Exception:
                    pass
                self.connected = False
                self.mtk = None
                self.da_handler = None
                self.set_mode("Disconnected")
                return True
            
            # ═══════════════════════════════════════════════════════════════════
            # Mode bytes mapping (from mtkclient META.Mode enum)
            # ═══════════════════════════════════════════════════════════════════
            mode_bytes_map = {
                "FASTBOOT": b"FASTBOOT",
                "META": b"METAMETA",
                "METAMETA": b"METAMETA",
                "ADVMETA": b"ADVEMETA",
                "ADVEMETA": b"ADVEMETA",
                "FACTORY": b"FACTFACT",
                "FACTFACT": b"FACTFACT",
                "FACTORYM": b"FACTORYM",  # ATE Signaling Test
                "ATNBOOT": b"AT+NBOOT",
                "AT+NBOOT": b"AT+NBOOT",
            }
            mode_bytes = mode_bytes_map.get(mode, mode.encode()[:8].ljust(8, b'\x00') if isinstance(mode, str) else mode)
            
            self._emit_log(f"📡 Target mode: {mode} ({mode_bytes})")
            
            # ═══════════════════════════════════════════════════════════════════
            # Detect current device state
            # ═══════════════════════════════════════════════════════════════════
            current_pid = getattr(self.mtk.port.cdc, 'pid', None) if hasattr(self.mtk, 'port') else None
            da_loaded = (self.da_handler is not None and 
                         hasattr(self.mtk, 'daloader') and 
                         self.mtk.daloader is not None)
            
            self._emit_log(f"📱 Current PID: {hex(current_pid) if current_pid else 'Unknown'}")
            self._emit_log(f"📱 DA loaded: {da_loaded}")
            
            BROM_PID = 0x0003
            PRELOADER_PIDS = [0x2000, 0x2001, 0x20FF, 0x3000, 0x6000, 0x1887]
            
            self._emit_log("")
            self._emit_log("━" * 45)
            
            # ═══════════════════════════════════════════════════════════════════
            # CASE 1: Device in Preloader VCOM (not DA) - use META.init() directly
            # This is the case after init_wdg has already been run
            # ═══════════════════════════════════════════════════════════════════
            if current_pid in PRELOADER_PIDS and not da_loaded:
                self._emit_log(f"📡 Preloader VCOM detected (PID {hex(current_pid)})")
                self._emit_log(f"🔄 Sending {mode} command directly...")
                self._emit_log("━" * 45)
                
                try:
                    meta = META(self.mtk, loglevel=logging.INFO)
                    if meta.init(metamode=mode_bytes, maxtries=10, display=False):
                        self._emit_log(f"✅ SUCCESS! Device switched to {mode} mode!")
                        self._emit_log("🏴 YOUR device, YOUR rules!")
                        # Keep connection alive! Don't close port or null mtk.
                        # The device needs an active host or it exits META.
                        self.da_handler = None  # No DA in META mode
                        self.set_mode("META")
                        return True
                    else:
                        self._emit_log("⚠️ META.init() returned False")
                        self._emit_log("💡 Device may have switched anyway - check device status")
                        return False
                except Exception as e:
                    self._emit_log(f"⚠️ META.init() error: {e}")
                    return False
            
            # ═══════════════════════════════════════════════════════════════════
            # CASE 2: Device in BROM - use META.init_wdg() then META.init()
            # init_wdg handles: handshake → hwcode → disable wdt → set META
            # register → trigger watchdog reset → device reboots to VCOM
            # ═══════════════════════════════════════════════════════════════════
            if current_pid == BROM_PID or (not da_loaded and current_pid not in PRELOADER_PIDS):
                self._emit_log(f"📱 BROM mode detected (PID: {hex(current_pid) if current_pid else '?'})")
                self._emit_log("🔧 BROM → META TRANSITION")
                self._emit_log("━" * 45)
                self._emit_log("")
                
                try:
                    meta = META(self.mtk, loglevel=logging.INFO)
                    self._emit_log("🔄 Running init_wdg (watchdog-based META transition)...")
                    
                    wdg_result = meta.init_wdg(display=True)
                    
                    if wdg_result:
                        self._emit_log("")
                        self._emit_log("✅ Watchdog reset triggered!")
                        self._emit_log("📱 Device resetting into Preloader/META mode...")
                        self._emit_log("")
                        self._emit_log("━" * 45)
                        self._emit_log("📋 IF YOU SEE 'USB DEVICE NOT RECOGNIZED':")
                        self._emit_log("   1. Do NOT unplug USB")
                        self._emit_log("   2. Hold Vol Up + Vol Down + Power")
                        self._emit_log("   3. Wait for 'META' text on screen (PRE-META)")
                        self._emit_log("   4. Hold all buttons again to trigger real META")
                        self._emit_log("   5. Screen goes BLACK = real META mode")
                        self._emit_log("━" * 45)
                        self._emit_log("")
                        self._emit_log("⏳ Waiting for device (this can take 30+ seconds)...")
                    else:
                        self._emit_log("⚠️ init_wdg() returned False - trying manual...")
                        try:
                            wdg_addr, _ = self.mtk.config.get_watchdog_addr()
                            self.mtk.preloader.setreg_disablewatchdogtimer(
                                self.mtk.config.hwcode, self.mtk.config.hwver
                            )
                            self.mtk.preloader.brom_register_access(
                                mode=3, address=0, length=1, data=b"\x01"
                            )
                            self.mtk.preloader.brom_register_access(
                                mode=2, address=0, length=1
                            )
                            time.sleep(0.2)
                            self.mtk.preloader.write32(wdg_addr + 0x14, 0x00001209)
                            self._emit_log("✅ Manual watchdog reset triggered!")
                        except Exception as e2:
                            self._emit_log(f"❌ Manual fallback failed: {e2}")
                            return False
                    
                except Exception as e:
                    self._emit_log(f"❌ init_wdg error: {e}")
                    import traceback
                    self._emit_log(traceback.format_exc())
                    return False
                
                # Close old BROM connection
                try:
                    if hasattr(self.mtk, 'port') and self.mtk.port:
                        self.mtk.port.close()
                except:
                    pass
                
                time.sleep(2)
                
                # ═══════════════════════════════════════════════════════════
                # META.init() is REQUIRED here. After init_wdg() the device
                # enters PRE-META (orange warning, PID ~0x1800). META.init()
                # catches the Preloader VCOM (PID 0x2000), does the
                # READY → METAMETA → ATEMATEM handshake, then sends
                # DISCONNECT which triggers the SECOND reboot into real
                # META mode (black screen).
                #
                # Without META.init(), device stays stuck in PRE-META.
                # After META.init() returns, the USB re-enumerates so
                # the old handle is dead — just clean up state.
                # ═══════════════════════════════════════════════════════════
                
                self._emit_log("")
                self._emit_log("🔍 Waiting for Preloader VCOM...")
                self._emit_log("━" * 45)
                self._emit_log("📋 WHILE WAITING:")
                self._emit_log("   • Do NOT unplug USB")
                self._emit_log("   • If you see orange warning / 'META' text:")
                self._emit_log("     Hold Vol Up + Vol Down + Power")
                self._emit_log("   • May need to hold buttons through 2 reboots")
                self._emit_log("   • Screen goes BLACK = real META mode ✅")
                self._emit_log("━" * 45)
                self._emit_log("")
                
                try:
                    new_config = MtkConfig(loglevel=logging.INFO)
                    new_config.reconnect = True
                    new_mtk = Mtk(config=new_config, loglevel=logging.INFO)
                    new_meta = META(new_mtk, loglevel=logging.INFO)
                    
                    meta_result = new_meta.init(metamode=mode_bytes, maxtries=50, display=True)
                    
                    if meta_result:
                        self._emit_log("")
                        self._emit_log("✅ META handshake complete!")
                        self._emit_log("📱 Device transitioning to real META mode...")
                    else:
                        self._emit_log("")
                        self._emit_log("⚠️ VCOM handshake uncertain")
                        self._emit_log("💡 Device may still transition — wait for black screen")
                    
                    # USB re-enumerates after DISCONNECT — old handle is dead
                    try:
                        new_mtk.port.close()
                    except:
                        pass
                    
                except Exception as e:
                    self._emit_log(f"⚠️ VCOM catch: {e}")
                    self._emit_log("💡 Device may still be transitioning")
                
                # Clean up old DA state
                self.mtk = None
                self.da_handler = None
                
                # ═══════════════════════════════════════════════════════════
                # Try to connect to META serial port (AT commands)
                # After DISCONNECT, device re-enumerates as USB CDC ACM.
                # If we find the COM port, we have real META mode!
                # ═══════════════════════════════════════════════════════════
                self._emit_log("")
                self._emit_log("🔍 Scanning for META serial port...")
                time.sleep(3)  # Give device time to re-enumerate
                
                if self.connect_meta_serial(max_wait=15):
                    self._emit_log("")
                    self._emit_log("━" * 45)
                    self._emit_log("🎉 CONNECTED TO REAL META MODE!")
                    self._emit_log("🏴 AT commands ready — YOUR device, YOUR rules!")
                    self._emit_log("━" * 45)
                    return True
                else:
                    self._emit_log("")
                    self._emit_log("⚠️ META serial port not found")
                    self._emit_log("💡 Device may still be in META mode without serial")
                    self._emit_log("💡 Falling back to DA reconnect...")
                    self._emit_log("")
                    # Fall through — worker will try DA reconnect
                    self.connected = False
                    self.set_mode("Disconnected")
                
                return True
            
            # ═══════════════════════════════════════════════════════════════════
            # CASE 3: DA is loaded (PID 0x2000 but speaking DA protocol)
            # Need to shutdown DA first, then user re-enters BROM
            # ═══════════════════════════════════════════════════════════════════
            self._emit_log(f"🔧 DA → {mode} TRANSITION")
            self._emit_log("━" * 45)
            self._emit_log("")
            
            # Try setmetamode first (works on some XFLASH devices)
            try:
                if self.mtk.daloader.setmetamode("usb"):
                    self._emit_log("✅ META boot flag set (XFLASH)")
            except Exception:
                pass
            
            # Shutdown DA - send reboot command
            try:
                self._emit_log("🔄 Sending reboot command to DA...")
                self._send_da_shutdown(bootmode=1, enablewdt=0)
                self._emit_log("✅ Reboot command sent")
            except Exception as e:
                self._emit_log(f"⚠️ Reboot error: {e}")
            
            # Close USB safely
            try:
                if hasattr(self.mtk, 'port') and self.mtk.port:
                    self.mtk.port.close(reset=False)
            except Exception:
                pass
            
            self.connected = False
            self.mtk = None
            self.da_handler = None
            
            # Quick try: catch Preloader VCOM if setmetamode worked
            self._emit_log("🔍 Scanning for Preloader VCOM (~10s)...")
            
            caught_vcom = False
            try:
                auto_config = MtkConfig(loglevel=logging.INFO)
                auto_mtk = Mtk(config=auto_config, loglevel=logging.INFO)
                auto_meta = META(auto_mtk, loglevel=logging.INFO)
                
                if auto_meta.init(metamode=mode_bytes, maxtries=30, display=False):
                    self._emit_log("")
                    self._emit_log("━" * 45)
                    self._emit_log(f"🔥 SUCCESS! Device switched to {mode} mode!")
                    self._emit_log("🏴 YOUR device, YOUR rules!")
                    self._emit_log("━" * 45)
                    caught_vcom = True
                    # Keep connection alive
                    self.mtk = auto_mtk
                    self.connected = True
                    self.da_handler = None
                    self.set_mode("META")
                    return True
                
                try:
                    auto_mtk.port.close(reset=False)
                except:
                    pass
            except Exception as e:
                self._emit_log(f"ℹ️ Quick scan: {e}")
            
            if not caught_vcom:
                # setmetamode didn't work - need BROM approach
                # Device has booted to Android by now
                self._emit_log("")
                self._emit_log("━" * 45)
                self._emit_log("⚠️ Auto-switch didn't work for this device")
                self._emit_log("━" * 45)
                self._emit_log("")
                self._emit_log("📋 THE DEVICE HAS REBOOTED. TO CONTINUE:")
                self._emit_log("   1. Power off the phone (hold power → shut down)")
                self._emit_log("   2. Hold Volume Down button")
                self._emit_log("   3. While holding Vol Down, plug USB cable in")
                self._emit_log("   4. Keep holding until status changes")
                self._emit_log("")
                self._emit_log("🔍 Waiting for BROM mode...")
                self._emit_log("")
                
                try:
                    # Use init_wdg which handles BROM catch + META register
                    # internally with robust retry logic
                    wdg_config = MtkConfig(loglevel=logging.INFO)
                    wdg_mtk = Mtk(config=wdg_config, loglevel=logging.INFO)
                    wdg_meta = META(wdg_mtk, loglevel=logging.INFO)
                    
                    # init_wdg: polls for BROM (up to 100 tries per attempt,
                    # retries up to 1000 times with close+reopen).
                    # When it catches BROM: hwcode → disable wdt → 
                    # set META register → trigger watchdog reset
                    if wdg_meta.init_wdg(display=True):
                        self._emit_log("")
                        self._emit_log("✅ BROM caught! Watchdog reset triggered!")
                        self._emit_log("📱 Device resetting with META flag...")
                        
                        # Close BROM connection
                        try:
                            wdg_mtk.port.close()
                        except:
                            pass
                        
                        time.sleep(2)
                        
                        # Catch Preloader VCOM
                        self._emit_log(f"📡 Catching Preloader VCOM for {mode}...")
                        
                        try:
                            vcom_config = MtkConfig(loglevel=logging.INFO)
                            vcom_config.reconnect = True
                            vcom_mtk = Mtk(config=vcom_config, loglevel=logging.INFO)
                            vcom_meta = META(vcom_mtk, loglevel=logging.INFO)
                            
                            if vcom_meta.init(metamode=mode_bytes, maxtries=50, display=True):
                                self._emit_log(f"✅ SUCCESS! Device switched to {mode} mode!")
                                self._emit_log("🏴 YOUR device, YOUR rules!")
                            else:
                                self._emit_log("⚠️ VCOM handshake uncertain - device likely IS in META mode")
                            
                            # Keep connection alive
                            self.mtk = vcom_mtk
                            self.connected = True
                            self.da_handler = None
                            self.set_mode("META")
                        except Exception as e:
                            self._emit_log(f"⚠️ VCOM catch: {e}")
                        
                        # Device DID reset with META flag
                        return True
                    else:
                        self._emit_log("⚠️ BROM not caught (timed out)")
                        
                        try:
                            wdg_mtk.port.close()
                        except:
                            pass
                            
                except Exception as e:
                    self._emit_log(f"⚠️ BROM catch error: {e}")
                
                self._emit_log("")
                self._emit_log("━" * 45)
                self._emit_log("❌ Mode switch did not complete")
                self._emit_log("━" * 45)
                self._emit_log("")
                self._emit_log("📋 TO SWITCH MANUALLY:")
                self._emit_log("   1. Power off the phone completely")
                self._emit_log("   2. Hold Volume Down + plug USB")
                self._emit_log("   3. Click 'Check Device' to connect in BROM")
                self._emit_log("   4. Click mode switch button again")
                
                self.set_mode("Disconnected")
                return False
            
        except Exception as e:
            self._emit_log(f"❌ Error setting meta mode: {e}")
            import traceback
            self._emit_log(traceback.format_exc())
            self.connected = False
            self.set_mode("Disconnected")
            return False
    
    # ═══════════════════════════════════════════════════════════════════════════
    # META MODE - Serial AT Command Interface
    # After META.init() sends DISCONNECT, the device re-enumerates as a USB
    # CDC ACM serial port. We connect via pyserial and send AT commands for
    # real META operations: IMEI read/write, network lock, etc.
    # ═══════════════════════════════════════════════════════════════════════════
    
    def connect_meta_serial(self, max_wait: int = 15) -> bool:
        """
        Scan for and connect to MTK META mode serial port.
        
        After META.init() sends DISCONNECT, the device re-enumerates as a
        USB CDC ACM serial device (VID 0x0E8D). Windows creates a COM port
        for it. We find it and connect via pyserial.
        
        Args:
            max_wait: Maximum seconds to wait for COM port to appear
            
        Returns:
            True if connected to META serial port
        """
        try:
            import serial
            import serial.tools.list_ports
        except ImportError:
            self._emit_log("❌ pyserial not installed — cannot connect to META serial")
            self._emit_log("💡 Install with: pip install pyserial")
            return False
        
        self._emit_log("🔍 Scanning for META mode COM port...")
        
        MTK_VID = 0x0E8D
        
        # Poll for the COM port to appear (device is re-enumerating)
        import time as _time
        start = _time.time()
        meta_port = None
        
        while _time.time() - start < max_wait:
            ports = serial.tools.list_ports.comports()
            for p in ports:
                if p.vid == MTK_VID:
                    self._emit_log(f"📡 Found MTK device: {p.device} (PID: {hex(p.pid) if p.pid else '?'})")
                    meta_port = p.device
                    break
            if meta_port:
                break
            _time.sleep(0.5)
        
        if not meta_port:
            self._emit_log(f"⚠️ No MTK COM port found after {max_wait}s")
            self._emit_log("💡 Device may not have entered META mode")
            return False
        
        # Connect to the serial port
        try:
            self.meta_serial = serial.Serial(
                port=meta_port,
                baudrate=115200,
                timeout=2,
                write_timeout=2,
            )
            self._emit_log(f"✅ Connected to META serial: {meta_port}")
            
            # Send a test AT command
            test_resp = self.meta_at_command("AT")
            if test_resp is not None:
                self._emit_log(f"✅ AT response: {test_resp}")
                self.meta_connected = True
                self.connected = True
                self.set_mode("META")
                return True
            else:
                self._emit_log("⚠️ No response to AT command")
                self._emit_log("💡 Port opened but device may not accept AT commands yet")
                # Keep the connection — some devices need a moment
                self.meta_connected = True
                self.connected = True
                self.set_mode("META")
                return True
                
        except Exception as e:
            self._emit_log(f"❌ Failed to open {meta_port}: {e}")
            return False
    
    def disconnect_meta_serial(self):
        """Close META serial connection."""
        if self.meta_serial:
            try:
                self.meta_serial.close()
            except Exception:
                pass
            self.meta_serial = None
        self.meta_connected = False
    
    def meta_at_command(self, cmd: str, timeout: float = 3.0) -> Optional[str]:
        """
        Send an AT command over META serial and return the response.
        
        Args:
            cmd: AT command string (e.g., "AT", "AT+EGMR=0,7")
            timeout: Response timeout in seconds
            
        Returns:
            Response string, or None if failed
        """
        if not self.meta_serial or not self.meta_serial.is_open:
            self._emit_log("❌ META serial not connected")
            return None
        
        try:
            # Clear any pending data
            self.meta_serial.reset_input_buffer()
            
            # Send command with CR+LF
            cmd_bytes = (cmd.strip() + "\r\n").encode('ascii')
            self.meta_serial.write(cmd_bytes)
            
            # Read response (accumulate until OK/ERROR or timeout)
            import time as _time
            response_lines = []
            start = _time.time()
            
            while _time.time() - start < timeout:
                if self.meta_serial.in_waiting:
                    line = self.meta_serial.readline().decode('ascii', errors='replace').strip()
                    if line:
                        response_lines.append(line)
                        # Check for final response indicators
                        if line in ("OK", "ERROR") or line.startswith("+CME ERROR"):
                            break
                else:
                    _time.sleep(0.05)
            
            return "\n".join(response_lines) if response_lines else None
            
        except Exception as e:
            self._emit_log(f"⚠️ AT command error: {e}")
            return None
    
    def meta_read_imei_at(self) -> Optional[list]:
        """
        Read IMEI values using META AT commands.
        
        AT+EGMR=0,7  → IMEI 1
        AT+EGMR=0,10 → IMEI 2
        
        Returns:
            List of IMEI strings, or None if failed
        """
        if not self.meta_connected:
            self._emit_log("❌ Not connected in META mode")
            return None
        
        self._emit_log("📱 Reading IMEI via META AT commands...")
        imeis = []
        
        for slot, egmr_id in [(1, 7), (2, 10)]:
            resp = self.meta_at_command(f"AT+EGMR=0,{egmr_id}")
            if resp:
                self._emit_log(f"   IMEI {slot} response: {resp}")
                # Parse +EGMR: "IMEI_VALUE"
                for line in resp.split("\n"):
                    if "+EGMR:" in line:
                        # Extract quoted value
                        import re
                        match = re.search(r'"(\d{15})"', line)
                        if match:
                            imei = match.group(1)
                            self._emit_log(f"   ✅ IMEI {slot}: {imei}")
                            imeis.append(imei)
                            break
                else:
                    self._emit_log(f"   ⚠️ Could not parse IMEI {slot} from response")
            else:
                self._emit_log(f"   ⚠️ No response for IMEI {slot}")
        
        if imeis:
            self._emit_log(f"✅ Found {len(imeis)} IMEI(s) via META")
            return imeis
        return None
    
    def meta_write_imei_at(self, imei: str, slot: int = 1) -> bool:
        """
        Write IMEI value using META AT commands.
        
        AT+EGMR=1,7,"IMEI"  → Write IMEI 1
        AT+EGMR=1,10,"IMEI" → Write IMEI 2
        
        Args:
            imei: 15-digit IMEI string
            slot: IMEI slot (1 or 2)
            
        Returns:
            True if write succeeded
        """
        if not self.meta_connected:
            self._emit_log("❌ Not connected in META mode")
            return False
        
        if len(imei) != 15 or not imei.isdigit():
            self._emit_log("❌ Invalid IMEI: must be exactly 15 digits")
            return False
        
        egmr_id = 7 if slot == 1 else 10
        self._emit_log(f"✏️ Writing IMEI {slot}: {imei}")
        
        resp = self.meta_at_command(f'AT+EGMR=1,{egmr_id},"{imei}"')
        if resp and "OK" in resp:
            self._emit_log(f"✅ IMEI {slot} written successfully!")
            return True
        elif resp and "ERROR" in resp:
            self._emit_log(f"❌ IMEI write failed: {resp}")
            return False
        else:
            self._emit_log(f"⚠️ Uncertain response: {resp}")
            return False
    
    def meta_check_network_lock_at(self) -> Optional[dict]:
        """
        Check network lock status using META AT commands.
        
        AT+CLCK="PN",2 → Query network personalization lock
        AT+CLCK="PU",2 → Query network subset lock
        AT+CLCK="PP",2 → Query service provider lock
        AT+CLCK="PC",2 → Query corporate lock
        
        Returns:
            Dict with lock statuses, or None if failed
        """
        if not self.meta_connected:
            self._emit_log("❌ Not connected in META mode")
            return None
        
        self._emit_log("🔒 Checking network lock status via META AT commands...")
        
        locks = {
            "PN": "Network Lock",
            "PU": "Network Subset Lock",
            "PP": "Service Provider Lock",
            "PC": "Corporate Lock",
        }
        
        results = {}
        for code, name in locks.items():
            resp = self.meta_at_command(f'AT+CLCK="{code}",2')
            if resp:
                if "+CLCK: 1" in resp:
                    self._emit_log(f"   🔒 {name}: LOCKED")
                    results[code] = True
                elif "+CLCK: 0" in resp:
                    self._emit_log(f"   🔓 {name}: UNLOCKED")
                    results[code] = False
                else:
                    self._emit_log(f"   ❓ {name}: {resp}")
                    results[code] = None
            else:
                self._emit_log(f"   ⚠️ {name}: No response")
                results[code] = None
        
        locked_count = sum(1 for v in results.values() if v is True)
        if locked_count > 0:
            self._emit_log(f"⚠️ {locked_count} lock(s) detected!")
        else:
            self._emit_log("✅ No active network locks detected")
        
        return results
    
    def meta_unlock_network_at(self, nck_code: str, lock_type: str = "PN") -> bool:
        """
        Apply NCK (Network Control Key) to unlock carrier lock via META AT commands.
        
        Uses standard 3GPP AT+CLCK command — same as entering the code on the phone.
        
        Lock types:
            PN = Network personalization (most common carrier lock)
            PU = Network subset
            PP = Service provider
            PC = Corporate
        
        Args:
            nck_code: The unlock code (from carrier or service)
            lock_type: Lock facility code (default "PN" = network lock)
            
        Returns:
            True if unlock succeeded
        """
        if not self.meta_connected:
            self._emit_log("❌ Not connected in META mode")
            return False
        
        lock_names = {
            "PN": "Network Lock",
            "PU": "Network Subset Lock",
            "PP": "Service Provider Lock",
            "PC": "Corporate Lock",
        }
        name = lock_names.get(lock_type, lock_type)
        
        self._emit_log(f"🔓 Applying NCK to {name}...")
        self._emit_log(f"   Code: {nck_code}")
        self._emit_log(f"   Command: AT+CLCK=\"{lock_type}\",0,\"{nck_code}\"")
        
        # AT+CLCK="PN",0,"code" — mode 0 = unlock
        resp = self.meta_at_command(f'AT+CLCK="{lock_type}",0,"{nck_code}"', timeout=10)
        
        if resp:
            self._emit_log(f"   Response: {resp}")
            if "OK" in resp and "ERROR" not in resp:
                self._emit_log(f"   ✅ {name} UNLOCKED successfully!")
                return True
            elif "+CME ERROR: 16" in resp:
                self._emit_log(f"   ❌ INCORRECT CODE — wrong NCK for this device")
                self._emit_log(f"   ⚠️ Too many wrong attempts can permanently lock!")
                return False
            elif "+CME ERROR: 12" in resp:
                self._emit_log(f"   ❌ PERMANENTLY LOCKED — too many failed attempts")
                return False
            elif "+CME ERROR: 3" in resp:
                self._emit_log(f"   ❌ Operation not allowed (lock type not supported)")
                return False
            elif "+CME ERROR" in resp:
                self._emit_log(f"   ❌ Modem error: {resp}")
                return False
            else:
                self._emit_log(f"   ⚠️ Unexpected response")
                return False
        else:
            self._emit_log("   ❌ No response from modem")
            return False
    
    def meta_try_engineering_codes(self) -> Optional[str]:
        """
        Try known default/engineering NCK codes via META AT commands.
        
        Many budget MTK devices (Tinno, Navon, generic Chinese ODMs) ship with
        default engineering codes. Professional tools maintain databases of these.
        
        Returns:
            The working code if found, None if all failed
        """
        if not self.meta_connected:
            self._emit_log("❌ Not connected in META mode")
            return None
        
        # First check if actually locked
        self._emit_log("🔧 Engineering Code Unlock Attempt")
        self._emit_log("━" * 50)
        self._emit_log("📋 Step 1: Checking current lock status...")
        
        resp = self.meta_at_command('AT+CLCK="PN",2')
        if resp and "+CLCK: 0" in resp:
            self._emit_log("   ✅ Device is already UNLOCKED — no code needed!")
            return "already_unlocked"
        elif resp and "+CLCK: 1" in resp:
            self._emit_log("   🔒 Network lock is ACTIVE — trying codes...")
        else:
            self._emit_log(f"   ❓ Could not determine status: {resp}")
            self._emit_log("   Trying codes anyway...")
        
        # Known default/engineering NCK codes
        # These are well-documented defaults from MTK reference designs
        # and budget device manufacturers
        engineering_codes = [
            ("00000000", "Generic default (8 zeros)"),
            ("0000000000000000", "Generic default (16 zeros)"),
            ("1234567890123456", "Common test code"),
            ("12345678", "Common 8-digit default"),
            ("20150327", "Navon/Tinno engineering (documented)"),
            ("11111111", "Generic ones"),
            ("00000001", "Default variant"),
            ("1111111111111111", "Generic 16-digit ones"),
            ("0123456789012345", "Sequential test"),
            ("99999999", "Max 8-digit"),
            ("FFFFFFFF", "Hex max (some devices accept hex)"),
        ]
        
        self._emit_log(f"📋 Step 2: Trying {len(engineering_codes)} known codes...")
        self._emit_log("   ⚠️ Each wrong attempt may count against retry limit!")
        self._emit_log("")
        
        # Check retry count first if possible
        retry_resp = self.meta_at_command('AT+EPBSE?')
        if retry_resp and "+EPBSE:" in retry_resp:
            self._emit_log(f"   Retry info: {retry_resp}")
        
        for i, (code, desc) in enumerate(engineering_codes):
            self._emit_log(f"   [{i+1}/{len(engineering_codes)}] Trying: {code} ({desc})")
            
            resp = self.meta_at_command(f'AT+CLCK="PN",0,"{code}"', timeout=5)
            
            if resp:
                if "OK" in resp and "ERROR" not in resp:
                    self._emit_log(f"   🎉 CODE ACCEPTED: \"{code}\"")
                    self._emit_log(f"   ✅ Network lock REMOVED!")
                    self._emit_log("")
                    self._emit_log(f"   💡 Save this code: {code}")
                    self._emit_log(f"   It may be needed again after factory reset.")
                    return code
                elif "+CME ERROR: 12" in resp:
                    self._emit_log(f"   🛑 PERMANENTLY LOCKED — stopping (no more retries)")
                    return None
                elif "+CME ERROR: 16" in resp:
                    # Wrong code — continue
                    pass
                elif "+CME ERROR: 3" in resp:
                    self._emit_log(f"   ❌ Lock type not supported on this device")
                    return None
                else:
                    # Unknown error — try next
                    pass
            
            # Re-check if we're still locked (some devices don't return OK)
            verify = self.meta_at_command('AT+CLCK="PN",2')
            if verify and "+CLCK: 0" in verify:
                self._emit_log(f"   🎉 Device now UNLOCKED after code: {code}")
                return code
        
        self._emit_log("")
        self._emit_log("━" * 50)
        self._emit_log("❌ None of the engineering codes worked")
        self._emit_log("")
        self._emit_log("💡 This device uses a unique NCK. Options:")
        self._emit_log("   1. Contact your carrier for the official unlock code")
        self._emit_log("   2. Use an online unlock service (by IMEI)")
        self._emit_log("   3. Enter the code in the NCK field above")
        self._emit_log("━" * 50)
        return None
    
    def scan_sml_data(self) -> dict:
        """
        Deep scan for SIM lock (SML) data structures in device partitions.
        
        Scans protect1, protect2, nvdata, and nvram partitions for
        SIM ME Lock structures, lock state bytes, MCC/MNC allowlists,
        and retry counters.
        
        Returns:
            Dict with scan results
        """
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return {}
        
        self._emit_log("🔬 DEEP SIM LOCK DATA SCAN")
        self._emit_log("━" * 50)
        
        results = {
            'partitions_scanned': [],
            'lock_structures': [],
            'lock_state_candidates': [],
            'mcc_mnc_found': [],
        }
        
        # Partitions to scan — protect1/protect2 are the primary SML locations
        scan_partitions = [
            ("protect1", "SIM/Radio settings (primary SML location)"),
            ("protect2", "SIM/Radio settings (secondary)"),
            ("nvdata", "NVRAM data (IMEI, calibration, some lock data)"),
            ("nvcfg", "NVRAM config"),
        ]
        
        for part_name, description in scan_partitions:
            self._emit_log(f"\n📦 Scanning {part_name} — {description}")
            self._emit_log("─" * 40)
            
            try:
                data = self.da_handler.da_read_partition(partitionname=part_name, display=False)
                if not data or data == b"":
                    self._emit_log(f"   ⚠️ Could not read {part_name}")
                    continue
                
                results['partitions_scanned'].append(part_name)
                self._emit_log(f"   ✅ Read {len(data)} bytes")
                
                # --- SML marker scan ---
                sml_markers = {
                    b"SIMMELOCK": "SIMMELOCK (MTK SIM ME Lock)",
                    b"SML_LOCK": "SML_LOCK (SIM Lock control)",
                    b"SIM_LOCK": "SIM_LOCK (Generic)",
                    b"NW_LOCK": "NW_LOCK (Network Lock)",
                    b"NS_LOCK": "NS_LOCK (Network Subset Lock)",
                    b"SP_LOCK": "SP_LOCK (Service Provider Lock)",
                    b"CP_LOCK": "CP_LOCK (Corporate Lock)",
                    b"SIM_LOCK_MAGIC": "SIM_LOCK_MAGIC (Lock header)",
                    b"SML_CTRL": "SML_CTRL (Lock control)",
                    b"NETWORK_LOCK": "NETWORK_LOCK (Alt marker)",
                    b"SUBSET_LOCK": "SUBSET_LOCK (Alt marker)",
                }
                
                for marker, name in sml_markers.items():
                    pos = 0
                    count = 0
                    offsets = []
                    while True:
                        idx = data.find(marker, pos)
                        if idx == -1:
                            break
                        count += 1
                        offsets.append(idx)
                        pos = idx + len(marker)
                    
                    if count > 0:
                        self._emit_log(f"   🔍 {name}: {count}x")
                        results['lock_structures'].append({
                            'partition': part_name,
                            'marker': marker.decode('ascii', errors='replace'),
                            'count': count,
                            'offsets': offsets[:5],  # First 5
                        })
                        
                        # Dump context around first occurrence
                        first_offset = offsets[0]
                        context_start = max(0, first_offset - 8)
                        context_end = min(len(data), first_offset + len(marker) + 48)
                        context_hex = data[context_start:context_end].hex()
                        self._emit_log(f"      @ 0x{first_offset:X}: ...{context_hex}...")
                        
                        # Check for lock state byte patterns near markers
                        # Common pattern: marker + ... + 0x01 (locked) or 0x00 (unlocked)
                        for offset in offsets[:3]:
                            # Look for lock state byte in the 64 bytes after marker
                            region = data[offset:offset + 64]
                            
                            # Pattern: After SIM_LOCK or NW_LOCK, look for
                            # category(1 byte) + state(1 byte, 01=locked 00=unlocked)
                            # + retry_count(1-4 bytes)
                            if len(region) >= len(marker) + 4:
                                after = region[len(marker):]
                                results['lock_state_candidates'].append({
                                    'partition': part_name,
                                    'marker': marker.decode('ascii', errors='replace'),
                                    'offset': offset,
                                    'after_bytes': after[:16].hex(),
                                })
                
                # --- MCC/MNC pattern scan ---
                # SIM lock allowlists contain 3-digit MCC + 2-3 digit MNC
                # as ASCII strings or BCD encoded
                import re
                # Look for clusters of MCC/MNC codes (ASCII format like "310260")
                mccmnc_pattern = re.compile(rb'(?:(?:2[0-9]{2}|3[0-9]{2}|4[0-4][0-9])[0-9]{2,3}){3,}')
                for match in mccmnc_pattern.finditer(data):
                    pos = match.start()
                    raw = match.group()[:30]
                    self._emit_log(f"   📡 MCC/MNC cluster at 0x{pos:X}: {raw[:24].decode('ascii', errors='replace')}")
                    results['mcc_mnc_found'].append({
                        'partition': part_name,
                        'offset': pos,
                        'data': raw[:24].decode('ascii', errors='replace'),
                    })
                
                # --- LDI header scan for lock-related NVRAM items ---
                ldi_magic = b"\x4C\x44\x49\x00"
                ldi_pos = 0
                while ldi_pos < len(data) - 0x20:
                    ldi_pos = data.find(ldi_magic, ldi_pos)
                    if ldi_pos == -1:
                        break
                    try:
                        lid = int.from_bytes(data[ldi_pos+4:ldi_pos+6], 'little')
                        items = int.from_bytes(data[ldi_pos+6:ldi_pos+8], 'little')
                        itemsize = int.from_bytes(data[ldi_pos+8:ldi_pos+0xC], 'little')
                        attr = int.from_bytes(data[ldi_pos+0xC:ldi_pos+0x10], 'little')
                        
                        # Known SML-related LIDs (device-specific but common ranges)
                        # 0x063B = SIM ME Lock on some devices
                        # 0x0640-0x0650 = Lock-related range
                        if (0x0630 <= lid <= 0x0660) or (lid in (0x063B, 0x063C, 0x063D)):
                            self._emit_log(f"   🔐 SML LDI at 0x{ldi_pos:X}: LID=0x{lid:04X} "
                                         f"items={items} size=0x{itemsize:X} attr=0x{attr:04X}")
                            results['lock_structures'].append({
                                'partition': part_name,
                                'marker': f"LDI:0x{lid:04X}",
                                'count': 1,
                                'offsets': [ldi_pos],
                                'items': items,
                                'itemsize': itemsize,
                                'attr': attr,
                            })
                    except:
                        pass
                    ldi_pos += 4
                    
            except Exception as e:
                self._emit_log(f"   ❌ Error scanning {part_name}: {e}")
        
        # Summary
        self._emit_log("")
        self._emit_log("━" * 50)
        self._emit_log("📋 SCAN SUMMARY")
        self._emit_log(f"   Partitions scanned: {len(results['partitions_scanned'])}")
        self._emit_log(f"   Lock structures found: {len(results['lock_structures'])}")
        self._emit_log(f"   Lock state candidates: {len(results['lock_state_candidates'])}")
        self._emit_log(f"   MCC/MNC clusters: {len(results['mcc_mnc_found'])}")
        
        if results['lock_structures']:
            self._emit_log("")
            self._emit_log("💡 Lock data exists in this device.")
            self._emit_log("   For carrier unlock: get your NCK from your carrier")
            self._emit_log("   or an unlock service, then use 'Apply NCK' above.")
        else:
            self._emit_log("")
            self._emit_log("✅ No SIM lock structures found.")
            self._emit_log("   Device may be factory unlocked or uses")
            self._emit_log("   a non-standard lock mechanism.")
        
        self._emit_log("━" * 50)
        return results
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Legacy mtkclient wrapper methods removed - now integrated into set_meta_mode()
    # ═══════════════════════════════════════════════════════════════════════════
    
    def read_rpmb(self, output_file: str, sector: int = None, sectors: int = None) -> bool:
        """
        Read RPMB partition.
        
        Uses mtk.daloader.read_rpmb() directly (from mtkclient 2.1.2).
        """
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log("🔐 Reading RPMB - the manufacturer's secret vault!")
            self._emit_log(f"📥 Output file: {output_file}")
            if sector is not None:
                self._emit_log(f"   Start sector: {sector}")
            if sectors is not None:
                self._emit_log(f"   Sector count: {sectors}")
            
            # Use mtk.daloader.read_rpmb directly - it returns True/False
            # Convert sector/sectors to string format as expected by read_rpmb
            sector_str = str(sector) if sector is not None else None
            sectors_str = str(sectors) if sectors is not None else None
            
            result = self.mtk.daloader.read_rpmb(
                filename=output_file,
                sector=sector_str,
                sectors=sectors_str
            )
            
            if result and os.path.exists(output_file):
                size = os.path.getsize(output_file)
                self._emit_log(f"✅ RPMB extracted: {output_file} ({size} bytes)")
                return True
            else:
                self._emit_log("❌ Failed to read RPMB")
                return False
            
        except Exception as e:
            self._emit_log(f"❌ Error reading RPMB: {e}")
            import traceback
            self._emit_log(traceback.format_exc())
            return False
    
    def write_rpmb(self, input_file: str, sector: int = None, sectors: int = None) -> bool:
        """
        Write to RPMB partition.
        
        Uses mtk.daloader.write_rpmb() directly (from mtkclient 2.1.2).
        
        ⚠️ DANGER: RPMB contains critical device security data!
        Writing incorrect data can PERMANENTLY BRICK your device.
        
        Only use this if you know EXACTLY what you're doing.
        
        Args:
            input_file: File to write from
            sector: Start sector (offset/0x100 bytes)
            sectors: Number of sectors to write
        """
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log("🔐 RPMB WRITE - Entering the danger zone!")
            self._emit_log("⚠️ WARNING: RPMB write can brick device if data is incorrect!")
            self._emit_log("🏴 But your device, your risk, your freedom!")
            
            if not os.path.exists(input_file):
                self._emit_log(f"❌ File not found: {input_file}")
                return False
            
            self._emit_log(f"📤 Input file: {input_file}")
            if sector is not None:
                self._emit_log(f"   Start sector: {sector}")
            if sectors is not None:
                self._emit_log(f"   Sector count: {sectors}")
            
            # Use mtk.daloader.write_rpmb directly - it returns True/False
            result = self.mtk.daloader.write_rpmb(
                filename=input_file,
                sector=sector if sector is not None else 0,
                sectors=sectors
            )
            
            if result:
                self._emit_log("━" * 45)
                self._emit_log("✅ RPMB written! Security blob updated!")
                return True
            else:
                self._emit_log("❌ Failed to write RPMB")
                return False
            
        except Exception as e:
            self._emit_log(f"❌ Error writing RPMB: {e}")
            import traceback
            self._emit_log(traceback.format_exc())
            return False
    
    def erase_rpmb(self, sector: int = None, sectors: int = None) -> bool:
        """
        Erase RPMB partition.
        
        Uses mtk.daloader.erase_rpmb() directly (from mtkclient 2.1.2).
        
        ⚠️ EXTREME DANGER: This erases security-critical data!
        Your device may become unbootable without proper RPMB content.
        
        Args:
            sector: Start sector to erase
            sectors: Number of sectors to erase
        """
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log("🔐 RPMB ERASE - Total security wipe!")
            self._emit_log("💀 WARNING: This deletes manufacturer security data!")
            self._emit_log("🏴 Breaking all chains... no going back!")
            
            if sector is not None:
                self._emit_log(f"   Start sector: {sector}")
            if sectors is not None:
                self._emit_log(f"   Sector count: {sectors}")
            
            # Use mtk.daloader.erase_rpmb directly - it returns True/False
            result = self.mtk.daloader.erase_rpmb(
                sector=sector if sector is not None else 0,
                sectors=sectors
            )
            
            if result:
                self._emit_log("━" * 45)
                self._emit_log("✅ RPMB erased! Device security wiped!")
                return True
            else:
                self._emit_log("❌ Failed to erase RPMB")
                return False
            
        except Exception as e:
            self._emit_log(f"❌ Error erasing RPMB: {e}")
            import traceback
            self._emit_log(traceback.format_exc())
            return False
    
    def auth_rpmb(self, rpmb_key: str = None) -> bool:
        """
        Authenticate RPMB with key.
        
        Uses mtk.daloader.auth_rpmb() directly (from mtkclient 2.1.2).
        
        Required for RPMB operations on locked devices.
        
        Args:
            rpmb_key: RPMB key as hexstring (32 bytes)
        """
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log("🔑 RPMB AUTH - Bypassing security checks!")
            
            # Convert hex string to bytes if provided
            rpmbkey_bytes = None
            if rpmb_key:
                try:
                    rpmbkey_bytes = bytes.fromhex(rpmb_key)
                    self._emit_log(f"   Using key: {rpmb_key[:16]}...")
                except ValueError as e:
                    self._emit_log(f"❌ Invalid RPMB key format: {e}")
                    return False
            
            # Use mtk.daloader.auth_rpmb directly - it returns True/False
            result = self.mtk.daloader.auth_rpmb(rpmbkey=rpmbkey_bytes)
            
            if result:
                self._emit_log("━" * 45)
                self._emit_log("✅ RPMB authenticated! Full access granted!")
                return True
            else:
                self._emit_log("❌ RPMB authentication failed")
                return False
            
        except Exception as e:
            self._emit_log(f"❌ Error authenticating RPMB: {e}")
            import traceback
            self._emit_log(traceback.format_exc())
            return False
    
    def get_target_config(self) -> Optional[Dict]:
        """Get target security configuration (SBC, DAA, SLA status)."""
        if not self.connected or not self.mtk:
            self._emit_log("❌ Device not connected")
            return None
        
        try:
            self._emit_log("🔍 Analyzing device security config...")
            
            config = {}
            
            # Try to get target_config from multiple locations
            tc = None
            
            # Method 1: Direct target_config attribute
            if hasattr(self.mtk.config, 'target_config') and self.mtk.config.target_config:
                tc = self.mtk.config.target_config
                self._emit_log("   (Using config.target_config)")
            
            # Method 2: Try chipconfig
            elif hasattr(self.mtk.config, 'chipconfig') and self.mtk.config.chipconfig:
                cc = self.mtk.config.chipconfig
                if hasattr(cc, 'damode'):
                    tc = {
                        'sbc': getattr(cc, 'sbc', False),
                        'sla': getattr(cc, 'sla', False),
                        'daa': getattr(cc, 'daa', False),
                    }
                    self._emit_log("   (Using chipconfig)")
            
            # Method 3: Try daloader if available
            if not tc and hasattr(self.mtk, 'daloader') and self.mtk.daloader:
                try:
                    # Some DA loaders have get_dev_info or similar
                    if hasattr(self.mtk.daloader, 'daconfig'):
                        dc = self.mtk.daloader.daconfig
                        if dc:
                            tc = {
                                'sbc': getattr(dc, 'sbc', False),
                                'sla': getattr(dc, 'sla', False),
                                'daa': getattr(dc, 'daa', False),
                            }
                            self._emit_log("   (Using daloader.daconfig)")
                except Exception:
                    pass
            
            if tc:
                # Handle both dict-like and object-like access
                if isinstance(tc, dict):
                    config = {
                        'sbc': tc.get('sbc', False),
                        'sla': tc.get('sla', False),
                        'daa': tc.get('daa', False),
                    }
                else:
                    config = {
                        'sbc': getattr(tc, 'sbc', False),
                        'sla': getattr(tc, 'sla', False),
                        'daa': getattr(tc, 'daa', False),
                    }
                
                self._emit_log(f"📋 Security Status:")
                self._emit_log(f"   SBC (Secure Boot): {'🔒 ENABLED' if config['sbc'] else '🔓 DISABLED'}")
                self._emit_log(f"   SLA (Auth): {'🔒 ENABLED' if config['sla'] else '🔓 DISABLED'}")
                self._emit_log(f"   DAA (DA Auth): {'🔒 ENABLED' if config['daa'] else '🔓 DISABLED'}")
                
                if not any(config.values()):
                    self._emit_log("🏴 DEVICE IS FULLY EXPLOITABLE! No restrictions!")
                else:
                    self._emit_log("⚠️ Device has security restrictions - but we can bypass!")
                
                return config
            else:
                # No target config available - report what we know
                self._emit_log("⚠️ Security config not available in current mode")
                self._emit_log(f"📱 Device Mode: {'DA' if not self.mtk.config.is_brom else 'BROM'}")
                
                # Return basic info we do have
                config = {
                    'mode': 'DA' if not self.mtk.config.is_brom else 'BROM',
                    'hwcode': hex(self.mtk.config.hwcode) if self.mtk.config.hwcode else 'Unknown',
                    'chip': self.mtk.config.chipconfig.name if self.mtk.config.chipconfig else 'Unknown',
                }
                self._emit_log(f"📱 HW Code: {config['hwcode']}")
                self._emit_log(f"📱 Chip: {config['chip']}")
                self._emit_log("💡 Try partition operations - they should work!")
                return config
            
        except Exception as e:
            self._emit_log(f"❌ Error reading config: {e}")
            import traceback
            self._emit_log(traceback.format_exc())
            return None
    
    def reset_device(self) -> bool:
        """Send reset command to device."""
        if not self.connected or not self.da_handler:
            self._emit_log("❌ Device not connected")
            return False
        
        try:
            self._emit_log("🔄 Sending reset command...")
            
            # Clean up state file
            state_file = os.path.join(self.mtk.config.hwparam_path, ".state")
            if os.path.exists(state_file):
                os.remove(state_file)
            
            # Use safe shutdown (bypasses fatal port.close(reset=True))
            self._send_da_shutdown(bootmode=0)
            
            # Close port safely
            try:
                if hasattr(self.mtk, 'port') and self.mtk.port:
                    self.mtk.port.close(reset=False)
            except Exception:
                pass
            
            self._emit_log("✅ Reset sent - disconnect USB to power off")
            self.connected = False
            self.mtk = None
            self.da_handler = None
            self.set_mode("Disconnected")
            self.connected_signal.emit(False)
            return True
            
        except Exception as e:
            self._emit_log(f"❌ Error resetting: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from device."""
        self._emit_log("🔌 Disconnecting...")
        self.connected = False
        self.partitions = []
        self.device_info = {}
        
        # Clean up META serial connection if active
        if hasattr(self, 'meta_serial') and self.meta_serial:
            try:
                self.disconnect_meta_serial()
            except Exception:
                pass
        
        # Restore stdout if we captured it
        if self._original_stdout and self._stdout_capture:
            try:
                sys.stdout = self._original_stdout
                self._stdout_capture = None
            except Exception:
                pass
        
        # Clean up logging handler
        if self._logging_handler:
            try:
                # Remove from all loggers we added to
                mtkclient_loggers = [
                    'mtkclient', 'Preloader', 'DA', 'META', 'Port', 'Config',
                    'GCpu', 'Dxcc', 'Sej', 'Cqdma', 'HwCrypto', 'Exploitation',
                    'usb', 'usb.core', 'LibUsb1Backend', 'PLTools', 'DAXFlash'
                ]
                for logger_name in mtkclient_loggers:
                    logger = logging.getLogger(logger_name)
                    logger.removeHandler(self._logging_handler)
                logging.getLogger().removeHandler(self._logging_handler)
            except Exception:
                pass
        
        try:
            self.connected_signal.emit(False)
        except Exception:
            pass


# Global device handler instance (persistent connection)
_device_handler: Optional[MtkDeviceHandler] = None

def get_device_handler() -> MtkDeviceHandler:
    """Get or create the global device handler."""
    global _device_handler
    if _device_handler is None:
        _device_handler = MtkDeviceHandler()
    return _device_handler


# ═══════════════════════════════════════════════════════════════════════════════
# Worker Thread for MTK Operations
# ═══════════════════════════════════════════════════════════════════════════════

class MtkWorkerThread(QThread):
    """Worker thread for MTK operations."""
    progress = pyqtSignal(int, int, str)  # current, total, message
    log = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)
    result_data = pyqtSignal(object)
    
    def __init__(self, operation: str, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
        self._cancelled = False
        self.process = None
    
    def cancel(self):
        self._cancelled = True
        if self.process:
            self.process.terminate()
    
    # Track last message to prevent duplicates
    _last_log_message = ""
    _log_repeat_count = 0
    
    def _log_callback(self, line: str):
        """Callback for streaming log output."""
        import re
        # Strip ANSI escape codes
        clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line).rstrip()
        clean_line = re.sub(r'\?0\[0m', '', clean_line)  # Corrupted ANSI codes
        
        if not clean_line:
            return
        
        # Filter out spammy/useless messages
        spam_patterns = [
            "Couldn't detect the device",
            "Couldn't get device configuration",
            "Handshake failed, retrying",
            "Is it connected",
            "Status: Waiting",
            "retrying...",
        ]
        
        # Check if this is spam
        for pattern in spam_patterns:
            if pattern.lower() in clean_line.lower():
                return  # Skip spam
        
        # Skip lines that are just class names (e.g., "Preloader", "DeviceClass", ".DeviceClass")
        stripped = clean_line.strip()
        if stripped in ['Preloader', 'DeviceClass', '.DeviceClass', 'Port', 'Port -']:
            return
        
        # Skip if timestamp-only lines like "[09:02:11] Preloader"
        if re.match(r'^\[\d{2}:\d{2}:\d{2}\]\s*(Preloader|DeviceClass|\.DeviceClass|Port)?\s*$', stripped):
            return
        
        # Dedupe consecutive identical messages
        if clean_line == MtkWorkerThread._last_log_message:
            MtkWorkerThread._log_repeat_count += 1
            if MtkWorkerThread._log_repeat_count > 2:
                return  # Already shown, skip duplicates
        else:
            MtkWorkerThread._last_log_message = clean_line
            MtkWorkerThread._log_repeat_count = 0
        
        self.log.emit(clean_line)
        
        # Parse progress if possible
        if '%' in clean_line:
            try:
                match = re.search(r'(\d+)%', clean_line)
                if match:
                    percent = int(match.group(1))
                    self.progress.emit(percent, 100, line.rstrip())
            except:
                pass
    
    def run(self):
        try:
            if self.operation == "check_device":
                self._check_device()
            elif self.operation == "get_info":
                self._get_device_info()
            elif self.operation == "read_partition":
                self._read_partition()
            elif self.operation == "read_flash":
                self._read_flash()
            elif self.operation == "write_partition":
                self._write_partition()
            elif self.operation == "write_flash":
                self._write_flash()
            elif self.operation == "erase_partition":
                self._erase_partition()
            elif self.operation == "unlock_bootloader":
                self._unlock_bootloader()
            elif self.operation == "lock_bootloader":
                self._lock_bootloader()
            elif self.operation == "erase_frp":
                self._erase_frp()
            elif self.operation == "dump_preloader":
                self._dump_preloader()
            elif self.operation == "dump_brom":
                self._dump_brom()
            elif self.operation == "get_gpt":
                self._get_gpt()
            elif self.operation == "dump_seccfg":
                self._dump_seccfg()
            elif self.operation == "reset_seccfg":
                self._reset_seccfg()
            elif self.operation == "get_rpmb":
                self._get_rpmb()
            elif self.operation == "custom_command":
                self._custom_command()
            # NEW v2.1.2 Operations
            elif self.operation == "patch_vbmeta":
                self._patch_vbmeta()
            elif self.operation == "read_imei":
                self._read_imei()
            elif self.operation == "write_imei":
                self._write_imei()
            elif self.operation == "patch_modem":
                self._patch_modem()
            elif self.operation == "read_efuses":
                self._read_efuses()
            elif self.operation == "memory_dump":
                self._memory_dump()
            elif self.operation == "set_meta_mode":
                self._set_meta_mode()
            elif self.operation == "get_target_config":
                self._get_target_config()
            elif self.operation == "reset_device":
                self._reset_device()
            elif self.operation == "read_rpmb":
                self._read_rpmb()
            elif self.operation == "write_rpmb":
                self._write_rpmb()
            elif self.operation == "erase_rpmb":
                self._erase_rpmb()
            elif self.operation == "auth_rpmb":
                self._auth_rpmb()
            elif self.operation == "scan_sml_data":
                self._scan_sml_data_worker()
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.finished_signal.emit(False, str(e))
    
    def _check_device(self):
        """Check for device in BROM/Preloader mode using Python library."""
        self.log.emit("━" * 45)
        self.log.emit("🔍 CONNECTING TO MEDIATEK DEVICE...")
        self.log.emit("━" * 45)
        self.log.emit("💡 Device must be in BROM or Preloader mode:")
        self.log.emit("   1. Device should be OFF")
        self.log.emit("   2. Hold Volume Down (or both Vol buttons)")
        self.log.emit("   3. While holding, connect USB cable")
        self.log.emit("━" * 45)
        
        # Get device handler
        handler = get_device_handler()
        
        # Check if library is available
        if not handler.is_library_available():
            self.log.emit(f"⚠️ mtkclient library not available: {handler.get_library_error()}")
            self.log.emit("📌 Falling back to CLI mode...")
            self._check_device_cli()
            return
        
        # Connect handler log signal to our log
        def log_handler(msg):
            self.log.emit(msg)
        
        handler.log_signal.connect(log_handler)
        
        try:
            # Initialize if needed
            if not handler.mtk:
                if not handler.initialize():
                    self.log.emit("❌ Failed to initialize MTK library")
                    self.result_data.emit({"detected": False, "error": "Init failed"})
                    self.finished_signal.emit(False, "Failed to initialize MTK library")
                    return
            
            # Try to connect
            output_dir = self.kwargs.get('output_dir', os.getcwd())
            if handler.connect_device(output_dir):
                # Successfully connected!
                result_data = {
                    "detected": True,
                    "connected": True,
                    "cpu": handler.device_info.get('chipset', 'Unknown'),
                    "hw_code": handler.device_info.get('hw_code', 'Unknown'),
                    "boot_mode": handler.device_info.get('boot_mode', 'Unknown'),
                }
                
                # Get partitions (wrapped in separate try to avoid crash on gpt read)
                try:
                    data, guid_gpt = handler.get_gpt()
                    if handler.partitions:
                        result_data["partitions"] = [p['name'] for p in handler.partitions]
                        self.log.emit(f"🏴 CONQUERED {len(handler.partitions)} PARTITIONS!")
                        self.log.emit("⚔️ The device's secrets are now exposed!")
                except Exception as gpt_err:
                    self.log.emit(f"⚠️ Could not read GPT: {gpt_err}")
                    self.log.emit("💡 Device connected but partition list unavailable")
                
                try:
                    self.result_data.emit(result_data)
                    self.log.emit("━" * 45)
                    self.log.emit("🔥 DEVICE CAPTURED! THE REBELLION HAS BEGUN!")
                    self.log.emit("⚡ All operations now use persistent connection")
                    self.log.emit("💀 OEM restrictions? What restrictions?")
                    self.log.emit("━" * 45)
                    self.finished_signal.emit(True, f"🔥 DEVICE PWNED - {handler.device_info.get('boot_mode', 'Liberation complete')}!")
                except Exception:
                    pass  # Signal emission error
            else:
                self.log.emit("━" * 45)
                self.log.emit("🔴 DEVICE NOT DETECTED OR CONNECTION FAILED!")
                self.log.emit("📱 Make sure you're entering BROM mode correctly:")
                self.log.emit("   • Device must be completely powered OFF")
                self.log.emit("   • Hold volume button BEFORE plugging USB")
                self.log.emit("   • Keep holding until capture succeeds")
                self.log.emit("━" * 45)
                self.result_data.emit({"detected": False})
                self.finished_signal.emit(False, "Device not detected - check BROM mode entry")
                
        except Exception as e:
            self.log.emit(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
            self.result_data.emit({"detected": False, "error": str(e)})
            self.finished_signal.emit(False, str(e))
        finally:
            try:
                handler.log_signal.disconnect(log_handler)
            except:
                pass
    
    def _check_device_cli(self):
        """Fallback CLI-based device check."""
        self.log.emit("🔌 Waiting for device in BROM/Preloader mode...")
        self.log.emit("💡 Connect device while holding Volume buttons")
        # Use a shorter timeout command - just check once, don't loop forever
        success, output = run_mtk_command(["printgpt"], callback=self._log_callback)
        
        output_lower = output.lower()
        
        # Check for SUCCESS indicators first (GPT table was read = success!)
        detected = (
            "gpt table" in output_lower or
            "total disk size" in output_lower or
            "device detected :)" in output_lower or
            "brom mode detected" in output_lower or
            "successfully uploaded" in output_lower or
            "offset 0x" in output_lower or  # Partition entries have "Offset 0x"
            success
        )
        
        if detected:
            result_data = {"detected": True, "output": output, "cli_mode": True}
            partitions = self._parse_partitions(output)
            if partitions:
                result_data["partitions"] = partitions
                self.log.emit(f"🏴 CONQUERED {len(partitions)} PARTITIONS!")
            self.result_data.emit(result_data)
            self.finished_signal.emit(True, f"🔥 Device captured! ({len(partitions) if partitions else 0} partitions)")
        else:
            # Only report failure if we didn't detect anything useful
            self.result_data.emit({"detected": False, "output": output})
            self.finished_signal.emit(False, "No device detected - check BROM mode entry")
    
    def _parse_partitions(self, output: str) -> list:
        """Parse partition names from mtkclient output.
        
        mtkclient output format:
        GPT Table:
        -------------
        boot:                Offset 0x..., Length 0x..., Flags 0x...
        recovery:            Offset 0x..., Length 0x..., Flags 0x...
        """
        partitions = []
        lines = output.split('\n')
        in_table = False
        
        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue
            
            # Detect "GPT Table:" or similar header
            if 'GPT Table' in line or 'gpt table' in line.lower():
                in_table = True
                continue
            
            # Skip separator lines
            if line_stripped.startswith('-') or line_stripped.startswith('='):
                continue
            
            if in_table:
                # mtkclient format: "partition_name:      Offset 0x..., Length 0x..."
                # The partition name ends with colon and is followed by spaces and "Offset"
                if 'Offset 0x' in line and ':' in line:
                    # Extract partition name (everything before the colon that precedes "Offset")
                    parts = line.split(':')
                    if len(parts) >= 2:
                        # First part is the partition name
                        part_name = parts[0].strip()
                        if part_name and not part_name.startswith('0x'):
                            partitions.append(part_name)
                # Alternative format: "name: Offset" directly
                elif ':' in line and 'Offset' in line:
                    part_name = line.split(':')[0].strip()
                    if part_name and not part_name.startswith('0x') and part_name.lower() not in ['gpt', 'table']:
                        partitions.append(part_name)
        
        # Fallback: look for lines with "Offset" and extract the name before colon
        if not partitions:
            for line in lines:
                if 'Offset' in line and ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        part_name = parts[0].strip()
                        if part_name and not part_name.lower().startswith(('0x', 'gpt', 'total')):
                            if part_name not in partitions:
                                partitions.append(part_name)
        
        # Second fallback: any line that looks like "name   0x..." pattern
        if not partitions:
            import re
            for line in lines:
                # Match: "partition_name" followed by hex values
                match = re.match(r'^(\w+)\s+(?:Offset\s+)?0x', line.strip())
                if match:
                    part_name = match.group(1)
                    if part_name.lower() not in ['gpt', 'table', 'total', 'disk']:
                        if part_name not in partitions:
                            partitions.append(part_name)
        
        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for p in partitions:
            p_lower = p.lower()
            if p_lower not in seen:
                seen.add(p_lower)
                unique.append(p)
        
        return unique
    
    def _get_device_info(self):
        """Get device information using library."""
        self.log.emit("📱 Getting device information...")
        
        handler = get_device_handler()
        
        if handler.connected and handler.device_info:
            self.result_data.emit(handler.device_info)
            self.finished_signal.emit(True, "Device info retrieved")
        else:
            self.log.emit("⚠️ Device not connected. Click Connect first.")
            self.result_data.emit({})
            self.finished_signal.emit(False, "Device not connected")
    
    def _read_partition(self):
        """Read a specific partition using persistent connection."""
        partition = self.kwargs.get('partition', '')
        base_output_dir = self.kwargs.get('output_dir', os.getcwd())
        
        # Create partition-specific subfolder (e.g., output/boot/ for boot.img)
        output_dir = os.path.join(base_output_dir, partition)
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"{partition}.img")
        
        self.log.emit(f"📥 Reading partition: {partition}")
        self.log.emit("━" * 45)
        
        handler = get_device_handler()
        
        # Check if library mode is available and connected
        if handler.is_library_available() and handler.connected:
            self.log.emit("🔗 Using persistent connection (Library Mode)")
            
            # Connect handler log signal
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            
            try:
                # Check if base partition exists, or if we should try A/B slots directly
                base_exists = handler.partition_exists(partition)
                a_slot_exists = handler.partition_exists(f"{partition}_a")
                
                # If base doesn't exist but _a does, go directly to A/B mode
                if not base_exists and a_slot_exists:
                    self.log.emit(f"🔀 Partition '{partition}' is A/B - trying slot _a")
                    slot_partition = f"{partition}_a"
                    slot_file = os.path.join(output_dir, f"{slot_partition}.img")
                    
                    if handler.read_partition(slot_partition, slot_file):
                        if os.path.exists(slot_file) and os.path.getsize(slot_file) > 0:
                            size = os.path.getsize(slot_file)
                            self.log.emit(f"🏴 A/B SLOT CONQUERED: {slot_file}")
                            self.log.emit(f"📦 Size: {size / (1024*1024):.1f} MB EXTRACTED!")
                            self.finished_signal.emit(True, slot_file)
                            return
                    
                    # Try slot B if A failed
                    slot_partition = f"{partition}_b"
                    slot_file = os.path.join(output_dir, f"{slot_partition}.img")
                    self.log.emit(f"📥 Trying slot _b: {slot_partition}")
                    
                    if handler.read_partition(slot_partition, slot_file):
                        if os.path.exists(slot_file) and os.path.getsize(slot_file) > 0:
                            size = os.path.getsize(slot_file)
                            self.log.emit(f"🏴 A/B SLOT CONQUERED: {slot_file}")
                            self.log.emit(f"📦 Size: {size / (1024*1024):.1f} MB EXTRACTED!")
                            self.finished_signal.emit(True, slot_file)
                            return
                    
                    self.finished_signal.emit(False, f"Failed to read partition: {partition}")
                    return
                
                # Try base partition first
                if handler.read_partition(partition, output_file):
                    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                        size = os.path.getsize(output_file)
                        self.log.emit(f"🏴 DATA LIBERATED: {output_file}")
                        self.log.emit(f"📦 Size: {size / (1024*1024):.1f} MB of FREEDOM!")
                        self.finished_signal.emit(True, output_file)
                        return
                
                # Base partition failed - try A/B slots (with silent_fail since this is fallback)
                for slot in ['_a', '_b']:
                    slot_partition = f"{partition}{slot}"
                    slot_file = os.path.join(output_dir, f"{slot_partition}.img")
                    self.log.emit(f"📥 Trying A/B partition: {slot_partition}")
                    
                    if handler.read_partition(slot_partition, slot_file, silent_fail=True):
                        if os.path.exists(slot_file) and os.path.getsize(slot_file) > 0:
                            size = os.path.getsize(slot_file)
                            self.log.emit(f"🏴 A/B SLOT CONQUERED: {slot_file}")
                            self.log.emit(f"📦 Size: {size / (1024*1024):.1f} MB EXTRACTED!")
                            self.finished_signal.emit(True, slot_file)
                            return
                
                self.finished_signal.emit(False, f"Failed to read partition: {partition}")
                
            except Exception as e:
                self.log.emit(f"❌ Error: {e}")
                self.finished_signal.emit(False, str(e))
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            # Not connected - tell user to connect first
            self.log.emit("━" * 45)
            self.log.emit("🔴 NO DEVICE CAPTURED YET!")
            self.log.emit("📱 Click 'Connect Device' to begin the liberation")
            self.log.emit("💡 Once connected, the portal stays open for all operations")
            self.log.emit("⚡ Your device awaits its freedom...")
            self.log.emit("━" * 45)
            self.finished_signal.emit(False, "Device not connected - begin the rebellion first!")
    
    def _read_flash(self):
        """Read full flash to file."""
        output_file = self.kwargs.get('output_file', 'flash_dump.bin')
        
        self.log.emit(f"📥 Reading full flash...")
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.read_flash(output_file):
                    if os.path.exists(output_file):
                        size = os.path.getsize(output_file)
                        self.log.emit(f"💣 FULL DEVICE CAPTURED: {output_file} ({size / (1024*1024*1024):.2f} GB)")
                        self.finished_signal.emit(True, output_file)
                    else:
                        self.finished_signal.emit(False, "Failed to read flash")
                else:
                    self.finished_signal.emit(False, "Failed to read flash")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _write_partition(self):
        """Write a partition using library."""
        partition = self.kwargs.get('partition', '')
        input_file = self.kwargs.get('input_file', '')
        
        self.log.emit(f"📤 Writing partition: {partition}")
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.write_partition(partition, input_file):
                    self.finished_signal.emit(True, f"🔥 {partition} WRITTEN SUCCESSFULLY!")
                else:
                    self.finished_signal.emit(False, f"Failed to write {partition}")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _write_flash(self):
        """Write full flash from file using library."""
        input_file = self.kwargs.get('input_file', '')
        
        self.log.emit(f"📤 Writing full flash from: {input_file}")
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.write_flash(input_file):
                    self.finished_signal.emit(True, "⚡ FLASH OVERWRITTEN - You own this device now!")
                else:
                    self.finished_signal.emit(False, "Failed to write flash")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _erase_partition(self):
        """Erase a partition using library."""
        partition = self.kwargs.get('partition', '')
        
        self.log.emit(f"💀 WIPING partition: {partition}")
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.erase_partition(partition):
                    self.finished_signal.emit(True, f"🗑️ {partition} OBLITERATED!")
                else:
                    self.finished_signal.emit(False, f"Failed to erase {partition}")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _unlock_bootloader(self):
        """Unlock bootloader using library."""
        self.log.emit("⚔️ BREAKING THE CHAINS - Unlocking bootloader...")
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.unlock_bootloader():
                    self.finished_signal.emit(True, "🔓 BOOTLOADER UNCHAINED! Freedom achieved!")
                else:
                    self.finished_signal.emit(False, "Failed to unlock bootloader")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _lock_bootloader(self):
        """Lock bootloader using library."""
        self.log.emit("🔒 Re-engaging security (why though?)...")
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.lock_bootloader():
                    self.finished_signal.emit(True, "🔒 Bootloader re-locked (conformist!)")
                else:
                    self.finished_signal.emit(False, "Failed to lock bootloader")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _erase_frp(self):
        """Erase FRP (Factory Reset Protection) using library."""
        self.log.emit("🏴 BYPASSING Google's grip on YOUR device...")
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.erase_partition("frp"):
                    self.log.emit("🔥 GOOGLE'S CHAINS HAVE BEEN BROKEN!")
                    self.log.emit("⚡ YOUR DEVICE IS NOW TRULY YOURS!")
                    self.finished_signal.emit(True, "💀 FRP ANNIHILATED! Freedom restored!")
                else:
                    self.finished_signal.emit(False, "Failed to erase FRP")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _dump_preloader(self):
        """Dump preloader from RAM using library or CLI."""
        output_dir = self.kwargs.get('output_dir', os.getcwd())
        output_file = os.path.join(output_dir, "preloader.bin")
        
        self.log.emit("📥 Dumping preloader from RAM...")
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.dump_preloader(output_file):
                    if os.path.exists(output_file):
                        self.log.emit(f"⚡ PRELOADER EXTRACTED: {output_file}")
                        self.finished_signal.emit(True, output_file)
                    else:
                        self.finished_signal.emit(False, "Preloader file not created")
                else:
                    self.finished_signal.emit(False, "Failed to dump preloader")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            # CLI fallback - use pldump command
            self.log.emit("📌 Using CLI mode for preloader dump...")
            success, output = run_mtk_command(
                ["pldump", "--out", output_dir],
                callback=self._log_callback
            )
            
            # Check for any .bin file created in output_dir with "preloader" in name
            import glob
            preloader_files = glob.glob(os.path.join(output_dir, "*preloader*.bin"))
            if not preloader_files:
                preloader_files = glob.glob(os.path.join(output_dir, "*.bin"))
            
            if preloader_files and os.path.exists(preloader_files[0]):
                self.log.emit(f"⚡ PRELOADER EXTRACTED: {preloader_files[0]}")
                self.finished_signal.emit(True, preloader_files[0])
            elif success:
                self.log.emit("✅ Preloader dump completed")
                self.finished_signal.emit(True, output_dir)
            else:
                self.finished_signal.emit(False, "Failed to dump preloader")
    
    def _dump_brom(self):
        """Dump Boot ROM using library or CLI."""
        output_dir = self.kwargs.get('output_dir', os.getcwd())
        output_file = os.path.join(output_dir, "brom.bin")
        
        self.log.emit("📥 Dumping Boot ROM...")
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.dump_brom(output_file):
                    if os.path.exists(output_file):
                        self.log.emit(f"🔥 BOOT ROM PWNED: {output_file}")
                        self.finished_signal.emit(True, output_file)
                    else:
                        self.finished_signal.emit(False, "BROM file not created")
                else:
                    self.finished_signal.emit(False, "Failed to dump BROM")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            # CLI fallback
            self.log.emit("📌 Using CLI mode for BROM dump...")
            success, output = run_mtk_command(
                ["dumpbrom", "--out", output_dir],
                callback=self._log_callback
            )
            
            import glob
            brom_files = glob.glob(os.path.join(output_dir, "*brom*.bin"))
            if brom_files and os.path.exists(brom_files[0]):
                self.log.emit(f"🔥 BOOT ROM PWNED: {brom_files[0]}")
                self.finished_signal.emit(True, brom_files[0])
            elif success:
                self.finished_signal.emit(True, output_dir)
            else:
                self.finished_signal.emit(False, "Failed to dump BROM")
    
    def _get_gpt(self):
        """Get GPT partition table using library."""
        output_dir = self.kwargs.get('output_dir', os.getcwd())
        
        self.log.emit("━" * 45)
        self.log.emit("📋 FETCHING GPT PARTITION TABLE...")
        self.log.emit("━" * 45)
        
        handler = get_device_handler()
        
        if handler.is_library_available() and handler.connected:
            self.log.emit("🔗 Using persistent connection (Library Mode)")
            
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            
            try:
                data, guid_gpt = handler.get_gpt()
                
                if handler.partitions:
                    partition_names = [p['name'] for p in handler.partitions]
                    self.log.emit(f"📋 Found {len(partition_names)} partitions")
                    self.result_data.emit({'partitions': partition_names, 'partition_data': handler.partitions})
                    self.finished_signal.emit(True, "GPT retrieved successfully")
                else:
                    self.log.emit("⚠️ No partitions found")
                    self.result_data.emit({'partitions': []})
                    self.finished_signal.emit(False, "No partitions found")
                    
            except Exception as e:
                self.log.emit(f"❌ Error: {e}")
                self.result_data.emit({'partitions': []})
                self.finished_signal.emit(False, str(e))
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected - click Connect first")
            self.result_data.emit({'partitions': []})
            self.finished_signal.emit(False, "Device not connected")
    
    def _dump_seccfg(self):
        """Dump seccfg partition using library."""
        output_dir = self.kwargs.get('output_dir', os.getcwd())
        output_file = os.path.join(output_dir, "seccfg.bin")
        
        self.log.emit("🔐 Extracting security config...")
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.read_partition("seccfg", output_file):
                    if os.path.exists(output_file):
                        self.log.emit(f"💀 SECCFG CAPTURED: {output_file}")
                        self.finished_signal.emit(True, output_file)
                    else:
                        self.finished_signal.emit(False, "seccfg file not created")
                else:
                    self.finished_signal.emit(False, "Failed to read seccfg")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _reset_seccfg(self):
        """Reset seccfg to unlock state using library."""
        self.log.emit("🔄 Resetting seccfg...")
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.unlock_bootloader():
                    self.finished_signal.emit(True, "seccfg reset")
                else:
                    self.finished_signal.emit(False, "Failed to reset seccfg")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _get_rpmb(self):
        """Extract RPMB/hardware keys using library."""
        output_dir = self.kwargs.get('output_dir', os.getcwd())
        
        self.log.emit("🔑 Extracting RPMB/hardware keys...")
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.generate_keys(output_dir):
                    self.finished_signal.emit(True, f"RPMB keys extracted to {output_dir}")
                else:
                    self.finished_signal.emit(False, "Failed to extract keys")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # NEW v2.1.2 Worker Methods - The Rebellion's New Weapons!
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _patch_vbmeta(self):
        """Patch vbmeta to disable verification/verity."""
        mode = self.kwargs.get('mode', 3)  # Default: disable both
        
        mode_names = {
            0: "RE-LOCK (why?!)",
            1: "DISABLE VERITY ONLY",
            2: "DISABLE VERIFICATION ONLY",
            3: "FULL FREEDOM (disable both)"
        }
        
        self.log.emit("━" * 45)
        self.log.emit("⚡ VBMETA PATCHING INITIATED!")
        self.log.emit(f"🎯 Mode: {mode_names.get(mode, 'Unknown')}")
        self.log.emit("━" * 45)
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.patch_vbmeta(mode):
                    self.log.emit("🏴 VBMETA CONQUERED! Android Verified Boot? More like Verified PWNED!")
                    self.finished_signal.emit(True, "vbmeta patched - Your device, your rules!")
                else:
                    self.finished_signal.emit(False, "Failed to patch vbmeta")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _read_imei(self):
        """Read and display IMEI values."""
        self.log.emit("━" * 45)
        self.log.emit("📱 IMEI EXTRACTION - Reading your device's identity...")
        self.log.emit("━" * 45)
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                imei_list = handler.read_imei()
                if imei_list is not None:
                    if len(imei_list) > 0:
                        self.log.emit("━" * 45)
                        self.log.emit("✅ IMEI extraction complete!")
                        self.result_data.emit({"imeis": imei_list})
                        self.finished_signal.emit(True, f"Found {len(imei_list)} IMEI(s)")
                    else:
                        self.log.emit("⚠️ No IMEI values found in nvdata")
                        self.finished_signal.emit(True, "No IMEI values found")
                else:
                    self.finished_signal.emit(False, "Failed to read IMEI - check connection")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _write_imei(self):
        """Write IMEI values to device."""
        self.log.emit("━" * 45)
        self.log.emit("📱 IMEI WRITE - Reclaiming YOUR device identity!")
        self.log.emit("🏴 You bought it. You own it. Your IMEI, your rules.")
        self.log.emit("━" * 45)
        
        imei1 = self.kwargs.get('imei1', '')
        imei2 = self.kwargs.get('imei2', '')
        product = self.kwargs.get('product', 'thunder')
        
        if not imei1:
            self.log.emit("❌ IMEI1 is required")
            self.finished_signal.emit(False, "IMEI1 required")
            return
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.write_imei(imei1, imei2 if imei2 else None, product):
                    self.log.emit("✅ IMEI written! Device identity restored!")
                    self.finished_signal.emit(True, "IMEI written successfully")
                else:
                    self.finished_signal.emit(False, "Failed to write IMEI")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _patch_modem(self):
        """Patch modem firmware for IMEI operations."""
        self.log.emit("━" * 45)
        self.log.emit("📡 MODEM PATCHING - Breaking the carrier's chains!")
        self.log.emit("🔧 Patching md1img to unlock IMEI operations...")
        self.log.emit("━" * 45)
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.patch_modem():
                    self.log.emit("✅ Modem patched! IMEI operations unlocked!")
                    self.finished_signal.emit(True, "Modem patched successfully")
                else:
                    self.finished_signal.emit(False, "Failed to patch modem")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _read_efuses(self):
        """Read eFuse values from device."""
        self.log.emit("━" * 45)
        self.log.emit("🔐 EFUSE EXTRACTION - The OEM's deepest secrets!")
        self.log.emit("━" * 45)
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.read_efuses():
                    self.log.emit("💀 eFuses exposed! Knowledge is power!")
                    self.finished_signal.emit(True, "eFuses extracted")
                else:
                    self.finished_signal.emit(False, "Failed to read eFuses")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _memory_dump(self):
        """Dump device memory to files."""
        output_dir = self.kwargs.get('output_dir', os.getcwd())
        dump_type = self.kwargs.get('dump_type', 'full')  # 'full' or 'dram'
        
        self.log.emit("━" * 45)
        self.log.emit(f"🧠 MEMORY EXTRACTION: {dump_type.upper()} DUMP")
        self.log.emit("💀 Ripping secrets straight from the silicon!")
        self.log.emit("━" * 45)
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.memory_dump(output_dir, dump_type):
                    self.log.emit("🏴 MEMORY DUMPED! The device's mind is now YOURS!")
                    self.finished_signal.emit(True, f"Memory dumped to {output_dir}")
                else:
                    self.finished_signal.emit(False, "Failed to dump memory")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _set_meta_mode(self):
        """Switch device to specified boot mode (DA→META/FASTBOOT/etc)."""
        mode = self.kwargs.get('mode', 'FASTBOOT')
        
        self.log.emit("━" * 45)
        self.log.emit(f"🔄 MODE SWITCH: {mode}")
        self.log.emit("━" * 45)
        
        # Check if this is a DA-only command
        if mode in ["off", "usb", "uart"]:
            self.log.emit(f"📡 DA meta port mode: {mode}")
            self.log.emit("⚠️ This only works in XFLASH DA mode")
        elif mode in ["SHUTDOWN", "REBOOT"]:
            self.log.emit(f"📡 Device control: {mode}")
        else:
            self.log.emit(f"🔌 BROM→{mode} transition")
            self.log.emit("💡 Follow the on-screen instructions")
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.set_meta_mode(mode):
                    self.log.emit("")
                    self.log.emit(f"✅ Mode switch to {mode} initiated!")
                    
                    if mode not in ["off", "usb", "uart", "SHUTDOWN", "REBOOT"]:
                        # Check if set_meta_mode already connected to META serial
                        if handler.meta_connected and handler.meta_serial:
                            self.log.emit("")
                            self.log.emit("🎉 Connected to META mode via serial!")
                            self.log.emit("📡 AT commands available for IMEI/network operations")
                            self.log.emit("🏴 YOUR device, YOUR rules!")
                            self.finished_signal.emit(True, f"Connected to {mode} via serial!")
                            return
                        
                        # META serial didn't connect — fall back to DA reconnect
                        self.log.emit("")
                        self.log.emit("⏳ META serial not available, trying DA reconnect...")
                        self.log.emit("📋 Hold Vol Up + Vol Down + Power through any reboots")
                        self.log.emit("📋 Release when you hear the USB 'doink' sound")
                        self.log.emit("")
                        
                        time.sleep(5)
                        
                        self.log.emit("🔄 Auto-reconnecting via DA...")
                        
                        handler.disconnect()
                        time.sleep(1)
                        
                        if handler.initialize():
                            output_dir = self.kwargs.get('output_dir', os.getcwd())
                            if handler.connect_device(output_dir):
                                self.log.emit("")
                                self.log.emit("🎉 RECONNECTED (DA mode)!")
                                self.log.emit("🔥 All DA operations available!")
                                self.log.emit("🏴 YOUR device, YOUR rules!")
                                self.finished_signal.emit(True, f"Switched to {mode}, reconnected via DA!")
                                return
                            else:
                                self.log.emit("⚠️ Auto-reconnect failed")
                                self.log.emit("💡 Try 'Check Device' button to reconnect")
                        else:
                            self.log.emit("⚠️ Could not re-initialize")
                            self.log.emit("💡 Try 'Check Device' button to reconnect")
                    
                    self.finished_signal.emit(True, f"Switched to {mode}")
                else:
                    self.log.emit("")
                    self.log.emit("❌ Mode switch failed")
                    self.log.emit("💡 Try: Power off → Hold Vol Down → Connect USB → Retry")
                    self.finished_signal.emit(False, "Failed to switch mode")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.log.emit("💡 Connect device in BROM mode first")
            self.finished_signal.emit(False, "Device not connected")
    
    def _get_target_config(self):
        """Get device security configuration."""
        self.log.emit("━" * 45)
        self.log.emit("🔍 SECURITY ANALYSIS - What's protecting this device?")
        self.log.emit("━" * 45)
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                config = handler.get_target_config()
                if config:
                    self.result_data.emit(config)
                    self.finished_signal.emit(True, "Security config retrieved")
                else:
                    self.finished_signal.emit(False, "Failed to get security config")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _reset_device(self):
        """Send reset command to device."""
        self.log.emit("━" * 45)
        self.log.emit("🔄 SENDING RESET COMMAND")
        self.log.emit("━" * 45)
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.reset_device():
                    self.log.emit("✅ Reset sent! Disconnect USB cable to power off.")
                    self.finished_signal.emit(True, "Device reset - disconnect USB")
                else:
                    self.finished_signal.emit(False, "Failed to reset device")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _read_rpmb(self):
        """Read RPMB partition."""
        output_dir = self.kwargs.get('output_dir', os.getcwd())
        output_file = os.path.join(output_dir, "rpmb.bin")
        sector = self.kwargs.get('sector', None)
        sectors = self.kwargs.get('sectors', None)
        
        self.log.emit("━" * 45)
        self.log.emit("🔐 RPMB EXTRACTION - The manufacturer's secret vault!")
        self.log.emit("━" * 45)
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.read_rpmb(output_file, sector, sectors):
                    self.log.emit(f"🏴 RPMB PWNED! Saved to: {output_file}")
                    self.finished_signal.emit(True, output_file)
                else:
                    self.finished_signal.emit(False, "Failed to read RPMB")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _write_rpmb(self):
        """Write to RPMB partition."""
        input_file = self.kwargs.get('input_file', '')
        sector = self.kwargs.get('sector', None)
        sectors = self.kwargs.get('sectors', None)
        
        self.log.emit("━" * 45)
        self.log.emit("🔐 RPMB WRITE - Entering the danger zone!")
        self.log.emit("⚠️ WARNING: Incorrect data can BRICK your device!")
        self.log.emit("🏴 But YOUR device, YOUR risk, YOUR freedom!")
        self.log.emit("━" * 45)
        
        if not input_file or not os.path.exists(input_file):
            self.log.emit(f"❌ Input file not found: {input_file}")
            self.finished_signal.emit(False, "Input file required")
            return
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.write_rpmb(input_file, sector, sectors):
                    self.log.emit("✅ RPMB written! Security blob updated!")
                    self.finished_signal.emit(True, "RPMB written successfully")
                else:
                    self.finished_signal.emit(False, "Failed to write RPMB")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _erase_rpmb(self):
        """Erase RPMB partition."""
        sector = self.kwargs.get('sector', None)
        sectors = self.kwargs.get('sectors', None)
        
        self.log.emit("━" * 45)
        self.log.emit("🔐 RPMB ERASE - Total security wipe!")
        self.log.emit("💀 WARNING: This deletes manufacturer security data!")
        self.log.emit("🏴 Breaking all chains... no going back!")
        self.log.emit("━" * 45)
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.erase_rpmb(sector, sectors):
                    self.log.emit("✅ RPMB ERASED! Device is factory-blank!")
                    self.finished_signal.emit(True, "RPMB erased successfully")
                else:
                    self.finished_signal.emit(False, "Failed to erase RPMB")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _auth_rpmb(self):
        """Authenticate RPMB with key."""
        rpmb_key = self.kwargs.get('rpmb_key', None)
        
        self.log.emit("━" * 45)
        self.log.emit("🔑 RPMB AUTHENTICATION - Bypassing security!")
        self.log.emit("━" * 45)
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                if handler.auth_rpmb(rpmb_key):
                    self.log.emit("✅ RPMB authenticated! Full access granted!")
                    self.finished_signal.emit(True, "RPMB authenticated")
                else:
                    self.finished_signal.emit(False, "Failed to authenticate RPMB")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _scan_sml_data_worker(self):
        """Worker method for deep SIM lock data scan."""
        self.log.emit("━" * 45)
        self.log.emit("🔬 DEEP SIM LOCK DATA SCAN")
        self.log.emit("━" * 45)
        
        handler = get_device_handler()
        if handler.is_library_available() and handler.connected:
            def log_handler(msg):
                self.log.emit(msg)
            handler.log_signal.connect(log_handler)
            try:
                results = handler.scan_sml_data()
                if results and results.get('lock_structures'):
                    self.finished_signal.emit(True, f"Found {len(results['lock_structures'])} lock structures")
                elif results:
                    self.finished_signal.emit(True, "Scan complete — no lock structures found")
                else:
                    self.finished_signal.emit(False, "Scan failed")
            finally:
                try:
                    handler.log_signal.disconnect(log_handler)
                except:
                    pass
        else:
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _custom_command(self):
        """Run custom MTK command - still uses CLI for flexibility."""
        command = self.kwargs.get('command', '')
        
        self.log.emit(f"⚡ Running custom command: mtk {command}")
        self.log.emit("⚠️ Note: Custom commands use CLI mode (device may reconnect)")
        
        args = command.split()
        success, output = run_mtk_command(args, callback=self._log_callback)
        
        self.finished_signal.emit(success, "Command completed" if success else output)


# ═══════════════════════════════════════════════════════════════════════════════
# Styled Components
# ═══════════════════════════════════════════════════════════════════════════════

class GlowingButton(QPushButton):
    """A button with hover glow effect."""
    
    def __init__(self, text: str, color: str = "#00d4ff", parent=None):
        super().__init__(text, parent)
        self.base_color = color
        self._setup_style()
    
    def _setup_style(self):
        self.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 {self.base_color}40, stop:1 {self.base_color}20);
                border: 2px solid {self.base_color}80;
                border-radius: 8px;
                color: white;
                font-weight: bold;
                font-size: 13px;
                padding: 12px 24px;
                min-height: 20px;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 {self.base_color}80, stop:1 {self.base_color}40);
                border: 2px solid {self.base_color};
            }}
            QPushButton:pressed {{
                background: {self.base_color}60;
            }}
            QPushButton:disabled {{
                background: #333;
                border: 2px solid #555;
                color: #888;
            }}
        """)


class StatusCard(QFrame):
    """A card widget for displaying status information."""
    
    def __init__(self, title: str, icon: str = "📱", parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self._setup_ui(title, icon)
    
    def _setup_ui(self, title: str, icon: str):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)
        
        # Header
        header = QHBoxLayout()
        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI Emoji", 20))
        title_label = QLabel(title)
        title_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #00d4ff;")
        header.addWidget(icon_label)
        header.addWidget(title_label)
        header.addStretch()
        layout.addLayout(header)
        
        # Value
        self.value_label = QLabel("Not Connected")
        self.value_label.setFont(QFont("Segoe UI", 11))
        self.value_label.setStyleSheet("color: #aaa;")
        self.value_label.setWordWrap(True)
        layout.addWidget(self.value_label)
        
        self.setStyleSheet("""
            StatusCard {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #1a1a2e, stop:1 #16213e);
                border: 1px solid #00d4ff40;
                border-radius: 12px;
            }
        """)
    
    def set_value(self, value: str, color: str = "#fff"):
        self.value_label.setText(value)
        self.value_label.setStyleSheet(f"color: {color};")


class OperationCard(QFrame):
    """A card widget for an operation with icon and description."""
    
    clicked = pyqtSignal()
    
    def __init__(self, title: str, description: str, icon: str, color: str = "#00d4ff", parent=None):
        super().__init__(parent)
        self.color = color
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._setup_ui(title, description, icon)
    
    def _setup_ui(self, title: str, description: str, icon: str):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)
        
        # Icon
        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI Emoji", 28))
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)
        
        # Title
        title_label = QLabel(title)
        title_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet(f"color: {self.color};")
        layout.addWidget(title_label)
        
        # Description
        desc_label = QLabel(description)
        desc_label.setFont(QFont("Segoe UI", 9))
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setStyleSheet("color: #888;")
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)
        
        self.setMinimumSize(140, 140)
        self.setMaximumSize(180, 180)
        
        self._update_style(False)
    
    def _update_style(self, hovered: bool):
        if hovered:
            self.setStyleSheet(f"""
                OperationCard {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 {self.color}30, stop:1 {self.color}15);
                    border: 2px solid {self.color};
                    border-radius: 16px;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                OperationCard {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 #1a1a2e, stop:1 #16213e);
                    border: 2px solid {self.color}40;
                    border-radius: 16px;
                }}
            """)
    
    def enterEvent(self, event):
        self._update_style(True)
        super().enterEvent(event)
    
    def leaveEvent(self, event):
        self._update_style(False)
        super().leaveEvent(event)
    
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


# ═══════════════════════════════════════════════════════════════════════════════
# Main Plugin Widget
# ═══════════════════════════════════════════════════════════════════════════════

class PluginWidget(QWidget):
    """Main MTK Toolkit plugin widget."""
    
    # Map button names to their operation identifiers for mode checking
    BUTTON_OPERATIONS = {
        # Read operations
        'read_btn': 'read_partition',
        'flash_btn': 'read_full_flash',
        'preloader_btn': 'dump_preloader',
        'brom_btn': 'dump_brom',
        # Write operations
        'write_btn': 'write_partition',
        'restore_btn': 'write_full_flash',
        # Erase operations
        'erase_btn': 'erase_partition',
        'frp_btn': 'erase_frp',
        'userdata_btn': 'erase_partition',
        'cache_btn': 'erase_partition',
        # Unlock/Security operations
        'unlock_btn': 'unlock_bootloader',
        'lock_btn': 'lock_bootloader',
        'frp_erase_btn': 'erase_frp',
        'rpmb_btn': 'get_rpmb',
        'dump_sec_btn': 'dump_seccfg',
        'reset_sec_btn': 'reset_seccfg',
        'vbmeta_btn': 'patch_vbmeta',
        # IMEI operations
        'read_imei_btn': 'read_imei',
        'write_imei_btn': 'write_imei',
        'read_efuse_btn': 'read_efuses',
        'target_config_btn': 'read_full_hw_info',
        'patch_modem_btn': 'patch_modem',
        # META operations
        'meta_connect_btn': 'switch_mode',
        'backup_nvram_btn': 'backup_nvram',
        'restore_nvram_btn': 'restore_nvram',
        'backup_modem_btn': 'backup_modem',
        'restore_modem_btn': 'restore_modem',
        'check_lock_btn': 'check_network_lock',
        'scan_sml_btn': 'scan_sml_data',
        # Advanced META operations
        'chipid_btn': 'read_chip_id',
        'meid_btn': 'read_me_id',
        'socid_btn': 'read_soc_id',
        'hwcode_btn': 'read_full_hw_info',
        'read_efuse_adv_btn': 'read_efuses',
        'dump_efuse_btn': 'dump_efuses',
        'read_seccfg_btn': 'dump_seccfg',
        'reset_seccfg_btn': 'reset_seccfg',
        'sbc_btn': 'check_sbc_status',
        'daa_btn': 'check_daa_status',
        'kamakiri_btn': 'run_kamakiri',
        'amonet_btn': 'run_amonet',
        'carbonara_btn': 'run_carbonara',
        'custom_payload_btn': 'load_custom_payload',
        'peek_btn': 'peek_memory',
        'poke_btn': 'poke_memory',
        # Advanced operations
        'memdump_btn': 'memory_dump',
        'rpmb_read_btn': 'read_rpmb',
        'rpmb_write_btn': 'write_rpmb',
        'rpmb_erase_btn': 'erase_rpmb',
        'rpmb_auth_btn': 'auth_rpmb',
        # Mode switching (always available when connected)
        'fastboot_btn': 'switch_mode',
        'recovery_btn': 'switch_mode',
        'normal_btn': 'switch_mode',
        'shutdown_btn': 'switch_mode',
        'meta_btn': 'set_meta_mode',
        'factory_btn': 'switch_mode',
        'advmeta_btn': 'set_meta_mode',
        'at_btn': 'switch_mode',
        'usb_btn': 'switch_mode',
        'uart_btn': 'switch_mode',
        'adb_btn': 'switch_mode',
        'reset_btn': 'switch_mode',
        'reboot_btn': 'switch_mode',
    }
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.device_connected = False
        self.partitions = []
        self.output_dir = os.path.expanduser("~/MTK_Output")
        os.makedirs(self.output_dir, exist_ok=True)
        self.current_mode = "Disconnected"
        self.mode_buttons = {}  # Store button references: {name: button_widget}
        self._setup_ui()
        self._check_mtk_client()
        
        # Connect to mode change signal from handler
        handler = get_device_handler()
        if handler:
            handler.mode_changed_signal.connect(self._on_mode_changed)
    
    def _setup_ui(self):
        """Setup the main UI."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("""
            QScrollArea {
                background: transparent;
                border: none;
            }
            QScrollBar:vertical {
                background: #1a1a2e;
                width: 10px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical {
                background: #00d4ff60;
                border-radius: 5px;
                min-height: 30px;
            }
            QScrollBar::handle:vertical:hover {
                background: #00d4ff;
            }
        """)
        
        # Content widget
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(20, 15, 20, 15)
        content_layout.setSpacing(12)
        
        # Header
        header = self._create_header()
        content_layout.addWidget(header)
        
        # Status cards row
        status_row = self._create_status_row()
        content_layout.addLayout(status_row)
        
        # Tab widget for operations
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                background: #0d1117;
                border: 1px solid #00d4ff40;
                border-radius: 8px;
                padding: 10px;
            }
            QTabBar::tab {
                background: #1a1a2e;
                color: #888;
                padding: 10px 20px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                margin-right: 2px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00d4ff40, stop:1 #00d4ff20);
                color: #00d4ff;
                border: 1px solid #00d4ff60;
                border-bottom: none;
            }
            QTabBar::tab:hover:!selected {
                background: #252540;
                color: #aaa;
            }
        """)
        
        # Add tabs
        self.tabs.addTab(self._create_quick_actions_tab(), "⚡ Quick Actions")
        self.tabs.addTab(self._create_read_tab(), "📥 Read")
        self.tabs.addTab(self._create_write_tab(), "📤 Write")
        self.tabs.addTab(self._create_erase_tab(), "🗑️ Erase")
        self.tabs.addTab(self._create_unlock_tab(), "🔓 Unlock/Security")
        self.tabs.addTab(self._create_modes_tab(), "🔄 Modes")
        self.tabs.addTab(self._create_meta_tab(), "📡 Meta Mode")
        self.tabs.addTab(self._create_advanced_meta_tab(), "🔬 Adv. Meta")
        self.tabs.addTab(self._create_advanced_tab(), "🛠️ Advanced")
        
        content_layout.addWidget(self.tabs, 1)  # Give tabs stretch factor
        
        # Log output - stays at bottom, no stretch
        log_group = self._create_log_section()
        content_layout.addWidget(log_group, 0)  # No stretch for log
        
        scroll.setWidget(content)
        main_layout.addWidget(scroll)
        
        # Auto-show floating console after UI loads
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(300, lambda: self._show_floating_console(welcome=True))
        
        # Apply dark theme
        self.setStyleSheet("""
            QWidget {
                background: #0d1117;
                color: #e6e6e6;
                font-family: "Segoe UI", sans-serif;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #00d4ff40;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                background: #0d111780;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 8px;
                color: #00d4ff;
            }
            QLineEdit, QComboBox, QSpinBox {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 6px;
                padding: 8px 12px;
                color: white;
                selection-background-color: #00d4ff;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #00d4ff;
            }
            QComboBox::drop-down {
                border: none;
                padding-right: 10px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid #00d4ff;
            }
            QListWidget {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 6px;
                padding: 4px;
            }
            QListWidget::item {
                padding: 8px;
                border-radius: 4px;
            }
            QListWidget::item:selected {
                background: #00d4ff40;
            }
            QListWidget::item:hover {
                background: #ffffff10;
            }
            QCheckBox {
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 2px solid #555;
                background: #1a1a2e;
            }
            QCheckBox::indicator:checked {
                background: #00d4ff;
                border: 2px solid #00d4ff;
            }
        """)
    
    def _create_header(self) -> QWidget:
        """Create the header section."""
        header = QWidget()
        layout = QHBoxLayout(header)
        layout.setContentsMargins(0, 0, 0, 10)
        
        # Logo/Title
        title_layout = QVBoxLayout()
        title = QLabel("⚡ MTK Toolkit")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        subtitle = QLabel("MediaTek BROM Exploit & Flash Tool")
        subtitle.setFont(QFont("Segoe UI", 11))
        subtitle.setStyleSheet("color: #888;")
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        layout.addLayout(title_layout)
        
        layout.addStretch()
        
        # Connection button
        self.connect_btn = GlowingButton("🔌 Connect Device", "#00d4ff")
        self.connect_btn.clicked.connect(self._check_device)
        layout.addWidget(self.connect_btn)
        
        # Status indicator
        self.status_indicator = QLabel("⚪")
        self.status_indicator.setFont(QFont("Segoe UI Emoji", 16))
        self.status_indicator.setToolTip("Device not connected")
        layout.addWidget(self.status_indicator)
        
        # Connection mode indicator
        self.mode_label = QLabel("🔗 Library Mode")
        self.mode_label.setStyleSheet("color: #00ff88; font-size: 10px; font-weight: bold;")
        self.mode_label.setToolTip("Using mtkclient Python library directly.\n"
                                   "Connection stays active for multiple operations!\n"
                                   "No need to reconnect between operations.")
        if not _mtkclient_available:
            self.mode_label.setText("⚠️ CLI Fallback")
            self.mode_label.setStyleSheet("color: #ff9900; font-size: 10px; font-weight: bold;")
            self.mode_label.setToolTip(f"Library not available: {_mtkclient_error}\n"
                                       "Using CLI mode - reconnect required for each operation.")
        layout.addWidget(self.mode_label)
        
        return header
    
    def _create_status_row(self) -> QHBoxLayout:
        """Create the status cards row."""
        layout = QHBoxLayout()
        layout.setSpacing(15)
        
        self.cpu_card = StatusCard("CPU/SoC", "🔲")
        self.hwcode_card = StatusCard("HW Code", "🔢")
        self.meid_card = StatusCard("ME ID", "🆔")
        self.status_card = StatusCard("Status", "📡")
        
        layout.addWidget(self.cpu_card)
        layout.addWidget(self.hwcode_card)
        layout.addWidget(self.meid_card)
        layout.addWidget(self.status_card)
        
        return layout
    
    def _create_quick_actions_tab(self) -> QWidget:
        """Create quick actions tab with operation cards."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(20)
        
        # Quick actions grid
        grid = QGridLayout()
        grid.setSpacing(15)
        
        actions = [
            ("Read Boot", "Auto-detects A/B slots", "📦", "#00d4ff", lambda: self._read_partition("boot")),
            ("Read Recovery", "Auto-detects A/B slots", "🔧", "#00d4ff", lambda: self._read_partition("recovery")),
            ("Read Preloader", "Dump preloader", "⚙️", "#00d4ff", lambda: self._dump_preloader()),
            ("Unlock BL", "Unlock bootloader", "🔓", "#00ff88", lambda: self._unlock_bootloader()),
            ("Erase FRP", "Remove Google lock", "🗑️", "#ff6b6b", lambda: self._erase_frp()),
            ("Get GPT", "List all partitions", "📋", "#ffa500", lambda: self._get_gpt()),
            ("Patch VBMeta", "Disable AVB (v2.1!)", "⚡", "#00ff88", lambda: self._quick_patch_vbmeta()),
            ("Full Backup", "Backup entire flash", "💾", "#9966ff", lambda: self._read_full_flash()),
        ]
        
        for i, (title, desc, icon, color, callback) in enumerate(actions):
            card = OperationCard(title, desc, icon, color)
            card.clicked.connect(callback)
            grid.addWidget(card, i // 4, i % 4)
        
        layout.addLayout(grid)
        
        return tab
    
    def _quick_patch_vbmeta(self):
        """Quick patch vbmeta with mode 3 (disable both)."""
        reply = QMessageBox.question(
            self, "Quick VBMeta Patch",
            "This will patch vbmeta to DISABLE BOTH verification and verity.\n\n"
            "This gives you full freedom to modify your device.\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._start_operation("patch_vbmeta", mode=3)
    
    def _create_read_tab(self) -> QWidget:
        """Create read operations tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        # Partition selection
        partition_group = QGroupBox("📁 Read Partition")
        partition_layout = QVBoxLayout(partition_group)
        
        # Partition list with refresh button
        list_header = QHBoxLayout()
        list_header.addWidget(QLabel("Select partitions to read:"))
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setMaximumWidth(100)
        refresh_btn.clicked.connect(self._get_gpt)
        list_header.addStretch()
        list_header.addWidget(refresh_btn)
        partition_layout.addLayout(list_header)
        
        self.partition_list = QListWidget()
        self.partition_list.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        self.partition_list.setMinimumHeight(200)
        self.partition_list.itemDoubleClicked.connect(self._on_partition_double_clicked)
        partition_layout.addWidget(self.partition_list)
        
        # Common partitions quick read buttons
        common_layout = QHBoxLayout()
        common_layout.addWidget(QLabel("Quick read:"))
        quick_partitions = [
            ("boot", "boot"),
            ("recovery", "recovery"),
            ("vbmeta", "vbmeta"),
            ("lk", "lk"),
            ("preloader", "preloader"),
            ("system", "system")
        ]
        for label, part in quick_partitions:
            btn = QPushButton(label)
            btn.setMinimumWidth(70)
            btn.setToolTip(f"Read {part} partition directly")
            btn.clicked.connect(lambda checked, p=part: self._quick_read_partition(p))
            common_layout.addWidget(btn)
        common_layout.addStretch()
        partition_layout.addLayout(common_layout)
        
        # Output directory
        output_layout = QHBoxLayout()
        output_layout.addWidget(QLabel("Output folder:"))
        self.read_output_edit = QLineEdit(self.output_dir)
        output_layout.addWidget(self.read_output_edit)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(lambda: self._browse_folder(self.read_output_edit))
        output_layout.addWidget(browse_btn)
        partition_layout.addLayout(output_layout)
        
        # Read button
        read_btn = GlowingButton("📥 Read Selected Partitions", "#00d4ff")
        read_btn.clicked.connect(self._read_selected_partitions)
        partition_layout.addWidget(read_btn)
        self._register_button('read_btn', read_btn)
        
        layout.addWidget(partition_group)
        
        # Full flash read
        flash_group = QGroupBox("💾 Full Flash Dump")
        flash_layout = QVBoxLayout(flash_group)
        
        flash_layout.addWidget(QLabel("Read entire flash memory to a single file:"))
        
        flash_output_layout = QHBoxLayout()
        flash_output_layout.addWidget(QLabel("Output file:"))
        self.flash_output_edit = QLineEdit(os.path.join(self.output_dir, "flash_dump.bin"))
        flash_output_layout.addWidget(self.flash_output_edit)
        flash_browse_btn = QPushButton("Browse...")
        flash_browse_btn.clicked.connect(lambda: self._browse_save_file(self.flash_output_edit))
        flash_output_layout.addWidget(flash_browse_btn)
        flash_layout.addLayout(flash_output_layout)
        
        flash_btn = GlowingButton("💾 Read Full Flash", "#9966ff")
        flash_btn.clicked.connect(self._read_full_flash)
        flash_layout.addWidget(flash_btn)
        self._register_button('flash_btn', flash_btn)
        
        layout.addWidget(flash_group)
        
        return tab
    
    def _create_write_tab(self) -> QWidget:
        """Create write operations tab with dynamic partition list."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        # ═══════════════════════════════════════════════════════════════════
        # Write Individual Partition
        # ═══════════════════════════════════════════════════════════════════
        write_group = QGroupBox("📤 Write Partition")
        write_layout = QVBoxLayout(write_group)
        
        # Partition list header with refresh
        list_header = QHBoxLayout()
        list_header.addWidget(QLabel("Select partition to write:"))
        write_refresh_btn = QPushButton("🔄 Refresh")
        write_refresh_btn.setMaximumWidth(100)
        write_refresh_btn.clicked.connect(self._refresh_write_partitions)
        list_header.addStretch()
        list_header.addWidget(write_refresh_btn)
        write_layout.addLayout(list_header)
        
        # Partition list with file selection for each
        self.write_partition_list = QListWidget()
        self.write_partition_list.setMinimumHeight(180)
        self.write_partition_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.write_partition_list.itemClicked.connect(self._on_write_partition_selected)
        write_layout.addWidget(self.write_partition_list)
        
        # Selected partition info
        selected_layout = QHBoxLayout()
        selected_layout.addWidget(QLabel("Selected:"))
        self.write_selected_label = QLabel("None")
        self.write_selected_label.setStyleSheet("color: #00d4ff; font-weight: bold;")
        selected_layout.addWidget(self.write_selected_label)
        selected_layout.addStretch()
        write_layout.addLayout(selected_layout)
        
        # Input file selection
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Image file:"))
        self.write_input_edit = QLineEdit()
        self.write_input_edit.setPlaceholderText("Select an image file to write...")
        input_layout.addWidget(self.write_input_edit)
        input_browse_btn = QPushButton("📂 Browse...")
        input_browse_btn.clicked.connect(lambda: self._browse_file(self.write_input_edit))
        input_layout.addWidget(input_browse_btn)
        write_layout.addLayout(input_layout)
        
        # Warning
        warning = QLabel("⚠️ WARNING: Writing incorrect data can BRICK your device!")
        warning.setStyleSheet("color: #ff6b6b; font-weight: bold; padding: 10px;")
        write_layout.addWidget(warning)
        
        # Write button
        write_btn = GlowingButton("📤 Write Selected Partition", "#ffa500")
        write_btn.clicked.connect(self._write_partition)
        write_layout.addWidget(write_btn)
        self._register_button('write_btn', write_btn)
        
        layout.addWidget(write_group)
        
        # ═══════════════════════════════════════════════════════════════════
        # Restore Full Flash
        # ═══════════════════════════════════════════════════════════════════
        restore_group = QGroupBox("💾 Restore Full Flash")
        restore_layout = QVBoxLayout(restore_group)
        
        restore_layout.addWidget(QLabel("Restore entire flash from a backup file (created with 'Read Full Flash'):"))
        
        # Input file
        restore_input_layout = QHBoxLayout()
        restore_input_layout.addWidget(QLabel("Flash dump file:"))
        self.restore_input_edit = QLineEdit()
        self.restore_input_edit.setPlaceholderText("Select flash_dump.bin or similar...")
        restore_input_layout.addWidget(self.restore_input_edit)
        restore_browse_btn = QPushButton("📂 Browse...")
        restore_browse_btn.clicked.connect(lambda: self._browse_file(self.restore_input_edit))
        restore_input_layout.addWidget(restore_browse_btn)
        restore_layout.addLayout(restore_input_layout)
        
        # Serious warning
        restore_warning = QLabel("⚠️ DANGER: This will OVERWRITE your ENTIRE device flash!\n"
                                 "Only use this to restore a backup from the SAME device!")
        restore_warning.setStyleSheet("color: #ff4444; font-weight: bold; padding: 10px; "
                                      "background: #ff444420; border-radius: 5px;")
        restore_layout.addWidget(restore_warning)
        
        # Restore button
        restore_btn = GlowingButton("💾 Restore Full Flash", "#ff6b6b")
        restore_btn.clicked.connect(self._write_full_flash)
        restore_layout.addWidget(restore_btn)
        self._register_button('restore_btn', restore_btn)
        
        layout.addWidget(restore_group)
        
        return tab
    
    def _create_erase_tab(self) -> QWidget:
        """Create erase operations tab with dynamic partition list."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        # ═══════════════════════════════════════════════════════════════════
        # Erase Individual Partitions
        # ═══════════════════════════════════════════════════════════════════
        erase_group = QGroupBox("🗑️ Erase Partition")
        erase_layout = QVBoxLayout(erase_group)
        
        # Partition list header with refresh
        list_header = QHBoxLayout()
        list_header.addWidget(QLabel("Select partition to erase:"))
        erase_refresh_btn = QPushButton("🔄 Refresh")
        erase_refresh_btn.setMaximumWidth(100)
        erase_refresh_btn.clicked.connect(self._refresh_erase_partitions)
        list_header.addStretch()
        list_header.addWidget(erase_refresh_btn)
        erase_layout.addLayout(list_header)
        
        # Partition list
        self.erase_partition_list = QListWidget()
        self.erase_partition_list.setMinimumHeight(200)
        self.erase_partition_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.erase_partition_list.itemClicked.connect(self._on_erase_partition_selected)
        erase_layout.addWidget(self.erase_partition_list)
        
        # Selected partition info
        erase_selected_layout = QHBoxLayout()
        erase_selected_layout.addWidget(QLabel("Selected:"))
        self.erase_selected_label = QLabel("None")
        self.erase_selected_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        erase_selected_layout.addWidget(self.erase_selected_label)
        erase_selected_layout.addStretch()
        erase_layout.addLayout(erase_selected_layout)
        
        # Warning
        erase_warning = QLabel("⚠️ WARNING: Erasing partitions is IRREVERSIBLE!\n"
                               "Make sure you have backups before erasing!")
        erase_warning.setStyleSheet("color: #ffa500; font-weight: bold; padding: 10px;")
        erase_layout.addWidget(erase_warning)
        
        # Erase button
        erase_btn = GlowingButton("🗑️ Erase Selected Partition", "#ff6b6b")
        erase_btn.clicked.connect(self._erase_selected_partition)
        erase_layout.addWidget(erase_btn)
        self._register_button('erase_btn', erase_btn)
        
        layout.addWidget(erase_group)
        
        # ═══════════════════════════════════════════════════════════════════
        # Quick Erase Common Partitions
        # ═══════════════════════════════════════════════════════════════════
        quick_group = QGroupBox("⚡ Quick Erase")
        quick_layout = QVBoxLayout(quick_group)
        
        quick_layout.addWidget(QLabel("Commonly erased partitions:"))
        
        quick_btns = QHBoxLayout()
        
        frp_btn = GlowingButton("🗑️ FRP", "#ff6b6b")
        frp_btn.setToolTip("Erase Factory Reset Protection (Google lock)")
        frp_btn.clicked.connect(self._erase_frp)
        quick_btns.addWidget(frp_btn)
        self._register_button('frp_btn', frp_btn)
        
        userdata_btn = GlowingButton("🗑️ Userdata", "#ff6b6b")
        userdata_btn.setToolTip("Erase user data (factory reset)")
        userdata_btn.clicked.connect(lambda: self._erase_partition_by_name("userdata"))
        quick_btns.addWidget(userdata_btn)
        self._register_button('userdata_btn', userdata_btn)
        
        cache_btn = GlowingButton("🗑️ Cache", "#ffa500")
        cache_btn.setToolTip("Erase cache partition")
        cache_btn.clicked.connect(lambda: self._erase_partition_by_name("cache"))
        quick_btns.addWidget(cache_btn)
        self._register_button('cache_btn', cache_btn)
        
        quick_layout.addLayout(quick_btns)
        
        layout.addWidget(quick_group)
        
        return tab
    
    def _refresh_write_partitions(self):
        """Refresh the write partition list from device."""
        self._log("🔄 Refreshing partition list for write...")
        handler = get_device_handler()
        if handler.connected and handler.partitions:
            self.write_partition_list.clear()
            for part in handler.partitions:
                name = part.get('name', 'unknown')
                size = part.get('size', 0)
                size_str = f"{size / (1024*1024):.1f} MB" if size > 1024*1024 else f"{size / 1024:.1f} KB"
                item = QListWidgetItem(f"📦 {name}  ({size_str})")
                item.setData(Qt.ItemDataRole.UserRole, name)
                self.write_partition_list.addItem(item)
            self._log(f"✅ Loaded {len(handler.partitions)} partitions")
        else:
            self._log("⚠️ Connect device first to see partitions")
            QMessageBox.information(self, "Not Connected", 
                "Please connect a device first to see the partition list.\n\n"
                "Click 'Connect Device' in the console or header.")
    
    def _refresh_erase_partitions(self):
        """Refresh the erase partition list from device."""
        self._log("🔄 Refreshing partition list for erase...")
        handler = get_device_handler()
        if handler.connected and handler.partitions:
            self.erase_partition_list.clear()
            for part in handler.partitions:
                name = part.get('name', 'unknown')
                size = part.get('size', 0)
                size_str = f"{size / (1024*1024):.1f} MB" if size > 1024*1024 else f"{size / 1024:.1f} KB"
                item = QListWidgetItem(f"🗑️ {name}  ({size_str})")
                item.setData(Qt.ItemDataRole.UserRole, name)
                self.erase_partition_list.addItem(item)
            self._log(f"✅ Loaded {len(handler.partitions)} partitions")
        else:
            self._log("⚠️ Connect device first to see partitions")
            QMessageBox.information(self, "Not Connected", 
                "Please connect a device first to see the partition list.\n\n"
                "Click 'Connect Device' in the console or header.")
    
    def _on_write_partition_selected(self, item):
        """Handle write partition selection."""
        name = item.data(Qt.ItemDataRole.UserRole)
        self.write_selected_label.setText(name)
        self.write_selected_label.setStyleSheet("color: #00ff88; font-weight: bold;")
    
    def _on_erase_partition_selected(self, item):
        """Handle erase partition selection."""
        name = item.data(Qt.ItemDataRole.UserRole)
        self.erase_selected_label.setText(name)
        self.erase_selected_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
    
    def _erase_selected_partition(self):
        """Erase the selected partition."""
        selected = self.erase_partition_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select a partition to erase.")
            return
        
        partition = selected.data(Qt.ItemDataRole.UserRole)
        
        reply = QMessageBox.warning(
            self, "Confirm Erase",
            f"⚠️ Are you sure you want to ERASE partition '{partition}'?\n\n"
            "This action is IRREVERSIBLE!\n"
            "All data on this partition will be permanently deleted.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._erase_partition_by_name(partition)
    
    def _erase_partition_by_name(self, partition: str):
        """Erase a partition by name."""
        self._log(f"🗑️ Erasing partition: {partition}")
        self._start_operation("erase_partition", partition=partition)

    def _create_unlock_tab(self) -> QWidget:
        """Create unlock/security tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        # Bootloader unlock
        bl_group = QGroupBox("🔓 Bootloader Operations")
        bl_layout = QVBoxLayout(bl_group)
        
        bl_layout.addWidget(QLabel("Unlock or lock the device bootloader:"))
        
        bl_btns = QHBoxLayout()
        unlock_btn = GlowingButton("🔓 Unlock Bootloader", "#00ff88")
        unlock_btn.clicked.connect(self._unlock_bootloader)
        lock_btn = GlowingButton("🔒 Lock Bootloader", "#ff6b6b")
        lock_btn.clicked.connect(self._lock_bootloader)
        bl_btns.addWidget(unlock_btn)
        bl_btns.addWidget(lock_btn)
        bl_layout.addLayout(bl_btns)
        self._register_button('unlock_btn', unlock_btn)
        self._register_button('lock_btn', lock_btn)
        
        layout.addWidget(bl_group)
        
        # FRP
        frp_group = QGroupBox("🗑️ Factory Reset Protection (FRP)")
        frp_layout = QVBoxLayout(frp_group)
        
        frp_layout.addWidget(QLabel("Erase FRP partition to bypass Google account lock:"))
        
        frp_warning = QLabel("⚠️ This should only be used on your own device!")
        frp_warning.setStyleSheet("color: #ffa500;")
        frp_layout.addWidget(frp_warning)
        
        frp_erase_btn = GlowingButton("🗑️ Erase FRP", "#ff6b6b")
        frp_erase_btn.clicked.connect(self._erase_frp)
        frp_layout.addWidget(frp_erase_btn)
        self._register_button('frp_erase_btn', frp_erase_btn)
        
        layout.addWidget(frp_group)
        
        # RPMB Keys
        rpmb_group = QGroupBox("🔑 RPMB Keys")
        rpmb_layout = QVBoxLayout(rpmb_group)
        
        rpmb_layout.addWidget(QLabel("Extract RPMB and other security keys:"))
        
        rpmb_output_layout = QHBoxLayout()
        rpmb_output_layout.addWidget(QLabel("Output folder:"))
        self.rpmb_output_edit = QLineEdit(self.output_dir)
        rpmb_output_layout.addWidget(self.rpmb_output_edit)
        rpmb_browse_btn = QPushButton("Browse...")
        rpmb_browse_btn.clicked.connect(lambda: self._browse_folder(self.rpmb_output_edit))
        rpmb_output_layout.addWidget(rpmb_browse_btn)
        rpmb_layout.addLayout(rpmb_output_layout)
        
        rpmb_btn = GlowingButton("🔑 Extract RPMB Keys", "#9966ff")
        rpmb_btn.clicked.connect(self._get_rpmb)
        rpmb_layout.addWidget(rpmb_btn)
        self._register_button('rpmb_btn', rpmb_btn)
        
        layout.addWidget(rpmb_group)
        
        # seccfg
        sec_group = QGroupBox("🔐 Security Config")
        sec_layout = QVBoxLayout(sec_group)
        
        sec_layout.addWidget(QLabel("Dump or reset seccfg partition:"))
        
        sec_btns = QHBoxLayout()
        dump_sec_btn = GlowingButton("📥 Dump seccfg", "#00d4ff")
        dump_sec_btn.clicked.connect(self._dump_seccfg)
        reset_sec_btn = GlowingButton("🔄 Reset seccfg", "#ffa500")
        reset_sec_btn.clicked.connect(self._reset_seccfg)
        sec_btns.addWidget(dump_sec_btn)
        sec_btns.addWidget(reset_sec_btn)
        sec_layout.addLayout(sec_btns)
        self._register_button('dump_sec_btn', dump_sec_btn)
        self._register_button('reset_sec_btn', reset_sec_btn)
        
        layout.addWidget(sec_group)
        
        # ═══════════════════════════════════════════════════════════════════
        # NEW v2.1.2 Features
        # ═══════════════════════════════════════════════════════════════════
        
        # VBMeta Patching (NEW!)
        vbmeta_group = QGroupBox("⚡ VBMeta Patching (NEW in v2.1!)")
        vbmeta_layout = QVBoxLayout(vbmeta_group)
        
        vbmeta_layout.addWidget(QLabel("Disable Android Verified Boot restrictions:"))
        
        vbmeta_mode_layout = QHBoxLayout()
        vbmeta_mode_layout.addWidget(QLabel("Mode:"))
        self.vbmeta_mode_combo = QComboBox()
        self.vbmeta_mode_combo.addItems([
            "3 - Disable BOTH (Full Freedom) 🏴",
            "2 - Disable Verification Only",
            "1 - Disable Verity Only",
            "0 - Re-lock (Enable All)"
        ])
        self.vbmeta_mode_combo.setCurrentIndex(0)
        vbmeta_mode_layout.addWidget(self.vbmeta_mode_combo)
        vbmeta_layout.addLayout(vbmeta_mode_layout)
        
        vbmeta_btn = GlowingButton("⚡ Patch VBMeta", "#00ff88")
        vbmeta_btn.clicked.connect(self._patch_vbmeta)
        vbmeta_layout.addWidget(vbmeta_btn)
        self._register_button('vbmeta_btn', vbmeta_btn)
        
        layout.addWidget(vbmeta_group)
        
        # IMEI & Device Info (NEW!)
        imei_group = QGroupBox("📱 Device Identity (NEW in v2.1!)")
        imei_layout = QVBoxLayout(imei_group)
        
        # IMEI Read section
        imei_read_layout = QHBoxLayout()
        read_imei_btn = GlowingButton("📱 Read IMEI", "#00d4ff")
        read_imei_btn.clicked.connect(self._read_imei)
        read_efuse_btn = GlowingButton("🔐 Read eFuses", "#9966ff")
        read_efuse_btn.clicked.connect(self._read_efuses)
        target_config_btn = GlowingButton("🔍 Security Status", "#ffa500")
        target_config_btn.clicked.connect(self._get_target_config)
        imei_read_layout.addWidget(read_imei_btn)
        imei_read_layout.addWidget(read_efuse_btn)
        imei_read_layout.addWidget(target_config_btn)
        imei_layout.addLayout(imei_read_layout)
        self._register_button('read_imei_btn', read_imei_btn)
        self._register_button('read_efuse_btn', read_efuse_btn)
        self._register_button('target_config_btn', target_config_btn)
        
        # IMEI Write section (NEW!)
        imei_write_group = QGroupBox("✍️ IMEI Write (ADVANCED)")
        imei_write_layout = QFormLayout(imei_write_group)
        
        warning_label = QLabel("⚠️ IMEI modification may be illegal in some jurisdictions.\n"
                               "This tool is for device recovery and legitimate repair only.")
        warning_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        imei_write_layout.addRow(warning_label)
        
        self.imei1_edit = QLineEdit()
        self.imei1_edit.setPlaceholderText("Enter IMEI 1 (14-15 digits)")
        self.imei1_edit.setMaxLength(15)
        imei_write_layout.addRow("IMEI 1:", self.imei1_edit)
        
        self.imei2_edit = QLineEdit()
        self.imei2_edit.setPlaceholderText("Enter IMEI 2 for dual-SIM (optional)")
        self.imei2_edit.setMaxLength(15)
        imei_write_layout.addRow("IMEI 2:", self.imei2_edit)
        
        imei_write_btns = QHBoxLayout()
        patch_modem_btn = GlowingButton("📡 Patch Modem", "#ffa500")
        patch_modem_btn.setToolTip("Required before IMEI write on some devices")
        patch_modem_btn.clicked.connect(self._patch_modem_ui)
        write_imei_btn = GlowingButton("✍️ Write IMEI", "#ff6b6b")
        write_imei_btn.clicked.connect(self._write_imei_ui)
        imei_write_btns.addWidget(patch_modem_btn)
        imei_write_btns.addWidget(write_imei_btn)
        imei_write_layout.addRow(imei_write_btns)
        self._register_button('patch_modem_btn', patch_modem_btn)
        self._register_button('write_imei_btn', write_imei_btn)
        
        imei_layout.addWidget(imei_write_group)
        
        layout.addWidget(imei_group)
        
        return tab
    
    def _create_advanced_tab(self) -> QWidget:
        """Create advanced operations tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        # Preloader/BROM dumps
        dump_group = QGroupBox("📥 Advanced Dumps")
        dump_layout = QVBoxLayout(dump_group)
        
        dump_output_layout = QHBoxLayout()
        dump_output_layout.addWidget(QLabel("Output folder:"))
        self.dump_output_edit = QLineEdit(self.output_dir)
        dump_output_layout.addWidget(self.dump_output_edit)
        dump_browse_btn = QPushButton("Browse...")
        dump_browse_btn.clicked.connect(lambda: self._browse_folder(self.dump_output_edit))
        dump_output_layout.addWidget(dump_browse_btn)
        dump_layout.addLayout(dump_output_layout)
        
        dump_btns = QHBoxLayout()
        preloader_btn = GlowingButton("⚙️ Dump Preloader", "#00d4ff")
        preloader_btn.clicked.connect(self._dump_preloader)
        brom_btn = GlowingButton("🔲 Dump BROM", "#9966ff")
        brom_btn.clicked.connect(self._dump_brom)
        dump_btns.addWidget(preloader_btn)
        dump_btns.addWidget(brom_btn)
        dump_layout.addLayout(dump_btns)
        self._register_button('preloader_btn', preloader_btn)
        self._register_button('brom_btn', brom_btn)
        
        layout.addWidget(dump_group)
        
        # Memory Dump (Enhanced!)
        memdump_group = QGroupBox("🧠 Memory Dump")
        memdump_layout = QVBoxLayout(memdump_group)
        
        memdump_layout.addWidget(QLabel("Extract device memory regions:"))
        
        memdump_type_layout = QHBoxLayout()
        memdump_type_layout.addWidget(QLabel("Memory region:"))
        self.memdump_type_combo = QComboBox()
        self.memdump_type_combo.addItems([
            "BROM - Boot ROM (read-only firmware)",
            "DRAM - Dynamic RAM (main memory)",
            "SRAM - Static RAM (fast cache)",
            "eFuse - One-time programmable fuses",
            "Full Dump - All regions combined"
        ])
        memdump_type_layout.addWidget(self.memdump_type_combo, 1)
        memdump_layout.addLayout(memdump_type_layout)
        
        # Address range (optional for advanced users)
        addr_layout = QHBoxLayout()
        addr_layout.addWidget(QLabel("Start addr (hex):"))
        self.memdump_start_edit = QLineEdit()
        self.memdump_start_edit.setPlaceholderText("Auto")
        self.memdump_start_edit.setMaximumWidth(120)
        addr_layout.addWidget(self.memdump_start_edit)
        addr_layout.addWidget(QLabel("Length:"))
        self.memdump_length_edit = QLineEdit()
        self.memdump_length_edit.setPlaceholderText("Auto")
        self.memdump_length_edit.setMaximumWidth(120)
        addr_layout.addWidget(self.memdump_length_edit)
        addr_layout.addStretch()
        memdump_layout.addLayout(addr_layout)
        
        memdump_btn = GlowingButton("🧠 Dump Memory", "#ff6b6b")
        memdump_btn.clicked.connect(self._memory_dump)
        memdump_layout.addWidget(memdump_btn)
        
        layout.addWidget(memdump_group)
        
        # ═══════════════════════════════════════════════════════════════════
        # RPMB Full Control (Enhanced in v2.1!)
        # ═══════════════════════════════════════════════════════════════════
        rpmb_direct_group = QGroupBox("🔐 RPMB Full Control (Enhanced in v2.1!)")
        rpmb_direct_layout = QVBoxLayout(rpmb_direct_group)
        
        rpmb_direct_layout.addWidget(QLabel("RPMB (Replay Protected Memory Block) - Manufacturer security storage"))
        
        # Read section
        rpmb_read_btn = GlowingButton("📥 Read RPMB", "#9966ff")
        rpmb_read_btn.clicked.connect(self._read_rpmb_direct)
        rpmb_direct_layout.addWidget(rpmb_read_btn)
        
        # Write section (DANGEROUS!)
        rpmb_write_group = QGroupBox("⚠️ RPMB Write (DANGER ZONE)")
        rpmb_write_layout = QVBoxLayout(rpmb_write_group)
        
        danger_label = QLabel("⚠️ EXTREME DANGER: Writing incorrect RPMB data can PERMANENTLY BRICK your device!\n"
                             "Only use if you have a valid RPMB backup or know EXACTLY what you're doing.")
        danger_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        rpmb_write_layout.addWidget(danger_label)
        
        rpmb_file_layout = QHBoxLayout()
        rpmb_file_layout.addWidget(QLabel("RPMB file:"))
        self.rpmb_file_edit = QLineEdit()
        self.rpmb_file_edit.setPlaceholderText("Select rpmb.bin file to write")
        rpmb_file_layout.addWidget(self.rpmb_file_edit)
        rpmb_browse_btn = QPushButton("Browse...")
        rpmb_browse_btn.clicked.connect(lambda: self._browse_rpmb_file())
        rpmb_file_layout.addWidget(rpmb_browse_btn)
        rpmb_write_layout.addLayout(rpmb_file_layout)
        
        rpmb_sector_layout = QHBoxLayout()
        rpmb_sector_layout.addWidget(QLabel("Start sector (optional):"))
        self.rpmb_sector_spin = QSpinBox()
        self.rpmb_sector_spin.setRange(0, 65535)
        self.rpmb_sector_spin.setValue(0)
        self.rpmb_sector_spin.setSpecialValueText("Auto")
        rpmb_sector_layout.addWidget(self.rpmb_sector_spin)
        rpmb_sector_layout.addWidget(QLabel("Sectors:"))
        self.rpmb_sectors_spin = QSpinBox()
        self.rpmb_sectors_spin.setRange(0, 65535)
        self.rpmb_sectors_spin.setValue(0)
        self.rpmb_sectors_spin.setSpecialValueText("All")
        rpmb_sector_layout.addWidget(self.rpmb_sectors_spin)
        rpmb_write_layout.addLayout(rpmb_sector_layout)
        
        rpmb_write_btns = QHBoxLayout()
        rpmb_write_btn = GlowingButton("📤 Write RPMB", "#ff6b6b")
        rpmb_write_btn.clicked.connect(self._write_rpmb_advanced)
        rpmb_erase_btn = GlowingButton("💀 Erase RPMB", "#ff0000")
        rpmb_erase_btn.clicked.connect(self._erase_rpmb_advanced)
        rpmb_write_btns.addWidget(rpmb_write_btn)
        rpmb_write_btns.addWidget(rpmb_erase_btn)
        rpmb_write_layout.addLayout(rpmb_write_btns)
        
        # RPMB Auth section
        rpmb_auth_layout = QHBoxLayout()
        rpmb_auth_layout.addWidget(QLabel("RPMB Key (hex, 32 bytes):"))
        self.rpmb_key_edit = QLineEdit()
        self.rpmb_key_edit.setPlaceholderText("Optional: RPMB key for authentication")
        rpmb_auth_layout.addWidget(self.rpmb_key_edit)
        rpmb_auth_btn = GlowingButton("🔑 Auth RPMB", "#ffa500")
        rpmb_auth_btn.clicked.connect(self._auth_rpmb_advanced)
        rpmb_auth_layout.addWidget(rpmb_auth_btn)
        rpmb_write_layout.addLayout(rpmb_auth_layout)
        
        rpmb_direct_layout.addWidget(rpmb_write_group)
        
        layout.addWidget(rpmb_direct_group)
        
        # Custom command
        custom_group = QGroupBox("⚡ Custom MTK Command")
        custom_layout = QVBoxLayout(custom_group)
        
        custom_layout.addWidget(QLabel("Run any mtkclient command (without 'mtk' prefix):"))
        
        self.custom_cmd_edit = QLineEdit()
        self.custom_cmd_edit.setPlaceholderText("e.g., printgpt  or  r boot boot.img  or  da seccfg unlock")
        custom_layout.addWidget(self.custom_cmd_edit)
        
        custom_examples = QLabel("Examples: printgpt, r boot boot.img, e frp, da seccfg unlock, rf flash.bin")
        custom_examples.setStyleSheet("color: #888; font-size: 11px;")
        custom_layout.addWidget(custom_examples)
        
        custom_btn = GlowingButton("⚡ Run Command", "#00d4ff")
        custom_btn.clicked.connect(self._run_custom_command)
        custom_layout.addWidget(custom_btn)
        
        layout.addWidget(custom_group)
        
        # MTKClient info
        info_group = QGroupBox("ℹ️ MTKClient Installation")
        info_layout = QVBoxLayout(info_group)
        
        self.mtk_info_label = QLabel("Checking MTKClient installation...")
        self.mtk_info_label.setWordWrap(True)
        info_layout.addWidget(self.mtk_info_label)
        
        # Installation instructions
        install_info = QLabel(
            "<b>MTKClient requires manual installation:</b><br><br>"
            "<b>Windows:</b><br>"
            "1. Install drivers (UsbDk + VC++ Redist) from buttons below<br>"
            "2. git clone https://github.com/bkerler/mtkclient.git<br>"
            "3. cd mtkclient && pip install -r requirements.txt<br><br>"
            "<b>Linux:</b><br>"
            "1. sudo apt install python3-pip libusb-1.0-0<br>"
            "2. git clone https://github.com/bkerler/mtkclient.git<br>"
            "3. cd mtkclient && pip install -r requirements.txt<br>"
            "4. sudo cp Setup/Linux/*.rules /etc/udev/rules.d/<br>"
            "5. sudo usermod -aG dialout,plugdev $USER"
        )
        install_info.setTextFormat(Qt.TextFormat.RichText)
        install_info.setWordWrap(True)
        install_info.setStyleSheet("color: #aaa; font-size: 11px; padding: 10px; background: #1a1a2e; border-radius: 6px;")
        info_layout.addWidget(install_info)
        
        # Clone button
        clone_btn = GlowingButton("📥 Clone MTKClient (opens terminal)", "#00d4ff")
        clone_btn.clicked.connect(self._clone_mtkclient)
        info_layout.addWidget(clone_btn)
        
        # Install requirements button
        req_btn = GlowingButton("📦 Install Requirements (pip)", "#ffa500")
        req_btn.clicked.connect(self._install_requirements)
        info_layout.addWidget(req_btn)
        
        # Open mtkclient folder button
        open_folder_btn = GlowingButton("📂 Open MTKClient Folder", "#888888")
        open_folder_btn.clicked.connect(self._open_mtkclient_folder)
        info_layout.addWidget(open_folder_btn)
        
        layout.addWidget(info_group)
        
        # Windows Drivers
        if sys.platform == 'win32':
            driver_group = QGroupBox("🔌 Windows Drivers")
            driver_layout = QVBoxLayout(driver_group)
            
            driver_layout.addWidget(QLabel("UsbDk is REQUIRED for MTKClient USB communication:"))
            
            driver_btns = QHBoxLayout()
            
            usbdk_btn = GlowingButton("📀 Install UsbDk (Required)", "#00d4ff")
            usbdk_btn.setToolTip("UsbDk_1.0.22_x64.msi - REQUIRED for USB communication with MTK devices")
            usbdk_btn.clicked.connect(lambda: self._install_driver("UsbDk_1.0.22_x64.msi"))
            driver_btns.addWidget(usbdk_btn)
            
            vcredist_btn = GlowingButton("📀 VC++ Redist (Optional)", "#888888")
            vcredist_btn.setToolTip("VC_redist.x64.exe - Only needed if you get VCRUNTIME errors. Most systems already have this.")
            vcredist_btn.clicked.connect(lambda: self._install_driver("VC_redist.x64.exe"))
            driver_btns.addWidget(vcredist_btn)
            
            driver_layout.addLayout(driver_btns)
            
            # Check driver status
            self.driver_status_label = QLabel("Checking drivers...")
            self.driver_status_label.setStyleSheet("color: #888;")
            driver_layout.addWidget(self.driver_status_label)
            self._check_drivers()
            
            layout.addWidget(driver_group)
        
        return tab
    
    # ═══════════════════════════════════════════════════════════════════════════
    # MODES TAB - Boot mode switching
    # ═══════════════════════════════════════════════════════════════════════════
    def _create_modes_tab(self) -> QWidget:
        """Create the Modes tab for boot mode switching."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        # Header
        header = QLabel("🔄 Device Boot Modes")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #00d4ff;")
        layout.addWidget(header)
        
        desc = QLabel("Switch your MediaTek device between different boot modes.\n"
                     "Each mode provides different access levels and functionality.")
        desc.setStyleSheet("color: #aaa;")
        layout.addWidget(desc)
        
        # Standard Modes
        std_group = QGroupBox("📱 Standard Boot Modes")
        std_layout = QVBoxLayout(std_group)
        
        modes_grid = QGridLayout()
        
        # Fastboot
        fastboot_btn = GlowingButton("⚡ FASTBOOT Mode", "#00d4ff")
        fastboot_btn.setToolTip("Standard Android fastboot mode for flashing")
        fastboot_btn.clicked.connect(lambda: self._switch_mode("FASTBOOT"))
        modes_grid.addWidget(fastboot_btn, 0, 0)
        self._register_button('fastboot_btn', fastboot_btn)
        
        # Recovery
        recovery_btn = GlowingButton("🔧 RECOVERY Mode", "#00ff88")
        recovery_btn.setToolTip("Boot to recovery mode")
        recovery_btn.clicked.connect(lambda: self._switch_mode("RECOVERY"))
        modes_grid.addWidget(recovery_btn, 0, 1)
        self._register_button('recovery_btn', recovery_btn)
        
        # Normal Boot
        normal_btn = GlowingButton("📱 Normal Boot", "#888888")
        normal_btn.setToolTip("Boot normally to Android")
        normal_btn.clicked.connect(lambda: self._switch_mode("off"))
        modes_grid.addWidget(normal_btn, 1, 0)
        self._register_button('normal_btn', normal_btn)
        
        # Shutdown
        shutdown_btn = GlowingButton("⏻ Shutdown", "#ff6b6b")
        shutdown_btn.setToolTip("Power off device")
        shutdown_btn.clicked.connect(lambda: self._switch_mode("SHUTDOWN"))
        modes_grid.addWidget(shutdown_btn, 1, 1)
        self._register_button('shutdown_btn', shutdown_btn)
        
        std_layout.addLayout(modes_grid)
        layout.addWidget(std_group)
        
        # Factory/Meta Modes  
        factory_group = QGroupBox("🏭 Factory & Meta Modes")
        factory_layout = QVBoxLayout(factory_group)
        
        factory_desc = QLabel("⚠️ These modes are used for factory testing and diagnostics.\n"
                             "Device may appear to be bricked but can be recovered.")
        factory_desc.setStyleSheet("color: #ffa500; font-size: 11px;")
        factory_layout.addWidget(factory_desc)
        
        factory_grid = QGridLayout()
        
        meta_btn = GlowingButton("📡 META Mode", "#9966ff")
        meta_btn.setToolTip("MediaTek META mode for SP Flash Tool")
        meta_btn.clicked.connect(lambda: self._switch_mode("METAMETA"))
        factory_grid.addWidget(meta_btn, 0, 0)
        self._register_button('meta_btn', meta_btn)
        
        factory_btn = GlowingButton("🏭 FACTORY Mode", "#ffa500")
        factory_btn.setToolTip("Factory test mode")
        factory_btn.clicked.connect(lambda: self._switch_mode("FACTFACT"))
        factory_grid.addWidget(factory_btn, 0, 1)
        self._register_button('factory_btn', factory_btn)
        
        advmeta_btn = GlowingButton("🔬 ADV META Mode", "#ff6b6b")
        advmeta_btn.setToolTip("Advanced META mode - more access")
        advmeta_btn.clicked.connect(lambda: self._switch_mode("ADVEMETA"))
        factory_grid.addWidget(advmeta_btn, 1, 0)
        self._register_button('advmeta_btn', advmeta_btn)
        
        at_btn = GlowingButton("📞 AT Command Mode", "#00d4ff")
        at_btn.setToolTip("AT command mode for modem access")
        at_btn.clicked.connect(lambda: self._switch_mode("ATCMDAT"))
        factory_grid.addWidget(at_btn, 1, 1)
        self._register_button('at_btn', at_btn)
        
        factory_layout.addLayout(factory_grid)
        layout.addWidget(factory_group)
        
        # Debug Modes
        debug_group = QGroupBox("🐛 Debug & Development Modes")
        debug_layout = QVBoxLayout(debug_group)
        
        debug_grid = QGridLayout()
        
        usb_btn = GlowingButton("🔌 USB Mode", "#00d4ff")
        usb_btn.setToolTip("USB debug mode")
        usb_btn.clicked.connect(lambda: self._switch_mode("usb"))
        debug_grid.addWidget(usb_btn, 0, 0)
        self._register_button('usb_btn', usb_btn)
        
        uart_btn = GlowingButton("📟 UART Mode", "#ffa500")
        uart_btn.setToolTip("UART serial debug mode")
        uart_btn.clicked.connect(lambda: self._switch_mode("uart"))
        debug_grid.addWidget(uart_btn, 0, 1)
        self._register_button('uart_btn', uart_btn)
        
        adb_btn = GlowingButton("🤖 ADB Mode", "#00ff88")
        adb_btn.setToolTip("Enable ADB debugging")
        adb_btn.clicked.connect(lambda: self._switch_mode("ADB"))
        debug_grid.addWidget(adb_btn, 1, 0)
        self._register_button('adb_btn', adb_btn)
        
        debug_layout.addLayout(debug_grid)
        layout.addWidget(debug_group)
        
        # Device Control
        control_group = QGroupBox("🎮 Device Control")
        control_layout = QHBoxLayout(control_group)
        
        reset_btn = GlowingButton("🔄 Reset Device", "#ffa500")
        reset_btn.setToolTip("Send reset command to device")
        reset_btn.clicked.connect(self._reset_device)
        control_layout.addWidget(reset_btn)
        self._register_button('reset_btn', reset_btn)
        
        reboot_btn = GlowingButton("♻️ Reboot to Current", "#00d4ff")
        reboot_btn.setToolTip("Reboot device without mode change")
        reboot_btn.clicked.connect(lambda: self._switch_mode("REBOOT"))
        control_layout.addWidget(reboot_btn)
        self._register_button('reboot_btn', reboot_btn)
        
        layout.addWidget(control_group)
        
        layout.addStretch()
        return tab
    
    # ═══════════════════════════════════════════════════════════════════════════
    # META MODE TAB - Standard Meta Mode operations
    # ═══════════════════════════════════════════════════════════════════════════
    def _create_meta_tab(self) -> QWidget:
        """Create the Meta Mode tab with MTK-specific meta operations."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        # Header
        header = QLabel("📡 META Mode Operations")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #9966ff;")
        layout.addWidget(header)
        
        desc = QLabel("META mode provides factory-level access to MediaTek devices.\n"
                     "Connect device in META mode first (hold Vol+ while connecting).")
        desc.setStyleSheet("color: #aaa;")
        layout.addWidget(desc)
        
        # Connection Status
        status_group = QGroupBox("📶 META Connection Status")
        status_layout = QVBoxLayout(status_group)
        
        self.meta_status_label = QLabel("⚪ Not connected in META mode")
        self.meta_status_label.setStyleSheet("font-size: 14px; padding: 10px;")
        status_layout.addWidget(self.meta_status_label)
        
        meta_connect_btn = GlowingButton("🔌 Connect META Mode", "#9966ff")
        meta_connect_btn.clicked.connect(self._connect_meta_mode)
        status_layout.addWidget(meta_connect_btn)
        self._register_button('meta_connect_btn', meta_connect_btn)
        
        layout.addWidget(status_group)
        
        # NVRAM Operations
        nvram_group = QGroupBox("💾 NVRAM Operations")
        nvram_layout = QVBoxLayout(nvram_group)
        
        nvram_desc = QLabel("NVRAM stores device calibration, IMEI, and configuration data.")
        nvram_desc.setStyleSheet("color: #888; font-size: 11px;")
        nvram_layout.addWidget(nvram_desc)
        
        nvram_btns = QGridLayout()
        
        backup_nvram_btn = GlowingButton("📥 Backup NVRAM", "#00d4ff")
        backup_nvram_btn.clicked.connect(self._backup_nvram)
        nvram_btns.addWidget(backup_nvram_btn, 0, 0)
        self._register_button('backup_nvram_btn', backup_nvram_btn)
        
        restore_nvram_btn = GlowingButton("📤 Restore NVRAM", "#ffa500")
        restore_nvram_btn.clicked.connect(self._restore_nvram)
        nvram_btns.addWidget(restore_nvram_btn, 0, 1)
        self._register_button('restore_nvram_btn', restore_nvram_btn)
        
        nvram_layout.addLayout(nvram_btns)
        layout.addWidget(nvram_group)
        
        # IMEI Operations
        imei_group = QGroupBox("📱 IMEI Operations")
        imei_layout = QVBoxLayout(imei_group)
        
        imei_warn = QLabel("⚠️ Changing IMEI may be illegal in your country. Use responsibly.")
        imei_warn.setStyleSheet("color: #ff6b6b; font-size: 11px;")
        imei_layout.addWidget(imei_warn)
        
        # Read IMEI
        read_imei_layout = QHBoxLayout()
        meta_read_imei_btn = GlowingButton("📖 Read IMEI", "#00d4ff")
        meta_read_imei_btn.clicked.connect(self._read_imei)
        meta_read_imei_btn.setToolTip("Click to read IMEI from device (reads nvdata partition)")
        read_imei_layout.addWidget(meta_read_imei_btn)
        # Don't register this one - it shares function with read_imei_btn
        
        self.imei_display = QLineEdit()
        self.imei_display.setReadOnly(True)
        self.imei_display.setPlaceholderText("← Click 'Read IMEI' to fetch from device")
        self.imei_display.setToolTip("IMEI will be displayed here after clicking Read IMEI")
        read_imei_layout.addWidget(self.imei_display, 1)
        imei_layout.addLayout(read_imei_layout)
        
        # Write IMEI
        write_imei_layout = QHBoxLayout()
        write_imei_layout.addWidget(QLabel("New IMEI:"))
        self.imei_input = QLineEdit()
        self.imei_input.setPlaceholderText("Enter 15-digit IMEI")
        self.imei_input.setMaxLength(15)
        write_imei_layout.addWidget(self.imei_input, 1)
        
        meta_write_imei_btn = GlowingButton("✏️ Write IMEI", "#ff6b6b")
        meta_write_imei_btn.clicked.connect(self._write_imei)
        write_imei_layout.addWidget(meta_write_imei_btn)
        imei_layout.addLayout(write_imei_layout)
        
        layout.addWidget(imei_group)
        
        # Modem/Baseband
        modem_group = QGroupBox("📶 Modem/Baseband")
        modem_layout = QVBoxLayout(modem_group)
        
        modem_btns = QHBoxLayout()
        
        backup_modem_btn = GlowingButton("📥 Backup Modem", "#00d4ff")
        backup_modem_btn.clicked.connect(self._backup_modem)
        modem_btns.addWidget(backup_modem_btn)
        self._register_button('backup_modem_btn', backup_modem_btn)
        
        restore_modem_btn = GlowingButton("📤 Restore Modem", "#ffa500")
        restore_modem_btn.clicked.connect(self._restore_modem)
        modem_btns.addWidget(restore_modem_btn)
        self._register_button('restore_modem_btn', restore_modem_btn)
        
        modem_layout.addLayout(modem_btns)
        layout.addWidget(modem_group)
        
        # Network / SIM Unlock
        network_group = QGroupBox("🔓 Network/SIM Unlock")
        network_layout = QVBoxLayout(network_group)
        
        network_desc = QLabel(
            "Remove carrier/network locks (SIM restrictions).\n"
            "🔥 'Unlock Network' patches the modem — works on most MTK devices!\n"
            "ℹ️ NCK/AT methods available for META mode. NOT FRP or bootloader lock."
        )
        network_desc.setStyleSheet("color: #888; font-size: 11px;")
        network_layout.addWidget(network_desc)
        
        # Lock status display
        self.lock_status_display = QLineEdit()
        self.lock_status_display.setReadOnly(True)
        self.lock_status_display.setPlaceholderText("← Click 'Check Lock Status' to query device")
        self.lock_status_display.setToolTip("Lock status from AT+CLCK or NVRAM scan")
        network_layout.addWidget(self.lock_status_display)
        
        # Row 1: Check + Scan
        check_row = QHBoxLayout()
        
        check_lock_btn = GlowingButton("🔍 Check Lock Status", "#00d4ff")
        check_lock_btn.clicked.connect(self._check_network_lock)
        check_lock_btn.setToolTip("Query lock status via META AT+CLCK or NVRAM scan")
        check_row.addWidget(check_lock_btn)
        self._register_button('check_lock_btn', check_lock_btn)
        
        scan_sml_btn = GlowingButton("🔬 Scan SML Data", "#ffa500")
        scan_sml_btn.clicked.connect(self._scan_sml_data)
        scan_sml_btn.setToolTip("Deep scan protect1/protect2/nvdata for SIM lock structures")
        check_row.addWidget(scan_sml_btn)
        self._register_button('scan_sml_btn', scan_sml_btn)
        
        network_layout.addLayout(check_row)
        
        # Row 2: NCK code input + Apply
        nck_row = QHBoxLayout()
        nck_row.addWidget(QLabel("NCK Code:"))
        self.nck_input = QLineEdit()
        self.nck_input.setPlaceholderText("Enter carrier unlock code (from carrier or service)")
        self.nck_input.setMaxLength(20)
        self.nck_input.setToolTip(
            "Network Control Key — get this from your carrier or an unlock service.\n"
            "Applied via AT+CLCK in META mode (same method as typing it on the phone)."
        )
        nck_row.addWidget(self.nck_input, 1)
        
        apply_nck_btn = GlowingButton("🔓 Apply NCK", "#00ff88")
        apply_nck_btn.clicked.connect(self._apply_nck_code)
        apply_nck_btn.setToolTip("Send unlock code to modem via AT+CLCK (META mode required)")
        nck_row.addWidget(apply_nck_btn)
        
        network_layout.addLayout(nck_row)
        
        # Row 3: Primary unlock + Engineering codes
        unlock_row = QHBoxLayout()
        
        unlock_modem_btn = GlowingButton("🔓 Unlock Network (Modem Patch)", "#00ff88")
        unlock_modem_btn.clicked.connect(self._modem_patch_for_unlock)
        unlock_modem_btn.setToolTip(
            "Patches modem firmware to remove carrier/network lock.\n"
            "Works on most MTK devices — no NCK code needed!\n"
            "Modem image is backed up automatically before patching."
        )
        unlock_row.addWidget(unlock_modem_btn)
        
        eng_unlock_btn = GlowingButton("🔧 Try Engineering Codes", "#ff6b6b")
        eng_unlock_btn.clicked.connect(self._try_engineering_unlock)
        eng_unlock_btn.setToolTip(
            "Try known default/engineering NCK codes via META AT commands.\n"
            "Works on some budget MTK devices that ship with default codes.\n"
            "Requires META mode connection."
        )
        unlock_row.addWidget(eng_unlock_btn)
        
        network_layout.addLayout(unlock_row)
        
        layout.addWidget(network_group)
        
        layout.addStretch()
        return tab
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ADVANCED META MODE TAB - Low-level meta operations
    # ═══════════════════════════════════════════════════════════════════════════
    def _create_advanced_meta_tab(self) -> QWidget:
        """Create the Advanced Meta Mode tab with low-level operations."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(15)
        
        # Header
        header = QLabel("🔬 Advanced META Operations")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff6b6b;")
        layout.addWidget(header)
        
        warning = QLabel("⚠️ DANGER ZONE: These operations can permanently damage your device!\n"
                        "Only use if you know exactly what you're doing.")
        warning.setStyleSheet("color: #ff6b6b; font-weight: bold; padding: 10px; "
                            "background: #ff6b6b20; border-radius: 6px;")
        layout.addWidget(warning)
        
        # Hardware Info
        hw_group = QGroupBox("🔧 Hardware Information")
        hw_layout = QVBoxLayout(hw_group)
        
        hw_btns = QGridLayout()
        
        chipid_btn = GlowingButton("🆔 Read Chip ID", "#00d4ff")
        chipid_btn.clicked.connect(self._read_chip_id)
        hw_btns.addWidget(chipid_btn, 0, 0)
        self._register_button('chipid_btn', chipid_btn)
        
        meid_btn = GlowingButton("📋 Read ME ID", "#00d4ff")
        meid_btn.clicked.connect(self._read_me_id)
        hw_btns.addWidget(meid_btn, 0, 1)
        self._register_button('meid_btn', meid_btn)
        
        socid_btn = GlowingButton("🔲 Read SOC ID", "#00d4ff")
        socid_btn.clicked.connect(self._read_soc_id)
        hw_btns.addWidget(socid_btn, 1, 0)
        self._register_button('socid_btn', socid_btn)
        
        hwcode_btn = GlowingButton("📊 Full HW Info", "#00d4ff")
        hwcode_btn.clicked.connect(self._read_full_hw_info)
        hw_btns.addWidget(hwcode_btn, 1, 1)
        self._register_button('hwcode_btn', hwcode_btn)
        
        hw_layout.addLayout(hw_btns)
        layout.addWidget(hw_group)
        
        # eFuse Operations
        efuse_group = QGroupBox("🔥 eFuse Operations (PERMANENT!)")
        efuse_layout = QVBoxLayout(efuse_group)
        
        efuse_warn = QLabel("⚠️ eFuses are ONE-TIME PROGRAMMABLE! Once blown, they CANNOT be undone!")
        efuse_warn.setStyleSheet("color: #ff0000; font-weight: bold;")
        efuse_layout.addWidget(efuse_warn)
        
        efuse_btns = QGridLayout()
        
        read_efuse_adv_btn = GlowingButton("📖 Read eFuses", "#00d4ff")
        read_efuse_adv_btn.clicked.connect(self._read_efuses)
        efuse_btns.addWidget(read_efuse_adv_btn, 0, 0)
        self._register_button('read_efuse_adv_btn', read_efuse_adv_btn)
        
        dump_efuse_btn = GlowingButton("📥 Dump eFuse to File", "#9966ff")
        dump_efuse_btn.clicked.connect(self._dump_efuses)
        efuse_btns.addWidget(dump_efuse_btn, 0, 1)
        self._register_button('dump_efuse_btn', dump_efuse_btn)
        
        efuse_layout.addLayout(efuse_btns)
        layout.addWidget(efuse_group)
        
        # Security Operations
        sec_group = QGroupBox("🛡️ Security Configuration")
        sec_layout = QVBoxLayout(sec_group)
        
        sec_btns = QGridLayout()
        
        read_seccfg_btn = GlowingButton("📖 Read SECCFG", "#00d4ff")
        read_seccfg_btn.clicked.connect(self._dump_seccfg)
        sec_btns.addWidget(read_seccfg_btn, 0, 0)
        self._register_button('read_seccfg_btn', read_seccfg_btn)
        
        reset_seccfg_adv_btn = GlowingButton("🔄 Reset SECCFG", "#ffa500")
        reset_seccfg_adv_btn.clicked.connect(self._reset_seccfg)
        sec_btns.addWidget(reset_seccfg_adv_btn, 0, 1)
        self._register_button('reset_seccfg_adv_btn', reset_seccfg_adv_btn)
        
        sbc_btn = GlowingButton("🔒 Check SBC Status", "#00d4ff")
        sbc_btn.clicked.connect(self._check_sbc_status)
        sec_btns.addWidget(sbc_btn, 1, 0)
        self._register_button('sbc_btn', sbc_btn)
        
        daa_btn = GlowingButton("🔐 Check DAA Status", "#00d4ff")
        daa_btn.clicked.connect(self._check_daa_status)
        sec_btns.addWidget(daa_btn, 1, 1)
        self._register_button('daa_btn', daa_btn)
        
        sec_layout.addLayout(sec_btns)
        layout.addWidget(sec_group)
        
        # BROM Exploits
        exploit_group = QGroupBox("💀 BROM Exploits & Bypass")
        exploit_layout = QVBoxLayout(exploit_group)
        
        exploit_desc = QLabel("Exploits to bypass security on protected devices.")
        exploit_desc.setStyleSheet("color: #888; font-size: 11px;")
        exploit_layout.addWidget(exploit_desc)
        
        exploit_btns = QGridLayout()
        
        kamakiri_btn = GlowingButton("🔥 Kamakiri Exploit", "#ff6b6b")
        kamakiri_btn.setToolTip("Use Kamakiri payload to bypass SBC")
        kamakiri_btn.clicked.connect(self._run_kamakiri)
        exploit_btns.addWidget(kamakiri_btn, 0, 0)
        self._register_button('kamakiri_btn', kamakiri_btn)
        
        amonet_btn = GlowingButton("⚡ Amonet Exploit", "#ff6b6b")
        amonet_btn.setToolTip("Use Amonet payload (older devices)")
        amonet_btn.clicked.connect(self._run_amonet)
        exploit_btns.addWidget(amonet_btn, 0, 1)
        self._register_button('amonet_btn', amonet_btn)
        
        carbonara_btn = GlowingButton("🍝 Carbonara Exploit", "#ff6b6b")
        carbonara_btn.setToolTip("Use Carbonara payload (MT67xx)")
        carbonara_btn.clicked.connect(self._run_carbonara)
        exploit_btns.addWidget(carbonara_btn, 1, 0)
        self._register_button('carbonara_btn', carbonara_btn)
        
        custom_payload_btn = GlowingButton("📦 Custom Payload", "#9966ff")
        custom_payload_btn.setToolTip("Load custom BROM payload")
        custom_payload_btn.clicked.connect(self._load_custom_payload)
        exploit_btns.addWidget(custom_payload_btn, 1, 1)
        self._register_button('custom_payload_btn', custom_payload_btn)
        
        exploit_layout.addLayout(exploit_btns)
        layout.addWidget(exploit_group)
        
        # Raw Memory Access
        raw_group = QGroupBox("🧠 Raw Memory Access")
        raw_layout = QVBoxLayout(raw_group)
        
        # Address input
        addr_layout = QHBoxLayout()
        addr_layout.addWidget(QLabel("Address (hex):"))
        self.raw_addr_input = QLineEdit()
        self.raw_addr_input.setPlaceholderText("0x00000000")
        addr_layout.addWidget(self.raw_addr_input)
        
        addr_layout.addWidget(QLabel("Length:"))
        self.raw_length_input = QLineEdit()
        self.raw_length_input.setPlaceholderText("0x1000")
        addr_layout.addWidget(self.raw_length_input)
        raw_layout.addLayout(addr_layout)
        
        raw_btns = QHBoxLayout()
        
        peek_btn = GlowingButton("👁️ Peek Memory", "#00d4ff")
        peek_btn.clicked.connect(self._peek_memory)
        raw_btns.addWidget(peek_btn)
        self._register_button('peek_btn', peek_btn)
        
        poke_btn = GlowingButton("✏️ Poke Memory", "#ff6b6b")
        poke_btn.setToolTip("Write to memory address - DANGEROUS!")
        poke_btn.clicked.connect(self._poke_memory)
        raw_btns.addWidget(poke_btn)
        self._register_button('poke_btn', poke_btn)
        
        raw_layout.addLayout(raw_btns)
        layout.addWidget(raw_group)
        
        layout.addStretch()
        return tab
    
    def _create_log_section(self) -> QGroupBox:
        """Create the log output section."""
        group = QGroupBox("📜 Output Log")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)
        
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMinimumHeight(150)
        self.log_output.setMaximumHeight(250)
        self.log_output.setStyleSheet("""
            QPlainTextEdit {
                background: #0a0a12;
                border: 1px solid #333;
                border-radius: 6px;
                font-family: "Cascadia Code", "Consolas", monospace;
                font-size: 10px;
                color: #00ff88;
                padding: 6px;
            }
        """)
        layout.addWidget(self.log_output)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background: #1a1a2e;
                border: 1px solid #333;
                border-radius: 4px;
                height: 6px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00d4ff, stop:1 #00ff88);
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(4)
        
        popout_btn = QPushButton("🔲 Pop-out")
        popout_btn.setToolTip("Open console in floating window")
        popout_btn.clicked.connect(self._show_floating_console)
        popout_btn.setMaximumWidth(80)
        
        clear_btn = QPushButton("🗑️ Clear")
        clear_btn.clicked.connect(self.log_output.clear)
        clear_btn.setMaximumWidth(70)
        
        save_btn = QPushButton("💾 Save")
        save_btn.clicked.connect(self._save_log)
        save_btn.setMaximumWidth(70)
        
        self.cancel_btn = QPushButton("❌ Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_operation)
        self.cancel_btn.setMaximumWidth(80)
        
        btn_layout.addWidget(popout_btn)
        btn_layout.addWidget(clear_btn)
        btn_layout.addWidget(save_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)
        
        return group
    
    def _show_floating_console(self, welcome: bool = False):
        """Show floating console window with rebellious Anarchy theme."""
        if hasattr(self, 'floating_console') and self.floating_console.isVisible():
            self.floating_console.raise_()
            self.floating_console.activateWindow()
            return
        
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QPlainTextEdit, QPushButton, QHBoxLayout, QLabel
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QFont
        
        self.floating_console = QDialog(self)
        self.floating_console.setWindowTitle("🔥 MTK ANARCHY TERMINAL 🔥")
        self.floating_console.setWindowFlags(
            Qt.WindowType.Window | 
            Qt.WindowType.WindowStaysOnTopHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        self.floating_console.resize(700, 450)
        
        layout = QVBoxLayout(self.floating_console)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        
        # Rebellious header
        header = QLabel("⚡ BREAK THE CHAINS • UNLEASH YOUR DEVICE ⚡")
        header.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("color: #ff4444; padding: 5px;")
        layout.addWidget(header)
        
        self.floating_log = QPlainTextEdit()
        self.floating_log.setReadOnly(True)
        self.floating_log.setPlainText(self.log_output.toPlainText())
        self.floating_log.setStyleSheet("""
            QPlainTextEdit {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0a0a0f, stop:1 #12121a);
                border: 2px solid #ff444480;
                border-radius: 10px;
                font-family: "Cascadia Code", "Fira Code", "Consolas", monospace;
                font-size: 11px;
                color: #00ff88;
                padding: 12px;
                selection-background-color: #ff4444;
            }
        """)
        layout.addWidget(self.floating_log)
        
        # Welcome message with rebellious text
        if welcome:
            import random
            rebellious_messages = [
                "🔥 WELCOME TO THE UNDERGROUND • Your device, YOUR rules!",
                "⚡ ANARCHY ENGAGED • No locks can hold you now!",
                "💀 SYSTEM OVERRIDE • Taking back what's yours!",
                "🔓 FREEDOM LOADING • Break free from factory chains!",
                "⚔️ REBELLION ACTIVE • Your bootloader fears you!",
                "🏴 ANARCHY MODE • OEMs hate this one simple trick!",
                "💣 CHAOS UNLEASHED • MediaTek bows to your will!",
                "🗡️ DIGITAL LIBERATION • The revolution starts here!",
                "🌋 VOLCANIC FREEDOM • Melt away those restrictions!",
                "⛓️ CHAINS BREAKING • You bought it, you OWN it!",
                "🎭 UNMASKING YOUR DEVICE • No more hidden secrets!",
                "🚀 LAUNCH SEQUENCE • Escaping manufacturer prison!",
            ]
            self._log(random.choice(rebellious_messages))
            self._log("━" * 50)
            self._log("🏴 You bought it. You own it. Now CONTROL it.")
            self._log("━" * 50)
            self._log("💡 Connect your MTK device in BROM/Preloader mode")
            self._log("💡 Hold Volume buttons while plugging USB cable")
            self._log("⚡ Then click CONNECT DEVICE to begin liberation!")
            self._log("━" * 50)
        
        # Buttons with rebellious labels
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        
        clear_btn = QPushButton("🗑️ Purge Logs")
        clear_btn.setToolTip("Wipe the evidence clean")
        clear_btn.clicked.connect(lambda: (self.floating_log.clear(), self.log_output.clear()))
        
        save_btn = QPushButton("💾 Archive Intel")
        save_btn.setToolTip("Save logs for later analysis")
        save_btn.clicked.connect(self._save_log)
        
        minimize_btn = QPushButton("📥 Dock Console")
        minimize_btn.setToolTip("Hide this window (still runs in background)")
        minimize_btn.clicked.connect(self.floating_console.hide)
        
        # Connect device button - prominent!
        connect_btn = QPushButton("⚡ CONNECT DEVICE")
        connect_btn.setToolTip("Capture your MediaTek device in BROM/Preloader mode")
        connect_btn.clicked.connect(self._check_device)
        connect_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00ff88, stop:1 #00cc66);
                border: 2px solid #00ff88;
                border-radius: 8px;
                padding: 10px 20px;
                color: #000;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00ffaa, stop:1 #00ff88);
                border: 2px solid #00ffaa;
            }
            QPushButton:pressed {
                background: #00cc66;
            }
        """)
        
        # Cancel/Kill button - for when things go wrong
        cancel_btn = QPushButton("💀 KILL")
        cancel_btn.setToolTip("Force kill any running MTK operation")
        cancel_btn.clicked.connect(self._cancel_operation)
        cancel_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ff4444, stop:1 #cc2222);
                border: 2px solid #ff4444;
                border-radius: 8px;
                padding: 10px 16px;
                color: #fff;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ff6666, stop:1 #ff4444);
                border: 2px solid #ff6666;
            }
            QPushButton:pressed {
                background: #cc2222;
            }
        """)
        
        btn_layout.addWidget(connect_btn)
        btn_layout.addWidget(cancel_btn)
        btn_layout.addWidget(clear_btn)
        btn_layout.addWidget(save_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(minimize_btn)
        layout.addLayout(btn_layout)
        
        # Footer with rebellious text
        footer = QLabel("🏴 Image Anarchy • Your device was never truly theirs 🏴")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setStyleSheet("color: #666; font-size: 9px; padding: 3px;")
        layout.addWidget(footer)
        
        self.floating_console.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0d1117, stop:0.5 #161b22, stop:1 #0d1117);
                border: 2px solid #ff444460;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2a2a3e, stop:1 #1a1a2e);
                border: 1px solid #ff444480;
                border-radius: 6px;
                padding: 8px 16px;
                color: #ff6666;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #3a3a4e, stop:1 #2a2a3e);
                border: 1px solid #ff4444;
                color: #ff4444;
            }
            QPushButton:pressed {
                background: #ff444440;
            }
        """)
        
        self.floating_console.show()
        
        # Scroll to bottom
        self.floating_log.verticalScrollBar().setValue(
            self.floating_log.verticalScrollBar().maximum()
        )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Helper Methods
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _log(self, message: str):
        """Add message to log output."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_line = f"[{timestamp}] {message}"
        self.log_output.appendPlainText(log_line)
        self.log_output.verticalScrollBar().setValue(
            self.log_output.verticalScrollBar().maximum()
        )
        
        # Also update floating console if open
        if hasattr(self, 'floating_log') and hasattr(self, 'floating_console'):
            if self.floating_console.isVisible():
                self.floating_log.appendPlainText(log_line)
                self.floating_log.verticalScrollBar().setValue(
                    self.floating_log.verticalScrollBar().maximum()
                )
    
    def _browse_folder(self, line_edit: QLineEdit):
        """Browse for folder."""
        folder = QFileDialog.getExistingDirectory(self, "Select Folder", line_edit.text())
        if folder:
            line_edit.setText(folder)
    
    def _browse_file(self, line_edit: QLineEdit):
        """Browse for file."""
        file, _ = QFileDialog.getOpenFileName(
            self, "Select File", "",
            "Image Files (*.img *.bin);;All Files (*)"
        )
        if file:
            line_edit.setText(file)
    
    def _browse_save_file(self, line_edit: QLineEdit):
        """Browse for save file."""
        file, _ = QFileDialog.getSaveFileName(
            self, "Save File", line_edit.text(),
            "Binary Files (*.bin);;Image Files (*.img);;All Files (*)"
        )
        if file:
            line_edit.setText(file)
    
    def _save_log(self):
        """Save log to file."""
        file, _ = QFileDialog.getSaveFileName(
            self, "Save Log", "mtk_log.txt", "Text Files (*.txt)"
        )
        if file:
            with open(file, 'w') as f:
                f.write(self.log_output.toPlainText())
            self._log(f"Log saved to: {file}")
    
    def _select_partition(self, partition: str):
        """Select partition in list by name."""
        for i in range(self.partition_list.count()):
            item = self.partition_list.item(i)
            if partition.lower() in item.text().lower():
                item.setSelected(True)
                break
    
    def _check_mtk_client(self):
        """Check if MTKClient is installed."""
        mtk_path = find_mtk_client()
        mtk_dir = get_mtkclient_dir()
        
        if mtk_path:
            self.mtk_info_label.setText(f"✅ MTKClient found: {mtk_path}")
            self.mtk_info_label.setStyleSheet("color: #00ff88; font-weight: bold;")
        elif mtk_dir:
            self.mtk_info_label.setText(f"⚠️ MTKClient directory found but mtk.py missing: {mtk_dir}")
            self.mtk_info_label.setStyleSheet("color: #ffa500;")
        else:
            app_dir = get_app_dir()
            expected_path = os.path.join(app_dir, "mtkclient")
            self.mtk_info_label.setText(f"❌ MTKClient not found. Clone to: {expected_path}")
            self.mtk_info_label.setStyleSheet("color: #ff6b6b;")
    
    def _on_mode_changed(self, mode: str):
        """Handle mode change - update button states based on available operations."""
        self.current_mode = mode
        handler = get_device_handler()
        if not handler:
            return
        
        allowed_ops = handler.get_allowed_operations()
        
        # Update status indicator with mode
        if mode == "Disconnected":
            self.status_indicator.setText("🔴")
            self.status_indicator.setToolTip("Device not connected")
            self.status_card.set_value("Disconnected", "#ff6b6b")
        else:
            mode_colors = {
                'BROM': '#00ff88',
                'Preloader': '#00d4ff',
                'DA': '#00ff88',
                'META': '#9966ff',
                'ADV_META': '#ff6b6b',
            }
            color = mode_colors.get(mode, '#ffa500')
            self.status_card.set_value(f"Connected ({mode})", color)
        
        # Update the Meta Mode status label if present
        if hasattr(self, 'meta_status_label'):
            if mode in ('META', 'ADV_META'):
                self.meta_status_label.setText(f"🟢 Connected in {mode}")
                self.meta_status_label.setStyleSheet("font-size: 14px; padding: 10px; color: #00ff88;")
            elif mode == "Disconnected":
                self.meta_status_label.setText("⚪ Not connected")
                self.meta_status_label.setStyleSheet("font-size: 14px; padding: 10px; color: #888;")
            else:
                self.meta_status_label.setText(f"🟡 Connected in {mode} (not META)")
                self.meta_status_label.setStyleSheet("font-size: 14px; padding: 10px; color: #ffa500;")
        
        # Update all tracked buttons
        disabled_count = 0
        enabled_count = 0
        for btn_name, operation in self.BUTTON_OPERATIONS.items():
            if btn_name in self.mode_buttons:
                btn = self.mode_buttons[btn_name]
                is_allowed = operation in allowed_ops
                btn.setEnabled(is_allowed)
                
                # Update tooltip to show why button is disabled
                if not is_allowed and mode != "Disconnected":
                    current_tooltip = btn.toolTip() or ""
                    # Don't add duplicate mode info
                    if "Not available in" not in current_tooltip:
                        btn.setToolTip(f"{current_tooltip}\n⚠️ Not available in {mode} mode" if current_tooltip else f"⚠️ Not available in {mode} mode")
                    disabled_count += 1
                else:
                    # Remove mode warning from tooltip if previously added
                    current_tooltip = btn.toolTip() or ""
                    if "⚠️ Not available in" in current_tooltip:
                        btn.setToolTip(current_tooltip.split("\n⚠️")[0])
                    if is_allowed:
                        enabled_count += 1
        
        # Log the mode change summary
        self._log(f"🔄 Mode: {mode} | {enabled_count} operations enabled, {disabled_count} disabled")
    
    def _register_button(self, name: str, button) -> None:
        """Register a button for mode-aware enable/disable."""
        self.mode_buttons[name] = button
    
    def _check_drivers(self):
        """Check if Windows drivers are available."""
        if sys.platform != 'win32':
            return
        
        drivers_dir = get_drivers_dir()
        usbdk = os.path.join(drivers_dir, "UsbDk_1.0.22_x64.msi")
        vcredist = os.path.join(drivers_dir, "VC_redist.x64.exe")
        
        status_parts = []
        if os.path.exists(usbdk):
            status_parts.append("✅ UsbDk available")
        else:
            status_parts.append("❌ UsbDk not found in drivers/")
        
        if os.path.exists(vcredist):
            status_parts.append("✅ VC++ Redist available")
        else:
            status_parts.append("❌ VC++ Redist not found in drivers/")
        
        self.driver_status_label.setText("  |  ".join(status_parts))
    
    def _install_driver(self, filename: str):
        """Install a driver from the drivers folder."""
        drivers_dir = get_drivers_dir()
        driver_path = os.path.join(drivers_dir, filename)
        
        if not os.path.exists(driver_path):
            QMessageBox.warning(
                self, "Driver Not Found",
                f"Driver not found: {driver_path}\n\n"
                f"Please download and place the following in the drivers/ folder:\n"
                f"• UsbDk_1.0.22_x64.msi\n"
                f"• VC_redist.x64.exe"
            )
            return
        
        self._log(f"Installing driver: {filename}")
        
        try:
            if filename.endswith('.msi'):
                # Use full path to msiexec to avoid PATH issues
                msiexec_path = os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32', 'msiexec.exe')
                subprocess.Popen([msiexec_path, '/i', driver_path])
            else:
                subprocess.Popen([driver_path])
            self._log(f"✅ Launched installer: {filename}")
        except Exception as e:
            self._log(f"❌ Error launching installer: {e}")
    
    def _clone_mtkclient(self):
        """Clone mtkclient repository into plugin directory."""
        plugin_dir = get_plugin_dir()
        mtk_dir = os.path.join(plugin_dir, "mtkclient")
        
        if os.path.exists(mtk_dir):
            reply = QMessageBox.question(
                self, "Directory Exists",
                f"MTKClient directory already exists at:\n{mtk_dir}\n\nDelete and re-clone?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                import shutil
                shutil.rmtree(mtk_dir, ignore_errors=True)
            else:
                return
        
        self._log(f"Cloning mtkclient to: {mtk_dir}")
        self._log("Running: git clone https://github.com/bkerler/mtkclient.git")
        
        try:
            result = subprocess.run(
                ["git", "clone", "https://github.com/bkerler/mtkclient.git", mtk_dir],
                capture_output=True, text=True, cwd=plugin_dir
            )
            if result.returncode == 0:
                self._log("✅ MTKClient cloned successfully!")
                self._log("Now click 'Install Requirements' to install Python dependencies.")
                self._check_mtk_client()
            else:
                self._log(f"❌ Clone failed: {result.stderr}")
                self._log("Make sure Git is installed: https://git-scm.com/")
        except FileNotFoundError:
            self._log("❌ Git not found! Please install Git first.")
            self._log("Download from: https://git-scm.com/download/win")
            QMessageBox.warning(
                self, "Git Not Found",
                "Git is not installed.\n\n"
                "Please install Git from:\nhttps://git-scm.com/download/win"
            )
        except Exception as e:
            self._log(f"❌ Error: {e}")
    
    def _install_requirements(self):
        """Install mtkclient requirements."""
        mtk_dir = get_mtkclient_dir()
        if not mtk_dir:
            # Default to plugin directory
            plugin_dir = get_plugin_dir()
            mtk_dir = os.path.join(plugin_dir, "mtkclient")
        
        req_file = os.path.join(mtk_dir, "requirements.txt")
        
        if not os.path.exists(req_file):
            QMessageBox.warning(
                self, "Requirements Not Found",
                f"requirements.txt not found at:\n{req_file}\n\n"
                "Please clone mtkclient first."
            )
            return
        
        self._log(f"Installing requirements from: {req_file}")
        self._log("Running: pip install -r requirements.txt")
        
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", req_file],
                capture_output=True, text=True
            )
            self._log(result.stdout)
            if result.returncode == 0:
                self._log("✅ Requirements installed successfully!")
                self._check_mtk_client()
            else:
                self._log(f"❌ Installation failed: {result.stderr}")
        except Exception as e:
            self._log(f"❌ Error: {e}")
    
    def _open_mtkclient_folder(self):
        """Open the mtkclient folder in file explorer."""
        mtk_dir = get_mtkclient_dir()
        if not mtk_dir:
            # Default to plugin directory
            plugin_dir = get_plugin_dir()
            mtk_dir = os.path.join(plugin_dir, "mtkclient")
        
        if os.path.exists(mtk_dir):
            if sys.platform == 'win32':
                os.startfile(mtk_dir)
            elif sys.platform == 'darwin':
                subprocess.run(['open', mtk_dir])
            else:
                subprocess.run(['xdg-open', mtk_dir])
            self._log(f"Opened folder: {mtk_dir}")
        else:
            QMessageBox.information(
                self, "Folder Not Found",
                f"MTKClient folder not found at:\n{mtk_dir}\n\n"
                "Clone it first using the button above."
            )
    
    def _set_busy(self, busy: bool):
        """Set UI busy state."""
        self.cancel_btn.setEnabled(busy)
        self.progress_bar.setVisible(busy)
        if busy:
            self.progress_bar.setRange(0, 0)  # Indeterminate
        else:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
    
    def _start_operation(self, operation: str, **kwargs):
        """Start a worker thread operation."""
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Busy", "Another operation is in progress.")
            return
        
        self._set_busy(True)
        self.worker = MtkWorkerThread(operation, **kwargs)
        self.worker.log.connect(self._log)
        self.worker.progress.connect(self._on_progress)
        self.worker.result_data.connect(self._on_result_data)
        self.worker.finished_signal.connect(self._on_finished)
        self.worker.start()
    
    def _cancel_operation(self):
        """Cancel current operation - forcefully kill the process."""
        # Kill the MTK process first
        if kill_mtk_process():
            self._log("💀 MTK process TERMINATED!")
        
        # Then cancel the worker thread
        if self.worker:
            self.worker.cancel()
            self._log("⚠️ Operation cancelled by user")
        
        # Reset UI state
        self._set_busy(False)
    
    def _test_gpt(self):
        """Quick test to list GPT partitions and show raw output for debugging."""
        self._log("━" * 50)
        self._log("📋 TESTING GPT - Running mtk printgpt --debugmode...")
        self._log("━" * 50)
        self._log("⚠️ Device must be in BROM/Preloader mode!")
        self._log("💡 If it hangs on 'Waiting for PreLoader', device needs reconnection")
        self._log("━" * 50)
        
        def log_and_parse(line):
            self._log(line.rstrip())
        
        success, output = run_mtk_command(["printgpt", "--debugmode"], callback=log_and_parse)
        
        self._log("━" * 50)
        self._log(f"✅ Command finished. Success: {success}")
        self._log(f"📄 Output length: {len(output)} chars")
        
        # Check for connection issues
        output_lower = output.lower()
        if "waiting for" in output_lower and "preloader" in output_lower:
            self._log("━" * 50)
            self._log("🔴 DEVICE NOT IN BROM MODE!")
            self._log("📱 To reconnect:")
            self._log("   1. Unplug USB cable")
            self._log("   2. Power off device completely")
            self._log("   3. Hold Volume Down (or both Vol buttons)")
            self._log("   4. While holding, plug USB cable")
            self._log("━" * 50)
            return
        
        # Try to parse partitions
        partitions = self._parse_partitions_static(output)
        
        if partitions:
            self._log(f"🎯 PARSED {len(partitions)} PARTITIONS:")
            for i, p in enumerate(partitions[:20], 1):  # Show first 20
                self._log(f"  {i}. {p}")
            if len(partitions) > 20:
                self._log(f"  ... and {len(partitions) - 20} more")
        else:
            self._log("⚠️ NO PARTITIONS PARSED!")
            self._log("🔍 Showing first 1000 chars of raw output:")
            self._log("─" * 40)
            for line in output[:1000].split('\n'):
                self._log(f"  │ {line}")
            self._log("─" * 40)
        
        self._log("━" * 50)
    
    def _parse_partitions_static(self, output: str) -> list:
        """Static version of partition parser for quick testing."""
        import re
        partitions = []
        lines = output.split('\n')
        in_table = False
        
        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue
            
            # Detect "GPT Table:" or similar header
            if 'GPT Table' in line or 'gpt table' in line.lower():
                in_table = True
                continue
            
            # Skip separator lines
            if line_stripped.startswith('-') or line_stripped.startswith('='):
                continue
            
            if in_table:
                # mtkclient format: "partition_name:      Offset 0x..., Length 0x..."
                if 'Offset 0x' in line and ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        part_name = parts[0].strip()
                        if part_name and not part_name.startswith('0x'):
                            partitions.append(part_name)
                elif ':' in line and 'Offset' in line:
                    part_name = line.split(':')[0].strip()
                    if part_name and not part_name.startswith('0x') and part_name.lower() not in ['gpt', 'table']:
                        partitions.append(part_name)
        
        # Fallback: any line with "Offset" and colon
        if not partitions:
            for line in lines:
                if 'Offset' in line and ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        part_name = parts[0].strip()
                        if part_name and not part_name.lower().startswith(('0x', 'gpt', 'total')):
                            if part_name not in partitions:
                                partitions.append(part_name)
        
        # Second fallback: regex
        if not partitions:
            for line in lines:
                match = re.match(r'^(\w+)\s+(?:Offset\s+)?0x', line.strip())
                if match:
                    part_name = match.group(1)
                    if part_name.lower() not in ['gpt', 'table', 'total', 'disk']:
                        if part_name not in partitions:
                            partitions.append(part_name)
        
        # Remove duplicates
        seen = set()
        unique = []
        for p in partitions:
            p_lower = p.lower()
            if p_lower not in seen:
                seen.add(p_lower)
                unique.append(p)
        
        return unique
    
    def _on_progress(self, current: int, total: int, message: str):
        """Handle progress update."""
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(current)
    
    def _on_result_data(self, data):
        """Handle result data from worker."""
        if isinstance(data, dict):
            if 'detected' in data:
                # Device check result
                if data['detected']:
                    self.device_connected = True
                    self.status_indicator.setText("🟢")
                    self.status_indicator.setToolTip("Device connected")
                    self.status_card.set_value("Connected (BROM)", "#00ff88")
                    # Note: Partitions should already be in the check_device response
                    # Don't auto-fetch GPT separately - it can hang
                else:
                    self.device_connected = False
                    self.status_indicator.setText("🔴")
                    self.status_indicator.setToolTip("Device not connected")
                    self.status_card.set_value("Not Connected", "#ff6b6b")
            
            if 'cpu' in data:
                self.cpu_card.set_value(data.get('cpu', 'Unknown'), "#00ff88")
            if 'hw_code' in data:
                self.hwcode_card.set_value(data.get('hw_code', 'Unknown'), "#00d4ff")
            if 'me_id' in data:
                self.meid_card.set_value(data.get('me_id', 'Unknown')[:20] + "...", "#ffa500")
            
            if 'partitions' in data:
                # Update Read tab partition list
                self.partition_list.clear()
                handler = get_device_handler()
                partition_data = data.get('partition_data', [])
                for i, part in enumerate(data['partitions']):
                    if part.strip():
                        # Try to get size from partition_data
                        size_str = ""
                        if partition_data and i < len(partition_data):
                            size = partition_data[i].get('size', 0)
                            size_str = f"  ({size / (1024*1024):.1f} MB)" if size > 1024*1024 else f"  ({size / 1024:.1f} KB)" if size > 0 else ""
                        item = QListWidgetItem(f"📦 {part}{size_str}")
                        item.setData(Qt.ItemDataRole.UserRole, part)
                        self.partition_list.addItem(item)
                
                # Also update Write tab partition list
                if hasattr(self, 'write_partition_list'):
                    self.write_partition_list.clear()
                    handler = get_device_handler()
                    if handler.partitions:
                        for part in handler.partitions:
                            name = part.get('name', 'unknown')
                            size = part.get('size', 0)
                            size_str = f"{size / (1024*1024):.1f} MB" if size > 1024*1024 else f"{size / 1024:.1f} KB"
                            item = QListWidgetItem(f"📦 {name}  ({size_str})")
                            item.setData(Qt.ItemDataRole.UserRole, name)
                            self.write_partition_list.addItem(item)
                    else:
                        for part in data['partitions']:
                            if part.strip():
                                item = QListWidgetItem(f"📦 {part}")
                                item.setData(Qt.ItemDataRole.UserRole, part)
                                self.write_partition_list.addItem(item)
                
                # Also update Erase tab partition list
                if hasattr(self, 'erase_partition_list'):
                    self.erase_partition_list.clear()
                    handler = get_device_handler()
                    if handler.partitions:
                        for part in handler.partitions:
                            name = part.get('name', 'unknown')
                            size = part.get('size', 0)
                            size_str = f"{size / (1024*1024):.1f} MB" if size > 1024*1024 else f"{size / 1024:.1f} KB"
                            item = QListWidgetItem(f"🗑️ {name}  ({size_str})")
                            item.setData(Qt.ItemDataRole.UserRole, name)
                            self.erase_partition_list.addItem(item)
                    else:
                        for part in data['partitions']:
                            if part.strip():
                                item = QListWidgetItem(f"🗑️ {part}")
                                item.setData(Qt.ItemDataRole.UserRole, part)
                                self.erase_partition_list.addItem(item)
            
            # Handle IMEI data - display in the META tab IMEI field
            if 'imeis' in data:
                imei_list = data['imeis']
                if imei_list and len(imei_list) > 0:
                    # Display IMEIs in the imei_display field
                    if hasattr(self, 'imei_display'):
                        imei_text = " / ".join(imei_list)
                        self.imei_display.setText(imei_text)
                        self._log(f"📱 Displayed IMEI(s): {imei_text}")
    
    def _on_finished(self, success: bool, message: str):
        """Handle operation finished."""
        self._set_busy(False)
        if success:
            self._log(f"✅ {message}")
        else:
            self._log(f"❌ {message}")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Operations
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _check_device(self):
        """Check for device connection."""
        self._start_operation("check_device")
    
    def _get_gpt(self):
        """Get GPT partition table."""
        self._start_operation("get_gpt", output_dir=self.output_dir)
    
    def _quick_read_partition(self, partition: str):
        """Quick read a partition - doesn't require list selection."""
        if not self.device_connected:
            QMessageBox.warning(self, "Not Connected", "Please connect a device first.")
            return
        output_dir = self.read_output_edit.text() if hasattr(self, 'read_output_edit') else self.output_dir
        self._log(f"📥 Quick reading: {partition}")
        self._start_operation("read_partition", partition=partition, output_dir=output_dir)
    
    def _read_partition(self, partition: str):
        """Read a specific partition."""
        output_dir = self.read_output_edit.text() if hasattr(self, 'read_output_edit') else self.output_dir
        self._start_operation("read_partition", partition=partition, output_dir=output_dir)
    
    def _read_selected_partitions(self):
        """Read all selected partitions."""
        selected = self.partition_list.selectedItems()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select at least one partition.")
            return
        
        # For now, read one at a time
        for item in selected:
            # Get partition name from UserRole data (preferred) or parse text as fallback
            partition = item.data(Qt.ItemDataRole.UserRole)
            if not partition:
                # Fallback: parse from text
                text = item.text()
                # Remove emoji prefix if present (📦)
                if text.startswith('📦'):
                    text = text[1:].strip()
                # Extract partition name (first word before any size info)
                partition = text.split()[0] if text else text
                partition = partition.replace(':', '').strip()
            if partition:
                self._read_partition(partition)
                break  # TODO: Queue multiple reads
    
    def _on_partition_double_clicked(self, item: QListWidgetItem):
        """Handle double-click on partition list item to read it directly."""
        # Get partition name from UserRole data (preferred) or parse text as fallback
        partition = item.data(Qt.ItemDataRole.UserRole)
        if not partition:
            # Fallback: parse from text
            text = item.text()
            if text.startswith('📦'):
                text = text[1:].strip()
            partition = text.split()[0] if text else text
            partition = partition.replace(':', '').strip()
        if partition:
            self._log(f"📥 Double-clicked: Reading partition '{partition}'")
            self._read_partition(partition)
    
    def _read_full_flash(self):
        """Read full flash dump."""
        output_file = self.flash_output_edit.text() if hasattr(self, 'flash_output_edit') else os.path.join(self.output_dir, "flash_dump.bin")
        self._start_operation("read_flash", output_file=output_file)
    
    def _write_partition(self):
        """Write a partition from list selection."""
        # Get selected partition from list
        selected = self.write_partition_list.currentItem() if hasattr(self, 'write_partition_list') else None
        if selected:
            partition = selected.data(Qt.ItemDataRole.UserRole)
        else:
            partition = self.write_selected_label.text() if hasattr(self, 'write_selected_label') else ""
        
        input_file = self.write_input_edit.text()
        
        if not partition or partition == "None":
            QMessageBox.warning(self, "No Selection", "Please select a partition from the list first.")
            return
        
        if not input_file:
            QMessageBox.warning(self, "No File", "Please select an image file to write.")
            return
        
        if not os.path.exists(input_file):
            QMessageBox.warning(self, "File Not Found", f"File not found: {input_file}")
            return
        
        reply = QMessageBox.question(
            self, "Confirm Write",
            f"⚠️ Are you sure you want to write:\n\n"
            f"  File: {os.path.basename(input_file)}\n"
            f"  To partition: {partition}\n\n"
            "This can BRICK your device if done incorrectly!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._start_operation("write_partition", partition=partition, input_file=input_file)
    
    def _write_full_flash(self):
        """Write/restore full flash from file."""
        input_file = self.restore_input_edit.text() if hasattr(self, 'restore_input_edit') else ""
        
        if not input_file:
            QMessageBox.warning(self, "No File", "Please select a flash dump file to restore.")
            return
        
        if not os.path.exists(input_file):
            QMessageBox.warning(self, "File Not Found", f"File not found: {input_file}")
            return
        
        # Get file size for confirmation
        size = os.path.getsize(input_file)
        size_str = f"{size / (1024*1024*1024):.2f} GB" if size > 1024*1024*1024 else f"{size / (1024*1024):.1f} MB"
        
        reply = QMessageBox.warning(
            self, "⚠️ DANGER - Full Flash Restore",
            f"⚠️⚠️⚠️ EXTREME WARNING ⚠️⚠️⚠️\n\n"
            f"You are about to OVERWRITE your ENTIRE device flash!\n\n"
            f"  File: {os.path.basename(input_file)}\n"
            f"  Size: {size_str}\n\n"
            "This will ERASE EVERYTHING on your device!\n"
            "Only proceed if this backup is from THE SAME DEVICE.\n\n"
            "Are you ABSOLUTELY sure?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Double confirm
            reply2 = QMessageBox.warning(
                self, "Final Confirmation",
                "FINAL WARNING!\n\n"
                "This is your last chance to cancel.\n"
                "Proceeding will overwrite your entire device.\n\n"
                "Continue with full flash restore?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply2 == QMessageBox.StandardButton.Yes:
                self._start_operation("write_flash", input_file=input_file)

    def _unlock_bootloader(self):
        """Unlock bootloader."""
        reply = QMessageBox.question(
            self, "Confirm Unlock",
            "Are you sure you want to unlock the bootloader?\n\n"
            "This will:\n"
            "• Enable flashing custom ROMs/recoveries\n"
            "• May void warranty\n"
            "• May wipe user data",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._start_operation("unlock_bootloader")
    
    def _lock_bootloader(self):
        """Lock bootloader."""
        reply = QMessageBox.question(
            self, "Confirm Lock",
            "Are you sure you want to lock the bootloader?\n\n"
            "⚠️ Make sure you have stock firmware installed!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._start_operation("lock_bootloader")
    
    def _erase_frp(self):
        """Erase FRP partition."""
        reply = QMessageBox.question(
            self, "Confirm FRP Erase",
            "Are you sure you want to erase the FRP partition?\n\n"
            "⚠️ Only do this on your own device!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._start_operation("erase_frp")
    
    def _dump_preloader(self):
        """Dump preloader."""
        output_dir = self.dump_output_edit.text() if hasattr(self, 'dump_output_edit') else self.output_dir
        self._start_operation("dump_preloader", output_dir=output_dir)
    
    def _dump_brom(self):
        """Dump Boot ROM."""
        output_dir = self.dump_output_edit.text() if hasattr(self, 'dump_output_edit') else self.output_dir
        self._start_operation("dump_brom", output_dir=output_dir)
    
    def _dump_seccfg(self):
        """Dump seccfg."""
        self._start_operation("dump_seccfg", output_dir=self.output_dir)
    
    def _reset_seccfg(self):
        """Reset seccfg."""
        reply = QMessageBox.question(
            self, "Confirm Reset",
            "Are you sure you want to reset seccfg?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._start_operation("reset_seccfg")
    
    def _get_rpmb(self):
        """Extract RPMB keys."""
        output_dir = self.rpmb_output_edit.text() if hasattr(self, 'rpmb_output_edit') else self.output_dir
        self._start_operation("get_rpmb", output_dir=output_dir)
    
    def _run_custom_command(self):
        """Run custom MTK command."""
        command = self.custom_cmd_edit.text().strip()
        if not command:
            QMessageBox.warning(self, "No Command", "Please enter a command to run.")
            return
        
        self._start_operation("custom_command", command=command)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # NEW v2.1.2 Feature Callbacks - The Rebellion Grows Stronger!
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _patch_vbmeta(self):
        """Patch vbmeta to disable verification."""
        mode_text = self.vbmeta_mode_combo.currentText()
        mode = int(mode_text.split(" - ")[0])  # Extract mode number
        
        mode_names = {
            0: "RE-LOCK (enable all restrictions)",
            1: "DISABLE VERITY ONLY",
            2: "DISABLE VERIFICATION ONLY",
            3: "DISABLE BOTH (full freedom)"
        }
        
        reply = QMessageBox.question(
            self, "Confirm VBMeta Patch",
            f"This will patch vbmeta to: {mode_names.get(mode, 'Unknown')}\n\n"
            "This modifies Android Verified Boot settings.\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._start_operation("patch_vbmeta", mode=mode)
    
    def _read_efuses(self):
        """Read eFuses from device."""
        self._start_operation("read_efuses")
    
    def _get_target_config(self):
        """Get device security configuration."""
        self._start_operation("get_target_config")
    
    def _memory_dump(self):
        """Dump device memory."""
        output_dir = self.dump_output_edit.text() if hasattr(self, 'dump_output_edit') else self.output_dir
        
        dump_type_text = self.memdump_type_combo.currentText()
        dump_type = "dram" if "DRAM Only" in dump_type_text else "full"
        
        reply = QMessageBox.question(
            self, "Confirm Memory Dump",
            f"This will dump device memory ({dump_type}).\n\n"
            "This may take several minutes for full dumps.\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._start_operation("memory_dump", output_dir=output_dir, dump_type=dump_type)
    
    def _set_meta_mode(self):
        """Switch device to meta mode."""
        mode_text = self.meta_mode_combo.currentText()
        mode = mode_text.split(" - ")[0].strip()  # Extract mode name
        
        reply = QMessageBox.question(
            self, "Confirm Mode Switch",
            f"This will switch the device to: {mode}\n\n"
            "The device will power off and restart via USB.\n"
            "Keep the USB cable connected!\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._start_operation("set_meta_mode", mode=mode)
    
    def _reset_device(self):
        """Send reset command to device."""
        reply = QMessageBox.question(
            self, "Confirm Reset",
            "This will send a reset command to the device.\n\n"
            "You will need to disconnect the USB cable to power off.\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._start_operation("reset_device")
    
    def _read_rpmb_direct(self):
        """Read RPMB partition directly."""
        output_dir = self.dump_output_edit.text() if hasattr(self, 'dump_output_edit') else self.output_dir
        self._start_operation("read_rpmb", output_dir=output_dir)
    
    def _write_imei_ui(self):
        """UI callback for IMEI write."""
        imei1 = self.imei1_edit.text().strip()
        imei2 = self.imei2_edit.text().strip()
        
        if not imei1:
            QMessageBox.warning(self, "Missing IMEI", "Please enter IMEI 1")
            return
        
        if not imei1.isdigit() or len(imei1) < 14 or len(imei1) > 15:
            QMessageBox.warning(self, "Invalid IMEI", "IMEI 1 must be 14-15 digits")
            return
        
        if imei2 and (not imei2.isdigit() or len(imei2) < 14 or len(imei2) > 15):
            QMessageBox.warning(self, "Invalid IMEI", "IMEI 2 must be 14-15 digits")
            return
        
        # Confirmation dialog with warning
        reply = QMessageBox.warning(
            self, "⚠️ IMEI Write Confirmation",
            f"⚠️ WARNING: IMEI modification may be illegal in some jurisdictions!\n\n"
            f"This should only be used for:\n"
            f"• Device recovery after corruption\n"
            f"• Legitimate repair purposes\n\n"
            f"IMEI 1: {imei1}\n"
            f"IMEI 2: {imei2 if imei2 else 'N/A'}\n\n"
            f"Are you sure you want to proceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._start_operation("write_imei", imei1=imei1, imei2=imei2, product="thunder")
    
    def _patch_modem_ui(self):
        """UI callback for modem patching."""
        reply = QMessageBox.question(
            self, "Patch Modem",
            "📡 MODEM PATCHING\n\n"
            "This patches the modem firmware (md1img) to allow IMEI operations.\n"
            "Required before IMEI write on some devices.\n\n"
            "Proceed with modem patching?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._start_operation("patch_modem")
    
    def _browse_rpmb_file(self):
        """Browse for RPMB file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select RPMB File", self.output_dir, "Binary Files (*.bin);;All Files (*)"
        )
        if file_path:
            self.rpmb_file_edit.setText(file_path)
    
    def _write_rpmb_advanced(self):
        """UI callback for RPMB write."""
        input_file = self.rpmb_file_edit.text().strip()
        
        if not input_file or not os.path.exists(input_file):
            QMessageBox.warning(self, "Missing File", "Please select a valid RPMB file to write")
            return
        
        sector = self.rpmb_sector_spin.value() if self.rpmb_sector_spin.value() > 0 else None
        sectors = self.rpmb_sectors_spin.value() if self.rpmb_sectors_spin.value() > 0 else None
        
        # EXTREME WARNING
        reply = QMessageBox.critical(
            self, "⚠️ EXTREME DANGER - RPMB WRITE",
            "💀 EXTREME DANGER: YOU ARE ABOUT TO WRITE TO RPMB!\n\n"
            "RPMB contains critical security data. Writing incorrect data\n"
            "can PERMANENTLY AND IRREVERSIBLY BRICK your device!\n\n"
            "Only proceed if:\n"
            "• You have a VERIFIED BACKUP of your RPMB\n"
            "• You know EXACTLY what this file contains\n"
            "• You accept ALL responsibility for the outcome\n\n"
            "⚠️ NO WARRANTY - YOUR DEVICE, YOUR RISK!\n\n"
            "Are you ABSOLUTELY CERTAIN?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._start_operation("write_rpmb", input_file=input_file, sector=sector, sectors=sectors)
    
    def _erase_rpmb_advanced(self):
        """UI callback for RPMB erase."""
        sector = self.rpmb_sector_spin.value() if self.rpmb_sector_spin.value() > 0 else None
        sectors = self.rpmb_sectors_spin.value() if self.rpmb_sectors_spin.value() > 0 else None
        
        # EXTREME WARNING
        reply = QMessageBox.critical(
            self, "☠️ MAXIMUM DANGER - RPMB ERASE",
            "☠️ MAXIMUM DANGER: YOU ARE ABOUT TO ERASE RPMB!\n\n"
            "This will DELETE ALL manufacturer security data!\n"
            "Your device may become PERMANENTLY UNBOOTABLE!\n\n"
            "This is the nuclear option. There is NO going back.\n\n"
            "⚠️ NO WARRANTY - CERTAIN BRICK RISK!\n\n"
            "Are you ABSOLUTELY CERTAIN you want to ERASE RPMB?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Double confirmation
            reply2 = QMessageBox.critical(
                self, "☠️ FINAL WARNING",
                "☠️ FINAL WARNING!\n\n"
                "You are about to ERASE RPMB. This action is IRREVERSIBLE.\n\n"
                "Type 'YES I UNDERSTAND' in your mind and click Yes only if\n"
                "you truly understand the consequences.\n\n"
                "PROCEED WITH RPMB ERASE?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply2 == QMessageBox.StandardButton.Yes:
                self._start_operation("erase_rpmb", sector=sector, sectors=sectors)
    
    def _auth_rpmb_advanced(self):
        """UI callback for RPMB authentication."""
        rpmb_key = self.rpmb_key_edit.text().strip()
        
        if rpmb_key:
            # Validate hex string
            try:
                bytes.fromhex(rpmb_key)
                if len(bytes.fromhex(rpmb_key)) != 32:
                    QMessageBox.warning(self, "Invalid Key", "RPMB key must be 32 bytes (64 hex characters)")
                    return
            except ValueError:
                QMessageBox.warning(self, "Invalid Key", "RPMB key must be a valid hex string")
                return
        
        self._start_operation("auth_rpmb", rpmb_key=rpmb_key if rpmb_key else None)

    # ═══════════════════════════════════════════════════════════════════════════
    # MODES TAB - Button Handlers
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _switch_mode(self, mode: str):
        """Switch device to specified boot mode."""
        
        # Map mode names to mtkclient commands
        mode_map = {
            "FASTBOOT": "FASTBOOT",
            "RECOVERY": "RECOVERY", 
            "METAMETA": "METAMETA",
            "FACTFACT": "FACTFACT",
            "ADVEMETA": "ADVEMETA",
            "ATCMDAT": "ATCMDAT",
            "ADB": "ADB",
            "SHUTDOWN": "SHUTDOWN",
            "REBOOT": "REBOOT",
            "off": "off",
            "usb": "usb",
            "uart": "uart",
        }
        
        mtk_mode = mode_map.get(mode, mode)
        
        # For mode transitions that require reboot, show info dialog
        if mtk_mode not in ["off", "usb", "uart", "SHUTDOWN", "REBOOT"]:
            # Create dialog with proper parent and flags to ensure visibility
            msg = QMessageBox(self)
            msg.setWindowTitle(f"Switch to {mode}")
            msg.setText(f"🔄 MODE SWITCH: {mode}")
            msg.setInformativeText(
                "HOW IT WORKS:\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "The device will go through up to 2 reboots:\n\n"
                "REBOOT 1: Watchdog reset (automatic)\n"
                "• USB may briefly show 'device not recognized'\n"
                "• Do NOT unplug the USB cable!\n\n"
                "REBOOT 2: PRE-META → Real META\n"
                "• You may see orange warning + 'META' text\n"
                "• Hold Vol Up + Vol Down + Power if needed\n"
                "• Screen goes BLACK = real META mode\n\n"
                "AFTER TRANSITION:\n"
                "• App will auto-scan for META serial port\n"
                "• If META serial found: AT commands available\n"
                "• If not: falls back to DA mode (still works!)\n\n"
                "Total time: ~15-30 seconds\n\n"
                "Continue?"
            )
            msg.setStandardButtons(QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
            msg.setDefaultButton(QMessageBox.StandardButton.Ok)
            msg.setIcon(QMessageBox.Icon.Information)
            
            # Ensure dialog appears on top and is focused
            msg.setWindowFlags(msg.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
            msg.activateWindow()
            msg.raise_()
            
            reply = msg.exec()
            if reply != QMessageBox.StandardButton.Ok:
                return
        
        self._log(f"🔄 Switching to {mtk_mode} mode...")
        self._start_operation("set_meta_mode", mode=mtk_mode)

    # ═══════════════════════════════════════════════════════════════════════════
    # META MODE TAB - Button Handlers
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _connect_meta_mode(self):
        """Connect to device in META mode via serial AT commands."""
        handler = get_device_handler()
        
        # Try META serial first
        self._log("📡 Scanning for META mode serial port...")
        self._log("━" * 45)
        self._log("🔍 Looking for MTK COM port (VID 0x0E8D)...")
        self._log("💡 Device must be in META mode (black screen)")
        self._log("━" * 45)
        
        if handler.connect_meta_serial(max_wait=10):
            self._log("")
            self._log("🎉 CONNECTED TO META MODE!")
            self._log("📡 AT commands ready")
            self._log("🏴 YOUR device, YOUR rules!")
            self._log("")
            self._log("💡 Use Read IMEI, Check Network Lock etc.")
        else:
            self._log("")
            self._log("⚠️ META serial port not found")
            self._log("💡 Trying normal connection (DA mode)...")
            self._log("💡 Most META tab operations work in DA mode too!")
            self._start_operation("check_device")
        
    def _backup_nvram(self):
        """Backup NVRAM partition."""
        output_dir = self.output_dir
        self._log("💾 Backing up NVRAM...")
        # Read nvram partition
        self._start_operation("read_partition", partition="nvram", output_dir=output_dir)
    
    def _restore_nvram(self):
        """Restore NVRAM partition."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select NVRAM Backup", "", "Binary Files (*.bin *.img);;All Files (*)"
        )
        if file_path:
            reply = QMessageBox.warning(
                self, "Confirm NVRAM Restore",
                "⚠️ Restoring NVRAM can affect device calibration!\n\n"
                "Only restore from a backup of THIS device.\n\n"
                "Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._start_operation("write_partition", partition="nvram", input_file=file_path)
    
    def _read_imei(self):
        """Read IMEI from device — uses META AT commands or DA method."""
        handler = get_device_handler()
        if handler.meta_connected and handler.meta_serial:
            self._log("📱 Reading IMEI via META AT commands...")
            imeis = handler.meta_read_imei_at()
            if imeis:
                self._log(f"✅ IMEI(s): {', '.join(imeis)}")
                if hasattr(self, 'imei_display'):
                    self.imei_display.setText(', '.join(imeis))
            else:
                self._log("⚠️ AT IMEI read failed, trying DA method...")
                self._start_operation("read_imei")
        else:
            self._log("📱 Reading IMEI via DA...")
            self._start_operation("read_imei")
    
    def _write_imei(self):
        """Write IMEI to device."""
        imei = self.imei_input.text().strip()
        
        if not imei:
            QMessageBox.warning(self, "Missing IMEI", "Please enter an IMEI")
            return
        
        if len(imei) != 15 or not imei.isdigit():
            QMessageBox.warning(self, "Invalid IMEI", "IMEI must be exactly 15 digits")
            return
        
        # Check if we successfully read IMEI first (indicates encryption is working)
        current_imei = self.imei_display.text().strip()
        if not current_imei or current_imei == "" or "Click" in self.imei_display.placeholderText():
            # No IMEI was read - warn strongly
            reply = QMessageBox.critical(
                self, "⚠️ DANGER - Read First!",
                "❌ You have not successfully read the IMEI!\n\n"
                "If IMEI reading failed, writing is EXTREMELY DANGEROUS:\n"
                "• The encryption format may not be compatible\n"
                "• Your device could lose its IMEI permanently\n"
                "• NVRAM corruption could brick your device\n\n"
                "STRONGLY RECOMMENDED: Click 'Read IMEI' first.\n"
                "Only proceed if you have a NVRAM backup.\n\n"
                "Write anyway? (NOT RECOMMENDED)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No  # Default to No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        
        reply = QMessageBox.warning(
            self, "Confirm IMEI Write",
            f"⚠️ You are about to write IMEI: {imei}\n\n"
            "Changing IMEI may be illegal in your country!\n"
            "Make sure you have a NVRAM backup first!\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            handler = get_device_handler()
            if handler.meta_connected and handler.meta_serial:
                self._log(f"📝 Writing IMEI via META AT command: {imei}")
                slot = getattr(self, 'imei_slot_combo', None)
                slot_num = 1 if (slot and slot.currentIndex() == 1) else 0
                if handler.meta_write_imei_at(imei, slot_num):
                    self._log("✅ IMEI written successfully via META!")
                    self._log("💡 Read IMEI to verify the change")
                else:
                    self._log("⚠️ AT write failed, trying DA method...")
                    self._start_operation("write_imei", imei=imei)
            else:
                self._start_operation("write_imei", imei=imei)
    
    def _backup_modem(self):
        """Backup modem partition."""
        output_dir = self.output_dir
        self._log("📶 Backing up modem/md1img...")
        self._start_operation("read_partition", partition="md1img", output_dir=output_dir)
    
    def _restore_modem(self):
        """Restore modem partition."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Modem Backup", "", "Binary Files (*.bin *.img);;All Files (*)"
        )
        if file_path:
            reply = QMessageBox.warning(
                self, "Confirm Modem Restore",
                "⚠️ Restoring modem can affect cellular connectivity!\n\n"
                "Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._start_operation("write_partition", partition="md1img", input_file=file_path)
    
    def _check_network_lock(self):
        """Check network lock status — uses META AT commands or DA method."""
        handler = get_device_handler()
        if handler.meta_connected and handler.meta_serial:
            self._log("🔍 Checking network lock via META AT commands...")
            self._log("━" * 45)
            results = handler.meta_check_network_lock_at()
            if results is not None:
                locked = [k for k, v in results.items() if v is True]
                unlocked = [k for k, v in results.items() if v is False]
                unknown = [k for k, v in results.items() if v is None]
                
                # Update the status display
                if locked:
                    status = f"🔒 LOCKED: {', '.join(locked)}"
                    if unlocked:
                        status += f"  |  ✅ Unlocked: {', '.join(unlocked)}"
                    self._log(f"⚠️ Active locks: {', '.join(locked)}")
                elif unlocked:
                    status = "✅ ALL UNLOCKED"
                    self._log("✅ No active network locks!")
                else:
                    status = "❓ Could not determine"
                    
                if hasattr(self, 'lock_status_display'):
                    self.lock_status_display.setText(status)
            else:
                self._log("⚠️ AT lock check failed, trying DA scan...")
                self._check_network_lock_da()
            self._log("━" * 45)
        else:
            self._check_network_lock_da()
    
    def _check_network_lock_da(self):
        """Check network lock status by reading nvdata partition."""
        self._log("🔍 Checking network lock status via partition scan...")
        self._log("━" * 45)
        self._log("📡 Reading nvdata to check SIM lock info...")
        
        handler = get_device_handler()
        if not handler.connected:
            self._log("❌ Device not connected")
            if hasattr(self, 'lock_status_display'):
                self.lock_status_display.setText("❌ Not connected")
            return
            
        try:
            import tempfile
            import os
            
            temp_file = os.path.join(tempfile.gettempdir(), "nvdata_check.bin")
            if handler.read_partition("nvdata", temp_file, silent_fail=True):
                with open(temp_file, "rb") as f:
                    nvdata = f.read()
                
                self._log(f"✅ Read {len(nvdata)} bytes from nvdata")
                
                lock_indicators = [
                    (b"SIM_LOCK", "SIM Lock data"),
                    (b"SIMMELOCK", "SIM ME Lock"),
                    (b"NW_LOCK", "Network Lock"),
                    (b"SP_LOCK", "Service Provider Lock"),
                    (b"CP_LOCK", "Corporate Lock"),
                    (b"SUBSET_LOCK", "Subset Lock"),
                ]
                
                found = []
                for pattern, name in lock_indicators:
                    if pattern in nvdata:
                        pos = nvdata.find(pattern)
                        self._log(f"⚠️ Found {name} at offset 0x{pos:X}")
                        found.append(name)
                
                if found:
                    status = f"⚠️ Lock indicators: {', '.join(found)}"
                    self._log("   Use 'Scan SML Data' for detailed analysis")
                else:
                    status = "✅ No lock indicators in nvdata"
                    self._log("✅ No SIM lock indicators found in nvdata")
                
                if hasattr(self, 'lock_status_display'):
                    self.lock_status_display.setText(status)
                
                os.remove(temp_file)
            else:
                self._log("❌ Failed to read nvdata partition")
                if hasattr(self, 'lock_status_display'):
                    self.lock_status_display.setText("❌ Could not read nvdata")
                    
        except Exception as e:
            self._log(f"❌ Error checking lock status: {e}")
            if hasattr(self, 'lock_status_display'):
                self.lock_status_display.setText(f"❌ Error: {e}")
    
    def _apply_nck_code(self):
        """Apply user-provided NCK code via META AT commands."""
        if not hasattr(self, 'nck_input'):
            self._log("❌ NCK input not available")
            return
        
        nck_code = self.nck_input.text().strip()
        if not nck_code:
            QMessageBox.warning(self, "No Code", "Please enter an NCK (unlock code) first.")
            return
        
        handler = get_device_handler()
        if not handler.meta_connected or not handler.meta_serial:
            QMessageBox.warning(
                self, "META Required",
                "⚠️ META Mode Required\n\n"
                "NCK unlock uses AT modem commands which require META mode.\n\n"
                "Steps:\n"
                "1. Go to the Modes tab\n"
                "2. Switch to META mode\n"
                "3. Come back here and try again"
            )
            return
        
        # Warn about retry limits
        reply = QMessageBox.warning(
            self, "Apply NCK Code",
            f"🔓 APPLY NETWORK UNLOCK CODE\n\n"
            f"Code: {nck_code}\n\n"
            f"⚠️ IMPORTANT:\n"
            f"• Wrong codes count against the retry limit!\n"
            f"• Too many wrong codes = PERMANENT LOCK\n"
            f"• Most devices allow 5-10 attempts\n\n"
            f"Are you sure this is the correct code?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self._log(f"🔓 Applying NCK code: {nck_code}")
        self._log("━" * 45)
        
        # Try all lock types — most devices only have PN (Network)
        lock_types = [
            ("PN", "Network Lock"),
            ("PU", "Network Subset Lock"),
            ("PP", "Service Provider Lock"),
            ("PC", "Corporate Lock"),
        ]
        
        any_success = False
        for facility, name in lock_types:
            # First check if this lock type is active
            resp = handler.meta_at_command(f'AT+CLCK="{facility}",2')
            if resp and "+CLCK: 1" in resp:
                self._log(f"🔒 {name} is ACTIVE — applying code...")
                result = handler.meta_unlock_network_at(nck_code, lock_type=facility)
                if result:
                    any_success = True
                    self._log(f"✅ {name} UNLOCKED!")
                else:
                    self._log(f"❌ {name} unlock FAILED")
            elif resp and "+CLCK: 0" in resp:
                self._log(f"✅ {name} already unlocked")
            else:
                self._log(f"   {name}: not supported or no response")
        
        self._log("━" * 45)
        
        if any_success:
            self._log("🎉 Unlock successful! Verifying...")
            if hasattr(self, 'lock_status_display'):
                self.lock_status_display.setText("✅ UNLOCKED")
            # Re-check status
            self._check_network_lock()
        else:
            self._log("❌ Code did not work on any lock type")
            if hasattr(self, 'lock_status_display'):
                self.lock_status_display.setText("❌ NCK rejected")
    
    def _try_engineering_unlock(self):
        """Try default engineering NCK codes."""
        handler = get_device_handler()
        if not handler.meta_connected or not handler.meta_serial:
            QMessageBox.warning(
                self, "META Required",
                "⚠️ META Mode Required\n\n"
                "Engineering code unlock requires META mode AT commands.\n\n"
                "Steps:\n"
                "1. Go to the Modes tab\n"
                "2. Switch to META mode\n"
                "3. Come back here and try again"
            )
            return
        
        reply = QMessageBox.warning(
            self, "⚠️ Engineering Codes",
            "🔧 TRY ENGINEERING UNLOCK CODES\n\n"
            "This will try ~10 known default/engineering NCK codes\n"
            "that work on some budget MTK devices.\n\n"
            "⚠️ WARNINGS:\n"
            "• Each wrong code counts against the retry limit\n"
            "• If all 10 fail, you'll have ~0 retries left\n"
            "• This is a LAST RESORT for carrier-locked devices\n"
            "• Use only if you can't get the real code\n\n"
            "Most devices allow 10+ retries before permanent lock.\n\n"
            "Proceed with engineering code attempts?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self._log("🔧 Starting engineering code attempts...")
        result = handler.meta_try_engineering_codes()
        
        if result == "already_unlocked":
            if hasattr(self, 'lock_status_display'):
                self.lock_status_display.setText("✅ Already unlocked!")
        elif result:
            self._log(f"🎉 Working code found: {result}")
            if hasattr(self, 'nck_input'):
                self.nck_input.setText(result)
            if hasattr(self, 'lock_status_display'):
                self.lock_status_display.setText(f"✅ UNLOCKED (code: {result})")
        else:
            if hasattr(self, 'lock_status_display'):
                self.lock_status_display.setText("❌ Engineering codes failed")
    
    def _scan_sml_data(self):
        """Scan protect1/protect2/nvdata for SIM lock data structures."""
        handler = get_device_handler()
        if not handler.connected:
            QMessageBox.warning(self, "Not Connected", "Device must be connected to scan partitions.")
            return
        
        reply = QMessageBox.information(
            self, "SML Scan",
            "🔬 DEEP SIM LOCK DATA SCAN\n\n"
            "This will read protect1, protect2, nvdata, and nvcfg\n"
            "partitions and scan for SIM lock data structures.\n\n"
            "The scan looks for:\n"
            "• SIMMELOCK / SML_LOCK markers\n"
            "• Lock state bytes (locked/unlocked)\n"
            "• MCC/MNC allowlists (carrier codes)\n"
            "• LDI headers with SML-related LIDs\n\n"
            "This is a READ-ONLY operation — nothing is modified.\n"
            "Results appear in the log below.",
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel
        )
        
        if reply == QMessageBox.StandardButton.Cancel:
            return
        
        self._log("🔬 Starting deep SML scan...")
        self._start_operation("scan_sml_data")
    
    def _modem_patch_for_unlock(self):
        """Patch modem firmware to remove carrier/network lock."""
        reply = QMessageBox.question(
            self, "🔓 Unlock Network",
            "🔓 NETWORK UNLOCK VIA MODEM PATCH\n\n"
            "This patches the modem firmware (md1img) to remove\n"
            "carrier/network lock restrictions.\n\n"
            "HOW IT WORKS:\n"
            "• Replaces carrier RSA key with our own\n"
            "• Patches SIM lock check instructions in modem code\n"
            "• Neutralizes SIMMELOCK/SML markers\n\n"
            "✅ Works on most MTK devices — no unlock code needed!\n"
            "📦 Your original modem is backed up automatically.\n\n"
            "After patching, reboot the phone and insert any SIM.\n\n"
            "Proceed with network unlock?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._log("🔓 Unlocking network via modem patch...")
            self._log("━" * 45)
            self._log("📦 Original modem backed up automatically")
            self._log("🔧 Patching RSA keys + SIM lock instructions...")
            self._log("━" * 45)
            self._start_operation("patch_modem")

    # ═══════════════════════════════════════════════════════════════════════════
    # ADVANCED META TAB - Button Handlers
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _read_chip_id(self):
        """Read device chip ID."""
        self._log("🆔 Reading Chip ID...")
        self._start_operation("get_target_config")
    
    def _read_me_id(self):
        """Read ME ID."""
        self._log("📋 Reading ME ID...")
        self._start_operation("check_device")
    
    def _read_soc_id(self):
        """Read SOC ID."""
        self._log("🔲 Reading SOC ID...")
        self._start_operation("check_device")
    
    def _read_full_hw_info(self):
        """Read full hardware info."""
        self._log("📊 Reading full hardware information...")
        self._start_operation("check_device")
    
    def _read_efuses(self):
        """Read eFuse values."""
        self._log("📖 Reading eFuses...")
        self._start_operation("read_efuses")
    
    def _dump_efuses(self):
        """Dump eFuses to file."""
        output_dir = self.output_dir
        self._log("📥 Dumping eFuses to file...")
        self._start_operation("read_efuses", output_dir=output_dir)
    
    def _check_sbc_status(self):
        """Check Secure Boot status."""
        self._log("🔒 Checking Secure Boot (SBC) status...")
        self._start_operation("get_target_config")
    
    def _check_daa_status(self):
        """Check Download Agent Authentication status."""
        self._log("🔐 Checking DAA status...")
        self._start_operation("get_target_config")
    
    def _run_kamakiri(self):
        """Run Kamakiri exploit."""
        reply = QMessageBox.warning(
            self, "Confirm Kamakiri Exploit",
            "🔥 This will attempt the Kamakiri BROM exploit.\n\n"
            "This is used to bypass Secure Boot on vulnerable devices.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._log("🔥 Running Kamakiri exploit...")
            self._run_custom_cmd("crash")  # Kamakiri is automatically used by mtkclient
    
    def _run_amonet(self):
        """Run Amonet exploit."""
        reply = QMessageBox.warning(
            self, "Confirm Amonet Exploit", 
            "⚡ This will attempt the Amonet BROM exploit.\n\n"
            "This works on older MTK devices (MT67xx and earlier).\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._log("⚡ Running Amonet exploit...")
            self._run_custom_cmd("crash amonet")
    
    def _run_carbonara(self):
        """Run Carbonara exploit."""
        reply = QMessageBox.warning(
            self, "Confirm Carbonara Exploit",
            "🍝 This will attempt the Carbonara BROM exploit.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._log("🍝 Running Carbonara exploit...")
            self._run_custom_cmd("crash carbonara")
    
    def _load_custom_payload(self):
        """Load and execute custom BROM payload."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Custom Payload", "", "Binary Files (*.bin);;All Files (*)"
        )
        
        if file_path:
            reply = QMessageBox.warning(
                self, "Confirm Custom Payload",
                f"⚠️ You are about to execute a custom payload!\n\n"
                f"File: {file_path}\n\n"
                "This can permanently damage your device!\n\n"
                "Only use payloads from trusted sources!\n\n"
                "Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self._log(f"📦 Loading custom payload: {file_path}")
                self._run_custom_cmd(f"payload --payload {file_path}")
    
    def _peek_memory(self):
        """Peek (read) memory at address."""
        addr = self.raw_addr_input.text().strip()
        length = self.raw_length_input.text().strip()
        
        if not addr:
            QMessageBox.warning(self, "Missing Address", "Please enter a memory address")
            return
        
        # Default length if not specified
        if not length:
            length = "0x100"
        
        self._log(f"👁️ Peeking memory at {addr}, length {length}...")
        self._run_custom_cmd(f"peek {addr} {length}")
    
    def _poke_memory(self):
        """Poke (write) memory at address."""
        addr = self.raw_addr_input.text().strip()
        
        if not addr:
            QMessageBox.warning(self, "Missing Address", "Please enter a memory address")
            return
        
        # Get data to write
        data, ok = QInputDialog.getText(
            self, "Memory Write", 
            "Enter hex data to write (e.g., DEADBEEF):"
        )
        
        if ok and data:
            reply = QMessageBox.critical(
                self, "☠️ CONFIRM MEMORY WRITE",
                f"☠️ EXTREME DANGER!\n\n"
                f"Address: {addr}\n"
                f"Data: {data}\n\n"
                "Writing to wrong address can PERMANENTLY BRICK your device!\n\n"
                "Are you ABSOLUTELY CERTAIN?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self._log(f"✏️ Poking memory at {addr} with {data}...")
                self._run_custom_cmd(f"poke {addr} {data}")
    
    def _run_custom_cmd(self, cmd: str):
        """Run a custom mtkclient command."""
        self._start_operation("custom_command", command=cmd)


# ═══════════════════════════════════════════════════════════════════════════════
# Plugin Class (Required by Image Anarchy plugin system)
# ═══════════════════════════════════════════════════════════════════════════════

class MtkToolkitPlugin:
    """MTK Toolkit Plugin for Image Anarchy."""
    
    def __init__(self):
        self.manifest = None
        self.parent_window = None
        self.widget = None
    
    def get_name(self) -> str:
        return self.manifest.name if self.manifest else "MTK Toolkit"
    
    def get_icon(self) -> str:
        return self.manifest.icon if self.manifest else "⚡"
    
    def get_description(self) -> str:
        return self.manifest.description if self.manifest else ""
    
    def get_version(self) -> str:
        return self.manifest.version if self.manifest else "1.0"
    
    def get_author(self) -> str:
        return self.manifest.author if self.manifest else "Image Anarchy Team"
    
    def create_widget(self, parent_window) -> QWidget:
        """Create and return the plugin widget."""
        self.parent_window = parent_window
        self.widget = PluginWidget(parent_window)
        return self.widget

    # ── Remote Control (Host/Professional) ──────────────────────────────────

    # All MTK operations with their risk levels and human-readable names
    _REMOTE_OP_DEFS = {
        # READ operations — safe, read-only
        'read_imei':             {'name': 'Read IMEI',              'risk': 'READ',   'desc': 'Read device IMEI numbers'},
        'meta_read_imei':        {'name': 'Read IMEI (META)',       'risk': 'READ',   'desc': 'Read IMEI via META mode AT commands'},
        'read_efuses':           {'name': 'Read eFuses',            'risk': 'READ',   'desc': 'Read hardware eFuse values'},
        'read_chip_id':          {'name': 'Read Chip ID',           'risk': 'READ',   'desc': 'Read MediaTek chip identifier'},
        'read_me_id':            {'name': 'Read ME ID',             'risk': 'READ',   'desc': 'Read ME identifier'},
        'read_soc_id':           {'name': 'Read SoC ID',            'risk': 'READ',   'desc': 'Read System-on-Chip identifier'},
        'read_full_hw_info':     {'name': 'Read Hardware Info',     'risk': 'READ',   'desc': 'Read full hardware configuration'},
        'check_network_lock':    {'name': 'Check Network Lock',     'risk': 'READ',   'desc': 'Check SIM/network lock status'},
        'meta_check_network_lock': {'name': 'Check Lock (META)',    'risk': 'READ',   'desc': 'Check network lock via META mode'},
        'scan_sml_data':         {'name': 'Scan SML Data',          'risk': 'READ',   'desc': 'Scan SIM lock data structures'},
        'check_sbc_status':      {'name': 'Check SBC Status',       'risk': 'READ',   'desc': 'Check Secure Boot status'},
        'check_daa_status':      {'name': 'Check DAA Status',       'risk': 'READ',   'desc': 'Check Download Agent Auth status'},
        'get_gpt':               {'name': 'Read Partition Table',    'risk': 'READ',   'desc': 'Read GPT partition layout'},
        'dump_seccfg':           {'name': 'Dump SecCfg',            'risk': 'READ',   'desc': 'Read security configuration'},
        'read_partition':        {'name': 'Read Partition',          'risk': 'READ',   'desc': 'Read a flash partition to file'},
        'read_full_flash':       {'name': 'Read Full Flash',        'risk': 'READ',   'desc': 'Read entire flash storage'},
        'dump_brom':             {'name': 'Dump BROM',              'risk': 'READ',   'desc': 'Dump Boot ROM'},
        'dump_preloader':        {'name': 'Dump Preloader',         'risk': 'READ',   'desc': 'Dump preloader partition'},
        # MODIFY operations — change device state
        'patch_modem':           {'name': 'Patch Modem',            'risk': 'MODIFY', 'desc': 'Patch modem for network unlock'},
        'write_imei':            {'name': 'Write IMEI',             'risk': 'MODIFY', 'desc': 'Write IMEI number to device'},
        'meta_write_imei':       {'name': 'Write IMEI (META)',      'risk': 'MODIFY', 'desc': 'Write IMEI via META mode'},
        'unlock_bootloader':     {'name': 'Unlock Bootloader',      'risk': 'MODIFY', 'desc': 'Unlock device bootloader'},
        'lock_bootloader':       {'name': 'Lock Bootloader',        'risk': 'MODIFY', 'desc': 'Re-lock device bootloader'},
        'patch_vbmeta':          {'name': 'Patch vbmeta',           'risk': 'MODIFY', 'desc': 'Disable verified boot'},
        'meta_unlock_network':   {'name': 'Unlock Network (META)',  'risk': 'MODIFY', 'desc': 'Attempt network unlock via META'},
        'meta_try_engineering_codes': {'name': 'Try Eng Codes',     'risk': 'MODIFY', 'desc': 'Try engineering unlock codes'},
        'backup_nvram':          {'name': 'Backup NVRAM',           'risk': 'MODIFY', 'desc': 'Backup NVRAM partition'},
        'restore_nvram':         {'name': 'Restore NVRAM',          'risk': 'MODIFY', 'desc': 'Restore NVRAM from backup'},
        'backup_modem':          {'name': 'Backup Modem',           'risk': 'MODIFY', 'desc': 'Backup modem partition'},
        'restore_modem':         {'name': 'Restore Modem',          'risk': 'MODIFY', 'desc': 'Restore modem from backup'},
        'set_meta_mode':         {'name': 'Switch to META',         'risk': 'MODIFY', 'desc': 'Switch device to META mode'},
        'switch_mode':           {'name': 'Switch Mode',            'risk': 'MODIFY', 'desc': 'Switch device boot mode'},
        'remove_network_lock':   {'name': 'Remove Network Lock',    'risk': 'MODIFY', 'desc': 'Remove SIM/network lock'},
        # DANGER operations — destructive
        'erase_partition':       {'name': 'Erase Partition',        'risk': 'DANGER', 'desc': 'Erase a flash partition'},
        'write_partition':       {'name': 'Write Partition',        'risk': 'DANGER', 'desc': 'Write data to flash partition'},
        'erase_frp':             {'name': 'Erase FRP',              'risk': 'DANGER', 'desc': 'Erase Factory Reset Protection'},
        'reset_seccfg':          {'name': 'Reset SecCfg',           'risk': 'DANGER', 'desc': 'Reset security configuration'},
        'memory_dump':           {'name': 'Memory Dump',            'risk': 'DANGER', 'desc': 'Dump raw memory regions'},
        'read_rpmb':             {'name': 'Read RPMB',              'risk': 'DANGER', 'desc': 'Read RPMB protected storage'},
        'write_rpmb':            {'name': 'Write RPMB',             'risk': 'DANGER', 'desc': 'Write to RPMB storage'},
        'erase_rpmb':            {'name': 'Erase RPMB',             'risk': 'DANGER', 'desc': 'Erase RPMB storage'},
        'auth_rpmb':             {'name': 'Auth RPMB',              'risk': 'DANGER', 'desc': 'Authenticate RPMB key'},
    }

    def get_remote_operations(self) -> list:
        """Return MTK operations available for remote control.
        
        Dynamically filters based on current device mode — only returns
        operations the device can actually perform right now.
        """
        # Need the widget's device handler to check mode
        handler = self._get_device_handler()
        if not handler:
            return []
        
        allowed = handler.get_allowed_operations()
        operations = []
        for op_id, info in self._REMOTE_OP_DEFS.items():
            if op_id in allowed:
                operations.append({
                    'id': op_id,
                    'name': info['name'],
                    'risk': info['risk'],
                    'description': info['desc'],
                    'params': [],
                })
        return operations

    def get_command_prefixes(self) -> list:
        """MTK Toolkit handles 'mtk' prefix commands."""
        return ['mtk']

    def execute_raw_command(self, command: str, log_callback=None) -> dict:
        """Execute a raw 'mtk <operation>' command from the master console.
        
        Supports:
            mtk read_imei
            mtk get_gpt
            mtk read_efuses
            mtk patch_modem
            mtk unlock_bootloader
            ... any operation from get_remote_operations()
        """
        parts = command.strip().split(None, 1)
        if len(parts) < 2:
            return {'success': False, 'output': '', 'error': 'Usage: mtk <operation> [params]\nExample: mtk read_imei'}
        
        operation = parts[1].strip()
        
        handler = self._get_device_handler()
        if not handler:
            return {'success': False, 'output': '', 'error': 'MTK device not connected'}
        
        if not handler.is_operation_allowed(operation):
            mode = handler.current_mode
            return {'success': False, 'output': '', 'error': f"Operation '{operation}' not available in {mode} mode"}
        
        # Capture log output during execution
        log_lines = []
        def capture(line):
            log_lines.append(str(line))
            if log_callback:
                log_callback(str(line))
        
        handler.log_signal.connect(capture)
        try:
            op_method = getattr(handler, operation, None)
            if op_method and callable(op_method):
                ret = op_method()
                success = ret if isinstance(ret, bool) else (ret is not None)
                output = '\n'.join(log_lines)
                if isinstance(ret, (list, dict)):
                    output += f'\n{ret}'
                return {'success': success, 'output': output, 'error': None}
            else:
                return {'success': False, 'output': '', 'error': f"Unknown MTK operation: {operation}"}
        except Exception as e:
            return {'success': False, 'output': '\n'.join(log_lines), 'error': str(e)}
        finally:
            try:
                handler.log_signal.disconnect(capture)
            except Exception:
                pass

    def _get_device_handler(self):
        """Get the MtkDeviceHandler instance from the widget."""
        if self.widget and hasattr(self.widget, 'device_handler'):
            return self.widget.device_handler
        return None


# Plugin entry point - required by Image Anarchy
Plugin = MtkToolkitPlugin
