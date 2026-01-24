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
from typing import Optional, List, Dict, Tuple, Any
from datetime import datetime
from pathlib import Path
from unittest import mock

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QComboBox,
    QPushButton, QLineEdit, QTextEdit, QListWidget, QListWidgetItem,
    QProgressBar, QFileDialog, QMessageBox, QAbstractItemView, QTabWidget,
    QFormLayout, QCheckBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QRadioButton, QButtonGroup, QScrollArea, QFrame, QSplitter,
    QGridLayout, QSpinBox, QStackedWidget, QToolButton, QSizePolicy,
    QPlainTextEdit, QApplication
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QPropertyAnimation, QEasingCurve, QObject
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


# Try to import mtkclient library
_mtkclient_available = False
_mtkclient_error = None

try:
    setup_mtkclient_path()
    from mtkclient.Library.mtk_class import Mtk
    from mtkclient.Library.DA.mtk_da_handler import DaHandler
    from mtkclient.Library.Partitions.gpt import GptSettings
    from mtkclient.config.mtk_config import MtkConfig
    _mtkclient_available = True
except ImportError as e:
    _mtkclient_error = str(e)
except Exception as e:
    _mtkclient_error = str(e)


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
        
        # Output directory for operations
        self.output_dir = os.getcwd()
    
    def _emit_log(self, message: str):
        """Thread-safe log emission."""
        self.log_signal.emit(message)
    
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
            
            # Create config similar to original GUI
            config = MtkConfig(
                loglevel=logging.INFO,
                gui=self.log_signal,
                guiprogress=self.progress_signal,
                update_status_text=self.status_signal
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
                
                if self.mtk.config.is_brom:
                    self.device_info['boot_mode'] = "BROM Mode"
                elif self.mtk.config.chipconfig.damode:
                    self.device_info['boot_mode'] = "DA Mode"
                else:
                    self.device_info['boot_mode'] = "Preloader Mode"
                
                self._emit_log("━" * 45)
                self._emit_log(f"🔥 DEVICE CONNECTED!")
                self._emit_log(f"📱 Chipset: {self.device_info['chipset']}")
                self._emit_log(f"📱 Mode: {self.device_info['boot_mode']}")
                self._emit_log(f"📱 HW Code: {self.device_info['hw_code']}")
                self._emit_log("━" * 45)
                
                self.connected_signal.emit(True)
                self.device_info_signal.emit(self.device_info)
                return True
            else:
                self._emit_log("❌ Failed to connect - configure_da returned None")
                self._emit_log("💡 Make sure device is in BROM/Preloader mode")
                self.connected = False
                self.connected_signal.emit(False)
                return False
                
        except Exception as e:
            self._emit_log(f"❌ Connection error: {e}")
            import traceback
            traceback.print_exc()
            self.connected = False
            self.connected_signal.emit(False)
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
            self.da_handler.handle_da_cmds(self.mtk, "r", variables)
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                size = os.path.getsize(output_file)
                self._emit_log(f"✅ Saved: {output_file} ({size / (1024*1024):.1f} MB)")
                return True
            else:
                if not silent_fail:
                    self._emit_log(f"❌ Failed to read partition {partition_name}")
                return False
                
        except Exception as e:
            if not silent_fail:
                self._emit_log(f"❌ Error reading partition: {e}")
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
    
    def disconnect(self):
        """Disconnect from device."""
        self._emit_log("🔌 Disconnecting...")
        self.connected = False
        self.partitions = []
        self.device_info = {}
        self.connected_signal.emit(False)


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
    
    def _log_callback(self, line: str):
        """Callback for streaming log output."""
        self.log.emit(line.rstrip())
        
        # Parse progress if possible
        if '%' in line:
            try:
                import re
                match = re.search(r'(\d+)%', line)
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
                
                # Get partitions
                data, guid_gpt = handler.get_gpt()
                if handler.partitions:
                    result_data["partitions"] = [p['name'] for p in handler.partitions]
                    self.log.emit(f"🏴 CONQUERED {len(handler.partitions)} PARTITIONS!")
                    self.log.emit("⚔️ The device's secrets are now exposed!")
                
                self.result_data.emit(result_data)
                self.log.emit("━" * 45)
                self.log.emit("🔥 DEVICE CAPTURED! THE REBELLION HAS BEGUN!")
                self.log.emit("⚡ All operations now use persistent connection")
                self.log.emit("💀 OEM restrictions? What restrictions?")
                self.log.emit("━" * 45)
                self.finished_signal.emit(True, f"🔥 DEVICE PWNED - {handler.device_info.get('boot_mode', 'Liberation complete')}!")
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
        success, output = run_mtk_command(["printgpt", "--debugmode"], callback=self._log_callback)
        
        output_lower = output.lower()
        
        if "waiting for" in output_lower and "preloader" in output_lower:
            self.result_data.emit({"detected": False, "output": output})
            self.finished_signal.emit(False, "No device detected - check BROM mode entry")
            return
        
        detected = (
            "brom" in output_lower or 
            "preloader" in output_lower or 
            "hw code" in output_lower or
            "partition" in output_lower or
            "gpt" in output_lower or
            success
        )
        
        if detected:
            result_data = {"detected": True, "output": output, "cli_mode": True}
            partitions = self._parse_partitions(output)
            if partitions:
                result_data["partitions"] = partitions
            self.result_data.emit(result_data)
            self.finished_signal.emit(True, "Device captured (CLI mode)")
        else:
            self.result_data.emit({"detected": False, "output": output})
            self.finished_signal.emit(False, "Device not captured")
    
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
        output_dir = self.kwargs.get('output_dir', os.getcwd())
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
        """Dump preloader from RAM using library."""
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
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
    def _dump_brom(self):
        """Dump Boot ROM using library."""
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
            self.log.emit("🔴 Device not connected")
            self.finished_signal.emit(False, "Device not connected")
    
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
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.device_connected = False
        self.partitions = []
        self.output_dir = os.path.expanduser("~/MTK_Output")
        os.makedirs(self.output_dir, exist_ok=True)
        self._setup_ui()
        self._check_mtk_client()
    
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
            ("Read vbmeta", "Auto-detects A/B slots", "🔐", "#00d4ff", lambda: self._read_partition("vbmeta")),
            ("Full Backup", "Backup entire flash", "💾", "#9966ff", lambda: self._read_full_flash()),
        ]
        
        for i, (title, desc, icon, color, callback) in enumerate(actions):
            card = OperationCard(title, desc, icon, color)
            card.clicked.connect(callback)
            grid.addWidget(card, i // 4, i % 4)
        
        layout.addLayout(grid)
        
        return tab
    
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
        
        userdata_btn = GlowingButton("🗑️ Userdata", "#ff6b6b")
        userdata_btn.setToolTip("Erase user data (factory reset)")
        userdata_btn.clicked.connect(lambda: self._erase_partition_by_name("userdata"))
        quick_btns.addWidget(userdata_btn)
        
        cache_btn = GlowingButton("🗑️ Cache", "#ffa500")
        cache_btn.setToolTip("Erase cache partition")
        cache_btn.clicked.connect(lambda: self._erase_partition_by_name("cache"))
        quick_btns.addWidget(cache_btn)
        
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
        
        layout.addWidget(bl_group)
        
        # FRP
        frp_group = QGroupBox("🗑️ Factory Reset Protection (FRP)")
        frp_layout = QVBoxLayout(frp_group)
        
        frp_layout.addWidget(QLabel("Erase FRP partition to bypass Google account lock:"))
        
        frp_warning = QLabel("⚠️ This should only be used on your own device!")
        frp_warning.setStyleSheet("color: #ffa500;")
        frp_layout.addWidget(frp_warning)
        
        frp_btn = GlowingButton("🗑️ Erase FRP", "#ff6b6b")
        frp_btn.clicked.connect(self._erase_frp)
        frp_layout.addWidget(frp_btn)
        
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
        
        layout.addWidget(sec_group)
        
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
        
        layout.addWidget(dump_group)
        
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
                for part in data['partitions']:
                    if part.strip():
                        self.partition_list.addItem(part)
                
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
            # Extract partition name from item text
            text = item.text()
            # Try to parse partition name (various formats)
            partition = text.split()[0] if text else text
            partition = partition.replace(':', '').strip()
            if partition:
                self._read_partition(partition)
                break  # TODO: Queue multiple reads
    
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


# Plugin entry point - required by Image Anarchy
Plugin = MtkToolkitPlugin
