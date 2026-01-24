"""
ADB Toolkit Plugin for Image Anarchy

Comprehensive ADB tools including:
- Device Info
- Partition Puller
- File Push/Pull
- APK Installer
- Reboot Options (System/Recovery/Bootloader/EDL)
- Shell Command
- Logcat Viewer
- Screenshot Capture
- App Manager (List/Uninstall)
- Screen Record
"""

import os
import sys
import subprocess
import shutil
import tempfile
from typing import Optional, List
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QApplication, QHBoxLayout, QGroupBox, QLabel, QComboBox,
    QPushButton, QLineEdit, QTextEdit, QListWidget, QListWidgetItem,
    QProgressBar, QFileDialog, QMessageBox, QAbstractItemView, QTabWidget,
    QFormLayout, QCheckBox, QSpinBox, QScrollArea, QFrame, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView, QPlainTextEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QPixmap, QImage, QKeyEvent


class ShellLineEdit(QLineEdit):
    """Custom QLineEdit with command history navigation."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._history = []
        self._history_index = -1
    
    def set_history(self, history: list):
        """Set the command history list."""
        self._history = history
    
    def reset_history_index(self):
        """Reset history navigation index."""
        self._history_index = -1
    
    def keyPressEvent(self, event: QKeyEvent):
        """Handle key events for history navigation."""
        if event.key() == Qt.Key.Key_Up:
            # Navigate history backwards
            if self._history and self._history_index < len(self._history) - 1:
                self._history_index += 1
                self.setText(self._history[-(self._history_index + 1)])
            return
        elif event.key() == Qt.Key.Key_Down:
            # Navigate history forwards
            if self._history_index > 0:
                self._history_index -= 1
                self.setText(self._history[-(self._history_index + 1)])
            elif self._history_index == 0:
                self._history_index = -1
                self.clear()
            return
        super().keyPressEvent(event)


def get_plugin_dir() -> str:
    """Get the directory where this plugin is installed."""
    return os.path.dirname(os.path.abspath(__file__))


def find_adb() -> Optional[str]:
    """Find ADB executable - checks plugin directory first for self-contained plugins."""
    plugin_dir = get_plugin_dir()
    
    # PRIORITY 1: Plugin's own bundled platform-tools (for Plugin Store downloads)
    plugin_adb_paths = [
        os.path.join(plugin_dir, "platform-tools", "adb.exe"),
        os.path.join(plugin_dir, "platform-tools", "adb"),
        os.path.join(plugin_dir, "adb.exe"),
        os.path.join(plugin_dir, "adb"),
    ]
    
    for path in plugin_adb_paths:
        if os.path.isfile(path):
            return path
    
    # PRIORITY 2: PyInstaller frozen exe bundled files
    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        app_dir = os.path.dirname(sys.executable)
        
        frozen_paths = [
            os.path.join(meipass, "platform-tools", "adb.exe"),
            os.path.join(meipass, "platform-tools", "adb"),
            os.path.join(app_dir, "platform-tools", "adb.exe"),
            os.path.join(app_dir, "platform-tools", "adb"),
        ]
        
        for path in frozen_paths:
            if os.path.isfile(path):
                return path
    else:
        # Development mode - check app root
        app_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        dev_paths = [
            os.path.join(app_dir, "platform-tools", "adb.exe"),
            os.path.join(app_dir, "platform-tools", "adb"),
        ]
        
        for path in dev_paths:
            if os.path.isfile(path):
                return path
    
    # PRIORITY 3: System PATH and common locations
    system_paths = [
        "adb", "adb.exe",
        os.path.join(os.environ.get("ANDROID_HOME", ""), "platform-tools", "adb"),
        os.path.join(os.environ.get("ANDROID_HOME", ""), "platform-tools", "adb.exe"),
        r"C:\platform-tools\adb.exe",
        r"C:\Android\platform-tools\adb.exe",
    ]
    
    for path in system_paths:
        if path and shutil.which(path):
            return shutil.which(path)
        if path and os.path.isfile(path):
            return path
    
    return None


def run_adb(args: List[str], device: Optional[str] = None, timeout: int = 30) -> tuple:
    """Run ADB command and return (success, output)."""
    adb_path = find_adb()
    if not adb_path:
        return False, "ADB not found"
    
    cmd = [adb_path]
    if device:
        cmd.extend(["-s", device])
    cmd.extend(args)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


class AdbWorkerThread(QThread):
    """Worker thread for ADB operations."""
    progress = pyqtSignal(int, int, str)
    log = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)
    result_data = pyqtSignal(object)
    
    def __init__(self, operation: str, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
        self._cancelled = False
        self.adb_path = find_adb()
    
    def cancel(self):
        self._cancelled = True
    
    def run(self):
        if not self.adb_path:
            self.finished_signal.emit(False, "ADB not found. Please ensure platform-tools is available.")
            return
        
        try:
            if self.operation == "list_devices":
                self._list_devices()
            elif self.operation == "device_info":
                self._get_device_info()
            elif self.operation == "list_partitions":
                self._list_partitions()
            elif self.operation == "pull_partition":
                self._pull_partition()
            elif self.operation == "pull_file":
                self._pull_file()
            elif self.operation == "push_file":
                self._push_file()
            elif self.operation == "install_apk":
                self._install_apk()
            elif self.operation == "shell":
                self._run_shell()
            elif self.operation == "screenshot":
                self._take_screenshot()
            elif self.operation == "list_packages":
                self._list_packages()
            elif self.operation == "uninstall":
                self._uninstall_package()
            elif self.operation == "reboot":
                self._reboot()
            elif self.operation == "logcat":
                self._logcat()
        except Exception as e:
            self.finished_signal.emit(False, str(e))
    
    def _list_devices(self):
        success, output = run_adb(["devices", "-l"])
        if not success:
            self.finished_signal.emit(False, output)
            return
        
        devices = []
        for line in output.strip().split('\n')[1:]:
            if '\t' in line or 'device' in line:
                parts = line.split()
                if len(parts) >= 2 and parts[1] in ('device', 'recovery', 'sideload', 'unauthorized'):
                    serial = parts[0]
                    state = parts[1]
                    model = "Unknown"
                    for part in parts[2:]:
                        if part.startswith("model:"):
                            model = part.split(":")[1]
                            break
                    devices.append({'serial': serial, 'state': state, 'model': model})
        
        self.result_data.emit(devices)
        self.finished_signal.emit(True, f"Found {len(devices)} device(s)")
    
    def _get_device_info(self):
        device = self.kwargs.get('device')
        info = {}
        
        props = [
            ("Model", "ro.product.model"),
            ("Manufacturer", "ro.product.manufacturer"),
            ("Device", "ro.product.device"),
            ("Android Version", "ro.build.version.release"),
            ("SDK Level", "ro.build.version.sdk"),
            ("Build ID", "ro.build.id"),
            ("Build Fingerprint", "ro.build.fingerprint"),
            ("Security Patch", "ro.build.version.security_patch"),
            ("Serial", "ro.serialno"),
            ("Bootloader", "ro.bootloader"),
            ("Hardware", "ro.hardware"),
            ("Board", "ro.product.board"),
            ("CPU ABI", "ro.product.cpu.abi"),
        ]
        
        for name, prop in props:
            success, output = run_adb(["shell", "getprop", prop], device)
            if success:
                info[name] = output.strip() or "N/A"
        
        # Get battery info
        success, output = run_adb(["shell", "dumpsys", "battery"], device)
        if success:
            for line in output.split('\n'):
                if 'level:' in line:
                    info['Battery'] = line.split(':')[1].strip() + '%'
                elif 'status:' in line:
                    status_map = {'1': 'Unknown', '2': 'Charging', '3': 'Discharging', '4': 'Not Charging', '5': 'Full'}
                    info['Battery Status'] = status_map.get(line.split(':')[1].strip(), 'Unknown')
        
        self.result_data.emit(info)
        self.finished_signal.emit(True, "Device info retrieved")
    
    def _list_partitions(self):
        device = self.kwargs.get('device')
        partitions = []
        
        for path in ["/dev/block/by-name/", "/dev/block/bootdevice/by-name/"]:
            success, output = run_adb(["shell", "ls", "-la", path], device)
            if success and "No such file" not in output:
                for line in output.strip().split('\n'):
                    if '->' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[-3] if len(parts) > 3 else parts[-1].split('->')[0].strip()
                            name = name.rstrip(' ->')
                            if name and name not in ['total', '.', '..']:
                                partitions.append({
                                    'name': name,
                                    'path': f"{path}{name}",
                                    'size': 'Unknown'
                                })
                if partitions:
                    break
        
        partitions.sort(key=lambda x: x['name'])
        self.result_data.emit(partitions)
        self.finished_signal.emit(True, f"Found {len(partitions)} partitions")
    
    def _pull_partition(self):
        device = self.kwargs.get('device')
        partition_path = self.kwargs.get('partition_path')
        partition_name = self.kwargs.get('partition_name')
        output_dir = self.kwargs.get('output_dir')
        
        output_file = os.path.join(output_dir, f"{partition_name}.img")
        self.log.emit(f"Pulling {partition_name}...")
        
        # Check for root
        success, output = run_adb(["shell", "su", "-c", "id"], device)
        has_root = success and "uid=0" in output
        
        if has_root:
            self.log.emit("Using root access...")
            process = subprocess.Popen(
                [self.adb_path, "-s", device, "shell", f"su -c 'dd if={partition_path}'"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            with open(output_file, 'wb') as f:
                while True:
                    if self._cancelled:
                        process.terminate()
                        return
                    chunk = process.stdout.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
            process.wait()
        else:
            success, output = run_adb(["pull", partition_path, output_file], device, timeout=300)
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            size = os.path.getsize(output_file)
            size_str = f"{size / (1024*1024):.1f} MB"
            self.log.emit(f"✓ Saved: {output_file} ({size_str})")
            self.finished_signal.emit(True, output_file)
        else:
            self.finished_signal.emit(False, "Failed to pull partition")
    
    def _pull_file(self):
        device = self.kwargs.get('device')
        remote_path = self.kwargs.get('remote_path')
        local_path = self.kwargs.get('local_path')
        
        self.log.emit(f"Pulling {remote_path}...")
        success, output = run_adb(["pull", remote_path, local_path], device, timeout=300)
        
        if success and os.path.exists(local_path):
            self.log.emit(f"✓ Saved: {local_path}")
            self.finished_signal.emit(True, local_path)
        else:
            self.finished_signal.emit(False, output)
    
    def _push_file(self):
        device = self.kwargs.get('device')
        local_path = self.kwargs.get('local_path')
        remote_path = self.kwargs.get('remote_path')
        
        self.log.emit(f"Pushing {os.path.basename(local_path)}...")
        success, output = run_adb(["push", local_path, remote_path], device, timeout=300)
        
        if success:
            self.log.emit(f"✓ Pushed to: {remote_path}")
            self.finished_signal.emit(True, remote_path)
        else:
            self.finished_signal.emit(False, output)
    
    def _install_apk(self):
        device = self.kwargs.get('device')
        apk_path = self.kwargs.get('apk_path')
        reinstall = self.kwargs.get('reinstall', False)
        
        self.log.emit(f"Installing {os.path.basename(apk_path)}...")
        args = ["install"]
        if reinstall:
            args.append("-r")
        args.append(apk_path)
        
        success, output = run_adb(args, device, timeout=120)
        
        if success and "Success" in output:
            self.log.emit("✓ APK installed successfully")
            self.finished_signal.emit(True, "Installed")
        else:
            self.finished_signal.emit(False, output)
    
    def _run_shell(self):
        device = self.kwargs.get('device')
        command = self.kwargs.get('command')
        
        # Use shell -c to run the full command string (preserves cd && cmd syntax)
        success, output = run_adb(["shell", command], device, timeout=60)
        self.result_data.emit(output)
        self.finished_signal.emit(success, output if not success else "Command executed")
    
    def _take_screenshot(self):
        device = self.kwargs.get('device')
        output_path = self.kwargs.get('output_path')
        
        self.log.emit("Capturing screenshot...")
        
        # Capture to device temp
        run_adb(["shell", "screencap", "-p", "/sdcard/screenshot.png"], device)
        # Pull to local
        success, output = run_adb(["pull", "/sdcard/screenshot.png", output_path], device)
        # Clean up
        run_adb(["shell", "rm", "/sdcard/screenshot.png"], device)
        
        if success and os.path.exists(output_path):
            self.log.emit(f"✓ Screenshot saved: {output_path}")
            self.finished_signal.emit(True, output_path)
        else:
            self.finished_signal.emit(False, "Failed to capture screenshot")
    
    def _list_packages(self):
        device = self.kwargs.get('device')
        show_system = self.kwargs.get('show_system', False)
        
        args = ["shell", "pm", "list", "packages", "-f"]
        if not show_system:
            args.append("-3")  # Third-party only
        
        success, output = run_adb(args, device)
        
        packages = []
        if success:
            for line in output.strip().split('\n'):
                if line.startswith('package:'):
                    # Format: package:/path/to/app.apk=com.package.name
                    try:
                        path_and_name = line[8:]  # Remove 'package:'
                        if '=' in path_and_name:
                            path, name = path_and_name.rsplit('=', 1)
                            packages.append({'name': name, 'path': path})
                    except:
                        pass
        
        packages.sort(key=lambda x: x['name'])
        self.result_data.emit(packages)
        self.finished_signal.emit(True, f"Found {len(packages)} packages")
    
    def _uninstall_package(self):
        device = self.kwargs.get('device')
        package = self.kwargs.get('package')
        keep_data = self.kwargs.get('keep_data', False)
        
        self.log.emit(f"Uninstalling {package}...")
        args = ["uninstall"]
        if keep_data:
            args.append("-k")
        args.append(package)
        
        success, output = run_adb(args, device)
        
        if success and "Success" in output:
            self.log.emit(f"✓ Uninstalled {package}")
            self.finished_signal.emit(True, "Uninstalled")
        else:
            self.finished_signal.emit(False, output)
    
    def _reboot(self):
        device = self.kwargs.get('device')
        mode = self.kwargs.get('mode', 'system')
        
        self.log.emit(f"Rebooting to {mode}...")
        
        if mode == 'system':
            success, output = run_adb(["reboot"], device)
        elif mode == 'recovery':
            success, output = run_adb(["reboot", "recovery"], device)
        elif mode == 'bootloader':
            success, output = run_adb(["reboot", "bootloader"], device)
        elif mode == 'edl':
            success, output = run_adb(["reboot", "edl"], device)
        elif mode == 'sideload':
            success, output = run_adb(["reboot", "sideload"], device)
        elif mode == 'fastbootd':
            success, output = run_adb(["reboot", "fastboot"], device)
        else:
            success, output = False, "Unknown reboot mode"
        
        self.finished_signal.emit(success, f"Rebooting to {mode}")
    
    def _logcat(self):
        device = self.kwargs.get('device')
        lines = self.kwargs.get('lines', 100)
        
        success, output = run_adb(["logcat", "-d", "-t", str(lines)], device, timeout=30)
        self.result_data.emit(output)
        self.finished_signal.emit(success, "Logcat retrieved")


class AdbToolkitPlugin:
    """Comprehensive ADB Toolkit Plugin."""
    
    def __init__(self):
        self.manifest = None
        self.parent_window = None
        self.current_device = None
        self.devices = []
        self.worker = None
    
    def get_name(self) -> str:
        return self.manifest.name if self.manifest else "ADB Toolkit"
    
    def get_icon(self) -> str:
        return self.manifest.icon if self.manifest else "📱"
    
    def get_description(self) -> str:
        return self.manifest.description if self.manifest else ""
    
    def get_version(self) -> str:
        return self.manifest.version if self.manifest else "1.0"
    
    def get_author(self) -> str:
        return self.manifest.author if self.manifest else "Image Anarchy"
    
    def create_widget(self, parent_window) -> QWidget:
        self.parent_window = parent_window
        
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(8, 8, 8, 8)
        
        # Device Selection
        device_group = QGroupBox("Device")
        device_layout = QHBoxLayout(device_group)
        
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(300)
        self.device_combo.currentIndexChanged.connect(self._on_device_changed)
        device_layout.addWidget(QLabel("Device:"))
        device_layout.addWidget(self.device_combo, 1)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_devices)
        device_layout.addWidget(refresh_btn)
        
        self.device_status = QLabel("No device")
        self.device_status.setStyleSheet("color: #888;")
        device_layout.addWidget(self.device_status)
        
        main_layout.addWidget(device_group)
        
        # Tools Tabs
        self.tabs = QTabWidget()
        
        # Tab 1: Device Info
        self.tabs.addTab(self._create_info_tab(), "📋 Info")
        
        # Tab 2: Partitions
        self.tabs.addTab(self._create_partitions_tab(), "💾 Partitions")
        
        # Tab 3: Files
        self.tabs.addTab(self._create_files_tab(), "📁 Files")
        
        # Tab 4: Apps
        self.tabs.addTab(self._create_apps_tab(), "📦 Apps")
        
        # Tab 5: Shell
        self.tabs.addTab(self._create_shell_tab(), "⌨️ Shell")
        
        # Tab 6: Tools
        self.tabs.addTab(self._create_tools_tab(), "🔧 Tools")
        
        # Tab 7: Reboot
        self.tabs.addTab(self._create_reboot_tab(), "🔄 Reboot")
        
        main_layout.addWidget(self.tabs)
        
        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(100)
        self.log_output.setStyleSheet("font-family: Consolas; font-size: 11px;")
        main_layout.addWidget(self.log_output)
        
        # Initial device scan
        QTimer.singleShot(500, self._refresh_devices)
        
        return main_widget
    
    def _log(self, msg: str):
        self.log_output.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        self.log_output.verticalScrollBar().setValue(self.log_output.verticalScrollBar().maximum())
    
    def _refresh_devices(self):
        self._log("Scanning for devices...")
        self.worker = AdbWorkerThread("list_devices")
        self.worker.result_data.connect(self._on_devices_found)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _on_devices_found(self, devices):
        self.devices = devices
        self.device_combo.clear()
        
        if not devices:
            self.device_combo.addItem("No devices found")
            self.device_status.setText("No device connected")
            self.device_status.setStyleSheet("color: #f44;")
        else:
            for dev in devices:
                self.device_combo.addItem(f"{dev['model']} ({dev['serial']}) - {dev['state']}", dev['serial'])
            self.device_status.setText(f"✓ {devices[0]['state']}")
            self.device_status.setStyleSheet("color: #4f4;")
    
    def _on_device_changed(self, index):
        if index >= 0 and self.devices:
            self.current_device = self.device_combo.currentData()
    
    def _get_device(self):
        return self.device_combo.currentData()
    
    # ===== INFO TAB =====
    def _create_info_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.info_table = QTableWidget()
        self.info_table.setColumnCount(2)
        self.info_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.info_table.horizontalHeader().setStretchLastSection(True)
        self.info_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.info_table)
        
        btn = QPushButton("🔄 Refresh Device Info")
        btn.clicked.connect(self._refresh_info)
        layout.addWidget(btn)
        
        return tab
    
    def _refresh_info(self):
        device = self._get_device()
        if not device:
            return
        
        self._log("Getting device info...")
        self.worker = AdbWorkerThread("device_info", device=device)
        self.worker.result_data.connect(self._on_info_received)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _on_info_received(self, info: dict):
        self.info_table.setRowCount(len(info))
        for i, (key, value) in enumerate(info.items()):
            self.info_table.setItem(i, 0, QTableWidgetItem(key))
            self.info_table.setItem(i, 1, QTableWidgetItem(str(value)))
    
    # ===== PARTITIONS TAB =====
    def _create_partitions_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.partition_list = QListWidget()
        self.partition_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        layout.addWidget(self.partition_list)
        
        # Quick select
        quick_row = QHBoxLayout()
        for name, parts in [
            ("Boot", ["boot", "boot_a", "boot_b", "init_boot", "init_boot_a", "init_boot_b"]),
            ("Recovery", ["recovery", "recovery_a", "recovery_b"]),
            ("Firmware", ["vbmeta", "dtbo", "vendor_boot"]),
            ("Clear", [])
        ]:
            btn = QPushButton(name)
            btn.clicked.connect(lambda c, p=parts: self._quick_select_partitions(p))
            quick_row.addWidget(btn)
        quick_row.addStretch()
        layout.addLayout(quick_row)
        
        # Output dir row (will be hidden when setup directories is active)
        self._output_row_widget = QWidget()
        out_row = QHBoxLayout(self._output_row_widget)
        out_row.setContentsMargins(0, 0, 0, 0)
        self.partition_output = QLineEdit(os.path.expanduser("~/adb_partitions"))
        out_row.addWidget(QLabel("Output:"))
        out_row.addWidget(self.partition_output)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(lambda: self._browse_dir(self.partition_output))
        out_row.addWidget(browse_btn)
        layout.addWidget(self._output_row_widget)
        
        # Setup directories indicator (hidden by default)
        self._setup_indicator = QLabel()
        self._setup_indicator.setStyleSheet("background: #2e7d32; color: white; padding: 8px; border-radius: 4px;")
        self._setup_indicator.setVisible(False)
        layout.addWidget(self._setup_indicator)
        
        # Buttons
        btn_row = QHBoxLayout()
        refresh_btn = QPushButton("🔄 List Partitions")
        refresh_btn.clicked.connect(self._list_partitions)
        btn_row.addWidget(refresh_btn)
        
        pull_btn = QPushButton("📥 Pull Selected")
        pull_btn.clicked.connect(self._pull_selected_partitions)
        btn_row.addWidget(pull_btn)
        
        # Setup Directories button - creates folders for each partition
        self.setup_dirs_btn = QPushButton("📁 Setup Directories")
        self.setup_dirs_btn.setToolTip("Create a folder for each partition in a selected directory.\nPerfect for organizing pulled partitions!")
        self.setup_dirs_btn.clicked.connect(self._setup_partition_directories)
        self.setup_dirs_btn.setEnabled(False)  # Disabled until partitions are loaded
        btn_row.addWidget(self.setup_dirs_btn)
        
        # Clear setup directories button (hidden by default)
        self._clear_setup_btn = QPushButton("✕ Clear Setup")
        self._clear_setup_btn.setToolTip("Return to manual output directory mode")
        self._clear_setup_btn.clicked.connect(self._clear_setup_directories)
        self._clear_setup_btn.setVisible(False)
        btn_row.addWidget(self._clear_setup_btn)
        
        btn_row.addStretch()
        layout.addLayout(btn_row)
        
        # Initialize setup directories base path
        self._setup_base_dir = None
        
        return tab
    
    def _list_partitions(self):
        device = self._get_device()
        if not device:
            return
        
        self._log("Listing partitions...")
        self.worker = AdbWorkerThread("list_partitions", device=device)
        self.worker.result_data.connect(self._on_partitions_found)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _on_partitions_found(self, partitions):
        self.partition_list.clear()
        self._loaded_partitions = partitions  # Store for Setup Directories
        for p in partitions:
            item = QListWidgetItem(f"{p['name']}")
            item.setData(Qt.ItemDataRole.UserRole, p)
            self.partition_list.addItem(item)
        
        # Enable/disable Setup Directories button
        if hasattr(self, 'setup_dirs_btn'):
            self.setup_dirs_btn.setEnabled(len(partitions) > 0)
    
    def _quick_select_partitions(self, names):
        if not names:
            self.partition_list.clearSelection()
            return
        for i in range(self.partition_list.count()):
            item = self.partition_list.item(i)
            data = item.data(Qt.ItemDataRole.UserRole)
            if data and data['name'] in names:
                item.setSelected(True)
    
    def _setup_partition_directories(self):
        """Create a directory for each loaded partition in a user-selected folder."""
        if not hasattr(self, '_loaded_partitions') or not self._loaded_partitions:
            QMessageBox.warning(self.parent_window, "No Partitions", 
                "No partitions loaded. Please list partitions first.")
            return
        
        # Ask user to select base directory
        base_dir = QFileDialog.getExistingDirectory(
            self.parent_window,
            "Select Base Directory for Partition Folders",
            os.path.expanduser("~"),
            QFileDialog.Option.ShowDirsOnly
        )
        
        if not base_dir:
            return
        
        # Create directories
        created = []
        errors = []
        for partition in self._loaded_partitions:
            part_name = partition['name']
            part_dir = os.path.join(base_dir, part_name)
            try:
                os.makedirs(part_dir, exist_ok=True)
                created.append(part_name)
            except Exception as e:
                errors.append(f"{part_name}: {str(e)}")
        
        # Report results and activate setup mode
        if created:
            self._log(f"✓ Created {len(created)} partition directories in {base_dir}")
            
            # Activate setup directories mode
            self._setup_base_dir = base_dir
            self._output_row_widget.setVisible(False)
            self._setup_indicator.setText(f"📁 Setup Active: {base_dir}\n   Each partition will be saved to its own folder automatically")
            self._setup_indicator.setVisible(True)
            self._clear_setup_btn.setVisible(True)
            self.setup_dirs_btn.setEnabled(False)
            
            msg = f"✓ Setup Directories Active!\n\n"
            msg += f"📁 Base: {base_dir}\n"
            msg += f"   Created {len(created)} folders\n\n"
            msg += "Partitions will now be pulled to their own folders:\n"
            msg += f"   • boot → {base_dir}/boot/boot.img\n"
            msg += f"   • recovery → {base_dir}/recovery/recovery.img\n"
            msg += "   etc..."
            
            if errors:
                msg += f"\n\n⚠️ {len(errors)} errors:\n" + "\n".join(errors[:5])
            
            QMessageBox.information(self.parent_window, "Setup Directories Active", msg)
        elif errors:
            QMessageBox.warning(self.parent_window, "Error", 
                f"Failed to create directories:\n" + "\n".join(errors[:10]))
    
    def _clear_setup_directories(self):
        """Clear setup directories mode and return to manual output."""
        self._setup_base_dir = None
        self._output_row_widget.setVisible(True)
        self._setup_indicator.setVisible(False)
        self._clear_setup_btn.setVisible(False)
        if hasattr(self, '_loaded_partitions') and self._loaded_partitions:
            self.setup_dirs_btn.setEnabled(True)
        self._log("Setup Directories mode cleared - using manual output directory")
    
    def _pull_selected_partitions(self):
        device = self._get_device()
        if not device:
            return
        
        selected = self.partition_list.selectedItems()
        if not selected:
            QMessageBox.warning(self.parent_window, "Error", "Select partitions first")
            return
        
        # Determine output directory based on setup mode
        if self._setup_base_dir:
            # Setup directories mode - each partition goes to its own folder
            data = selected[0].data(Qt.ItemDataRole.UserRole)
            output_dir = os.path.join(self._setup_base_dir, data['name'])
            os.makedirs(output_dir, exist_ok=True)
        else:
            # Manual output directory mode
            output_dir = self.partition_output.text()
            os.makedirs(output_dir, exist_ok=True)
        
        # Pull first selected (simplified - could queue all)
        data = selected[0].data(Qt.ItemDataRole.UserRole)
        self.worker = AdbWorkerThread("pull_partition", device=device,
                                       partition_path=data['path'],
                                       partition_name=data['name'],
                                       output_dir=output_dir)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== FILES TAB =====
    def _create_files_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Push section
        push_group = QGroupBox("Push File to Device")
        push_layout = QFormLayout(push_group)
        
        self.push_local = QLineEdit()
        push_browse = QPushButton("Browse...")
        push_browse.clicked.connect(lambda: self._browse_file(self.push_local))
        push_local_row = QHBoxLayout()
        push_local_row.addWidget(self.push_local)
        push_local_row.addWidget(push_browse)
        push_layout.addRow("Local File:", push_local_row)
        
        self.push_remote = QLineEdit("/sdcard/")
        push_layout.addRow("Remote Path:", self.push_remote)
        
        push_btn = QPushButton("📤 Push")
        push_btn.clicked.connect(self._push_file)
        push_layout.addRow("", push_btn)
        layout.addWidget(push_group)
        
        # Pull section
        pull_group = QGroupBox("Pull File from Device")
        pull_layout = QFormLayout(pull_group)
        
        self.pull_remote = QLineEdit("/sdcard/")
        pull_layout.addRow("Remote Path:", self.pull_remote)
        
        self.pull_local = QLineEdit(os.path.expanduser("~"))
        pull_browse = QPushButton("Browse...")
        pull_browse.clicked.connect(lambda: self._browse_dir(self.pull_local))
        pull_local_row = QHBoxLayout()
        pull_local_row.addWidget(self.pull_local)
        pull_local_row.addWidget(pull_browse)
        pull_layout.addRow("Local Dir:", pull_local_row)
        
        pull_btn = QPushButton("📥 Pull")
        pull_btn.clicked.connect(self._pull_file)
        pull_layout.addRow("", pull_btn)
        layout.addWidget(pull_group)
        
        layout.addStretch()
        return tab
    
    def _push_file(self):
        device = self._get_device()
        if not device or not self.push_local.text():
            return
        
        self.worker = AdbWorkerThread("push_file", device=device,
                                       local_path=self.push_local.text(),
                                       remote_path=self.push_remote.text())
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _pull_file(self):
        device = self._get_device()
        if not device or not self.pull_remote.text():
            return
        
        remote = self.pull_remote.text()
        local = os.path.join(self.pull_local.text(), os.path.basename(remote))
        
        self.worker = AdbWorkerThread("pull_file", device=device,
                                       remote_path=remote, local_path=local)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== APPS TAB =====
    def _create_apps_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # App list
        self.app_list = QListWidget()
        self.app_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        layout.addWidget(self.app_list)
        
        # Options
        opt_row = QHBoxLayout()
        self.show_system_apps = QCheckBox("Show System Apps")
        opt_row.addWidget(self.show_system_apps)
        
        refresh_btn = QPushButton("🔄 List Apps")
        refresh_btn.clicked.connect(self._list_apps)
        opt_row.addWidget(refresh_btn)
        opt_row.addStretch()
        layout.addLayout(opt_row)
        
        # Install APK
        install_group = QGroupBox("Install APK")
        install_layout = QHBoxLayout(install_group)
        self.apk_path = QLineEdit()
        install_layout.addWidget(self.apk_path)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(lambda: self._browse_file(self.apk_path, "APK Files (*.apk)"))
        install_layout.addWidget(browse_btn)
        install_btn = QPushButton("📦 Install")
        install_btn.clicked.connect(self._install_apk)
        install_layout.addWidget(install_btn)
        layout.addWidget(install_group)
        
        # Uninstall
        uninstall_row = QHBoxLayout()
        self.keep_data = QCheckBox("Keep Data")
        uninstall_row.addWidget(self.keep_data)
        uninstall_btn = QPushButton("🗑️ Uninstall Selected")
        uninstall_btn.clicked.connect(self._uninstall_app)
        uninstall_row.addWidget(uninstall_btn)
        uninstall_row.addStretch()
        layout.addLayout(uninstall_row)
        
        return tab
    
    def _list_apps(self):
        device = self._get_device()
        if not device:
            return
        
        self._log("Listing packages...")
        self.worker = AdbWorkerThread("list_packages", device=device,
                                       show_system=self.show_system_apps.isChecked())
        self.worker.result_data.connect(self._on_apps_found)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _on_apps_found(self, packages):
        self.app_list.clear()
        for p in packages:
            item = QListWidgetItem(p['name'])
            item.setData(Qt.ItemDataRole.UserRole, p)
            self.app_list.addItem(item)
    
    def _install_apk(self):
        device = self._get_device()
        if not device or not self.apk_path.text():
            return
        
        self.worker = AdbWorkerThread("install_apk", device=device,
                                       apk_path=self.apk_path.text())
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _uninstall_app(self):
        device = self._get_device()
        selected = self.app_list.selectedItems()
        if not device or not selected:
            return
        
        pkg = selected[0].data(Qt.ItemDataRole.UserRole)['name']
        self.worker = AdbWorkerThread("uninstall", device=device,
                                       package=pkg, keep_data=self.keep_data.isChecked())
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: [self._log(m), self._list_apps()])
        self.worker.start()
    
    # ===== SHELL TAB =====
    def _create_shell_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Shell info/status bar
        shell_info = QHBoxLayout()
        
        self.shell_cwd_label = QLabel("📁 /")
        self.shell_cwd_label.setStyleSheet("color: #4fc3f7; font-family: Consolas;")
        shell_info.addWidget(self.shell_cwd_label)
        
        shell_info.addStretch()
        
        # Run as Root checkbox
        self.shell_root_cb = QCheckBox("🔓 Run as Root (su)")
        self.shell_root_cb.setToolTip("Wrap commands with 'su -c' to execute as root.\nRequires a rooted device with su binary.")
        self.shell_root_cb.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        shell_info.addWidget(self.shell_root_cb)
        
        # Initialize shell state
        self._shell_cwd = "/"  # Current working directory
        self._shell_history = []  # Command history (shared with ShellLineEdit)
        self._load_custom_commands()  # Load user's custom commands
        
        layout.addLayout(shell_info)
        
        # Use splitter for console and commands panel
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Console output
        self.shell_output = QPlainTextEdit()
        self.shell_output.setReadOnly(True)
        self.shell_output.setStyleSheet("font-family: Consolas; background: #1a1a2e;")
        self.shell_output.setMinimumHeight(150)
        splitter.addWidget(self.shell_output)
        
        # ⛓️‍💥 UNCHAINED - Command Liberation Panel
        commands_panel = QWidget()
        commands_layout = QVBoxLayout(commands_panel)
        commands_layout.setContentsMargins(0, 5, 0, 0)
        
        # Header label
        unchained_header = QLabel("⛓️‍💥 <b>UNCHAINED</b> <i>- Break the chains. Free your commands.</i>")
        unchained_header.setStyleSheet("color: #ff6b6b; font-size: 13px; padding: 5px;")
        commands_layout.addWidget(unchained_header)
        
        # Tabs for Rebel Arsenal and My Manifesto
        cmd_tabs = QTabWidget()
        cmd_tabs.setMaximumHeight(230)
        
        # Built-in Commands Tab
        builtin_widget = QWidget()
        builtin_layout = QVBoxLayout(builtin_widget)
        builtin_layout.setContentsMargins(5, 5, 5, 5)
        
        # Define built-in commands: (name, command, icon, has_dialog, dialog_fields)
        self._builtin_commands = [
            # System Info
            ("Device Info", "getprop", "📱", False, None),
            ("CPU Info", "cat /proc/cpuinfo", "🔲", False, None),
            ("Memory Info", "cat /proc/meminfo", "💾", False, None),
            ("Disk Usage", "df -h", "💿", False, None),
            ("Battery Status", "dumpsys battery", "🔋", False, None),
            ("Running Processes", "ps -A", "📊", False, None),
            # Network
            ("IP Address", "ip addr show", "🌐", False, None),
            ("WiFi Info", "dumpsys wifi | grep -E 'mWifiInfo|SSID'", "📶", False, None),
            ("Network Stats", "cat /proc/net/dev", "📈", False, None),
            # Storage
            ("List Partitions", "ls -la /dev/block/by-name/", "📦", False, None),
            ("Mount Points", "mount", "🗂️", False, None),
            ("Storage Info", "dumpsys diskstats", "💽", False, None),
            # Package
            ("List Packages", "pm list packages", "📋", False, None),
            ("List System Apps", "pm list packages -s", "🏛️", False, None),
            ("List 3rd Party", "pm list packages -3", "📲", False, None),
            # With Dialogs
            ("Get Package Path", "pm path {package}", "📍", True, [("package", "Package name (e.g., com.android.chrome)")]),
            ("Package Info", "dumpsys package {package}", "ℹ️", True, [("package", "Package name")]),
            ("Force Stop App", "am force-stop {package}", "⛔", True, [("package", "Package to force stop")]),
            ("Clear App Data", "pm clear {package}", "🗑️", True, [("package", "Package to clear data")]),
            ("Start Activity", "am start -n {activity}", "▶️", True, [("activity", "Activity (e.g., com.app/.MainActivity)")]),
            ("Send Broadcast", "am broadcast -a {action}", "📡", True, [("action", "Broadcast action")]),
            ("Kill Process", "kill {pid}", "💀", True, [("pid", "Process ID")]),
            ("Cat File", "cat {filepath}", "📄", True, [("filepath", "File path to read")]),
            ("Find Files", "find {path} -name '{pattern}'", "🔍", True, [("path", "Search path"), ("pattern", "File pattern (e.g., *.apk)")]),
            ("Grep Search", "grep -r '{pattern}' {path}", "🔎", True, [("pattern", "Search text"), ("path", "Directory to search")]),
            ("Set Property", "setprop {property} {value}", "⚙️", True, [("property", "Property name"), ("value", "New value")]),
        ]
        
        # Create scrollable grid for built-in commands
        builtin_scroll = QScrollArea()
        builtin_scroll.setWidgetResizable(True)
        builtin_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        
        builtin_grid_widget = QWidget()
        builtin_grid = QVBoxLayout(builtin_grid_widget)
        
        # Group commands by category - Rebel Arsenal
        categories = {
            "📱 Reconnaissance": self._builtin_commands[:6],
            "🌐 Network Infiltration": self._builtin_commands[6:9],
            "💾 Storage Liberation": self._builtin_commands[9:12],
            "📦 Package Raids": self._builtin_commands[12:15],
            "⚡ Direct Action": self._builtin_commands[15:],
        }
        
        for cat_name, commands in categories.items():
            cat_label = QLabel(f"<b>{cat_name}</b>")
            cat_label.setStyleSheet("color: #4fc3f7; margin-top: 5px;")
            builtin_grid.addWidget(cat_label)
            
            flow_widget = QWidget()
            flow_layout = QHBoxLayout(flow_widget)
            flow_layout.setContentsMargins(0, 0, 0, 0)
            flow_layout.setSpacing(5)
            
            for name, cmd, icon, has_dialog, fields in commands:
                btn = QPushButton(f"{icon} {name}")
                btn.setToolTip(cmd)
                btn.setStyleSheet("padding: 5px 10px;")
                if has_dialog:
                    btn.clicked.connect(lambda checked, c=cmd, f=fields, n=name: self._show_command_dialog(n, c, f))
                else:
                    btn.clicked.connect(lambda checked, c=cmd: self._execute_quick_command(c))
                flow_layout.addWidget(btn)
            
            flow_layout.addStretch()
            builtin_grid.addWidget(flow_widget)
        
        builtin_grid.addStretch()
        builtin_scroll.setWidget(builtin_grid_widget)
        builtin_layout.addWidget(builtin_scroll)
        
        cmd_tabs.addTab(builtin_widget, "🔥 Rebel Arsenal")
        
        # Custom Commands Tab - My Manifesto
        custom_widget = QWidget()
        custom_layout = QVBoxLayout(custom_widget)
        custom_layout.setContentsMargins(5, 5, 5, 5)
        
        # Toolbar for custom commands
        custom_toolbar = QHBoxLayout()
        
        add_cmd_btn = QPushButton("✊ New Revolt")
        add_cmd_btn.clicked.connect(self._add_custom_command)
        custom_toolbar.addWidget(add_cmd_btn)
        
        edit_cmd_btn = QPushButton("✏️ Edit")
        edit_cmd_btn.clicked.connect(self._edit_custom_command)
        custom_toolbar.addWidget(edit_cmd_btn)
        
        del_cmd_btn = QPushButton("🗑️ Delete")
        del_cmd_btn.clicked.connect(self._delete_custom_command)
        custom_toolbar.addWidget(del_cmd_btn)
        
        import_btn = QPushButton("📥 Import")
        import_btn.clicked.connect(self._import_commands)
        custom_toolbar.addWidget(import_btn)
        
        export_btn = QPushButton("📤 Export")
        export_btn.clicked.connect(self._export_commands)
        custom_toolbar.addWidget(export_btn)
        
        custom_toolbar.addStretch()
        custom_layout.addLayout(custom_toolbar)
        
        # Custom commands list - The Manifesto
        self.custom_cmd_list = QListWidget()
        self.custom_cmd_list.setStyleSheet("QListWidget::item { padding: 5px; }")
        self.custom_cmd_list.itemDoubleClicked.connect(self._run_custom_command)
        self._refresh_custom_commands_list()
        custom_layout.addWidget(self.custom_cmd_list)
        
        # Run selected button
        run_custom_btn = QPushButton("⚡ Execute Revolution")
        run_custom_btn.clicked.connect(self._run_custom_command)
        custom_layout.addWidget(run_custom_btn)
        
        cmd_tabs.addTab(custom_widget, "📜 My Manifesto")
        
        commands_layout.addWidget(cmd_tabs)
        splitter.addWidget(commands_panel)
        
        # Set splitter proportions (console takes more space)
        splitter.setSizes([300, 200])
        layout.addWidget(splitter)
        
        # Command input row
        cmd_row = QHBoxLayout()
        self.shell_input = ShellLineEdit()
        self.shell_input.setPlaceholderText("Enter shell command...")
        self.shell_input.returnPressed.connect(self._run_shell_command)
        self.shell_input.set_history(self._shell_history)
        cmd_row.addWidget(self.shell_input)
        
        run_btn = QPushButton("▶ Run")
        run_btn.clicked.connect(self._run_shell_command)
        cmd_row.addWidget(run_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.shell_output.clear)
        cmd_row.addWidget(clear_btn)
        
        reset_btn = QPushButton("🔄 Reset")
        reset_btn.setToolTip("Reset to root directory")
        reset_btn.clicked.connect(self._reset_shell)
        cmd_row.addWidget(reset_btn)
        
        layout.addLayout(cmd_row)
        
        # Show welcome message
        self.shell_output.appendPlainText("⛓️‍💥 UNCHAINED Shell - Break free from restrictive commands.")
        self.shell_output.appendPlainText("Use the Rebel Arsenal below or write your own Manifesto.")
        self.shell_output.appendPlainText("Directory persists between commands. Ⓐ Free your device. Ⓐ\n")
        
        return tab
    
    def _load_custom_commands(self):
        """Load custom commands from JSON file."""
        import json
        self._custom_commands = []
        config_dir = os.path.dirname(os.path.abspath(__file__))
        self._custom_commands_file = os.path.join(config_dir, "custom_shell_commands.json")
        
        if os.path.exists(self._custom_commands_file):
            try:
                with open(self._custom_commands_file, "r") as f:
                    self._custom_commands = json.load(f)
            except:
                self._custom_commands = []
    
    def _save_custom_commands(self):
        """Save custom commands to JSON file."""
        import json
        try:
            with open(self._custom_commands_file, "w") as f:
                json.dump(self._custom_commands, f, indent=2)
        except Exception as e:
            QMessageBox.warning(self.main_widget, "Error", f"Failed to save commands: {e}")
    
    def _refresh_custom_commands_list(self):
        """Refresh the custom commands list widget."""
        if not hasattr(self, 'custom_cmd_list'):
            return
        self.custom_cmd_list.clear()
        for cmd in self._custom_commands:
            icon = cmd.get("icon", "⚡")
            name = cmd.get("name", "Unnamed")
            command = cmd.get("command", "")
            has_vars = "{" in command
            
            item = QListWidgetItem(f"{icon} {name}" + (" [has input fields]" if has_vars else ""))
            item.setToolTip(command)
            item.setData(Qt.ItemDataRole.UserRole, cmd)
            self.custom_cmd_list.addItem(item)
    
    def _show_command_dialog(self, name: str, command_template: str, fields: list):
        """Show dialog to fill in command parameters."""
        from PyQt6.QtWidgets import QDialog, QDialogButtonBox
        
        dialog = QDialog(self.main_widget)
        dialog.setWindowTitle(f"⚡ Direct Action: {name}")
        dialog.setMinimumWidth(400)
        layout = QVBoxLayout(dialog)
        
        # Description
        desc_label = QLabel(f"<b>Command:</b> <code>{command_template}</code>")
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)
        
        # Input fields
        form = QFormLayout()
        inputs = {}
        
        for field_name, field_desc in fields:
            input_field = QLineEdit()
            input_field.setPlaceholderText(field_desc)
            inputs[field_name] = input_field
            form.addRow(f"{field_name}:", input_field)
        
        layout.addLayout(form)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Build command from template
            final_cmd = command_template
            for field_name, input_field in inputs.items():
                value = input_field.text().strip()
                if not value:
                    QMessageBox.warning(self.main_widget, "Missing Input", f"Please enter a value for '{field_name}'")
                    return
                final_cmd = final_cmd.replace(f"{{{field_name}}}", value)
            
            self._execute_quick_command(final_cmd)
    
    def _execute_quick_command(self, command: str):
        """Execute a quick command in the shell."""
        device = self._get_device()
        if not device:
            QMessageBox.warning(self.main_widget, "No Device", "Please select a device first.")
            return
        
        # Show root indicator in prompt if enabled
        root_mode = hasattr(self, 'shell_root_cb') and self.shell_root_cb.isChecked()
        prompt = f"{self._shell_cwd}#" if root_mode else f"{self._shell_cwd}$"
        self.shell_output.appendPlainText(f"{prompt} {command}")
        
        # Add to history
        if command and (not self._shell_history or self._shell_history[-1] != command):
            self._shell_history.append(command)
        
        self._run_in_cwd(device, command)
    
    def _add_custom_command(self):
        """Add a new custom command."""
        from PyQt6.QtWidgets import QDialog, QDialogButtonBox
        
        dialog = QDialog(self.main_widget)
        dialog.setWindowTitle("✊ Write New Revolt")
        dialog.setMinimumWidth(500)
        layout = QVBoxLayout(dialog)
        
        # Manifesto header
        header = QLabel("<b>⛓️‍💥 Declare your command liberation</b>")
        header.setStyleSheet("color: #ff6b6b; padding: 5px;")
        layout.addWidget(header)
        
        form = QFormLayout()
        
        name_input = QLineEdit()
        name_input.setPlaceholderText("e.g., Liberate Downloads")
        form.addRow("Battle Cry:", name_input)
        
        icon_input = QLineEdit()
        icon_input.setPlaceholderText("e.g., 📁 (optional, default: ⚡)")
        icon_input.setMaximumWidth(50)
        form.addRow("Icon:", icon_input)
        
        cmd_input = QLineEdit()
        cmd_input.setPlaceholderText("e.g., ls -la /sdcard/Download")
        form.addRow("Command:", cmd_input)
        
        layout.addLayout(form)
        
        # Help text
        help_label = QLabel(
            "<b>💡 Anarchist's Guide:</b><br>"
            "• Use <code>{variable}</code> for liberation parameters<br>"
            "• Example: <code>cat {filepath}</code> asks for the target<br>"
            "• Chain actions: <code>mv {source} {dest}</code>"
        )
        help_label.setWordWrap(True)
        help_label.setStyleSheet("background: #2d2d30; padding: 10px; border-radius: 5px;")
        layout.addWidget(help_label)
        
        # Variable definition section
        var_group = QGroupBox("📝 Liberation Parameters (optional)")
        var_layout = QFormLayout(var_group)
        var_inputs = {}
        
        def update_var_fields():
            # Clear existing
            for i in reversed(range(var_layout.count())):
                item = var_layout.itemAt(i)
                if item.widget():
                    item.widget().deleteLater()
            var_inputs.clear()
            
            # Find variables in command
            import re
            cmd = cmd_input.text()
            variables = re.findall(r'\{(\w+)\}', cmd)
            
            for var in set(variables):
                desc_input = QLineEdit()
                desc_input.setPlaceholderText(f"Description for {var}")
                var_inputs[var] = desc_input
                var_layout.addRow(f"{var}:", desc_input)
        
        cmd_input.textChanged.connect(update_var_fields)
        layout.addWidget(var_group)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            name = name_input.text().strip()
            cmd = cmd_input.text().strip()
            icon = icon_input.text().strip() or "⚡"
            
            if not name or not cmd:
                QMessageBox.warning(self.main_widget, "Error", "Name and command are required.")
                return
            
            # Build fields list
            import re
            variables = re.findall(r'\{(\w+)\}', cmd)
            fields = []
            for var in set(variables):
                desc = var_inputs.get(var, None)
                desc_text = desc.text().strip() if desc else var
                fields.append([var, desc_text or var])
            
            self._custom_commands.append({
                "name": name,
                "command": cmd,
                "icon": icon,
                "fields": fields
            })
            self._save_custom_commands()
            self._refresh_custom_commands_list()
    
    def _edit_custom_command(self):
        """Edit selected custom command."""
        from PyQt6.QtWidgets import QDialog, QDialogButtonBox
        
        item = self.custom_cmd_list.currentItem()
        if not item:
            QMessageBox.information(self.main_widget, "Select Revolt", "Please select a revolt to revise.")
            return
        
        cmd_data = item.data(Qt.ItemDataRole.UserRole)
        idx = self._custom_commands.index(cmd_data)
        
        dialog = QDialog(self.main_widget)
        dialog.setWindowTitle("✏️ Revise Your Revolt")
        dialog.setMinimumWidth(500)
        layout = QVBoxLayout(dialog)
        
        form = QFormLayout()
        
        name_input = QLineEdit(cmd_data.get("name", ""))
        form.addRow("Battle Cry:", name_input)
        
        icon_input = QLineEdit(cmd_data.get("icon", "⚡"))
        icon_input.setMaximumWidth(50)
        form.addRow("Icon:", icon_input)
        
        cmd_input = QLineEdit(cmd_data.get("command", ""))
        form.addRow("Command:", cmd_input)
        
        layout.addLayout(form)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            import re
            name = name_input.text().strip()
            cmd = cmd_input.text().strip()
            icon = icon_input.text().strip() or "⚡"
            
            if not name or not cmd:
                QMessageBox.warning(self.main_widget, "Error", "Name and command are required.")
                return
            
            # Update fields
            variables = re.findall(r'\{(\w+)\}', cmd)
            fields = [[var, var] for var in set(variables)]
            
            self._custom_commands[idx] = {
                "name": name,
                "command": cmd,
                "icon": icon,
                "fields": fields
            }
            self._save_custom_commands()
            self._refresh_custom_commands_list()
    
    def _delete_custom_command(self):
        """Delete selected custom command."""
        item = self.custom_cmd_list.currentItem()
        if not item:
            QMessageBox.information(self.main_widget, "Select Revolt", "Please select a revolt to abolish.")
            return
        
        cmd_data = item.data(Qt.ItemDataRole.UserRole)
        
        reply = QMessageBox.question(
            self.main_widget,
            "⛓️‍💥 Abolish Revolt",
            f"Abolish '{cmd_data.get('name', 'this revolt')}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._custom_commands.remove(cmd_data)
            self._save_custom_commands()
            self._refresh_custom_commands_list()
    
    def _run_custom_command(self, item=None):
        """Run selected custom command."""
        if item is None:
            item = self.custom_cmd_list.currentItem()
        
        if not item:
            QMessageBox.information(self.main_widget, "Select Revolt", "Please select a revolt to execute.")
            return
        
        cmd_data = item.data(Qt.ItemDataRole.UserRole)
        command = cmd_data.get("command", "")
        fields = cmd_data.get("fields", [])
        
        if fields and "{" in command:
            # Show dialog for fields
            self._show_command_dialog(cmd_data.get("name", "Command"), command, fields)
        else:
            self._execute_quick_command(command)
    
    def _import_commands(self):
        """Import custom commands from JSON file."""
        import json
        
        file_path, _ = QFileDialog.getOpenFileName(
            self.main_widget,
            "📥 Import Manifesto",
            "",
            "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                with open(file_path, "r") as f:
                    imported = json.load(f)
                
                if isinstance(imported, list):
                    count = 0
                    for cmd in imported:
                        if isinstance(cmd, dict) and "name" in cmd and "command" in cmd:
                            self._custom_commands.append(cmd)
                            count += 1
                    
                    self._save_custom_commands()
                    self._refresh_custom_commands_list()
                    QMessageBox.information(self.main_widget, "⛓️‍💥 Liberation Complete", f"Imported {count} revolts into your manifesto.")
                else:
                    QMessageBox.warning(self.main_widget, "Invalid Manifesto", "File must contain a JSON array of revolts.")
            except Exception as e:
                QMessageBox.critical(self.main_widget, "Import Failed", f"Failed to liberate: {e}")
    
    def _export_commands(self):
        """Export custom commands to JSON file."""
        import json
        
        if not self._custom_commands:
            QMessageBox.information(self.main_widget, "Empty Manifesto", "No revolts to spread.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self.main_widget,
            "📤 Spread the Manifesto",
            "manifesto_revolts.json",
            "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                with open(file_path, "w") as f:
                    json.dump(self._custom_commands, f, indent=2)
                QMessageBox.information(self.main_widget, "⛓️‍💥 Manifesto Spread", f"Exported {len(self._custom_commands)} revolts to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self.main_widget, "Export Failed", f"Failed to spread: {e}")
    
    def _reset_shell(self):
        """Reset shell to root directory."""
        self._shell_cwd = "/"
        self.shell_cwd_label.setText("📁 /")
        self.shell_output.appendPlainText("\n--- Shell reset to / ---\n")
    
    def _run_shell_command(self):
        """Run a shell command with persistent working directory."""
        device = self._get_device()
        cmd = self.shell_input.text().strip()
        if not device or not cmd:
            return
        
        # Add to history and sync with ShellLineEdit
        if cmd and (not self._shell_history or self._shell_history[-1] != cmd):
            self._shell_history.append(cmd)
        self.shell_input.reset_history_index()
        
        # Show root indicator in prompt if enabled
        root_mode = hasattr(self, 'shell_root_cb') and self.shell_root_cb.isChecked()
        prompt = f"{self._shell_cwd}#" if root_mode else f"{self._shell_cwd}$"
        self.shell_output.appendPlainText(f"{prompt} {cmd}")
        self.shell_input.clear()
        
        # Handle 'cd' command specially to track directory
        if cmd.startswith("cd "):
            target_dir = cmd[3:].strip()
            self._handle_cd_command(device, target_dir)
        elif cmd == "cd":
            # cd with no args goes to home (or stay at root for Android)
            self._shell_cwd = "/"
            self.shell_cwd_label.setText("📁 /")
            self.shell_output.appendPlainText("(changed to /)\n")
        elif cmd == "pwd":
            self.shell_output.appendPlainText(self._shell_cwd + "\n")
        else:
            # Run command with cd prefix to maintain working directory
            self._run_in_cwd(device, cmd)
    
    def _handle_cd_command(self, device: str, target_dir: str):
        """Handle cd command and update working directory."""
        # Resolve the target path
        if target_dir.startswith("/"):
            # Absolute path
            new_path = target_dir
        elif target_dir == "..":
            # Go up one directory
            if self._shell_cwd == "/":
                new_path = "/"
            else:
                new_path = "/".join(self._shell_cwd.rstrip("/").split("/")[:-1]) or "/"
        elif target_dir == ".":
            new_path = self._shell_cwd
        elif target_dir.startswith(".."):
            # Handle paths like ../foo or ../../bar
            parts = target_dir.split("/")
            current_parts = self._shell_cwd.rstrip("/").split("/")
            for part in parts:
                if part == "..":
                    if len(current_parts) > 1:
                        current_parts.pop()
                elif part and part != ".":
                    current_parts.append(part)
            new_path = "/".join(current_parts) or "/"
        else:
            # Relative path
            if self._shell_cwd == "/":
                new_path = "/" + target_dir
            else:
                new_path = self._shell_cwd.rstrip("/") + "/" + target_dir
        
        # Clean up the path
        new_path = new_path.replace("//", "/")
        
        # Verify the directory exists
        success, output = run_adb(["shell", f"cd {new_path} && pwd"], device, timeout=10)
        
        if success and output.strip():
            actual_path = output.strip().split('\n')[-1]  # Get last line (pwd output)
            if actual_path and actual_path.startswith("/"):
                self._shell_cwd = actual_path
                self.shell_cwd_label.setText(f"📁 {self._shell_cwd}")
                self.shell_output.appendPlainText("")
            else:
                self._shell_cwd = new_path
                self.shell_cwd_label.setText(f"📁 {self._shell_cwd}")
                self.shell_output.appendPlainText("")
        else:
            self.shell_output.appendPlainText(f"cd: {target_dir}: No such file or directory\n")
    
    def _run_in_cwd(self, device: str, command: str):
        """Run a command in the current working directory."""
        # Wrap command to run in the current directory
        full_cmd = f"cd {self._shell_cwd} && {command}"
        
        # If root mode is enabled, wrap with su -c
        if hasattr(self, 'shell_root_cb') and self.shell_root_cb.isChecked():
            # Escape single quotes in the command for su -c
            escaped_cmd = full_cmd.replace("'", "'\"'\"'")
            full_cmd = f"su -c '{escaped_cmd}'"
        
        self.worker = AdbWorkerThread("shell", device=device, command=full_cmd)
        self.worker.result_data.connect(lambda out: self.shell_output.appendPlainText(out + "\n"))
        self.worker.start()
    
    # Keep old method for compatibility with other uses
    def _run_shell(self):
        device = self._get_device()
        cmd = self.shell_input.text()
        if not device or not cmd:
            return
        
        self.shell_output.appendPlainText(f"$ {cmd}")
        self.shell_input.clear()
        
        self.worker = AdbWorkerThread("shell", device=device, command=cmd)
        self.worker.result_data.connect(lambda out: self.shell_output.appendPlainText(out))
        self.worker.start()
    
    # ===== TOOLS TAB =====
    def _create_tools_tab(self):
        tab = QWidget()
        main_layout = QVBoxLayout(tab)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Scroll area for all content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        
        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        
        # OEM Unlock Helper
        unlock_group = QGroupBox("🔓 OEM Unlock Helper")
        unlock_layout = QVBoxLayout(unlock_group)
        
        # Status display
        self.oem_status_label = QLabel("Click 'Check Status' to see OEM unlock state")
        self.oem_status_label.setWordWrap(True)
        self.oem_status_label.setStyleSheet("padding: 8px; background: #2d2d30; border-radius: 4px;")
        unlock_layout.addWidget(self.oem_status_label)
        
        # Buttons row
        unlock_btn_row = QHBoxLayout()
        
        check_oem_btn = QPushButton("🔍 Check Status")
        check_oem_btn.clicked.connect(self._check_oem_unlock_status)
        unlock_btn_row.addWidget(check_oem_btn)
        
        enable_oem_btn = QPushButton("🔓 Enable OEM Unlock")
        enable_oem_btn.setToolTip("Attempts to enable OEM unlocking via settings")
        enable_oem_btn.clicked.connect(self._enable_oem_unlock)
        unlock_btn_row.addWidget(enable_oem_btn)
        
        dev_options_btn = QPushButton("⚙️ Open Dev Options")
        dev_options_btn.setToolTip("Opens Developer Options on the device")
        dev_options_btn.clicked.connect(self._open_developer_options)
        unlock_btn_row.addWidget(dev_options_btn)
        
        unlock_layout.addLayout(unlock_btn_row)
        
        # Info/help text
        unlock_info = QLabel(
            "<b>Why is OEM Unlock greyed out?</b><br>"
            "• <b>FRP Lock:</b> Factory reset protection active (Google account signed in)<br>"
            "• <b>Carrier Lock:</b> Device is carrier-locked (contact carrier)<br>"
            "• <b>Knox/MDM:</b> Enterprise management enabled<br>"
            "• <b>Time Lock:</b> Some devices require 7 days after adding Google account<br>"
            "• <b>Missing:</b> Some carriers remove the option entirely (need carrier unlock)"
        )
        unlock_info.setWordWrap(True)
        unlock_info.setStyleSheet("font-size: 11px; color: #888; padding: 4px;")
        unlock_layout.addWidget(unlock_info)
        
        layout.addWidget(unlock_group)
        
        # Screenshot
        screen_group = QGroupBox("Screenshot")
        screen_layout = QHBoxLayout(screen_group)
        self.screenshot_path = QLineEdit(os.path.expanduser("~/screenshot.png"))
        screen_layout.addWidget(self.screenshot_path)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(lambda: self._browse_save(self.screenshot_path, "PNG (*.png)"))
        screen_layout.addWidget(browse_btn)
        capture_btn = QPushButton("📸 Capture")
        capture_btn.clicked.connect(self._take_screenshot)
        screen_layout.addWidget(capture_btn)
        layout.addWidget(screen_group)
        
        # Logcat
        log_group = QGroupBox("Logcat")
        log_layout = QVBoxLayout(log_group)
        
        self.logcat_output = QPlainTextEdit()
        self.logcat_output.setReadOnly(True)
        self.logcat_output.setMaximumHeight(200)
        self.logcat_output.setStyleSheet("font-family: Consolas; font-size: 10px;")
        log_layout.addWidget(self.logcat_output)
        
        log_btn_row = QHBoxLayout()
        self.logcat_lines = QSpinBox()
        self.logcat_lines.setRange(10, 1000)
        self.logcat_lines.setValue(100)
        log_btn_row.addWidget(QLabel("Lines:"))
        log_btn_row.addWidget(self.logcat_lines)
        
        logcat_btn = QPushButton("📜 Get Logcat")
        logcat_btn.clicked.connect(self._get_logcat)
        log_btn_row.addWidget(logcat_btn)
        log_btn_row.addStretch()
        log_layout.addLayout(log_btn_row)
        layout.addWidget(log_group)
        
        layout.addStretch()
        
        scroll.setWidget(scroll_content)
        main_layout.addWidget(scroll)
        return tab
    
    def _get_oem_state(self, device, adb_path):
        """Get comprehensive OEM unlock state. Returns dict with all relevant info."""
        state = {
            'settings_value': None,      # What's in settings database (user toggled)
            'runtime_value': None,       # sys.oem_unlock_allowed (actual runtime state)
            'supported': None,           # ro.oem_unlock_supported
            'carrier': None,
            'frp_partition': None,
            'verified_boot': None,
            'is_truly_enabled': False,   # The REAL answer
            'needs_reboot': False,       # Settings changed but runtime doesn't reflect
            'blocked_reason': None,      # Why it might be blocked
        }
        
        try:
            result = subprocess.run(
                [adb_path, "-s", device, "shell", "settings", "get", "global", "oem_unlock_allowed"],
                capture_output=True, text=True, timeout=10
            )
            val = result.stdout.strip()
            state['settings_value'] = val if val and val != 'null' else None
        except:
            pass
        
        try:
            result = subprocess.run(
                [adb_path, "-s", device, "shell", "getprop", "sys.oem_unlock_allowed"],
                capture_output=True, text=True, timeout=10
            )
            val = result.stdout.strip()
            state['runtime_value'] = val if val else None
        except:
            pass
        
        try:
            result = subprocess.run(
                [adb_path, "-s", device, "shell", "getprop", "ro.oem_unlock_supported"],
                capture_output=True, text=True, timeout=10
            )
            state['supported'] = result.stdout.strip()
        except:
            pass
        
        try:
            result = subprocess.run(
                [adb_path, "-s", device, "shell", "getprop", "ro.carrier"],
                capture_output=True, text=True, timeout=10
            )
            state['carrier'] = result.stdout.strip() or None
        except:
            pass
        
        try:
            result = subprocess.run(
                [adb_path, "-s", device, "shell", "getprop", "ro.frp.pst"],
                capture_output=True, text=True, timeout=10
            )
            state['frp_partition'] = result.stdout.strip() or None
        except:
            pass
        
        try:
            result = subprocess.run(
                [adb_path, "-s", device, "shell", "getprop", "ro.boot.verifiedbootstate"],
                capture_output=True, text=True, timeout=10
            )
            state['verified_boot'] = result.stdout.strip() or None
        except:
            pass
        
        # Determine the REAL state - runtime value is the truth
        if state['runtime_value'] == '1':
            state['is_truly_enabled'] = True
            # If settings says disabled but runtime is still enabled, need reboot to disable
            if state['settings_value'] == '0':
                state['needs_reboot'] = True  # Reboot needed to DISABLE
        elif state['runtime_value'] == '0':
            state['is_truly_enabled'] = False
            # If settings says enabled but runtime is 0, it's BLOCKED (not needs reboot)
            # Enabling takes effect immediately, so if runtime is 0 it means blocked
        
        if state['supported'] == '0':
            state['blocked_reason'] = "Device does not support OEM unlocking"
        elif state['settings_value'] == '1' and state['runtime_value'] == '0':
            state['blocked_reason'] = "Blocked by carrier, FRP, Knox, or MDM policy"
        
        return state
    
    def _format_oem_status(self, state):
        """Format OEM state into user-friendly HTML display."""
        lines = []
        
        if state['is_truly_enabled'] and state['needs_reboot']:
            # OEM is enabled but user turned it off - needs reboot to disable
            lines.append("⚠ <b style='color:#dcdcaa;font-size:14px;'>OEM UNLOCK STILL ACTIVE</b>")
            lines.append("<span style='color:#dcdcaa;'>Setting changed to disabled, but still active until reboot.</span>")
            lines.append("<span style='color:#dcdcaa;'>Reboot phone to fully disable OEM unlock.</span>")
        elif state['is_truly_enabled']:
            lines.append("✓ <b style='color:#4ec9b0;font-size:14px;'>OEM UNLOCK IS ENABLED</b>")
            lines.append("<span style='color:#4ec9b0;'>You can unlock bootloader via fastboot</span>")
        elif state['settings_value'] == '1' and state['runtime_value'] == '0':
            lines.append("✗ <b style='color:#f44747;font-size:14px;'>OEM UNLOCK BLOCKED</b>")
            lines.append("<span style='color:#f44747;'>Setting enabled but system is blocking it.</span>")
            if state['blocked_reason']:
                lines.append(f"<span style='color:#f44747;'>Reason: {state['blocked_reason']}</span>")
        elif state['settings_value'] == '0' or state['runtime_value'] == '0':
            lines.append("✗ <b style='color:#f44747;font-size:14px;'>OEM UNLOCK IS DISABLED</b>")
            lines.append("<span style='color:#888;'>Enable in Settings → Developer Options → OEM Unlocking</span>")
        else:
            lines.append("? <b style='color:#888;font-size:14px;'>OEM UNLOCK STATUS UNKNOWN</b>")
        
        lines.append("")
        lines.append("<b>Detailed Status:</b>")
        
        if state['settings_value'] is not None:
            icon = "✓" if state['settings_value'] == '1' else "✗"
            lines.append(f"  {icon} Settings database: {state['settings_value']}")
        
        if state['runtime_value'] is not None:
            icon = "✓" if state['runtime_value'] == '1' else "✗"
            color = "#4ec9b0" if state['runtime_value'] == '1' else "#f44747"
            lines.append(f"  <span style='color:{color};'>{icon} Runtime state: {state['runtime_value']} (THE REAL STATE)</span>")
        
        if state['supported']:
            icon = "✓" if state['supported'] == '1' else "✗"
            lines.append(f"  {icon} Device supports unlock: {state['supported']}")
        
        if state['carrier']:
            lines.append(f"  Carrier: {state['carrier']}")
        
        if state['verified_boot']:
            lines.append(f"  Verified boot: {state['verified_boot']}")
        
        return "<br>".join(lines)
    
    def _check_oem_unlock_status(self):
        """Check OEM unlock status and related device info"""
        device = self._get_device()
        if not device:
            return
        
        adb_path = find_adb()
        if not adb_path:
            self._log("✗ ADB not found")
            return
        
        self._log("Checking OEM unlock status...")
        print("[OEM Check] Gathering device unlock information...")
        
        state = self._get_oem_state(device, adb_path)
        
        print(f"[OEM Check] Settings value: {state['settings_value']}")
        print(f"[OEM Check] Runtime value: {state['runtime_value']}")
        print(f"[OEM Check] Is truly enabled: {state['is_truly_enabled']}")
        print(f"[OEM Check] Needs reboot: {state['needs_reboot']}")
        if state['blocked_reason']:
            print(f"[OEM Check] Blocked reason: {state['blocked_reason']}")
        
        self.oem_status_label.setText(self._format_oem_status(state))
        self._log("OEM status check complete")
        print("[OEM Check] Status check complete")
    
    def _enable_oem_unlock(self):
        """Attempt to enable OEM unlocking via settings"""
        device = self._get_device()
        if not device:
            return
        
        adb_path = find_adb()
        if not adb_path:
            self._log("✗ ADB not found")
            return
        
        self._log("Checking current OEM state...")
        before_state = self._get_oem_state(device, adb_path)
        
        if before_state['is_truly_enabled']:
            self._log("OEM unlock is already enabled!")
            self.oem_status_label.setText(self._format_oem_status(before_state))
            QMessageBox.information(
                self.parent_window, "Already Enabled",
                "OEM unlock is already enabled on this device.\n\n"
                "You can proceed with bootloader unlock via fastboot."
            )
            return
        
        self._log("Attempting to enable OEM unlock...")
        print("[OEM Unlock] Attempting to enable OEM unlock setting...")
        
        try:
            result = subprocess.run(
                [adb_path, "-s", device, "shell", "settings", "put", "global", "oem_unlock_allowed", "1"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode != 0:
                self._log(f"✗ Command failed: {result.stderr}")
                self.oem_status_label.setText(
                    f"✗ <b style='color:#f44747;'>Failed to run command</b><br>"
                    f"{result.stderr.strip() if result.stderr else 'Permission denied'}"
                )
                return
            
            print("[OEM Unlock] Command executed, checking new state...")
            after_state = self._get_oem_state(device, adb_path)
            
            if after_state['is_truly_enabled']:
                self._log("✓ OEM unlock enabled successfully!")
                self.oem_status_label.setText(self._format_oem_status(after_state))
                QMessageBox.information(
                    self.parent_window, "Success!",
                    "OEM unlock is now ENABLED!\n\n"
                    "You can now unlock the bootloader:\n"
                    "1. Reboot to bootloader (fastboot mode)\n"
                    "2. Run: fastboot oem unlock\n\n"
                    "⚠️ WARNING: This will WIPE ALL DATA on the device!"
                )
            elif after_state['settings_value'] == '1' and after_state['runtime_value'] != '1':
                self._log("⚠ Setting changed - reboot required")
                self.oem_status_label.setText(self._format_oem_status(after_state))
                
                reply = QMessageBox.question(
                    self.parent_window, "Reboot Required",
                    "The OEM unlock setting has been changed, but the phone needs to "
                    "reboot for the change to take effect.\n\n"
                    "After reboot, check the status again to confirm.\n\n"
                    "Do you want to reboot the phone now?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                
                if reply == QMessageBox.StandardButton.Yes:
                    self._reboot_and_wait_for_oem(device, adb_path)
            elif before_state['settings_value'] == after_state['settings_value']:
                self._log("✗ Setting did not change - blocked by system")
                self.oem_status_label.setText(
                    "✗ <b style='color:#f44747;'>OEM UNLOCK BLOCKED</b><br><br>"
                    "The system prevented the change. Possible reasons:<br>"
                    "• Device is carrier-locked (contact carrier for unlock)<br>"
                    "• FRP (Factory Reset Protection) is active<br>"
                    "• Knox or MDM enterprise policy<br>"
                    "• Need to wait 7 days after adding Google account<br><br>"
                    "<b>Try:</b> Go to Settings → Developer Options and manually toggle OEM Unlocking"
                )
                QMessageBox.warning(
                    self.parent_window, "Blocked",
                    "The system blocked the OEM unlock setting change.\n\n"
                    "This is usually due to:\n"
                    "• Carrier lock (contact your carrier)\n"
                    "• Google account FRP protection\n"
                    "• Enterprise/Knox management\n\n"
                    "Try enabling it manually in Developer Options."
                )
            else:
                self.oem_status_label.setText(self._format_oem_status(after_state))
                
        except Exception as e:
            self._log(f"✗ Error: {e}")
            print(f"[OEM Unlock] ✗ Exception: {e}")
            self.oem_status_label.setText(f"✗ <b style='color:#f44747'>Error: {e}</b>")
    
    def _reboot_and_wait_for_oem(self, device, adb_path):
        """Reboot device and wait for it to come back, then check OEM status."""
        self._log("Rebooting device...")
        self.oem_status_label.setText(
            "⏳ <b style='color:#dcdcaa;'>Rebooting device...</b><br>"
            "Please wait for the device to restart."
        )
        QApplication.processEvents()
        
        try:
            subprocess.run([adb_path, "-s", device, "reboot"], timeout=10)
        except:
            pass
        
        import time
        self._log("Waiting for device to disconnect...")
        time.sleep(5)
        
        self._log("Waiting for device to reconnect...")
        self.oem_status_label.setText(
            "⏳ <b style='color:#dcdcaa;'>Waiting for device to reconnect...</b><br>"
            "This may take up to 2 minutes."
        )
        QApplication.processEvents()
        
        max_wait = 120
        waited = 0
        device_back = False
        
        while waited < max_wait:
            try:
                result = subprocess.run(
                    [adb_path, "devices"],
                    capture_output=True, text=True, timeout=5
                )
                if device in result.stdout and "device" in result.stdout:
                    device_back = True
                    break
            except:
                pass
            
            time.sleep(3)
            waited += 3
            self.oem_status_label.setText(
                f"⏳ <b style='color:#dcdcaa;'>Waiting for device... ({waited}s)</b><br>"
                "Please wait for the device to fully boot."
            )
            QApplication.processEvents()
        
        if not device_back:
            self._log("⚠ Device did not reconnect in time")
            self.oem_status_label.setText(
                "⚠ <b style='color:#dcdcaa;'>Device not detected</b><br>"
                "The device may still be booting. Click 'Check Status' when it's ready."
            )
            return
        
        self._log("Device reconnected, waiting for full boot...")
        time.sleep(5)
        
        self._log("Checking OEM status after reboot...")
        new_state = self._get_oem_state(device, adb_path)
        self.oem_status_label.setText(self._format_oem_status(new_state))
        
        if new_state['is_truly_enabled']:
            self._log("✓ OEM unlock is now active!")
            QMessageBox.information(
                self.parent_window, "Success!",
                "OEM unlock is now ENABLED after reboot!\n\n"
                "You can now unlock the bootloader:\n"
                "1. Reboot to bootloader (fastboot mode)\n"
                "2. Run: fastboot oem unlock\n\n"
                "⚠️ WARNING: This will WIPE ALL DATA on the device!"
            )
        else:
            self._log("⚠ OEM unlock still not active after reboot")
            QMessageBox.warning(
                self.parent_window, "Still Blocked",
                "OEM unlock is still not active after reboot.\n\n"
                "The system is likely blocking it due to:\n"
                "• Carrier lock\n"
                "• FRP protection\n"
                "• Enterprise policy\n\n"
                "You may need to contact your carrier or remove "
                "Google account and factory reset."
            )
    
    def _open_developer_options(self):
        """Open Developer Options on the device"""
        device = self._get_device()
        if not device:
            return
        
        adb_path = find_adb()
        if not adb_path:
            self._log("✗ ADB not found")
            return
        
        self._log("Opening Developer Options...")
        print("[OEM] Opening Developer Options on device...")
        
        try:
            # Try the standard developer options intent
            result = subprocess.run(
                [adb_path, "-s", device, "shell", "am", "start", "-a", 
                 "android.settings.APPLICATION_DEVELOPMENT_SETTINGS"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0 and "Error" not in result.stdout:
                self._log("✓ Developer Options opened on device")
                print("[OEM] ✓ Developer Options opened")
            else:
                # Try alternate method
                result2 = subprocess.run(
                    [adb_path, "-s", device, "shell", "am", "start", "-n",
                     "com.android.settings/.DevelopmentSettings"],
                    capture_output=True, text=True, timeout=10
                )
                if result2.returncode == 0:
                    self._log("✓ Developer Options opened on device")
                    print("[OEM] ✓ Developer Options opened (alternate)")
                else:
                    self._log("⚠ Could not open Developer Options directly")
                    print(f"[OEM] ⚠ Could not open: {result.stdout} {result2.stdout}")
                    
        except Exception as e:
            self._log(f"✗ Error: {e}")
            print(f"[OEM] ✗ Error opening Developer Options: {e}")
    
    def _take_screenshot(self):
        device = self._get_device()
        if not device:
            return
        
        self.worker = AdbWorkerThread("screenshot", device=device,
                                       output_path=self.screenshot_path.text())
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _get_logcat(self):
        device = self._get_device()
        if not device:
            return
        
        self.worker = AdbWorkerThread("logcat", device=device,
                                       lines=self.logcat_lines.value())
        self.worker.result_data.connect(self.logcat_output.setPlainText)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== REBOOT TAB =====
    def _create_reboot_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        layout.addWidget(QLabel("⚠️ Device will disconnect after reboot"))
        layout.addSpacing(20)
        
        buttons = [
            ("🔄 Reboot System", "system"),
            ("🔧 Reboot Recovery", "recovery"),
            ("⚡ Reboot Bootloader", "bootloader"),
            ("📦 Reboot Fastbootd", "fastbootd"),
            ("📲 Reboot Sideload", "sideload"),
            ("🔥 Reboot EDL (Emergency)", "edl"),
        ]
        
        for text, mode in buttons:
            btn = QPushButton(text)
            btn.setMinimumHeight(40)
            btn.clicked.connect(lambda c, m=mode: self._reboot(m))
            layout.addWidget(btn)
        
        layout.addStretch()
        return tab
    
    def _reboot(self, mode):
        device = self._get_device()
        if not device:
            return
        
        reply = QMessageBox.question(self.parent_window, "Confirm",
                                     f"Reboot device to {mode}?")
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = AdbWorkerThread("reboot", device=device, mode=mode)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== HELPERS =====
    def _browse_file(self, line_edit, filter="All Files (*)"):
        path, _ = QFileDialog.getOpenFileName(self.parent_window, "Select File", "", filter)
        if path:
            line_edit.setText(path)
    
    def _browse_dir(self, line_edit):
        path = QFileDialog.getExistingDirectory(self.parent_window, "Select Directory")
        if path:
            line_edit.setText(path)
    
    def _browse_save(self, line_edit, filter="All Files (*)"):
        path, _ = QFileDialog.getSaveFileName(self.parent_window, "Save File", line_edit.text(), filter)
        if path:
            line_edit.setText(path)


Plugin = AdbToolkitPlugin
