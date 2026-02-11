"""
Scrcpy Toolkit Plugin for ImageAnarchy
=======================================

Mirror your Android device screen in real-time using the scrcpy executable.
Features:
- Live screen mirroring (opens scrcpy window)
- Screenshot capture via ADB
- Screen recording via scrcpy
- WiFi connection support
- Multiple device support

Requirements:
- ADB Toolkit plugin (provides ADB executable)
- scrcpy.exe bundled with plugin
- ADB debugging enabled on device
- Device connected via USB or TCP/IP

Uses scrcpy executable directly - no Python dependencies needed.
"""

import os
import sys
import time
import subprocess
import threading
import logging
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

from __main__ import PluginBase
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QComboBox,
    QPushButton, QLineEdit, QProgressBar, QFileDialog, QMessageBox,
    QTabWidget, QFormLayout, QCheckBox, QSpinBox, QFrame, QSizePolicy,
    QApplication, QTextEdit, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QProcess
from PyQt6.QtGui import QImage, QPixmap, QFont

# Setup logger
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Path Finding Utilities
# ═══════════════════════════════════════════════════════════════════════════════

def get_base_path() -> Path:
    """Get the base application path."""
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    else:
        return Path(__file__).parent.parent.parent


def find_adb_toolkit_path() -> Optional[str]:
    """Find ADB executable from ADB Toolkit plugin."""
    base_path = get_base_path()
    
    # Check ADB Toolkit plugin path (primary source)
    adb_toolkit_path = base_path / 'plugins' / 'adb_toolkit' / 'platform-tools' / 'adb.exe'
    if adb_toolkit_path.exists():
        return str(adb_toolkit_path)
    
    # Check root platform-tools
    root_adb = base_path / 'platform-tools' / 'adb.exe'
    if root_adb.exists():
        return str(root_adb)
    
    # Linux/Mac paths
    adb_toolkit_unix = base_path / 'plugins' / 'adb_toolkit' / 'platform-tools' / 'adb'
    if adb_toolkit_unix.exists():
        return str(adb_toolkit_unix)
    
    root_adb_unix = base_path / 'platform-tools' / 'adb'
    if root_adb_unix.exists():
        return str(root_adb_unix)
    
    # Fall back to system PATH
    return shutil.which('adb')


def find_scrcpy_path() -> Optional[str]:
    """Find scrcpy executable."""
    base_path = get_base_path()
    
    # Check plugin folder
    plugin_scrcpy = base_path / 'plugins' / 'scrcpy_toolkit' / 'scrcpy.exe'
    if plugin_scrcpy.exists():
        return str(plugin_scrcpy)
    
    # Check plugin tools subfolder
    plugin_tools = base_path / 'plugins' / 'scrcpy_toolkit' / 'tools' / 'scrcpy.exe'
    if plugin_tools.exists():
        return str(plugin_tools)
    
    # Check root tools
    root_tools = base_path / 'tools' / 'scrcpy.exe'
    if root_tools.exists():
        return str(root_tools)
    
    # Linux/Mac
    plugin_scrcpy_unix = base_path / 'plugins' / 'scrcpy_toolkit' / 'scrcpy'
    if plugin_scrcpy_unix.exists():
        return str(plugin_scrcpy_unix)
    
    # Fall back to system PATH
    return shutil.which('scrcpy')


def check_adb_toolkit_installed() -> bool:
    """Check if ADB Toolkit plugin is installed."""
    return (get_base_path() / 'plugins' / 'adb_toolkit').exists()


# ═══════════════════════════════════════════════════════════════════════════════
# ADB Helper Class
# ═══════════════════════════════════════════════════════════════════════════════

class AdbHelper:
    """Helper class for ADB operations using ADB Toolkit."""
    
    def __init__(self):
        self.adb_path = find_adb_toolkit_path()
        self._available = self.adb_path is not None
    
    @property
    def available(self) -> bool:
        return self._available
    
    def refresh(self):
        """Re-check ADB availability."""
        self.adb_path = find_adb_toolkit_path()
        self._available = self.adb_path is not None
    
    def _run_adb(self, args: List[str], serial: str = None, 
                 timeout: int = 30, binary: bool = False) -> subprocess.CompletedProcess:
        """Run ADB command."""
        if not self.adb_path:
            raise RuntimeError("ADB not found. Install ADB Toolkit plugin.")
        
        cmd = [self.adb_path]
        if serial:
            cmd.extend(['-s', serial])
        cmd.extend(args)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=not binary,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            return result
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"ADB command timed out: {' '.join(args)}")
    
    def get_devices(self) -> List[Dict[str, str]]:
        """Get list of connected devices."""
        if not self._available:
            return []
        
        try:
            result = self._run_adb(['devices', '-l'])
            devices = []
            
            for line in result.stdout.strip().split('\n')[1:]:
                if not line.strip() or 'offline' in line:
                    continue
                
                parts = line.split()
                if len(parts) >= 2 and parts[1] in ('device', 'unauthorized', 'recovery'):
                    serial = parts[0]
                    state = parts[1]
                    
                    # Parse model from device info
                    model = serial
                    for part in parts[2:]:
                        if part.startswith('model:'):
                            model = part.split(':')[1]
                            break
                    
                    devices.append({
                        'serial': serial,
                        'state': state,
                        'model': model
                    })
            
            return devices
        except Exception as e:
            logger.error(f"Failed to get devices: {e}")
            return []
    
    def shell(self, serial: str, command: str, binary: bool = False):
        """Run shell command on device."""
        result = self._run_adb(['shell', command], serial=serial, binary=binary)
        if binary:
            return result.stdout
        return result.stdout.strip()
    
    def get_device_ip(self, serial: str) -> Optional[str]:
        """Get device IP address for WiFi connection."""
        try:
            # Try ip route
            ip = self.shell(serial, "ip route | awk '/wlan0/ {print $9}' | head -1")
            if ip and '.' in ip:
                return ip
            
            # Try ip addr
            ip = self.shell(serial, "ip addr show wlan0 | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1")
            if ip and '.' in ip:
                return ip
            
            return None
        except:
            return None
    
    def enable_tcpip(self, serial: str, port: int = 5555) -> bool:
        """Enable TCP/IP mode on device."""
        try:
            result = self._run_adb(['tcpip', str(port)], serial=serial)
            return result.returncode == 0
        except:
            return False
    
    def connect_wifi(self, ip: str, port: int = 5555) -> bool:
        """Connect to device via WiFi."""
        try:
            result = self._run_adb(['connect', f'{ip}:{port}'])
            return 'connected' in result.stdout.lower()
        except:
            return False
    
    def screencap(self, serial: str) -> bytes:
        """Take a screenshot and return PNG data."""
        return self.shell(serial, 'screencap -p', binary=True)


# ═══════════════════════════════════════════════════════════════════════════════
# Scrcpy Process Manager
# ═══════════════════════════════════════════════════════════════════════════════

class ScrcpyProcess:
    """Manages a scrcpy process."""
    
    def __init__(self, scrcpy_path: str, adb_path: str):
        self.scrcpy_path = scrcpy_path
        self.adb_path = adb_path
        self.process: Optional[subprocess.Popen] = None
        self._is_running = False
    
    @property
    def is_running(self) -> bool:
        if self.process:
            return self.process.poll() is None
        return False
    
    def start_mirror(self, serial: str, options: dict = None) -> bool:
        """Start scrcpy for mirroring."""
        if self.is_running:
            self.stop()
        
        options = options or {}
        
        cmd = [self.scrcpy_path]
        cmd.extend(['--serial', serial])
        
        # Set ADB path
        env = os.environ.copy()
        adb_dir = str(Path(self.adb_path).parent)
        env['PATH'] = adb_dir + os.pathsep + env.get('PATH', '')
        
        # Apply options
        if options.get('max_fps'):
            cmd.extend(['--max-fps', str(options['max_fps'])])
        
        if options.get('bitrate'):
            cmd.extend(['--video-bit-rate', f"{options['bitrate']}M"])
        
        if options.get('max_size'):
            cmd.extend(['--max-size', str(options['max_size'])])
        
        if options.get('stay_awake'):
            cmd.append('--stay-awake')
        
        if options.get('show_touches'):
            cmd.append('--show-touches')
        
        if options.get('screen_off'):
            cmd.append('--turn-screen-off')
        
        if options.get('always_on_top'):
            cmd.append('--always-on-top')
        
        if options.get('window_title'):
            cmd.extend(['--window-title', options['window_title']])
        
        try:
            # Don't use CREATE_NO_WINDOW since we want to see the scrcpy window
            self.process = subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self._is_running = True
            return True
        except Exception as e:
            logger.error(f"Failed to start scrcpy: {e}")
            return False
    
    def start_recording(self, serial: str, output_path: str, options: dict = None) -> bool:
        """Start scrcpy with recording enabled."""
        if self.is_running:
            self.stop()
        
        options = options or {}
        
        cmd = [self.scrcpy_path]
        cmd.extend(['--serial', serial])
        cmd.extend(['--record', output_path])
        
        # Set ADB path
        env = os.environ.copy()
        adb_dir = str(Path(self.adb_path).parent)
        env['PATH'] = adb_dir + os.pathsep + env.get('PATH', '')
        
        # Apply options
        if options.get('max_fps'):
            cmd.extend(['--max-fps', str(options['max_fps'])])
        
        if options.get('bitrate'):
            cmd.extend(['--video-bit-rate', f"{options['bitrate']}M"])
        
        if options.get('no_display'):
            cmd.append('--no-display')
        
        try:
            self.process = subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self._is_running = True
            return True
        except Exception as e:
            logger.error(f"Failed to start recording: {e}")
            return False
    
    def stop(self):
        """Stop the scrcpy process."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except:
                pass
            self.process = None
        self._is_running = False


# ═══════════════════════════════════════════════════════════════════════════════
# Main Plugin Widget
# ═══════════════════════════════════════════════════════════════════════════════

class PluginWidget(QWidget):
    """Scrcpy Toolkit plugin widget with PyQt6 UI."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.adb_helper = AdbHelper()
        self.scrcpy_path = find_scrcpy_path()
        self.scrcpy_process = None
        self.recording_start_time = None
        self.recording_timer = None
        
        self._setup_ui()
        QTimer.singleShot(100, self._check_dependencies)
    
    def _setup_ui(self):
        """Setup the plugin UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Create tab widget
        tabs = QTabWidget()
        tabs.addTab(self._create_mirror_tab(), "📺 Mirror")
        tabs.addTab(self._create_record_tab(), "🎬 Record")
        tabs.addTab(self._create_settings_tab(), "⚙️ Settings")
        tabs.addTab(self._create_help_tab(), "❓ Help")
        layout.addWidget(tabs)
    
    def _create_mirror_tab(self) -> QWidget:
        """Create the mirror tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Device selection group
        device_group = QGroupBox("Device Selection")
        device_layout = QHBoxLayout(device_group)
        
        device_layout.addWidget(QLabel("Device:"))
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(200)
        device_layout.addWidget(self.device_combo, 1)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_devices)
        device_layout.addWidget(refresh_btn)
        
        wifi_btn = QPushButton("📡 WiFi")
        wifi_btn.setToolTip("Connect current device via WiFi")
        wifi_btn.clicked.connect(self._connect_wifi)
        device_layout.addWidget(wifi_btn)
        
        layout.addWidget(device_group)
        
        # Mirror options group
        options_group = QGroupBox("Mirror Options")
        options_layout = QFormLayout(options_group)
        
        self.max_fps_spin = QSpinBox()
        self.max_fps_spin.setRange(1, 120)
        self.max_fps_spin.setValue(60)
        options_layout.addRow("Max FPS:", self.max_fps_spin)
        
        self.bitrate_spin = QSpinBox()
        self.bitrate_spin.setRange(1, 50)
        self.bitrate_spin.setValue(8)
        self.bitrate_spin.setSuffix(" Mbps")
        options_layout.addRow("Bitrate:", self.bitrate_spin)
        
        self.max_size_spin = QSpinBox()
        self.max_size_spin.setRange(0, 4096)
        self.max_size_spin.setValue(540)  # Default to ~1/2 size of 1080p devices
        self.max_size_spin.setSpecialValueText("Original")
        self.max_size_spin.setSuffix(" px")
        options_layout.addRow("Max Size:", self.max_size_spin)
        
        self.stay_awake_cb = QCheckBox("Keep device awake")
        self.stay_awake_cb.setChecked(True)
        options_layout.addRow("", self.stay_awake_cb)
        
        self.show_touches_cb = QCheckBox("Show touch indicators")
        options_layout.addRow("", self.show_touches_cb)
        
        self.always_on_top_cb = QCheckBox("Window always on top")
        self.always_on_top_cb.setChecked(True)  # Default to always on top like MTK Toolkit
        options_layout.addRow("", self.always_on_top_cb)
        
        layout.addWidget(options_group)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("▶️ Start Mirror")
        self.start_btn.setStyleSheet("QPushButton { padding: 12px 24px; font-weight: bold; font-size: 14px; }")
        self.start_btn.clicked.connect(self._start_mirror)
        btn_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹️ Stop Mirror")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("QPushButton { padding: 12px 24px; }")
        self.stop_btn.clicked.connect(self._stop_mirror)
        btn_layout.addWidget(self.stop_btn)
        
        screenshot_btn = QPushButton("📷 Screenshot")
        screenshot_btn.setStyleSheet("QPushButton { padding: 12px 24px; }")
        screenshot_btn.clicked.connect(self._take_screenshot)
        btn_layout.addWidget(screenshot_btn)
        
        layout.addLayout(btn_layout)
        
        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #888; padding: 5px; font-size: 12px;")
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        return widget
    
    def _create_record_tab(self) -> QWidget:
        """Create the recording tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Recording settings
        settings_group = QGroupBox("Recording Settings")
        form = QFormLayout(settings_group)
        
        # Device selection (shared)
        self.record_device_combo = QComboBox()
        self.record_device_combo.setMinimumWidth(200)
        form.addRow("Device:", self.record_device_combo)
        
        # Output path
        path_layout = QHBoxLayout()
        self.recording_path_edit = QLineEdit()
        self.recording_path_edit.setPlaceholderText("Select output file...")
        path_layout.addWidget(self.recording_path_edit)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_recording_path)
        path_layout.addWidget(browse_btn)
        form.addRow("Save To:", path_layout)
        
        # FPS
        self.record_fps_spin = QSpinBox()
        self.record_fps_spin.setRange(1, 60)
        self.record_fps_spin.setValue(30)
        form.addRow("FPS:", self.record_fps_spin)
        
        # Bitrate
        self.record_bitrate_spin = QSpinBox()
        self.record_bitrate_spin.setRange(1, 50)
        self.record_bitrate_spin.setValue(8)
        self.record_bitrate_spin.setSuffix(" Mbps")
        form.addRow("Bitrate:", self.record_bitrate_spin)
        
        # No display option
        self.no_display_cb = QCheckBox("Record without display (background)")
        form.addRow("", self.no_display_cb)
        
        layout.addWidget(settings_group)
        
        # Recording status
        status_group = QGroupBox("Recording Status")
        status_layout = QVBoxLayout(status_group)
        
        self.recording_status_label = QLabel("Status: Not Recording")
        self.recording_status_label.setStyleSheet("font-size: 14px;")
        status_layout.addWidget(self.recording_status_label)
        
        self.recording_duration_label = QLabel("Duration: 00:00:00")
        self.recording_duration_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        status_layout.addWidget(self.recording_duration_label)
        
        layout.addWidget(status_group)
        
        # Recording controls
        btn_layout = QHBoxLayout()
        
        self.start_record_btn = QPushButton("🔴 Start Recording")
        self.start_record_btn.setStyleSheet("QPushButton { padding: 12px 24px; font-weight: bold; }")
        self.start_record_btn.clicked.connect(self._start_recording)
        btn_layout.addWidget(self.start_record_btn)
        
        self.stop_record_btn = QPushButton("⏹️ Stop Recording")
        self.stop_record_btn.setEnabled(False)
        self.stop_record_btn.setStyleSheet("QPushButton { padding: 12px 24px; }")
        self.stop_record_btn.clicked.connect(self._stop_recording)
        btn_layout.addWidget(self.stop_record_btn)
        
        layout.addLayout(btn_layout)
        
        # Recording timer
        self.recording_timer = QTimer()
        self.recording_timer.timeout.connect(self._update_recording_duration)
        
        layout.addStretch()
        return widget
    
    def _create_settings_tab(self) -> QWidget:
        """Create the settings tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Scrcpy path settings
        scrcpy_group = QGroupBox("Scrcpy Executable")
        scrcpy_layout = QVBoxLayout(scrcpy_group)
        
        path_layout = QHBoxLayout()
        self.scrcpy_path_edit = QLineEdit()
        self.scrcpy_path_edit.setPlaceholderText("scrcpy path (auto-detected)...")
        self.scrcpy_path_edit.setText(self.scrcpy_path or "")
        path_layout.addWidget(self.scrcpy_path_edit)
        
        browse_scrcpy_btn = QPushButton("Browse...")
        browse_scrcpy_btn.clicked.connect(self._browse_scrcpy_path)
        path_layout.addWidget(browse_scrcpy_btn)
        scrcpy_layout.addLayout(path_layout)
        
        info_label = QLabel("scrcpy is bundled with this plugin. Path is auto-detected.")
        info_label.setStyleSheet("padding: 5px; color: #888;")
        scrcpy_layout.addWidget(info_label)
        
        layout.addWidget(scrcpy_group)
        
        # Dependency status
        deps_group = QGroupBox("Dependencies")
        deps_layout = QVBoxLayout(deps_group)
        
        self.deps_label = QLabel()
        self.deps_label.setStyleSheet("font-size: 12px;")
        deps_layout.addWidget(self.deps_label)
        
        # Add refresh button
        refresh_deps_btn = QPushButton("🔄 Re-check Dependencies")
        refresh_deps_btn.setToolTip("Click to refresh dependency status")
        refresh_deps_btn.clicked.connect(self._check_dependencies)
        deps_layout.addWidget(refresh_deps_btn)
        
        layout.addWidget(deps_group)
        
        layout.addStretch()
        return widget
    
    def _create_help_tab(self) -> QWidget:
        """Create the help tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_text.setHtml("""
        <h2>Scrcpy Toolkit Help</h2>
        
        <h3>Requirements</h3>
        <ul>
            <li><b>ADB Toolkit Plugin</b> - Install from Plugin Store first</li>
            <li><b>USB Debugging</b> - Enable on your Android device</li>
            <li><b>Device Connection</b> - Connect via USB or WiFi</li>
        </ul>
        
        <h3>Setup Instructions</h3>
        <ol>
            <li>Install ADB Toolkit plugin from Plugin Store</li>
            <li>Enable USB Debugging on your Android device</li>
            <li>Connect device via USB</li>
            <li>Click Refresh to detect your device</li>
        </ol>
        
        <h3>Mirror Tab</h3>
        <p>Start live screen mirroring. A scrcpy window will open showing your device screen.
        You can interact with the device using mouse and keyboard.</p>
        
        <h3>Record Tab</h3>
        <p>Record your device screen to MP4/MKV. Choose "Record without display" to record
        in the background without opening a window.</p>
        
        <h3>Keyboard Shortcuts (in scrcpy window)</h3>
        <ul>
            <li><b>Ctrl+H</b> - Home</li>
            <li><b>Ctrl+B</b> - Back</li>
            <li><b>Ctrl+S</b> - App Switch</li>
            <li><b>Ctrl+M</b> - Menu</li>
            <li><b>Ctrl+O</b> - Turn screen off</li>
            <li><b>Ctrl+Shift+O</b> - Turn screen on</li>
            <li><b>Ctrl+R</b> - Rotate</li>
            <li><b>Ctrl+N</b> - Expand notifications</li>
        </ul>
        
        <h3>WiFi Connection</h3>
        <p>Click the WiFi button to enable wireless ADB. Your device must be connected via USB first.
        After enabling, you can disconnect USB and use WiFi.</p>
        """)
        layout.addWidget(help_text)
        
        return widget
    
    def _check_dependencies(self):
        """Check and display dependency status."""
        # Re-check paths
        self.adb_helper.refresh()
        self.scrcpy_path = self.scrcpy_path_edit.text() or find_scrcpy_path()
        
        deps = []
        all_ok = True
        
        # Check ADB Toolkit
        if self.adb_helper.available:
            deps.append(f"✅ ADB: {Path(self.adb_helper.adb_path).name}")
        else:
            if check_adb_toolkit_installed():
                deps.append("⚠️ ADB Toolkit installed but adb not found")
            else:
                deps.append("❌ ADB: Install ADB Toolkit plugin from Plugin Store")
            all_ok = False
        
        # Check scrcpy
        if self.scrcpy_path and Path(self.scrcpy_path).exists():
            deps.append(f"✅ scrcpy: {Path(self.scrcpy_path).name}")
        else:
            deps.append("❌ scrcpy: Not found - try reinstalling plugin from Plugin Store")
            all_ok = False
        
        self.deps_label.setText("\n".join(deps))
        
        if all_ok:
            self.start_btn.setEnabled(True)
            self.start_record_btn.setEnabled(True)
            self.status_label.setText("✅ Ready - All dependencies found")
            self._refresh_devices()
        else:
            self.start_btn.setEnabled(False)
            self.start_record_btn.setEnabled(False)
            if not self.adb_helper.available:
                self.status_label.setText("⚠️ Install ADB Toolkit plugin from Plugin Store")
            else:
                self.status_label.setText("⚠️ Download scrcpy and set path in Settings")
    
    def _refresh_devices(self):
        """Refresh the device list."""
        self.device_combo.clear()
        self.record_device_combo.clear()
        
        if not self.adb_helper.available:
            self.device_combo.addItem("Install ADB Toolkit plugin")
            self.record_device_combo.addItem("Install ADB Toolkit plugin")
            return
        
        try:
            devices = self.adb_helper.get_devices()
            
            if not devices:
                self.device_combo.addItem("No devices found")
                self.record_device_combo.addItem("No devices found")
                self.status_label.setText("No devices found - Connect a device via USB")
                return
            
            for device in devices:
                serial = device['serial']
                model = device['model']
                state = device['state']
                
                if state == 'unauthorized':
                    display = f"⚠️ {model} (unauthorized - check device)"
                else:
                    display = f"{model} ({serial})"
                
                self.device_combo.addItem(display, serial)
                self.record_device_combo.addItem(display, serial)
            
            self.status_label.setText(f"✅ Found {len(devices)} device(s)")
        except Exception as e:
            self.device_combo.addItem("ADB error")
            self.record_device_combo.addItem("ADB error")
            self.status_label.setText(f"Error: {e}")
    
    def _connect_wifi(self):
        """Connect current device via WiFi."""
        if not self.adb_helper.available:
            QMessageBox.warning(self, "Error", "Install ADB Toolkit plugin first")
            return
        
        serial = self.device_combo.currentData()
        if not serial:
            QMessageBox.warning(self, "No Device", "Please select a device first")
            return
        
        try:
            self.status_label.setText("Getting device IP...")
            QApplication.processEvents()
            
            ip = self.adb_helper.get_device_ip(serial)
            
            if not ip:
                QMessageBox.warning(self, "Error", "Could not determine device IP. Is WiFi connected?")
                self.status_label.setText("Failed to get device IP")
                return
            
            self.status_label.setText("Enabling TCP/IP mode...")
            QApplication.processEvents()
            
            if not self.adb_helper.enable_tcpip(serial, 5555):
                QMessageBox.warning(self, "Error", "Failed to enable TCP/IP mode")
                self.status_label.setText("Failed to enable TCP/IP")
                return
            
            time.sleep(2)
            
            self.status_label.setText(f"Connecting to {ip}:5555...")
            QApplication.processEvents()
            
            if self.adb_helper.connect_wifi(ip, 5555):
                QMessageBox.information(self, "Success", 
                    f"Connected via WiFi: {ip}:5555\nYou can now disconnect USB.")
                self._refresh_devices()
            else:
                QMessageBox.warning(self, "Error", f"Failed to connect to {ip}:5555")
                self.status_label.setText("WiFi connection failed")
            
        except Exception as e:
            QMessageBox.warning(self, "WiFi Error", str(e))
            self.status_label.setText(f"Error: {e}")
    
    def _start_mirror(self):
        """Start screen mirroring."""
        if not self.adb_helper.available:
            QMessageBox.warning(self, "ADB Required", 
                "Install ADB Toolkit plugin from the Plugin Store first.")
            return
        
        if not self.scrcpy_path or not Path(self.scrcpy_path).exists():
            QMessageBox.warning(self, "Scrcpy Not Found",
                "scrcpy not found. Try reinstalling the plugin from Plugin Store,\n"
                "or install scrcpy via your system package manager.")
            return
        
        serial = self.device_combo.currentData()
        if not serial:
            QMessageBox.warning(self, "No Device", "Please select a device first")
            return
        
        options = {
            'max_fps': self.max_fps_spin.value(),
            'bitrate': self.bitrate_spin.value(),
            'max_size': self.max_size_spin.value() if self.max_size_spin.value() > 0 else None,
            'stay_awake': self.stay_awake_cb.isChecked(),
            'show_touches': self.show_touches_cb.isChecked(),
            'always_on_top': self.always_on_top_cb.isChecked(),
            'window_title': f"Scrcpy - {self.device_combo.currentText()}"
        }
        
        self.scrcpy_process = ScrcpyProcess(self.scrcpy_path, self.adb_helper.adb_path)
        
        if self.scrcpy_process.start_mirror(serial, options):
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.status_label.setText("🔴 Mirroring active - scrcpy window opened")
            
            # Start checking if process is still running
            self._check_mirror_timer = QTimer()
            self._check_mirror_timer.timeout.connect(self._check_mirror_status)
            self._check_mirror_timer.start(1000)
        else:
            QMessageBox.warning(self, "Error", "Failed to start scrcpy")
    
    def _check_mirror_status(self):
        """Check if mirror is still running."""
        if self.scrcpy_process and not self.scrcpy_process.is_running:
            self._stop_mirror()
    
    def _stop_mirror(self):
        """Stop screen mirroring."""
        if hasattr(self, '_check_mirror_timer'):
            self._check_mirror_timer.stop()
        
        if self.scrcpy_process:
            self.scrcpy_process.stop()
            self.scrcpy_process = None
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Mirror stopped")
    
    def _take_screenshot(self):
        """Take a screenshot using ADB."""
        if not self.adb_helper.available:
            QMessageBox.warning(self, "ADB Required",
                "Install ADB Toolkit plugin from the Plugin Store first.")
            return
        
        serial = self.device_combo.currentData()
        if not serial:
            QMessageBox.warning(self, "No Device", "Please select a device first")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save Screenshot", f"screenshot_{timestamp}.png",
            "PNG Images (*.png)"
        )
        
        if not output_path:
            return
        
        try:
            self.status_label.setText("Taking screenshot...")
            QApplication.processEvents()
            
            png_data = self.adb_helper.screencap(serial)
            
            if png_data:
                with open(output_path, 'wb') as f:
                    f.write(png_data)
                self.status_label.setText(f"Screenshot saved: {Path(output_path).name}")
                QMessageBox.information(self, "Success", f"Screenshot saved to:\n{output_path}")
            else:
                QMessageBox.warning(self, "Error", "Failed to capture screenshot")
                self.status_label.setText("Screenshot failed")
        except Exception as e:
            QMessageBox.warning(self, "Screenshot Error", str(e))
            self.status_label.setText(f"Error: {e}")
    
    def _browse_recording_path(self):
        """Browse for recording output path."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Recording", f"recording_{timestamp}.mp4",
            "Video Files (*.mp4 *.mkv)"
        )
        if path:
            self.recording_path_edit.setText(path)
    
    def _browse_scrcpy_path(self):
        """Browse for scrcpy executable."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select scrcpy executable", "",
            "Executable (scrcpy.exe scrcpy);;All Files (*)"
        )
        if path:
            self.scrcpy_path_edit.setText(path)
            self.scrcpy_path = path
            self._check_dependencies()
    
    def _start_recording(self):
        """Start screen recording."""
        if not self.adb_helper.available:
            QMessageBox.warning(self, "ADB Required",
                "Install ADB Toolkit plugin from the Plugin Store first.")
            return
        
        if not self.scrcpy_path or not Path(self.scrcpy_path).exists():
            QMessageBox.warning(self, "Scrcpy Not Found",
                "scrcpy not found. Try reinstalling the plugin from Plugin Store,\n"
                "or install scrcpy via your system package manager.")
            return
        
        serial = self.record_device_combo.currentData()
        if not serial:
            QMessageBox.warning(self, "No Device", "Please select a device first")
            return
        
        output_path = self.recording_path_edit.text()
        if not output_path:
            self._browse_recording_path()
            output_path = self.recording_path_edit.text()
            if not output_path:
                return
        
        options = {
            'max_fps': self.record_fps_spin.value(),
            'bitrate': self.record_bitrate_spin.value(),
            'no_display': self.no_display_cb.isChecked()
        }
        
        self.scrcpy_process = ScrcpyProcess(self.scrcpy_path, self.adb_helper.adb_path)
        
        if self.scrcpy_process.start_recording(serial, output_path, options):
            self.start_record_btn.setEnabled(False)
            self.stop_record_btn.setEnabled(True)
            self.recording_status_label.setText("Status: 🔴 Recording")
            self.recording_status_label.setStyleSheet("color: red; font-size: 14px; font-weight: bold;")
            
            self.recording_start_time = time.time()
            self.recording_timer.start(1000)
            
            # Check if process is still running
            self._check_record_timer = QTimer()
            self._check_record_timer.timeout.connect(self._check_recording_status)
            self._check_record_timer.start(1000)
        else:
            QMessageBox.warning(self, "Error", "Failed to start recording")
    
    def _check_recording_status(self):
        """Check if recording is still running."""
        if self.scrcpy_process and not self.scrcpy_process.is_running:
            self._stop_recording()
    
    def _stop_recording(self):
        """Stop screen recording."""
        if hasattr(self, '_check_record_timer'):
            self._check_record_timer.stop()
        
        self.recording_timer.stop()
        
        if self.scrcpy_process:
            self.scrcpy_process.stop()
            self.scrcpy_process = None
        
        self.start_record_btn.setEnabled(True)
        self.stop_record_btn.setEnabled(False)
        self.recording_status_label.setText("Status: Recording saved")
        self.recording_status_label.setStyleSheet("color: green; font-size: 14px;")
        
        output_path = self.recording_path_edit.text()
        if output_path and Path(output_path).exists():
            QMessageBox.information(self, "Recording Complete", 
                f"Recording saved to:\n{output_path}")
    
    def _update_recording_duration(self):
        """Update recording duration display."""
        if self.recording_start_time:
            elapsed = int(time.time() - self.recording_start_time)
            hours = elapsed // 3600
            minutes = (elapsed % 3600) // 60
            seconds = elapsed % 60
            self.recording_duration_label.setText(f"Duration: {hours:02d}:{minutes:02d}:{seconds:02d}")
    
    def cleanup(self):
        """Cleanup resources."""
        if self.scrcpy_process:
            self.scrcpy_process.stop()
        if self.recording_timer:
            self.recording_timer.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# Plugin Class (inherits PluginBase)
# ═══════════════════════════════════════════════════════════════════════════════

class ScrcpyToolkitPlugin(PluginBase):
    """Scrcpy Toolkit plugin for ImageAnarchy."""
    
    def create_widget(self, parent_window) -> QWidget:
        """Create and return the plugin widget."""
        return PluginWidget(parent_window)


# Export the plugin class
Plugin = ScrcpyToolkitPlugin
