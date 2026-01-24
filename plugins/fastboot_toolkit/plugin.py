"""
Fastboot Toolkit Plugin for Image Anarchy

Comprehensive Fastboot tools including:
- Device Info (getvar all)
- Flash Partitions
- Boot Image (temporary)
- Erase Partitions
- OEM Unlock/Lock
- Fetch Partitions
- Reboot Options
- Format Data
- Set Active Slot
"""

import os
import sys
import subprocess
import shutil
import struct
from typing import Optional, List
from datetime import datetime
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QComboBox,
    QPushButton, QLineEdit, QTextEdit, QListWidget, QListWidgetItem,
    QProgressBar, QFileDialog, QMessageBox, QAbstractItemView, QTabWidget,
    QFormLayout, QCheckBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QRadioButton, QButtonGroup, QScrollArea, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer


# =============================================================================
# VBMETA PATCHER - Inline implementation for self-contained plugin
# =============================================================================

AVB_MAGIC = b'AVB0'

class VbmetaPatcher:
    """
    Patches vbmeta images to disable dm-verity and/or AVB verification.
    
    This allows booting with modified system/boot partitions.
    Note: Bootloader must be unlocked to use patched vbmeta.
    """
    
    FLAG_DISABLE_VERITY = 0x01        # AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED
    FLAG_DISABLE_VERIFICATION = 0x02  # AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED
    FLAGS_OFFSET = 120  # Offset of flags field in vbmeta header
    
    def __init__(self, input_path: str):
        self.input_path = Path(input_path)
    
    def get_info(self) -> dict:
        """Get vbmeta info including current flags."""
        try:
            with open(self.input_path, 'rb') as f:
                data = f.read(256)  # Just need header
            
            if data[:4] != AVB_MAGIC:
                return {'valid': False, 'error': 'Invalid vbmeta magic'}
            
            flags = struct.unpack('>I', data[self.FLAGS_OFFSET:self.FLAGS_OFFSET+4])[0]
            
            return {
                'valid': True,
                'size': self.input_path.stat().st_size,
                'flags': flags,
                'verity_disabled': bool(flags & self.FLAG_DISABLE_VERITY),
                'verification_disabled': bool(flags & self.FLAG_DISABLE_VERIFICATION),
            }
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def patch(self, output_path: str, disable_verity: bool = False, 
              disable_verification: bool = False) -> tuple[bool, str]:
        """
        Patch vbmeta flags.
        
        Returns:
            (success, message)
        """
        if not disable_verity and not disable_verification:
            return False, "No patches selected"
        
        try:
            with open(self.input_path, 'rb') as f:
                data = bytearray(f.read())
            
            if data[:4] != AVB_MAGIC:
                return False, "Invalid vbmeta magic - not a valid vbmeta image"
            
            # Read current flags
            current_flags = struct.unpack('>I', data[self.FLAGS_OFFSET:self.FLAGS_OFFSET+4])[0]
            
            # Apply new flags
            new_flags = current_flags
            if disable_verity:
                new_flags |= self.FLAG_DISABLE_VERITY
            if disable_verification:
                new_flags |= self.FLAG_DISABLE_VERIFICATION
            
            # Write new flags
            data[self.FLAGS_OFFSET:self.FLAGS_OFFSET+4] = struct.pack('>I', new_flags)
            
            # Save patched vbmeta
            with open(output_path, 'wb') as f:
                f.write(data)
            
            changes = []
            if disable_verity:
                changes.append("verity disabled")
            if disable_verification:
                changes.append("verification disabled")
            
            return True, f"Patched: {', '.join(changes)} (flags: 0x{current_flags:02X} → 0x{new_flags:02X})"
            
        except Exception as e:
            return False, f"Patch failed: {e}"


def get_plugin_dir() -> str:
    """Get the directory where this plugin is installed."""
    return os.path.dirname(os.path.abspath(__file__))


def find_fastboot() -> Optional[str]:
    """Find Fastboot executable - checks plugin directory first for self-contained plugins."""
    plugin_dir = get_plugin_dir()
    
    # PRIORITY 1: Plugin's own bundled platform-tools (for Plugin Store downloads)
    plugin_fb_paths = [
        os.path.join(plugin_dir, "platform-tools", "fastboot.exe"),
        os.path.join(plugin_dir, "platform-tools", "fastboot"),
        os.path.join(plugin_dir, "fastboot.exe"),
        os.path.join(plugin_dir, "fastboot"),
    ]
    
    for path in plugin_fb_paths:
        if os.path.isfile(path):
            return path
    
    # PRIORITY 2: PyInstaller frozen exe bundled files
    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        app_dir = os.path.dirname(sys.executable)
        
        frozen_paths = [
            os.path.join(meipass, "platform-tools", "fastboot.exe"),
            os.path.join(meipass, "platform-tools", "fastboot"),
            os.path.join(app_dir, "platform-tools", "fastboot.exe"),
            os.path.join(app_dir, "platform-tools", "fastboot"),
        ]
        
        for path in frozen_paths:
            if os.path.isfile(path):
                return path
    else:
        # Development mode - check app root
        app_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        dev_paths = [
            os.path.join(app_dir, "platform-tools", "fastboot.exe"),
            os.path.join(app_dir, "platform-tools", "fastboot"),
        ]
        
        for path in dev_paths:
            if os.path.isfile(path):
                return path
    
    # PRIORITY 3: System PATH and common locations
    system_paths = [
        "fastboot", "fastboot.exe",
        os.path.join(os.environ.get("ANDROID_HOME", ""), "platform-tools", "fastboot"),
        os.path.join(os.environ.get("ANDROID_HOME", ""), "platform-tools", "fastboot.exe"),
        r"C:\platform-tools\fastboot.exe",
        r"C:\Android\platform-tools\fastboot.exe",
    ]
    
    for path in system_paths:
        if path and shutil.which(path):
            return shutil.which(path)
        if path and os.path.isfile(path):
            return path
    
    return None


def run_fastboot(args: List[str], device: Optional[str] = None, timeout: int = 60) -> tuple:
    """Run Fastboot command and return (success, output)."""
    fb_path = find_fastboot()
    if not fb_path:
        return False, "Fastboot not found"
    
    cmd = [fb_path]
    if device:
        cmd.extend(["-s", device])
    cmd.extend(args)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        # Fastboot often returns success info in stderr
        return result.returncode == 0 or "OKAY" in output or "Finished" in output, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


class FastbootWorkerThread(QThread):
    """Worker thread for Fastboot operations."""
    progress = pyqtSignal(int, int, str)
    log = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)
    result_data = pyqtSignal(object)
    
    def __init__(self, operation: str, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
        self._cancelled = False
        self.fb_path = find_fastboot()
    
    def cancel(self):
        self._cancelled = True
    
    def run(self):
        if not self.fb_path:
            self.finished_signal.emit(False, "Fastboot not found. Please ensure platform-tools is available.")
            return
        
        try:
            if self.operation == "list_devices":
                self._list_devices()
            elif self.operation == "device_info":
                self._get_device_info()
            elif self.operation == "flash":
                self._flash_partition()
            elif self.operation == "boot":
                self._boot_image()
            elif self.operation == "erase":
                self._erase_partition()
            elif self.operation == "fetch":
                self._fetch_partition()
            elif self.operation == "oem_unlock":
                self._oem_unlock()
            elif self.operation == "oem_lock":
                self._oem_lock()
            elif self.operation == "flashing_unlock":
                self._flashing_unlock()
            elif self.operation == "flashing_lock":
                self._flashing_lock()
            elif self.operation == "set_active":
                self._set_active_slot()
            elif self.operation == "format":
                self._format_partition()
            elif self.operation == "reboot":
                self._reboot()
            elif self.operation == "getvar":
                self._getvar()
            elif self.operation == "list_partitions":
                self._list_partitions()
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.finished_signal.emit(False, str(e))
    
    def _list_partitions(self):
        """List partitions using getvar all - extracts partition info."""
        device = self.kwargs.get('device')
        lg_safe = self.kwargs.get('lg_safe', False)
        
        partitions = []
        seen = set()
        
        if lg_safe:
            # LG Safe Mode: Provide common partition names without querying
            # This avoids 'getvar all' which causes LG devices to reboot
            common_partitions = [
                'boot', 'boot_a', 'boot_b', 'recovery', 'system', 'system_a', 'system_b',
                'vendor', 'vendor_a', 'vendor_b', 'userdata', 'cache', 'dtbo', 'dtbo_a', 'dtbo_b',
                'vbmeta', 'vbmeta_a', 'vbmeta_b', 'abl', 'abl_a', 'abl_b', 'xbl', 'xbl_a', 'xbl_b',
                'modem', 'modem_a', 'modem_b', 'super', 'laf', 'laf_a', 'laf_b'
            ]
            for p in common_partitions:
                partitions.append({'name': p, 'size': '(LG Safe Mode)', 'size_bytes': 0})
            
            self.result_data.emit(partitions)
            self.finished_signal.emit(True, f"Common partitions listed (LG Safe Mode - no query)")
            return
        
        success, output = run_fastboot(["getvar", "all"], device, timeout=30)
        
        # Parse getvar all output for partition info
        # Formats vary by device but common patterns:
        # (bootloader) partition-size:boot: 0x4000000
        # (bootloader) partition-type:boot: raw
        # partition-size:boot_a: 0x6000000
        for line in output.split('\n'):
            line = line.replace('(bootloader)', '').strip()
            
            # Look for partition-size entries
            if 'partition-size:' in line.lower():
                try:
                    # Extract partition name and size
                    parts = line.split(':')
                    if len(parts) >= 2:
                        part_name = parts[1].strip()
                        size_hex = parts[2].strip() if len(parts) > 2 else '0'
                        
                        if part_name and part_name not in seen:
                            seen.add(part_name)
                            # Convert hex size to human readable
                            try:
                                size_bytes = int(size_hex, 16)
                                if size_bytes >= 1024*1024*1024:
                                    size_str = f"{size_bytes / (1024*1024*1024):.1f} GB"
                                elif size_bytes >= 1024*1024:
                                    size_str = f"{size_bytes / (1024*1024):.1f} MB"
                                elif size_bytes >= 1024:
                                    size_str = f"{size_bytes / 1024:.1f} KB"
                                else:
                                    size_str = f"{size_bytes} B"
                            except:
                                size_str = size_hex
                            
                            partitions.append({
                                'name': part_name,
                                'size': size_str,
                                'size_bytes': size_bytes if 'size_bytes' in dir() else 0
                            })
                except:
                    continue
            
            # Also check for has-slot entries to find A/B partitions
            elif 'has-slot:' in line.lower():
                try:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        part_name = parts[1].strip()
                        if part_name and part_name not in seen and parts[-1].strip().lower() == 'yes':
                            # This partition has slots, add _a and _b versions if not already present
                            for suffix in ['_a', '_b']:
                                slot_name = part_name + suffix
                                if slot_name not in seen:
                                    seen.add(slot_name)
                                    partitions.append({'name': slot_name, 'size': 'A/B slot', 'size_bytes': 0})
                except:
                    continue
        
        # Sort by name
        partitions.sort(key=lambda x: x['name'])
        
        self.result_data.emit(partitions)
        self.finished_signal.emit(True, f"Found {len(partitions)} partitions")
    
    def _list_devices(self):
        lg_safe = self.kwargs.get('lg_safe', False)
        
        # LG Safe Mode: Use simple 'fastboot devices' without -l flag
        # The -l flag can cause issues on some devices
        if lg_safe:
            success, output = run_fastboot(["devices"], timeout=10)
        else:
            success, output = run_fastboot(["devices", "-l"], timeout=10)
        
        devices = []
        for line in output.strip().split('\n'):
            if line.strip() and ('fastboot' in line.lower() or '\t' in line):
                parts = line.split()
                if len(parts) >= 1:
                    serial = parts[0]
                    # Check it's not an error message
                    if serial and not serial.startswith('*') and not serial.lower().startswith('error'):
                        devices.append({'serial': serial, 'state': 'fastboot'})
        
        self.result_data.emit(devices)
        self.finished_signal.emit(True, f"Found {len(devices)} device(s) in fastboot")
    
    def _get_device_info(self):
        device = self.kwargs.get('device')
        lg_safe = self.kwargs.get('lg_safe', False)
        
        info = {}
        
        if lg_safe:
            # LG Safe Mode: Query individual variables instead of 'getvar all'
            # 'getvar all' causes LG devices to reboot!
            safe_vars = [
                'product', 'serialno', 'secure', 'unlocked', 
                'variant', 'slot-count', 'current-slot'
            ]
            for var in safe_vars:
                success, output = run_fastboot(["getvar", var], device, timeout=5)
                if success:
                    for line in output.split('\n'):
                        if ':' in line and var in line.lower():
                            line = line.replace('(bootloader)', '').strip()
                            key, _, value = line.partition(':')
                            value = value.strip()
                            if value and value not in ['OKAY', 'Finished']:
                                info[var] = value
                                break
            
            self.result_data.emit(info)
            self.finished_signal.emit(True, f"Device info retrieved (LG Safe Mode - {len(info)} vars)")
        else:
            # Normal mode: use getvar all
            success, output = run_fastboot(["getvar", "all"], device, timeout=30)
            
            for line in output.split('\n'):
                if ':' in line and line.startswith('(bootloader)') or ':' in line:
                    line = line.replace('(bootloader)', '').strip()
                    if ':' in line:
                        key, _, value = line.partition(':')
                        key = key.strip()
                        value = value.strip()
                        if key and value and key not in ['OKAY', 'Finished']:
                            info[key] = value
            
            self.result_data.emit(info)
            self.finished_signal.emit(True, "Device info retrieved")
    
    def _flash_partition(self):
        device = self.kwargs.get('device')
        partition = self.kwargs.get('partition')
        image_path = self.kwargs.get('image_path')
        
        if not os.path.exists(image_path):
            self.finished_signal.emit(False, f"Image not found: {image_path}")
            return
        
        self.log.emit(f"Flashing {partition}...")
        self.progress.emit(0, 100, f"Flashing {partition}...")
        
        success, output = run_fastboot(["flash", partition, image_path], device, timeout=300)
        
        self.progress.emit(100, 100, "Done")
        if success or "OKAY" in output:
            self.log.emit(f"✓ {partition} flashed successfully")
            self.finished_signal.emit(True, f"Flashed {partition}")
        else:
            self.log.emit(f"✗ Failed: {output}")
            self.finished_signal.emit(False, output)
    
    def _boot_image(self):
        device = self.kwargs.get('device')
        image_path = self.kwargs.get('image_path')
        
        if not os.path.exists(image_path):
            self.finished_signal.emit(False, f"Image not found: {image_path}")
            return
        
        self.log.emit(f"Booting {os.path.basename(image_path)}...")
        
        success, output = run_fastboot(["boot", image_path], device, timeout=120)
        
        if success or "OKAY" in output:
            self.log.emit("✓ Boot image sent, device should be booting...")
            self.finished_signal.emit(True, "Booted")
        else:
            self.finished_signal.emit(False, output)
    
    def _erase_partition(self):
        device = self.kwargs.get('device')
        partition = self.kwargs.get('partition')
        
        self.log.emit(f"Erasing {partition}...")
        
        success, output = run_fastboot(["erase", partition], device, timeout=60)
        
        if success or "OKAY" in output:
            self.log.emit(f"✓ {partition} erased")
            self.finished_signal.emit(True, f"Erased {partition}")
        else:
            self.finished_signal.emit(False, output)
    
    def _fetch_partition(self):
        device = self.kwargs.get('device')
        partition = self.kwargs.get('partition')
        output_path = self.kwargs.get('output_path')
        
        self.log.emit(f"Fetching {partition}...")
        self.progress.emit(0, 100, f"Fetching {partition}...")
        
        success, output = run_fastboot(["fetch", partition, output_path], device, timeout=300)
        
        self.progress.emit(100, 100, "Done")
        
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            size = os.path.getsize(output_path)
            size_str = f"{size / (1024*1024):.1f} MB"
            self.log.emit(f"✓ {partition} saved ({size_str})")
            self.finished_signal.emit(True, output_path)
        else:
            # Fetch might not be supported, try alternative
            self.log.emit("Fetch not supported, try using ADB in recovery mode")
            self.finished_signal.emit(False, "Fetch not supported on this device")
    
    def _oem_unlock(self):
        device = self.kwargs.get('device')
        
        self.log.emit("Sending OEM unlock command...")
        success, output = run_fastboot(["oem", "unlock"], device, timeout=30)
        
        if success or "OKAY" in output:
            self.log.emit("✓ OEM unlock command sent")
            self.log.emit("Check device screen to confirm unlock")
            self.finished_signal.emit(True, "OEM unlock sent")
        else:
            self.finished_signal.emit(False, output)
    
    def _oem_lock(self):
        device = self.kwargs.get('device')
        
        self.log.emit("Sending OEM lock command...")
        success, output = run_fastboot(["oem", "lock"], device, timeout=30)
        
        if success or "OKAY" in output:
            self.log.emit("✓ OEM lock command sent")
            self.finished_signal.emit(True, "OEM locked")
        else:
            self.finished_signal.emit(False, output)
    
    def _flashing_unlock(self):
        device = self.kwargs.get('device')
        
        self.log.emit("Sending flashing unlock command...")
        success, output = run_fastboot(["flashing", "unlock"], device, timeout=30)
        
        if success or "OKAY" in output:
            self.log.emit("✓ Flashing unlock command sent")
            self.log.emit("Check device screen to confirm")
            self.finished_signal.emit(True, "Flashing unlock sent")
        else:
            self.finished_signal.emit(False, output)
    
    def _flashing_lock(self):
        device = self.kwargs.get('device')
        
        self.log.emit("Sending flashing lock command...")
        success, output = run_fastboot(["flashing", "lock"], device, timeout=30)
        
        if success or "OKAY" in output:
            self.log.emit("✓ Bootloader locked")
            self.finished_signal.emit(True, "Bootloader locked")
        else:
            self.finished_signal.emit(False, output)
    
    def _set_active_slot(self):
        device = self.kwargs.get('device')
        slot = self.kwargs.get('slot')
        
        self.log.emit(f"Setting active slot to {slot}...")
        success, output = run_fastboot(["set_active", slot], device)
        
        if success or "OKAY" in output:
            self.log.emit(f"✓ Active slot set to {slot}")
            self.finished_signal.emit(True, f"Active: {slot}")
        else:
            self.finished_signal.emit(False, output)
    
    def _format_partition(self):
        device = self.kwargs.get('device')
        partition = self.kwargs.get('partition')
        fs_type = self.kwargs.get('fs_type', 'ext4')
        
        self.log.emit(f"Formatting {partition} as {fs_type}...")
        success, output = run_fastboot(["format", f"{partition}:{fs_type}"], device, timeout=120)
        
        if success or "OKAY" in output:
            self.log.emit(f"✓ {partition} formatted")
            self.finished_signal.emit(True, f"Formatted {partition}")
        else:
            self.finished_signal.emit(False, output)
    
    def _reboot(self):
        device = self.kwargs.get('device')
        mode = self.kwargs.get('mode', '')
        
        self.log.emit(f"Rebooting{' to ' + mode if mode else ''}...")
        
        if mode == 'bootloader':
            success, output = run_fastboot(["reboot-bootloader"], device)
        elif mode == 'fastbootd':
            success, output = run_fastboot(["reboot-fastboot"], device)
        elif mode == 'recovery':
            success, output = run_fastboot(["reboot-recovery"], device)
        elif mode == 'edl':
            success, output = run_fastboot(["oem", "edl"], device)
        else:
            success, output = run_fastboot(["reboot"], device)
        
        self.finished_signal.emit(True, f"Rebooting{' to ' + mode if mode else ''}")
    
    def _getvar(self):
        device = self.kwargs.get('device')
        var = self.kwargs.get('var', 'all')
        
        success, output = run_fastboot(["getvar", var], device)
        self.result_data.emit(output)
        self.finished_signal.emit(success, output)


class FastbootToolkitPlugin:
    """Comprehensive Fastboot Toolkit Plugin."""
    
    def __init__(self):
        self.manifest = None
        self.parent_window = None
        self.current_device = None
        self.devices = []
        self.worker = None
    
    def get_name(self) -> str:
        return self.manifest.name if self.manifest else "Fastboot Toolkit"
    
    def get_icon(self) -> str:
        return self.manifest.icon if self.manifest else "⚡"
    
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
        
        # Warning banner
        warning = QLabel("⚠️ Fastboot operations can brick your device. Proceed with caution!")
        warning.setStyleSheet("background: #442200; color: #ffaa00; padding: 8px; border-radius: 4px;")
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(warning)
        
        # LG Safe Mode checkbox (LG devices reboot on certain fastboot commands)
        self.lg_safe_mode = QCheckBox("🛡️ LG Safe Mode (prevents reboots on LG/quirky devices)")
        self.lg_safe_mode.setToolTip(
            "Enable this for LG devices that randomly reboot when using fastboot.\n"
            "LG's fastboot implementation is buggy and reboots on 'getvar all' and other commands.\n"
            "Safe mode uses minimal commands to avoid triggering reboots."
        )
        self.lg_safe_mode.setStyleSheet("color: #88ccff; padding: 4px;")
        main_layout.addWidget(self.lg_safe_mode)
        
        # Device Selection
        device_group = QGroupBox("Device (Fastboot Mode)")
        device_layout = QHBoxLayout(device_group)
        
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(300)
        device_layout.addWidget(QLabel("Device:"))
        device_layout.addWidget(self.device_combo, 1)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_devices)
        device_layout.addWidget(refresh_btn)
        
        self.device_status = QLabel("No device in fastboot")
        self.device_status.setStyleSheet("color: #888;")
        device_layout.addWidget(self.device_status)
        
        main_layout.addWidget(device_group)
        
        # Tools Tabs
        self.tabs = QTabWidget()
        
        self.tabs.addTab(self._create_info_tab(), "📋 Info")
        self.tabs.addTab(self._create_flash_tab(), "⚡ Flash")
        self.tabs.addTab(self._create_boot_tab(), "🚀 Boot")
        self.tabs.addTab(self._create_fetch_tab(), "📥 Fetch")
        self.tabs.addTab(self._create_erase_tab(), "🗑️ Erase")
        self.tabs.addTab(self._create_patch_tab(), "🔧 Patch")
        self.tabs.addTab(self._create_oem_tab(), "🔓 OEM")
        self.tabs.addTab(self._create_slot_tab(), "🔀 Slot")
        self.tabs.addTab(self._create_reboot_tab(), "🔄 Reboot")
        
        main_layout.addWidget(self.tabs)
        
        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(120)
        self.log_output.setStyleSheet("font-family: Consolas; font-size: 11px;")
        main_layout.addWidget(self.log_output)
        
        # Initial device scan (with delay, and no auto-scan to avoid LG issues)
        # User must click refresh manually to be safe for LG devices
        self._log("Click 'Refresh' to scan for fastboot devices")
        
        return main_widget
    
    def _log(self, msg: str):
        self.log_output.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        self.log_output.verticalScrollBar().setValue(self.log_output.verticalScrollBar().maximum())
    
    def _refresh_devices(self):
        lg_safe = self.lg_safe_mode.isChecked()
        self._log(f"Scanning for fastboot devices...{' (LG Safe Mode)' if lg_safe else ''}")
        self.worker = FastbootWorkerThread("list_devices", lg_safe=lg_safe)
        self.worker.result_data.connect(self._on_devices_found)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _on_devices_found(self, devices):
        self.devices = devices
        self.device_combo.clear()
        
        if not devices:
            self.device_combo.addItem("No fastboot devices found")
            self.device_status.setText("Boot to bootloader with: adb reboot bootloader")
            self.device_status.setStyleSheet("color: #f84;")
        else:
            for dev in devices:
                self.device_combo.addItem(f"{dev['serial']} (fastboot)", dev['serial'])
            self.device_status.setText("✓ Connected")
            self.device_status.setStyleSheet("color: #4f4;")
    
    def _get_device(self):
        if not self.devices:
            return None
        return self.device_combo.currentData()
    
    # ===== INFO TAB =====
    def _create_info_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.info_table = QTableWidget()
        self.info_table.setColumnCount(2)
        self.info_table.setHorizontalHeaderLabels(["Variable", "Value"])
        self.info_table.horizontalHeader().setStretchLastSection(True)
        self.info_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.info_table)
        
        btn = QPushButton("🔄 Get Device Info (getvar all)")
        btn.setToolTip("Use LG Safe Mode checkbox if your device reboots when clicking this")
        btn.clicked.connect(self._get_info)
        layout.addWidget(btn)
        
        return tab
    
    def _get_info(self):
        device = self._get_device()
        if not device:
            return
        
        lg_safe = self.lg_safe_mode.isChecked()
        self._log(f"Getting device variables...{' (LG Safe Mode)' if lg_safe else ''}")
        self.worker = FastbootWorkerThread("device_info", device=device, lg_safe=lg_safe)
        self.worker.result_data.connect(self._on_info_received)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _on_info_received(self, info: dict):
        self.info_table.setRowCount(len(info))
        for i, (key, value) in enumerate(sorted(info.items())):
            self.info_table.setItem(i, 0, QTableWidgetItem(key))
            self.info_table.setItem(i, 1, QTableWidgetItem(str(value)))
    
    # ===== FLASH TAB =====
    def _create_flash_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Quick flash presets
        presets_group = QGroupBox("Quick Flash")
        presets_layout = QVBoxLayout(presets_group)
        
        preset_row1 = QHBoxLayout()
        for name, partition in [("Boot", "boot"), ("Recovery", "recovery"), ("Vendor Boot", "vendor_boot")]:
            btn = QPushButton(f"⚡ {name}")
            btn.clicked.connect(lambda c, p=partition: self._quick_flash(p))
            preset_row1.addWidget(btn)
        presets_layout.addLayout(preset_row1)
        
        preset_row2 = QHBoxLayout()
        for name, partition in [("DTBO", "dtbo"), ("Vbmeta", "vbmeta"), ("Init Boot", "init_boot")]:
            btn = QPushButton(f"⚡ {name}")
            btn.clicked.connect(lambda c, p=partition: self._quick_flash(p))
            preset_row2.addWidget(btn)
        presets_layout.addLayout(preset_row2)
        
        layout.addWidget(presets_group)
        
        # Custom flash
        custom_group = QGroupBox("Custom Flash")
        custom_layout = QFormLayout(custom_group)
        
        self.flash_partition = QLineEdit()
        self.flash_partition.setPlaceholderText("e.g., boot, recovery, vbmeta")
        custom_layout.addRow("Partition:", self.flash_partition)
        
        self.flash_image = QLineEdit()
        flash_browse = QPushButton("Browse...")
        flash_browse.clicked.connect(lambda: self._browse_file(self.flash_image, "Image Files (*.img)"))
        flash_row = QHBoxLayout()
        flash_row.addWidget(self.flash_image)
        flash_row.addWidget(flash_browse)
        custom_layout.addRow("Image:", flash_row)
        
        self.flash_progress = QProgressBar()
        custom_layout.addRow("Progress:", self.flash_progress)
        
        flash_btn = QPushButton("⚡ Flash Partition")
        flash_btn.setStyleSheet("background: #c62828; font-weight: bold;")
        flash_btn.clicked.connect(self._flash_partition)
        custom_layout.addRow("", flash_btn)
        
        layout.addWidget(custom_group)
        layout.addStretch()
        
        return tab
    
    def _quick_flash(self, partition):
        path, _ = QFileDialog.getOpenFileName(
            self.parent_window, f"Select {partition}.img", "", "Image Files (*.img)"
        )
        if path:
            self.flash_partition.setText(partition)
            self.flash_image.setText(path)
            self._flash_partition()
    
    def _flash_partition(self):
        device = self._get_device()
        partition = self.flash_partition.text()
        image = self.flash_image.text()
        
        if not device or not partition or not image:
            QMessageBox.warning(self.parent_window, "Error", "Device, partition, and image are required")
            return
        
        reply = QMessageBox.question(
            self.parent_window, "Confirm Flash",
            f"Flash {partition} with:\n{os.path.basename(image)}\n\nThis cannot be undone!"
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = FastbootWorkerThread("flash", device=device, partition=partition, image_path=image)
        self.worker.log.connect(self._log)
        self.worker.progress.connect(lambda c, t, m: self.flash_progress.setValue(c))
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== BOOT TAB =====
    def _create_boot_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        layout.addWidget(QLabel("Boot an image without flashing (temporary).\nDevice will return to normal on reboot."))
        
        boot_group = QGroupBox("Boot Image")
        boot_layout = QFormLayout(boot_group)
        
        self.boot_image = QLineEdit()
        boot_browse = QPushButton("Browse...")
        boot_browse.clicked.connect(lambda: self._browse_file(self.boot_image, "Image Files (*.img)"))
        boot_row = QHBoxLayout()
        boot_row.addWidget(self.boot_image)
        boot_row.addWidget(boot_browse)
        boot_layout.addRow("Image:", boot_row)
        
        boot_btn = QPushButton("🚀 Boot Image")
        boot_btn.setStyleSheet("background: #1565c0; font-weight: bold;")
        boot_btn.clicked.connect(self._boot_image)
        boot_layout.addRow("", boot_btn)
        
        layout.addWidget(boot_group)
        
        # Common boot images info
        info = QLabel(
            "Common uses:\n"
            "• Boot patched boot.img to test Magisk root\n"
            "• Boot TWRP recovery without installing\n"
            "• Boot custom kernels for testing\n"
            "• Boot LineageOS recovery for sideloading"
        )
        info.setStyleSheet("color: #888; padding: 10px;")
        layout.addWidget(info)
        
        layout.addStretch()
        return tab
    
    def _boot_image(self):
        device = self._get_device()
        image = self.boot_image.text()
        
        if not device or not image:
            return
        
        self.worker = FastbootWorkerThread("boot", device=device, image_path=image)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== FETCH TAB =====
    def _create_fetch_tab(self):
        tab = QWidget()
        main_layout = QVBoxLayout(tab)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Use scroll area for content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        
        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        layout.setSpacing(8)
        
        layout.addWidget(QLabel("Download partition images from device (requires unlocked bootloader)"))
        
        # Partition list from device
        list_group = QGroupBox("Device Partitions")
        list_layout = QVBoxLayout(list_group)
        
        self.fb_partition_list = QListWidget()
        self.fb_partition_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.fb_partition_list.setMinimumHeight(100)
        self.fb_partition_list.setMaximumHeight(150)
        self.fb_partition_list.itemDoubleClicked.connect(self._on_partition_double_click)
        list_layout.addWidget(self.fb_partition_list)
        
        list_btn_row = QHBoxLayout()
        list_refresh_btn = QPushButton("🔄 List Partitions")
        list_refresh_btn.clicked.connect(self._list_partitions)
        list_btn_row.addWidget(list_refresh_btn)
        
        fetch_selected_btn = QPushButton("📥 Fetch Selected")
        fetch_selected_btn.clicked.connect(self._fetch_selected_partitions)
        list_btn_row.addWidget(fetch_selected_btn)
        list_btn_row.addStretch()
        list_layout.addLayout(list_btn_row)
        
        layout.addWidget(list_group)
        
        # Manual fetch section
        self._fetch_group = QGroupBox("Manual Fetch")
        fetch_layout = QVBoxLayout(self._fetch_group)
        
        # Partition input row
        part_row = QHBoxLayout()
        part_row.addWidget(QLabel("Partition:"))
        self.fetch_partition = QLineEdit()
        self.fetch_partition.setPlaceholderText("e.g., boot, recovery, vbmeta")
        part_row.addWidget(self.fetch_partition)
        fetch_layout.addLayout(part_row)
        
        # Output row (will be hidden when setup directories active)
        self._fetch_output_row = QWidget()
        output_row_layout = QHBoxLayout(self._fetch_output_row)
        output_row_layout.setContentsMargins(0, 0, 0, 0)
        output_row_layout.addWidget(QLabel("Output Dir:"))
        self.fetch_output = QLineEdit(os.path.expanduser("~"))
        output_row_layout.addWidget(self.fetch_output)
        fetch_browse = QPushButton("Browse...")
        fetch_browse.clicked.connect(lambda: self._browse_dir(self.fetch_output))
        output_row_layout.addWidget(fetch_browse)
        fetch_layout.addWidget(self._fetch_output_row)
        
        # Setup directories indicator (hidden by default)
        self._fb_setup_indicator = QLabel()
        self._fb_setup_indicator.setStyleSheet("background: #2e7d32; color: white; padding: 8px; border-radius: 4px;")
        self._fb_setup_indicator.setVisible(False)
        fetch_layout.addWidget(self._fb_setup_indicator)
        
        # Progress bar
        progress_row = QHBoxLayout()
        progress_row.addWidget(QLabel("Progress:"))
        self.fetch_progress = QProgressBar()
        progress_row.addWidget(self.fetch_progress)
        fetch_layout.addLayout(progress_row)
        
        fetch_btn = QPushButton("📥 Fetch Partition")
        fetch_btn.clicked.connect(self._fetch_partition)
        fetch_layout.addWidget(fetch_btn)
        
        layout.addWidget(self._fetch_group)
        
        # Quick fetch
        quick_group = QGroupBox("Quick Fetch")
        quick_layout = QHBoxLayout(quick_group)
        for part in ["boot", "recovery", "vbmeta", "dtbo"]:
            btn = QPushButton(f"📥 {part}")
            btn.clicked.connect(lambda c, p=part: self._quick_fetch(p))
            quick_layout.addWidget(btn)
        layout.addWidget(quick_group)
        
        # Setup Directories - creates folders for common partitions
        setup_group = QGroupBox("Setup Directories")
        setup_layout = QVBoxLayout(setup_group)
        setup_layout.addWidget(QLabel("Create folders for each partition in a selected directory."))
        
        setup_btn_row = QHBoxLayout()
        self.setup_dirs_btn = QPushButton("📁 Setup Directories (Common)")
        self.setup_dirs_btn.setToolTip("Create folders for common Android partitions")
        self.setup_dirs_btn.clicked.connect(self._setup_partition_directories)
        setup_btn_row.addWidget(self.setup_dirs_btn)
        
        self.setup_dirs_device_btn = QPushButton("📁 Setup Directories (From Device)")
        self.setup_dirs_device_btn.setToolTip("Create folders based on partitions detected from device")
        self.setup_dirs_device_btn.clicked.connect(self._setup_device_partition_directories)
        self.setup_dirs_device_btn.setEnabled(False)
        setup_btn_row.addWidget(self.setup_dirs_device_btn)
        
        self._fb_clear_setup_btn = QPushButton("✕ Clear Setup")
        self._fb_clear_setup_btn.setToolTip("Return to manual output directory mode")
        self._fb_clear_setup_btn.clicked.connect(self._clear_fb_setup_directories)
        self._fb_clear_setup_btn.setVisible(False)
        setup_btn_row.addWidget(self._fb_clear_setup_btn)
        
        setup_layout.addLayout(setup_btn_row)
        layout.addWidget(setup_group)
        
        # Initialize setup directories base path
        self._fb_setup_base_dir = None
        
        layout.addStretch()
        
        scroll.setWidget(scroll_content)
        main_layout.addWidget(scroll)
        return tab
    
    def _list_partitions(self):
        """List partitions from device using getvar all."""
        device = self._get_device()
        if not device:
            QMessageBox.warning(self.parent_window, "Error", "No device connected in fastboot mode")
            return
        
        lg_safe = self.lg_safe_mode.isChecked()
        self._log(f"Listing partitions from device...{' (LG Safe Mode)' if lg_safe else ''}")
        self.worker = FastbootWorkerThread("list_partitions", device=device, lg_safe=lg_safe)
        self.worker.result_data.connect(self._on_partitions_found)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _on_partitions_found(self, partitions):
        """Handle partition list results."""
        self.fb_partition_list.clear()
        self._fb_loaded_partitions = partitions  # Store for Setup Directories
        
        for p in partitions:
            item = QListWidgetItem(f"{p['name']} ({p['size']})")
            item.setData(Qt.ItemDataRole.UserRole, p)
            self.fb_partition_list.addItem(item)
        
        # Enable device-based Setup Directories button
        if hasattr(self, 'setup_dirs_device_btn'):
            self.setup_dirs_device_btn.setEnabled(len(partitions) > 0)
    
    def _on_partition_double_click(self, item):
        """Double-click partition to fill in fetch field."""
        data = item.data(Qt.ItemDataRole.UserRole)
        if data:
            self.fetch_partition.setText(data['name'])
    
    def _fetch_selected_partitions(self):
        """Fetch all selected partitions."""
        device = self._get_device()
        if not device:
            return
        
        selected = self.fb_partition_list.selectedItems()
        if not selected:
            QMessageBox.warning(self.parent_window, "Error", "Select partitions first")
            return
        
        # Fetch first selected - set the partition name and let _fetch_partition handle directory logic
        data = selected[0].data(Qt.ItemDataRole.UserRole)
        self.fetch_partition.setText(data['name'])
        self._fetch_partition()
    
    def _setup_device_partition_directories(self):
        """Create directories for partitions detected from device."""
        if not hasattr(self, '_fb_loaded_partitions') or not self._fb_loaded_partitions:
            QMessageBox.warning(self.parent_window, "No Partitions", 
                "No partitions loaded. Please list partitions first.")
            return
        
        base_dir = QFileDialog.getExistingDirectory(
            self.parent_window,
            "Select Base Directory for Partition Folders",
            os.path.expanduser("~"),
            QFileDialog.Option.ShowDirsOnly
        )
        
        if not base_dir:
            return
        
        created = []
        errors = []
        for partition in self._fb_loaded_partitions:
            part_name = partition['name']
            part_dir = os.path.join(base_dir, part_name)
            try:
                os.makedirs(part_dir, exist_ok=True)
                created.append(part_name)
            except Exception as e:
                errors.append(f"{part_name}: {str(e)}")
        
        if created:
            self._log(f"✓ Created {len(created)} partition directories in {base_dir}")
            
            # Activate setup directories mode
            self._fb_setup_base_dir = base_dir
            self._fetch_output_row.setVisible(False)
            self._fb_setup_indicator.setText(f"📁 Setup Active: {base_dir}\n   Each partition will be saved to its own folder")
            self._fb_setup_indicator.setVisible(True)
            self._fb_clear_setup_btn.setVisible(True)
            self.setup_dirs_btn.setEnabled(False)
            self.setup_dirs_device_btn.setEnabled(False)
            
            msg = f"✓ Setup Directories Active!\\n\\n"
            msg += f"📁 Base: {base_dir}\\n"
            msg += f"   Created {len(created)} folders\\n\\n"
            msg += "Partitions will now be fetched to their own folders:\\n"
            msg += f"   • boot → {base_dir}/boot/boot.img\\n"
            msg += f"   • recovery → {base_dir}/recovery/recovery.img\\n"
            msg += "   etc..."
            
            if errors:
                msg += f"\\n\\n⚠️ {len(errors)} errors:\\n" + "\\n".join(errors[:5])
            
            QMessageBox.information(self.parent_window, "Setup Directories Active", msg)
        elif errors:
            QMessageBox.warning(self.parent_window, "Error", 
                f"Failed to create directories:\\n" + "\\n".join(errors[:10]))
    
    def _clear_fb_setup_directories(self):
        """Clear setup directories mode and return to manual output."""
        self._fb_setup_base_dir = None
        self._fetch_output_row.setVisible(True)
        self._fb_setup_indicator.setVisible(False)
        self._fb_clear_setup_btn.setVisible(False)
        self.setup_dirs_btn.setEnabled(True)
        if hasattr(self, '_fb_loaded_partitions') and self._fb_loaded_partitions:
            self.setup_dirs_device_btn.setEnabled(True)
        self._log("Setup Directories mode cleared - using manual output directory")
    
    def _quick_fetch(self, partition):
        self.fetch_partition.setText(partition)
        self._fetch_partition()
    
    def _setup_partition_directories(self):
        """Create a directory for each common partition in a user-selected folder."""
        # Common Android partitions that users typically work with
        common_partitions = [
            "boot", "boot_a", "boot_b",
            "init_boot", "init_boot_a", "init_boot_b",
            "recovery", "recovery_a", "recovery_b",
            "vendor_boot", "vendor_boot_a", "vendor_boot_b",
            "vbmeta", "vbmeta_a", "vbmeta_b",
            "vbmeta_system", "vbmeta_system_a", "vbmeta_system_b",
            "dtbo", "dtbo_a", "dtbo_b",
            "super", "system", "system_a", "system_b",
            "vendor", "vendor_a", "vendor_b",
            "product", "product_a", "product_b",
            "odm", "odm_a", "odm_b",
            "system_ext", "system_ext_a", "system_ext_b",
            "cache", "userdata", "metadata", "persist",
            "modem", "modem_a", "modem_b",
            "abl", "abl_a", "abl_b",
            "xbl", "xbl_a", "xbl_b",
            "tz", "tz_a", "tz_b",
            "hyp", "hyp_a", "hyp_b",
            "keymaster", "keymaster_a", "keymaster_b",
            "cmnlib", "cmnlib_a", "cmnlib_b",
            "devcfg", "devcfg_a", "devcfg_b",
            "dsp", "dsp_a", "dsp_b",
            "bluetooth", "bluetooth_a", "bluetooth_b",
            "logo", "splash", "misc", "frp"
        ]
        
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
        for part_name in common_partitions:
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
            self._fb_setup_base_dir = base_dir
            self._fetch_output_row.setVisible(False)
            self._fb_setup_indicator.setText(f"📁 Setup Active: {base_dir}\\n   Each partition will be saved to its own folder")
            self._fb_setup_indicator.setVisible(True)
            self._fb_clear_setup_btn.setVisible(True)
            self.setup_dirs_btn.setEnabled(False)
            self.setup_dirs_device_btn.setEnabled(False)
            
            msg = f"✓ Setup Directories Active!\\n\\n"
            msg += f"📁 Base: {base_dir}\\n"
            msg += f"   Created {len(created)} folders\\n\\n"
            msg += "Partitions will now be fetched to their own folders:\\n"
            msg += f"   • boot → {base_dir}/boot/boot.img\\n"
            msg += f"   • recovery → {base_dir}/recovery/recovery.img\\n"
            msg += "   etc..."
            
            if errors:
                msg += f"\\n\\n⚠️ {len(errors)} errors:\\n" + "\\n".join(errors[:5])
            
            QMessageBox.information(self.parent_window, "Setup Directories Active", msg)
        elif errors:
            QMessageBox.warning(self.parent_window, "Error", 
                f"Failed to create directories:\\n" + "\\n".join(errors[:10]))
    
    def _fetch_partition(self):
        device = self._get_device()
        partition = self.fetch_partition.text()
        
        if not device or not partition:
            return
        
        # Determine output directory based on setup mode
        if hasattr(self, '_fb_setup_base_dir') and self._fb_setup_base_dir:
            # Setup directories mode - each partition goes to its own folder
            output_dir = os.path.join(self._fb_setup_base_dir, partition)
            os.makedirs(output_dir, exist_ok=True)
        else:
            # Manual output directory mode
            output_dir = self.fetch_output.text()
            os.makedirs(output_dir, exist_ok=True)
        
        output_path = os.path.join(output_dir, f"{partition}.img")
        
        self.worker = FastbootWorkerThread("fetch", device=device, partition=partition, output_path=output_path)
        self.worker.log.connect(self._log)
        self.worker.progress.connect(lambda c, t, m: self.fetch_progress.setValue(c))
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== ERASE TAB =====
    def _create_erase_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        warning = QLabel("⚠️ DANGER: Erasing partitions can make your device unbootable!")
        warning.setStyleSheet("color: #ff4444; font-weight: bold;")
        layout.addWidget(warning)
        
        erase_group = QGroupBox("Erase Partition")
        erase_layout = QFormLayout(erase_group)
        
        self.erase_partition = QLineEdit()
        self.erase_partition.setPlaceholderText("e.g., userdata, cache")
        erase_layout.addRow("Partition:", self.erase_partition)
        
        erase_btn = QPushButton("🗑️ Erase Partition")
        erase_btn.setStyleSheet("background: #b71c1c; font-weight: bold;")
        erase_btn.clicked.connect(self._erase_partition)
        erase_layout.addRow("", erase_btn)
        
        layout.addWidget(erase_group)
        
        # Format data
        format_group = QGroupBox("Format Data (Factory Reset)")
        format_layout = QVBoxLayout(format_group)
        
        format_btn = QPushButton("🗑️ Format Userdata (Factory Reset)")
        format_btn.setStyleSheet("background: #b71c1c;")
        format_btn.clicked.connect(self._format_data)
        format_layout.addWidget(format_btn)
        
        format_layout.addWidget(QLabel("This will erase ALL user data, apps, and settings!"))
        layout.addWidget(format_group)
        
        layout.addStretch()
        return tab
    
    def _erase_partition(self):
        device = self._get_device()
        partition = self.erase_partition.text()
        
        if not device or not partition:
            return
        
        reply = QMessageBox.question(
            self.parent_window, "⚠️ Confirm Erase",
            f"ERASE partition '{partition}'?\n\nThis CANNOT be undone!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = FastbootWorkerThread("erase", device=device, partition=partition)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _format_data(self):
        device = self._get_device()
        if not device:
            return
        
        reply = QMessageBox.question(
            self.parent_window, "⚠️ Factory Reset",
            "This will ERASE ALL USER DATA!\n\nPhotos, apps, settings - EVERYTHING!\n\nAre you absolutely sure?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = FastbootWorkerThread("erase", device=device, partition="userdata")
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== PATCH TAB =====
    def _create_patch_tab(self):
        """Create vbmeta patching tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Info header
        info_label = QLabel(
            "🔧 <b>vbmeta Patcher</b> - Disable dm-verity and AVB verification<br>"
            "<span style='color: #FFA500;'>⚠️ Bootloader must be unlocked to use patched vbmeta</span>"
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Input file selection
        input_group = QGroupBox("Input vbmeta Image")
        input_layout = QHBoxLayout(input_group)
        
        self.patch_input_edit = QLineEdit()
        self.patch_input_edit.setPlaceholderText("Select vbmeta.img file...")
        self.patch_input_edit.textChanged.connect(self._on_patch_input_changed)
        input_layout.addWidget(self.patch_input_edit, 1)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(lambda: self._browse_file(self.patch_input_edit, "Image Files (*.img);;All Files (*)"))
        input_layout.addWidget(browse_btn)
        
        layout.addWidget(input_group)
        
        # Current vbmeta info display
        self.patch_info_group = QGroupBox("Current vbmeta Status")
        info_layout = QVBoxLayout(self.patch_info_group)
        
        self.patch_status_label = QLabel("No file selected")
        self.patch_status_label.setStyleSheet("color: #888;")
        info_layout.addWidget(self.patch_status_label)
        
        self.patch_flags_label = QLabel("")
        info_layout.addWidget(self.patch_flags_label)
        
        layout.addWidget(self.patch_info_group)
        
        # Patch options
        options_group = QGroupBox("Patch Options")
        options_layout = QVBoxLayout(options_group)
        
        self.disable_verity_check = QCheckBox("Disable dm-verity (--disable-verity)")
        self.disable_verity_check.setToolTip(
            "Disables dm-verity hashtree verification.\n"
            "Allows modifying system/vendor partitions without boot failure."
        )
        self.disable_verity_check.setChecked(True)
        options_layout.addWidget(self.disable_verity_check)
        
        self.disable_verification_check = QCheckBox("Disable AVB verification (--disable-verification)")
        self.disable_verification_check.setToolTip(
            "Disables Android Verified Boot signature checking.\n"
            "Required when using modified boot/system images."
        )
        self.disable_verification_check.setChecked(True)
        options_layout.addWidget(self.disable_verification_check)
        
        layout.addWidget(options_group)
        
        # Output options
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout(output_group)
        
        output_row = QHBoxLayout()
        self.patch_output_edit = QLineEdit()
        self.patch_output_edit.setPlaceholderText("Output path (default: vbmeta_patched.img)")
        output_row.addWidget(self.patch_output_edit, 1)
        
        output_browse_btn = QPushButton("📁 Browse")
        output_browse_btn.clicked.connect(self._browse_patch_output)
        output_row.addWidget(output_browse_btn)
        output_layout.addLayout(output_row)
        
        layout.addWidget(output_group)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        self.patch_btn = QPushButton("🔧 Patch vbmeta")
        self.patch_btn.setMinimumHeight(40)
        self.patch_btn.setStyleSheet("font-weight: bold; font-size: 13px;")
        self.patch_btn.clicked.connect(self._patch_vbmeta)
        self.patch_btn.setEnabled(False)
        btn_layout.addWidget(self.patch_btn)
        
        self.patch_and_flash_btn = QPushButton("⚡ Patch && Flash")
        self.patch_and_flash_btn.setMinimumHeight(40)
        self.patch_and_flash_btn.setToolTip("Patch the vbmeta and immediately flash it to the device")
        self.patch_and_flash_btn.clicked.connect(self._patch_and_flash_vbmeta)
        self.patch_and_flash_btn.setEnabled(False)
        btn_layout.addWidget(self.patch_and_flash_btn)
        
        layout.addLayout(btn_layout)
        
        layout.addStretch()
        return tab
    
    def _on_patch_input_changed(self, path):
        """Handle patch input file selection."""
        if not path or not os.path.isfile(path):
            self.patch_status_label.setText("No file selected")
            self.patch_status_label.setStyleSheet("color: #888;")
            self.patch_flags_label.setText("")
            self.patch_btn.setEnabled(False)
            self.patch_and_flash_btn.setEnabled(False)
            return
        
        # Analyze the vbmeta
        patcher = VbmetaPatcher(path)
        info = patcher.get_info()
        
        if not info.get('valid', False):
            self.patch_status_label.setText(f"❌ Invalid: {info.get('error', 'Unknown error')}")
            self.patch_status_label.setStyleSheet("color: #f44;")
            self.patch_flags_label.setText("")
            self.patch_btn.setEnabled(False)
            self.patch_and_flash_btn.setEnabled(False)
            return
        
        # Show current status
        size_kb = info['size'] / 1024
        self.patch_status_label.setText(f"✅ Valid vbmeta image ({size_kb:.1f} KB)")
        self.patch_status_label.setStyleSheet("color: #4f4;")
        
        # Show flag status
        flags_text = f"Current flags: 0x{info['flags']:02X}"
        flag_details = []
        if info['verity_disabled']:
            flag_details.append("🔓 Verity DISABLED")
            self.disable_verity_check.setChecked(True)
        else:
            flag_details.append("🔒 Verity enabled")
        
        if info['verification_disabled']:
            flag_details.append("🔓 Verification DISABLED")
            self.disable_verification_check.setChecked(True)
        else:
            flag_details.append("🔒 Verification enabled")
        
        self.patch_flags_label.setText(f"{flags_text}  •  {' | '.join(flag_details)}")
        
        self.patch_btn.setEnabled(True)
        self.patch_and_flash_btn.setEnabled(True)
        
        # Set default output path
        if not self.patch_output_edit.text():
            base = os.path.splitext(path)[0]
            self.patch_output_edit.setText(f"{base}_patched.img")
    
    def _browse_patch_output(self):
        """Browse for patch output file."""
        path, _ = QFileDialog.getSaveFileName(
            self.parent_window, 
            "Save Patched vbmeta", 
            self.patch_output_edit.text() or "vbmeta_patched.img",
            "Image Files (*.img);;All Files (*)"
        )
        if path:
            self.patch_output_edit.setText(path)
    
    def _patch_vbmeta(self):
        """Patch the vbmeta image."""
        input_path = self.patch_input_edit.text()
        if not input_path or not os.path.isfile(input_path):
            QMessageBox.warning(self.parent_window, "Error", "Please select a valid input file")
            return
        
        output_path = self.patch_output_edit.text()
        if not output_path:
            output_path = os.path.splitext(input_path)[0] + "_patched.img"
            self.patch_output_edit.setText(output_path)
        
        disable_verity = self.disable_verity_check.isChecked()
        disable_verification = self.disable_verification_check.isChecked()
        
        if not disable_verity and not disable_verification:
            QMessageBox.warning(self.parent_window, "Error", "Please select at least one patch option")
            return
        
        self._log(f"Patching vbmeta: {os.path.basename(input_path)}")
        
        patcher = VbmetaPatcher(input_path)
        success, message = patcher.patch(output_path, disable_verity, disable_verification)
        
        if success:
            self._log(f"✅ {message}")
            self._log(f"📁 Saved to: {output_path}")
            QMessageBox.information(
                self.parent_window, 
                "Patch Complete", 
                f"vbmeta patched successfully!\n\n{message}\n\nSaved to:\n{output_path}"
            )
            # Refresh the info display
            self._on_patch_input_changed(output_path)
        else:
            self._log(f"❌ {message}")
            QMessageBox.critical(self.parent_window, "Patch Failed", message)
    
    def _patch_and_flash_vbmeta(self):
        """Patch vbmeta and flash it to the device."""
        device = self._get_device()
        if not device:
            return
        
        input_path = self.patch_input_edit.text()
        if not input_path or not os.path.isfile(input_path):
            QMessageBox.warning(self.parent_window, "Error", "Please select a valid input file")
            return
        
        # Create temp patched file
        import tempfile
        temp_dir = tempfile.mkdtemp()
        output_path = os.path.join(temp_dir, "vbmeta_patched.img")
        
        disable_verity = self.disable_verity_check.isChecked()
        disable_verification = self.disable_verification_check.isChecked()
        
        if not disable_verity and not disable_verification:
            QMessageBox.warning(self.parent_window, "Error", "Please select at least one patch option")
            return
        
        # Confirm flash
        reply = QMessageBox.warning(
            self.parent_window,
            "Flash Patched vbmeta",
            f"This will:\n"
            f"1. Patch the vbmeta image\n"
            f"2. Flash it to the 'vbmeta' partition\n\n"
            f"Device: {device}\n\n"
            f"⚠️ Make sure your bootloader is unlocked!\n\n"
            f"Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self._log(f"Patching vbmeta: {os.path.basename(input_path)}")
        
        patcher = VbmetaPatcher(input_path)
        success, message = patcher.patch(output_path, disable_verity, disable_verification)
        
        if not success:
            self._log(f"❌ Patch failed: {message}")
            QMessageBox.critical(self.parent_window, "Patch Failed", message)
            shutil.rmtree(temp_dir, ignore_errors=True)
            return
        
        self._log(f"✅ {message}")
        self._log(f"⚡ Flashing patched vbmeta to device...")
        
        # Store temp dir for cleanup
        self._patch_temp_dir = temp_dir
        self._patch_temp_file = output_path
        
        # Flash the patched vbmeta
        self.worker = FastbootWorkerThread("flash", device=device, partition="vbmeta", file=output_path)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(self._on_patch_flash_complete)
        self.worker.start()
    
    def _on_patch_flash_complete(self, success, message):
        """Handle patch+flash completion."""
        self._log(message)
        
        # Cleanup temp files
        if hasattr(self, '_patch_temp_dir') and self._patch_temp_dir:
            shutil.rmtree(self._patch_temp_dir, ignore_errors=True)
            self._patch_temp_dir = None
        
        if success:
            QMessageBox.information(
                self.parent_window,
                "Flash Complete",
                "Patched vbmeta flashed successfully!\n\n"
                "You may need to reboot for changes to take effect."
            )

    # ===== OEM TAB =====
    def _create_oem_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        layout.addWidget(QLabel("Bootloader lock/unlock operations"))
        
        # Unlock
        unlock_group = QGroupBox("Unlock Bootloader")
        unlock_layout = QVBoxLayout(unlock_group)
        
        unlock_layout.addWidget(QLabel(
            "Requirements:\n"
            "• OEM unlocking enabled in Developer Options\n"
            "• Google account removed (for some devices)\n"
            "• ⚠️ This will FACTORY RESET your device!"
        ))
        
        oem_unlock_btn = QPushButton("🔓 OEM Unlock")
        oem_unlock_btn.setStyleSheet("background: #e65100;")
        oem_unlock_btn.clicked.connect(self._oem_unlock)
        unlock_layout.addWidget(oem_unlock_btn)
        
        flashing_unlock_btn = QPushButton("🔓 Flashing Unlock (Pixel/newer)")
        flashing_unlock_btn.setStyleSheet("background: #e65100;")
        flashing_unlock_btn.clicked.connect(self._flashing_unlock)
        unlock_layout.addWidget(flashing_unlock_btn)
        
        layout.addWidget(unlock_group)
        
        # Lock
        lock_group = QGroupBox("Lock Bootloader")
        lock_layout = QVBoxLayout(lock_group)
        
        lock_layout.addWidget(QLabel(
            "⚠️ Only lock if you're running STOCK firmware!\n"
            "Locking with custom ROM/recovery = BRICK"
        ))
        
        oem_lock_btn = QPushButton("🔒 OEM Lock")
        oem_lock_btn.clicked.connect(self._oem_lock)
        lock_layout.addWidget(oem_lock_btn)
        
        flashing_lock_btn = QPushButton("🔒 Flashing Lock (Pixel/newer)")
        flashing_lock_btn.clicked.connect(self._flashing_lock)
        lock_layout.addWidget(flashing_lock_btn)
        
        layout.addWidget(lock_group)
        layout.addStretch()
        
        return tab
    
    def _oem_unlock(self):
        device = self._get_device()
        if not device:
            return
        
        reply = QMessageBox.question(
            self.parent_window, "⚠️ OEM Unlock",
            "This will:\n• Factory reset your device\n• Void warranty (possibly)\n• Enable custom firmware\n\nContinue?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = FastbootWorkerThread("oem_unlock", device=device)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _flashing_unlock(self):
        device = self._get_device()
        if not device:
            return
        
        reply = QMessageBox.question(
            self.parent_window, "⚠️ Flashing Unlock",
            "This will:\n• Factory reset your device\n• Enable flashing custom images\n\nContinue?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = FastbootWorkerThread("flashing_unlock", device=device)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _oem_lock(self):
        device = self._get_device()
        if not device:
            return
        
        reply = QMessageBox.question(
            self.parent_window, "⚠️ OEM Lock",
            "Only do this if running STOCK firmware!\n\nLocking with custom ROM = BRICK\n\nAre you on stock?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = FastbootWorkerThread("oem_lock", device=device)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _flashing_lock(self):
        device = self._get_device()
        if not device:
            return
        
        reply = QMessageBox.question(
            self.parent_window, "⚠️ Flashing Lock",
            "Only do this if running STOCK firmware!\n\nContinue?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = FastbootWorkerThread("flashing_lock", device=device)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== SLOT TAB =====
    def _create_slot_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        layout.addWidget(QLabel("A/B slot management for devices with seamless updates"))
        
        slot_group = QGroupBox("Set Active Slot")
        slot_layout = QVBoxLayout(slot_group)
        
        self.slot_a = QRadioButton("Slot A")
        self.slot_b = QRadioButton("Slot B")
        self.slot_a.setChecked(True)
        
        slot_layout.addWidget(self.slot_a)
        slot_layout.addWidget(self.slot_b)
        
        set_slot_btn = QPushButton("🔀 Set Active Slot")
        set_slot_btn.clicked.connect(self._set_slot)
        slot_layout.addWidget(set_slot_btn)
        
        layout.addWidget(slot_group)
        
        info = QLabel(
            "About A/B slots:\n"
            "• Modern devices have two copies of system partitions\n"
            "• boot_a/boot_b, system_a/system_b, etc.\n"
            "• Allows seamless OTA updates\n"
            "• Can switch between slots if one fails"
        )
        info.setStyleSheet("color: #888;")
        layout.addWidget(info)
        
        layout.addStretch()
        return tab
    
    def _set_slot(self):
        device = self._get_device()
        if not device:
            return
        
        slot = "a" if self.slot_a.isChecked() else "b"
        
        self.worker = FastbootWorkerThread("set_active", device=device, slot=slot)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== REBOOT TAB =====
    def _create_reboot_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        buttons = [
            ("🔄 Reboot System", ""),
            ("⚡ Reboot Bootloader", "bootloader"),
            ("📦 Reboot Fastbootd", "fastbootd"),
            ("🔧 Reboot Recovery", "recovery"),
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
        
        self.worker = FastbootWorkerThread("reboot", device=device, mode=mode)
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


Plugin = FastbootToolkitPlugin
