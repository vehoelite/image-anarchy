"""
Root Patcher Plugin for Image Anarchy

Patch boot images with popular rooting solutions:
- Magisk (most compatible, supports all devices)
- APatch (newer, KernelPatch-based)
- KernelSU (kernel-level, requires GKI kernel)
- Phh GSI (Generic System Image with built-in root)

Features:
- Automated device connection via ADB/Fastboot
- Boot image extraction directly from connected device
- Automated patching with magiskboot
- Direct flash back to device

Includes compatibility checks to prevent bricking devices.
"""

import os
import sys
import subprocess
import struct
import shutil
import tempfile
import json
import re
import urllib.request
import zipfile
from typing import Optional, Dict, Tuple, List
from datetime import datetime
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QComboBox,
    QPushButton, QLineEdit, QTextEdit, QProgressBar, QFileDialog, 
    QMessageBox, QTabWidget, QFormLayout, QCheckBox, QRadioButton,
    QButtonGroup, QFrame, QScrollArea, QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont


# =============================================================================
# Constants
# =============================================================================

BOOT_MAGIC = b'ANDROID!'
VENDOR_BOOT_MAGIC = b'VNDRBOOT'

# KernelSU requires GKI (Generic Kernel Image) kernels - Android 12+ with specific kernel versions
GKI_KERNEL_VERSIONS = ['5.10', '5.15', '6.1', '6.6']

# Known kernel configs that indicate KernelSU compatibility
KERNELSU_COMPATIBLE_CONFIGS = [
    'CONFIG_KSU=y',
    'CONFIG_KPROBES=y',  # Required for KernelSU
]

# APatch minimum Android version
APATCH_MIN_ANDROID = 11

# Download URLs
MAGISK_RELEASES_URL = "https://api.github.com/repos/topjohnwu/Magisk/releases/latest"
APATCH_RELEASES_URL = "https://api.github.com/repos/bmax121/APatch/releases/latest"
KERNELSU_RELEASES_URL = "https://api.github.com/repos/tiann/KernelSU/releases/latest"

# Common boot partition paths on Android devices
BOOT_PARTITION_PATHS = [
    "/dev/block/bootdevice/by-name/boot",
    "/dev/block/by-name/boot",
    "/dev/block/platform/soc/1d84000.ufshc/by-name/boot",
    "/dev/block/platform/msm_sdcc.1/by-name/boot",
    "/dev/block/platform/mtk-msdc.0/11230000.msdc0/by-name/boot",
]


# =============================================================================
# ADB/Fastboot Helper Functions
# =============================================================================

def get_plugin_dir() -> str:
    """Get the directory where this plugin is installed."""
    return os.path.dirname(os.path.abspath(__file__))


def find_adb() -> Optional[str]:
    """Find ADB executable."""
    plugin_dir = get_plugin_dir()
    
    # Check plugin directory directly (bundled_binaries download here)
    direct_paths = [
        os.path.join(plugin_dir, "adb.exe"),
        os.path.join(plugin_dir, "adb"),
    ]
    for path in direct_paths:
        if os.path.isfile(path):
            return path
    
    # Check plugin's platform-tools subfolder (legacy)
    plugin_adb_paths = [
        os.path.join(plugin_dir, "platform-tools", "adb.exe"),
        os.path.join(plugin_dir, "platform-tools", "adb"),
    ]
    for path in plugin_adb_paths:
        if os.path.isfile(path):
            return path
    
    # Check ADB Toolkit plugin (if installed)
    adb_toolkit_paths = [
        os.path.join(plugin_dir, "..", "adb_toolkit", "adb.exe"),
        os.path.join(plugin_dir, "..", "adb_toolkit", "adb"),
        os.path.join(plugin_dir, "..", "adb_toolkit", "platform-tools", "adb.exe"),
        os.path.join(plugin_dir, "..", "adb_toolkit", "platform-tools", "adb"),
    ]
    for path in adb_toolkit_paths:
        norm_path = os.path.normpath(path)
        if os.path.isfile(norm_path):
            return norm_path
    
    # Check frozen app
    if getattr(sys, 'frozen', False):
        app_dir = os.path.dirname(sys.executable)
        meipass = getattr(sys, '_MEIPASS', app_dir)
        for base in [meipass, app_dir]:
            for p in ["adb.exe", "adb", "platform-tools/adb.exe", "platform-tools/adb"]:
                path = os.path.join(base, p)
                if os.path.isfile(path):
                    return path
    else:
        # Dev mode - check app root
        app_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        for p in ["adb.exe", "adb", "platform-tools/adb.exe", "platform-tools/adb"]:
            path = os.path.join(app_dir, p)
            if os.path.isfile(path):
                return path
    
    # System PATH
    for path in ["adb", "adb.exe"]:
        found = shutil.which(path)
        if found:
            return found
    
    # Common locations
    android_home = os.environ.get("ANDROID_HOME", "")
    if android_home:
        for p in ["platform-tools/adb.exe", "platform-tools/adb"]:
            path = os.path.join(android_home, p)
            if os.path.isfile(path):
                return path
    
    return None


def find_fastboot() -> Optional[str]:
    """Find Fastboot executable."""
    plugin_dir = get_plugin_dir()
    
    # Check plugin directory directly (bundled_binaries download here)
    direct_paths = [
        os.path.join(plugin_dir, "fastboot.exe"),
        os.path.join(plugin_dir, "fastboot"),
    ]
    for path in direct_paths:
        if os.path.isfile(path):
            return path
    
    # Check plugin's platform-tools subfolder (legacy)
    plugin_fb_paths = [
        os.path.join(plugin_dir, "platform-tools", "fastboot.exe"),
        os.path.join(plugin_dir, "platform-tools", "fastboot"),
    ]
    for path in plugin_fb_paths:
        if os.path.isfile(path):
            return path
    
    # Check Fastboot Toolkit plugin (if installed)
    fb_toolkit_paths = [
        os.path.join(plugin_dir, "..", "fastboot_toolkit", "fastboot.exe"),
        os.path.join(plugin_dir, "..", "fastboot_toolkit", "fastboot"),
        os.path.join(plugin_dir, "..", "fastboot_toolkit", "platform-tools", "fastboot.exe"),
        os.path.join(plugin_dir, "..", "fastboot_toolkit", "platform-tools", "fastboot"),
    ]
    for path in fb_toolkit_paths:
        norm_path = os.path.normpath(path)
        if os.path.isfile(norm_path):
            return norm_path
    
    # Check frozen app
    if getattr(sys, 'frozen', False):
        app_dir = os.path.dirname(sys.executable)
        meipass = getattr(sys, '_MEIPASS', app_dir)
        for base in [meipass, app_dir]:
            for p in ["fastboot.exe", "fastboot", "platform-tools/fastboot.exe", "platform-tools/fastboot"]:
                path = os.path.join(base, p)
                if os.path.isfile(path):
                    return path
    else:
        app_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        for p in ["fastboot.exe", "fastboot", "platform-tools/fastboot.exe", "platform-tools/fastboot"]:
            path = os.path.join(app_dir, p)
            if os.path.isfile(path):
                return path
    
    # System PATH
    for path in ["fastboot", "fastboot.exe"]:
        found = shutil.which(path)
        if found:
            return found
    
    return None


def run_adb(args: List[str], device: Optional[str] = None, timeout: int = 60) -> Tuple[bool, str]:
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


def run_fastboot(args: List[str], device: Optional[str] = None, timeout: int = 120) -> Tuple[bool, str]:
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
        return result.returncode == 0 or "OKAY" in output, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


# =============================================================================
# Boot Image Parser
# =============================================================================

class BootImageInfo:
    """Parsed boot image information."""
    
    def __init__(self):
        self.valid = False
        self.error = ""
        self.header_version = 0
        self.kernel_size = 0
        self.ramdisk_size = 0
        self.page_size = 4096
        self.os_version = ""
        self.os_patch_level = ""
        self.cmdline = ""
        self.kernel_offset = 0
        self.ramdisk_offset = 0
        
        # Kernel analysis
        self.kernel_version = ""
        self.kernel_compression = ""
        self.is_gki = False
        self.has_kprobes = False
        
        # Compatibility flags
        self.magisk_compatible = True
        self.apatch_compatible = False
        self.kernelsu_compatible = False
        
        self.compatibility_notes = []


def parse_boot_image(path: str) -> BootImageInfo:
    """Parse a boot.img file and determine rooting compatibility."""
    info = BootImageInfo()
    
    try:
        with open(path, 'rb') as f:
            header = f.read(4096)
        
        # Check magic
        if header[:8] != BOOT_MAGIC:
            info.error = "Not a valid Android boot image (missing ANDROID! magic)"
            return info
        
        info.valid = True
        
        # Parse header based on version
        # Header version is at offset 10 (after magic + 2 unused bytes in some versions)
        # But more reliably: kernel_size at offset 8, ramdisk_size at 16, etc.
        
        info.kernel_size = struct.unpack('<I', header[8:12])[0]
        info.ramdisk_size = struct.unpack('<I', header[16:20])[0]
        
        # Second stage size at offset 24
        second_size = struct.unpack('<I', header[24:28])[0]
        
        # Page size at offset 36
        info.page_size = struct.unpack('<I', header[36:40])[0]
        if info.page_size == 0:
            info.page_size = 4096
        
        # Header version at offset 40 (boot image v1+)
        info.header_version = struct.unpack('<I', header[40:44])[0]
        
        # OS version at offset 44 (encoded)
        os_ver_patch = struct.unpack('<I', header[44:48])[0]
        if os_ver_patch > 0:
            os_ver = (os_ver_patch >> 11) & 0x7FF
            os_major = (os_ver >> 14) & 0x7F
            os_minor = (os_ver >> 7) & 0x7F
            os_patch = os_ver & 0x7F
            info.os_version = f"{os_major}.{os_minor}.{os_patch}" if os_major > 0 else ""
            
            patch_level = os_ver_patch & 0x7FF
            patch_year = 2000 + ((patch_level >> 4) & 0x7F)
            patch_month = patch_level & 0xF
            info.os_patch_level = f"{patch_year}-{patch_month:02d}"
        
        # Command line at offset 64 (512 bytes in v0-v2, different in v3+)
        if info.header_version < 3:
            cmdline_bytes = header[64:64+512]
            info.cmdline = cmdline_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
        
        # Calculate offsets
        pages = lambda size: (size + info.page_size - 1) // info.page_size
        info.kernel_offset = info.page_size  # Kernel starts after header page
        info.ramdisk_offset = info.kernel_offset + pages(info.kernel_size) * info.page_size
        
        # Analyze kernel for version and compatibility
        _analyze_kernel(path, info)
        
        # Determine compatibility
        _check_compatibility(info)
        
    except Exception as e:
        info.error = str(e)
    
    return info


def _analyze_kernel(path: str, info: BootImageInfo):
    """Analyze the kernel to determine version and capabilities."""
    try:
        with open(path, 'rb') as f:
            f.seek(info.kernel_offset)
            kernel_data = f.read(min(info.kernel_size, 1024 * 1024))  # Read first 1MB
        
        # Check compression
        if kernel_data[:2] == b'\x1f\x8b':
            info.kernel_compression = 'gzip'
        elif kernel_data[:4] == b'\x28\xb5\x2f\xfd':
            info.kernel_compression = 'zstd'
        elif kernel_data[:2] == b'\x5d\x00':
            info.kernel_compression = 'lzma'
        elif kernel_data[:4] == b'\x04\x22\x4d\x18':
            info.kernel_compression = 'lz4'
        elif kernel_data[:9] == b'UNCOMPRESSED_IMG':
            info.kernel_compression = 'none'
        else:
            info.kernel_compression = 'unknown'
        
        # Search for Linux version string
        # Pattern: "Linux version X.Y.Z..."
        version_pattern = rb'Linux version (\d+\.\d+\.\d+[^\s]*)'
        match = re.search(version_pattern, kernel_data)
        if match:
            info.kernel_version = match.group(1).decode('utf-8', errors='ignore')
        
        # Check for GKI kernel indicators
        # GKI kernels have specific version patterns and are Android 12+
        if info.kernel_version:
            major_minor = '.'.join(info.kernel_version.split('.')[:2])
            if major_minor in GKI_KERNEL_VERSIONS:
                # Additional GKI check: look for android-gki or similar
                if b'android' in kernel_data.lower() and b'gki' in kernel_data.lower():
                    info.is_gki = True
                elif major_minor in ['5.10', '5.15', '6.1', '6.6']:
                    # These versions are likely GKI on Android 12+
                    info.is_gki = True
        
        # Check for kprobes support (needed for KernelSU)
        if b'kprobes' in kernel_data.lower() or b'CONFIG_KPROBES' in kernel_data:
            info.has_kprobes = True
            
    except Exception as e:
        info.compatibility_notes.append(f"Kernel analysis failed: {e}")


def _check_compatibility(info: BootImageInfo):
    """Determine which rooting methods are compatible."""
    
    # Magisk: Compatible with almost everything
    info.magisk_compatible = True
    info.compatibility_notes.append("✅ Magisk: Universal compatibility")
    
    # APatch: Requires Android 11+ and specific kernel features
    android_ver = 0
    if info.os_version:
        try:
            android_ver = int(info.os_version.split('.')[0])
        except:
            pass
    
    if android_ver >= APATCH_MIN_ANDROID:
        info.apatch_compatible = True
        info.compatibility_notes.append(f"✅ APatch: Android {android_ver} supported")
    else:
        info.apatch_compatible = False
        if android_ver > 0:
            info.compatibility_notes.append(f"❌ APatch: Requires Android 11+, found Android {android_ver}")
        else:
            info.compatibility_notes.append("⚠️ APatch: Could not detect Android version")
    
    # KernelSU: Requires GKI kernel with kprobes
    if info.is_gki and info.has_kprobes:
        info.kernelsu_compatible = True
        info.compatibility_notes.append(f"✅ KernelSU: GKI kernel {info.kernel_version} with kprobes")
    elif info.is_gki:
        info.kernelsu_compatible = False
        info.compatibility_notes.append(f"⚠️ KernelSU: GKI kernel but kprobes not detected")
    else:
        info.kernelsu_compatible = False
        if info.kernel_version:
            info.compatibility_notes.append(f"❌ KernelSU: Non-GKI kernel ({info.kernel_version})")
        else:
            info.compatibility_notes.append("❌ KernelSU: Could not determine kernel type")


# =============================================================================
# Worker Thread
# =============================================================================

class PatchWorker(QThread):
    """Worker thread for patching operations."""
    progress = pyqtSignal(int, str)
    log = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)
    
    def __init__(self, operation: str, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
    
    def run(self):
        try:
            if self.operation == "analyze":
                self._analyze()
            elif self.operation == "patch_magisk":
                self._patch_magisk()
            elif self.operation == "patch_apatch":
                self._patch_apatch()
            elif self.operation == "patch_kernelsu":
                self._patch_kernelsu()
            elif self.operation == "patch_gsi":
                self._patch_gsi()
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.finished_signal.emit(False, str(e))
    
    def _analyze(self):
        """Analyze boot image."""
        path = self.kwargs.get('path')
        self.log.emit(f"Analyzing: {os.path.basename(path)}")
        self.progress.emit(50, "Parsing boot image...")
        
        info = parse_boot_image(path)
        
        self.progress.emit(100, "Analysis complete")
        self.finished_signal.emit(True, json.dumps({
            'valid': info.valid,
            'error': info.error,
            'header_version': info.header_version,
            'kernel_size': info.kernel_size,
            'ramdisk_size': info.ramdisk_size,
            'page_size': info.page_size,
            'os_version': info.os_version,
            'os_patch_level': info.os_patch_level,
            'kernel_version': info.kernel_version,
            'kernel_compression': info.kernel_compression,
            'is_gki': info.is_gki,
            'has_kprobes': info.has_kprobes,
            'magisk_compatible': info.magisk_compatible,
            'apatch_compatible': info.apatch_compatible,
            'kernelsu_compatible': info.kernelsu_compatible,
            'compatibility_notes': info.compatibility_notes,
        }))
    
    def _patch_magisk(self):
        """Instructions for Magisk patching (done via app)."""
        self.log.emit("Magisk patching must be done through the Magisk app.")
        self.log.emit("")
        self.log.emit("Steps:")
        self.log.emit("1. Install Magisk app on your device (or another Android device)")
        self.log.emit("2. Transfer boot.img to the device")
        self.log.emit("3. Open Magisk → Install → Select and Patch a File")
        self.log.emit("4. Select your boot.img")
        self.log.emit("5. Magisk will create magisk_patched_[random].img in Download folder")
        self.log.emit("6. Transfer patched file back to PC")
        self.log.emit("7. Flash with: fastboot flash boot magisk_patched.img")
        self.log.emit("   Or mtkclient: python -m mtkclient w boot magisk_patched.img")
        self.finished_signal.emit(True, "Instructions provided")
    
    def _patch_apatch(self):
        """Instructions for APatch patching."""
        self.log.emit("APatch patching must be done through the APatch app.")
        self.log.emit("")
        self.log.emit("Steps:")
        self.log.emit("1. Download APatch from: https://github.com/bmax121/APatch/releases")
        self.log.emit("2. Install APatch app on your device")
        self.log.emit("3. Transfer boot.img to the device")
        self.log.emit("4. Open APatch → Patch → Select boot.img")
        self.log.emit("5. APatch will create patched boot image")
        self.log.emit("6. Transfer patched file back to PC")
        self.log.emit("7. Flash with: fastboot flash boot apatch_patched.img")
        self.log.emit("")
        self.log.emit("Note: APatch uses KernelPatch for root access")
        self.finished_signal.emit(True, "Instructions provided")
    
    def _patch_kernelsu(self):
        """Instructions for KernelSU."""
        self.log.emit("KernelSU requires a compatible kernel or kernel patching.")
        self.log.emit("")
        self.log.emit("Option 1 - Use pre-built KernelSU kernel (recommended):")
        self.log.emit("1. Check if your device has a KernelSU build available:")
        self.log.emit("   https://github.com/tiann/KernelSU/releases")
        self.log.emit("2. Download the correct kernel for your device")
        self.log.emit("3. Flash the kernel image")
        self.log.emit("")
        self.log.emit("Option 2 - Patch boot.img with ksud (for GKI kernels):")
        self.log.emit("1. Download ksud from KernelSU releases")
        self.log.emit("2. Run: ksud boot-patch -b boot.img")
        self.log.emit("3. Flash the patched boot image")
        self.log.emit("")
        self.log.emit("Option 3 - Build custom kernel with KernelSU:")
        self.log.emit("1. Get kernel source for your device")
        self.log.emit("2. Apply KernelSU patches")
        self.log.emit("3. Build and flash")
        self.finished_signal.emit(True, "Instructions provided")
    
    def _patch_gsi(self):
        """Instructions for Phh-based GSI with root."""
        self.log.emit("Phh-based GSI (Generic System Image) with built-in root access")
        self.log.emit("")
        self.log.emit("⚠️ WARNING: This replaces your system partition!")
        self.log.emit("⚠️ Your device must support Project Treble (Android 8+)")
        self.log.emit("⚠️ This is best for testing or devices where other methods fail")
        self.log.emit("")
        self.log.emit("=" * 50)
        self.log.emit("Step 1: Determine your device type")
        self.log.emit("=" * 50)
        self.log.emit("")
        self.log.emit("Run this in ADB to check:")
        self.log.emit("  adb shell getprop ro.product.cpu.abi")
        self.log.emit("  → arm64-v8a = ARM64 (most modern phones)")
        self.log.emit("  → armeabi-v7a = ARM32 (older phones)")
        self.log.emit("")
        self.log.emit("Check partition scheme:")
        self.log.emit("  adb shell getprop ro.build.ab_update")
        self.log.emit("  → true = A/B partitions")
        self.log.emit("  → (empty) = A-only partitions")
        self.log.emit("")
        self.log.emit("Check if Treble is supported:")
        self.log.emit("  adb shell getprop ro.treble.enabled")
        self.log.emit("  → Must be 'true' for GSI to work!")
        self.log.emit("")
        self.log.emit("=" * 50)
        self.log.emit("Step 2: Download the correct GSI")
        self.log.emit("=" * 50)
        self.log.emit("")
        self.log.emit("Phh-Treble releases (with root):")
        self.log.emit("  https://github.com/phhusson/treble_experimentations/releases")
        self.log.emit("")
        self.log.emit("Choose based on your device:")
        self.log.emit("  • ARM64 A-only: system-arm64-ab-vanilla.img.xz (or -gapps)")
        self.log.emit("  • ARM64 A/B:    system-arm64-ab-vanilla.img.xz (or -gapps)")
        self.log.emit("  • ARM32:        system-arm-ab-vanilla.img.xz")
        self.log.emit("")
        self.log.emit("Variants explained:")
        self.log.emit("  • vanilla = No Google apps (smallest, cleanest)")
        self.log.emit("  • gapps = With Google Play Services")
        self.log.emit("  • vndklite = For Android 11+ vendor on older GSI")
        self.log.emit("")
        self.log.emit("=" * 50)
        self.log.emit("Step 3: Flash the GSI")
        self.log.emit("=" * 50)
        self.log.emit("")
        self.log.emit("Method A - Using Fastboot:")
        self.log.emit("  1. Boot to bootloader: adb reboot bootloader")
        self.log.emit("  2. Erase system: fastboot erase system")
        self.log.emit("  3. Flash GSI: fastboot flash system system-*.img")
        self.log.emit("  4. Wipe userdata: fastboot -w")
        self.log.emit("  5. Reboot: fastboot reboot")
        self.log.emit("")
        self.log.emit("Method B - Using mtkclient (MTK devices):")
        self.log.emit("  1. Power off device completely")
        self.log.emit("  2. python -m mtkclient w system system-*.img")
        self.log.emit("  3. Factory reset via recovery after first boot")
        self.log.emit("")
        self.log.emit("=" * 50)
        self.log.emit("Step 4: Enable root access")
        self.log.emit("=" * 50)
        self.log.emit("")
        self.log.emit("After booting GSI:")
        self.log.emit("  1. Open Settings → Phh Treble Settings")
        self.log.emit("  2. Find 'Misc features' section")
        self.log.emit("  3. Enable 'Use built-in su/root'")
        self.log.emit("  4. Reboot")
        self.log.emit("")
        self.log.emit("You now have root via 'su' command!")
        self.log.emit("")
        self.log.emit("Optional: Install Magisk on top:")
        self.log.emit("  1. After GSI is working, extract current boot.img")
        self.log.emit("  2. Patch with Magisk as normal")
        self.log.emit("  3. Flash patched boot for better root management")
        self.finished_signal.emit(True, "Instructions provided")


# =============================================================================
# Device Patcher Worker - Automated ADB/Fastboot Operations
# =============================================================================

class DevicePatcherWorker(QThread):
    """Worker thread for device-based patching operations."""
    progress = pyqtSignal(int, str)
    log = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)
    device_info = pyqtSignal(dict)
    
    def __init__(self, operation: str, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
        self._cancelled = False
        self.adb_path = find_adb()
        self.fastboot_path = find_fastboot()
    
    def cancel(self):
        self._cancelled = True
    
    def run(self):
        try:
            if self.operation == "detect_devices":
                self._detect_devices()
            elif self.operation == "get_device_info":
                self._get_device_info()
            elif self.operation == "extract_boot":
                self._extract_boot()
            elif self.operation == "patch_magisk_auto":
                self._patch_magisk_auto()
            elif self.operation == "flash_boot":
                self._flash_boot()
            elif self.operation == "full_root":
                self._full_root_process()
            elif self.operation == "full_patch_workflow":
                self._full_patch_workflow()
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.finished_signal.emit(False, str(e))
    
    def _run_adb(self, args: List[str], timeout: int = 60) -> Tuple[bool, str]:
        """Run ADB command with the selected device."""
        device = self.kwargs.get('device')
        if not self.adb_path:
            return False, "ADB not found"
        
        cmd = [self.adb_path]
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
    
    def _run_fastboot(self, args: List[str], timeout: int = 120) -> Tuple[bool, str]:
        """Run Fastboot command with the selected device."""
        device = self.kwargs.get('device')
        if not self.fastboot_path:
            return False, "Fastboot not found"
        
        cmd = [self.fastboot_path]
        if device:
            cmd.extend(["-s", device])
        cmd.extend(args)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = result.stdout + result.stderr
            return result.returncode == 0 or "OKAY" in output, output
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)
    
    def _detect_devices(self):
        """Detect connected ADB and Fastboot devices."""
        self.log.emit("🔍 Scanning for connected devices...")
        devices = {'adb': [], 'fastboot': []}
        
        # Check ADB devices
        if self.adb_path:
            self.progress.emit(25, "Checking ADB devices...")
            success, output = run_adb(["devices"])
            if success:
                for line in output.strip().split('\n')[1:]:
                    if '\t' in line:
                        serial, state = line.split('\t')
                        if state.strip() in ['device', 'recovery']:
                            devices['adb'].append({
                                'serial': serial.strip(),
                                'state': state.strip(),
                                'mode': 'adb'
                            })
        
        # Check Fastboot devices
        if self.fastboot_path:
            self.progress.emit(50, "Checking Fastboot devices...")
            success, output = run_fastboot(["devices"])
            if success:
                for line in output.strip().split('\n'):
                    if '\t' in line or 'fastboot' in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            devices['fastboot'].append({
                                'serial': parts[0].strip(),
                                'state': 'fastboot',
                                'mode': 'fastboot'
                            })
        
        self.progress.emit(100, "Scan complete")
        self.device_info.emit(devices)
        
        total = len(devices['adb']) + len(devices['fastboot'])
        if total == 0:
            self.log.emit("❌ No devices found. Ensure:")
            self.log.emit("   • USB debugging is enabled")
            self.log.emit("   • Device is connected via USB")
            self.log.emit("   • USB drivers are installed")
            self.finished_signal.emit(False, "No devices found")
        else:
            self.log.emit(f"✅ Found {len(devices['adb'])} ADB device(s), {len(devices['fastboot'])} Fastboot device(s)")
            self.finished_signal.emit(True, f"Found {total} device(s)")
    
    def _get_device_info(self):
        """Get detailed info about a connected device."""
        device = self.kwargs.get('device')
        mode = self.kwargs.get('mode', 'adb')
        
        info = {
            'serial': device,
            'mode': mode,
            'model': 'Unknown',
            'manufacturer': 'Unknown',
            'android_version': 'Unknown',
            'sdk_level': 'Unknown',
            'arch': 'Unknown',
            'kernel_version': '',
            'is_rooted': False,
            'has_treble': False,
            'is_ab': False,
            'boot_slot': '',
            'bootloader_unlocked': None,  # None = unknown, True = unlocked, False = locked
        }
        
        if mode == 'adb':
            self.log.emit(f"📱 Getting device info for {device}...")
            
            # Get basic props
            props_to_get = [
                ('ro.product.model', 'model'),
                ('ro.product.manufacturer', 'manufacturer'),
                ('ro.build.version.release', 'android_version'),
                ('ro.build.version.sdk', 'sdk_level'),
                ('ro.product.cpu.abi', 'arch'),
                ('ro.treble.enabled', 'has_treble'),
                ('ro.build.ab_update', 'is_ab'),
                ('ro.boot.slot_suffix', 'boot_slot'),
            ]
            
            for prop, key in props_to_get:
                success, output = self._run_adb(["shell", "getprop", prop])
                if success and output.strip():
                    value = output.strip()
                    if key in ['has_treble', 'is_ab']:
                        info[key] = value.lower() == 'true'
                    else:
                        info[key] = value
            
            # Get kernel version
            success, output = self._run_adb(["shell", "uname", "-r"])
            if success and output.strip():
                info['kernel_version'] = output.strip()
                self.log.emit(f"   Kernel: {info['kernel_version']}")
            
            # Check bootloader unlock status
            self.log.emit("🔓 Checking bootloader status...")
            # Try multiple props that indicate bootloader status
            bootloader_props = [
                'ro.boot.flash.locked',  # 0 = unlocked, 1 = locked
                'ro.boot.verifiedbootstate',  # orange = unlocked
                'ro.boot.vbmeta.device_state',  # unlocked
                'ro.secureboot.lockstate',  # unlocked
            ]
            for prop in bootloader_props:
                success, output = self._run_adb(["shell", "getprop", prop])
                if success and output.strip():
                    val = output.strip().lower()
                    if prop == 'ro.boot.flash.locked':
                        info['bootloader_unlocked'] = val == '0'
                        break
                    elif val in ['unlocked', 'orange']:
                        info['bootloader_unlocked'] = True
                        break
                    elif val in ['locked', 'green']:
                        info['bootloader_unlocked'] = False
                        break
            
            if info.get('bootloader_unlocked') is True:
                self.log.emit("✅ Bootloader is UNLOCKED")
            elif info.get('bootloader_unlocked') is False:
                self.log.emit("❌ Bootloader is LOCKED")
            else:
                self.log.emit("⚠️ Could not determine bootloader status")
            
            # Check root access
            self.log.emit("🔑 Checking root access...")
            success, output = self._run_adb(["shell", "su", "-c", "id"])
            info['is_rooted'] = success and 'uid=0' in output
            
            if info['is_rooted']:
                self.log.emit("✅ Device has root access!")
            else:
                self.log.emit("ℹ️ Device is not rooted (can still patch via app)")
            
            self.log.emit(f"📱 {info['manufacturer']} {info['model']}")
            self.log.emit(f"   Android {info['android_version']} (SDK {info['sdk_level']})")
            self.log.emit(f"   Architecture: {info['arch']}")
            self.log.emit(f"   Treble: {'Yes' if info['has_treble'] else 'No'}, A/B: {'Yes' if info['is_ab'] else 'No'}")
            
        elif mode == 'fastboot':
            self.log.emit(f"⚡ Getting fastboot device info for {device}...")
            
            # Try to get some info via fastboot
            success, output = self._run_fastboot(["getvar", "product"])
            if success:
                for line in output.split('\n'):
                    if 'product:' in line.lower():
                        info['model'] = line.split(':')[-1].strip()
            
            success, output = self._run_fastboot(["getvar", "slot-count"])
            if success and '2' in output:
                info['is_ab'] = True
            
            success, output = self._run_fastboot(["getvar", "current-slot"])
            if success:
                for line in output.split('\n'):
                    if 'current-slot:' in line.lower():
                        info['boot_slot'] = line.split(':')[-1].strip()
            
            # Check bootloader unlock status in fastboot
            self.log.emit("🔓 Checking bootloader status...")
            success, output = self._run_fastboot(["getvar", "unlocked"])
            if success:
                for line in output.split('\n'):
                    if 'unlocked:' in line.lower():
                        val = line.split(':')[-1].strip().lower()
                        info['bootloader_unlocked'] = val == 'yes' or val == 'true'
                        break
            
            if info.get('bootloader_unlocked') is None:
                # Try alternative check
                success, output = self._run_fastboot(["getvar", "secure"])
                if success:
                    for line in output.split('\n'):
                        if 'secure:' in line.lower():
                            val = line.split(':')[-1].strip().lower()
                            # secure=no typically means unlocked
                            info['bootloader_unlocked'] = val == 'no'
                            break
            
            if info.get('bootloader_unlocked') is True:
                self.log.emit("✅ Bootloader is UNLOCKED - Ready to flash!")
            elif info.get('bootloader_unlocked') is False:
                self.log.emit("❌ Bootloader is LOCKED - Cannot flash boot images")
            else:
                self.log.emit("⚠️ Could not determine bootloader status")
        
        self.device_info.emit(info)
        self.finished_signal.emit(True, "Device info retrieved")
    
    def _find_boot_partition(self) -> Optional[str]:
        """Find the boot partition path on the device."""
        self.log.emit("🔍 Looking for boot partition...")
        
        # Try common paths
        for path in BOOT_PARTITION_PATHS:
            success, output = self._run_adb(["shell", "su", "-c", f"test -e {path} && echo exists"])
            if success and 'exists' in output:
                self.log.emit(f"   Found: {path}")
                return path
        
        # Try to find via ls
        success, output = self._run_adb(["shell", "su", "-c", "ls -la /dev/block/by-name/ 2>/dev/null | grep boot"])
        if success and output.strip():
            self.log.emit(f"   Found via ls: {output.strip()}")
            # Parse the output to get the path
            for line in output.split('\n'):
                if 'boot' in line.lower() and '->' in line:
                    parts = line.split('->')
                    if len(parts) >= 2:
                        target = parts[-1].strip()
                        return f"/dev/block/by-name/boot"
        
        # MTK specific path
        success, output = self._run_adb(["shell", "su", "-c", "ls /dev/block/platform/*/by-name/boot 2>/dev/null"])
        if success and output.strip() and 'No such file' not in output:
            path = output.strip().split('\n')[0]
            self.log.emit(f"   Found MTK path: {path}")
            return path
        
        return None
    
    def _extract_boot(self):
        """Extract boot.img from connected device."""
        device = self.kwargs.get('device')
        output_path = self.kwargs.get('output_path')
        
        self.log.emit("=" * 50)
        self.log.emit("📥 EXTRACTING BOOT IMAGE FROM DEVICE")
        self.log.emit("=" * 50)
        
        # Check root access
        self.progress.emit(10, "Checking root access...")
        success, output = self._run_adb(["shell", "su", "-c", "id"])
        if not success or 'uid=0' not in output:
            self.log.emit("❌ Root access required to extract boot.img")
            self.log.emit("   Please root your device first, or extract boot from firmware")
            self.finished_signal.emit(False, "Root access required")
            return
        
        # Find boot partition
        self.progress.emit(20, "Finding boot partition...")
        boot_path = self._find_boot_partition()
        if not boot_path:
            self.log.emit("❌ Could not find boot partition")
            self.log.emit("   Try extracting from firmware instead")
            self.finished_signal.emit(False, "Boot partition not found")
            return
        
        # Check for A/B slot
        success, output = self._run_adb(["shell", "getprop", "ro.boot.slot_suffix"])
        slot_suffix = output.strip() if success and output.strip() else ""
        
        if slot_suffix:
            boot_path_with_slot = f"{boot_path}{slot_suffix}"
            # Check if slot-specific path exists
            success, _ = self._run_adb(["shell", "su", "-c", f"test -e {boot_path_with_slot} && echo exists"])
            if success:
                boot_path = boot_path_with_slot
                self.log.emit(f"   Using A/B slot: {slot_suffix}")
        
        self.log.emit(f"📍 Boot partition: {boot_path}")
        
        # Extract boot image using dd
        self.progress.emit(40, "Extracting boot image...")
        temp_path = "/sdcard/boot_extracted.img"
        
        self.log.emit(f"   Running: dd if={boot_path} of={temp_path}")
        success, output = self._run_adb(
            ["shell", "su", "-c", f"dd if={boot_path} of={temp_path}"],
            timeout=120
        )
        
        if not success:
            self.log.emit(f"❌ Failed to extract boot: {output}")
            self.finished_signal.emit(False, "Boot extraction failed")
            return
        
        # Pull the file
        self.progress.emit(70, "Pulling boot image to PC...")
        self.log.emit(f"   Pulling to: {output_path}")
        
        success, output = self._run_adb(["pull", temp_path, output_path], timeout=120)
        if not success:
            self.log.emit(f"❌ Failed to pull boot image: {output}")
            self.finished_signal.emit(False, "Failed to pull boot image")
            return
        
        # Cleanup
        self.progress.emit(90, "Cleaning up...")
        self._run_adb(["shell", "su", "-c", f"rm -f {temp_path}"])
        
        # Verify
        if os.path.exists(output_path):
            size = os.path.getsize(output_path)
            self.log.emit(f"✅ Boot image extracted successfully!")
            self.log.emit(f"   Size: {size / 1024 / 1024:.2f} MB")
            self.log.emit(f"   Path: {output_path}")
            self.progress.emit(100, "Complete!")
            self.finished_signal.emit(True, output_path)
        else:
            self.finished_signal.emit(False, "Output file not found")
    
    def _patch_magisk_auto(self):
        """Automatically patch boot.img with Magisk on connected device."""
        device = self.kwargs.get('device')
        boot_path = self.kwargs.get('boot_path')
        
        self.log.emit("=" * 50)
        self.log.emit("🔧 PATCHING WITH MAGISK (On-Device)")
        self.log.emit("=" * 50)
        
        if not os.path.exists(boot_path):
            self.finished_signal.emit(False, f"Boot image not found: {boot_path}")
            return
        
        # Check if Magisk is installed
        self.progress.emit(10, "Checking for Magisk app...")
        success, output = self._run_adb(["shell", "pm", "list", "packages", "|", "grep", "magisk"])
        
        magisk_pkg = None
        for pkg in ['com.topjohnwu.magisk', 'io.github.vvb2060.magisk', 'com.dergoogler.mmrl']:
            success, _ = self._run_adb(["shell", "pm", "path", pkg])
            if success:
                magisk_pkg = pkg
                break
        
        if not magisk_pkg:
            self.log.emit("❌ Magisk app not installed on device")
            self.log.emit("   Please install Magisk first:")
            self.log.emit("   https://github.com/topjohnwu/Magisk/releases")
            self.finished_signal.emit(False, "Magisk not installed")
            return
        
        self.log.emit(f"✅ Found Magisk: {magisk_pkg}")
        
        # Push boot.img to device
        self.progress.emit(30, "Pushing boot.img to device...")
        dest_path = "/sdcard/Download/boot_to_patch.img"
        
        success, output = self._run_adb(["push", boot_path, dest_path])
        if not success:
            self.log.emit(f"❌ Failed to push boot image: {output}")
            self.finished_signal.emit(False, "Failed to push boot image")
            return
        
        self.log.emit(f"✅ Pushed boot.img to {dest_path}")
        
        # Try to trigger Magisk patching via intent (may not work on all versions)
        self.progress.emit(50, "Attempting to start Magisk...")
        
        # Launch Magisk app
        self._run_adb(["shell", "am", "start", "-n", f"{magisk_pkg}/.ui.MainActivity"])
        
        self.log.emit("")
        self.log.emit("📱 MANUAL STEPS REQUIRED:")
        self.log.emit("=" * 40)
        self.log.emit("1. The Magisk app should now be open on your device")
        self.log.emit("2. Tap 'Install' next to Magisk")
        self.log.emit("3. Select 'Select and Patch a File'")
        self.log.emit("4. Navigate to Download folder")
        self.log.emit("5. Select 'boot_to_patch.img'")
        self.log.emit("6. Wait for patching to complete")
        self.log.emit("7. The patched file will be in Download folder")
        self.log.emit("=" * 40)
        self.log.emit("")
        self.log.emit("⏳ Waiting for patched file...")
        self.log.emit("   (Press 'Pull Patched' when Magisk is done)")
        
        self.progress.emit(100, "Waiting for user action")
        self.finished_signal.emit(True, "ready_for_pull")
    
    def _full_patch_workflow(self):
        """Full patching workflow: extract magiskboot from APK, patch on device automatically."""
        boot_path = self.kwargs.get('boot_path')
        apk_path = self.kwargs.get('apk_path')
        method = self.kwargs.get('method', 'magisk')
        device = self.kwargs.get('device')
        
        self.log.emit("=" * 50)
        self.log.emit(f"🔧 Starting Automated {method.title()} Patching")
        self.log.emit("=" * 50)
        
        # For Magisk, we can fully automate using magiskboot
        if method == 'magisk':
            self._patch_with_magiskboot(boot_path, apk_path, device)
        else:
            # For KernelSU/APatch, fall back to semi-automated workflow
            self._patch_semi_automated(boot_path, apk_path, method, device)
    
    def _patch_with_magiskboot(self, boot_path: str, apk_path: str, device: str):
        """Fully automated Magisk patching using magiskboot extracted from APK."""
        import zipfile
        import tempfile
        
        self.log.emit("\n🔓 Using fully automated magiskboot patching...")
        
        # Get device architecture first
        self.progress.emit(5, "Detecting device architecture...")
        success, arch_output = self._run_adb(["shell", "getprop", "ro.product.cpu.abi"])
        device_arch = arch_output.strip() if success else "arm64-v8a"
        self.log.emit(f"   Device architecture: {device_arch}")
        
        # Map device arch to APK lib path
        arch_map = {
            'arm64-v8a': 'arm64-v8a',
            'armeabi-v7a': 'armeabi-v7a',
            'armeabi': 'armeabi-v7a',
            'x86_64': 'x86_64',
            'x86': 'x86'
        }
        target_arch = arch_map.get(device_arch, 'arm64-v8a')
        
        # IMPORTANT: Magisk v26.3+ has broken ARM32 binaries due to toolchain issue
        # For ARMv7 devices, we need to use Magisk v25.2 which has working ARM32 magiskboot
        # See: https://github.com/topjohnwu/Magisk/issues/7706
        use_legacy_apk = target_arch == 'armeabi-v7a'
        
        if use_legacy_apk:
            self.log.emit("⚠️ ARM32 device detected - using Magisk v25.2 for compatible magiskboot")
            legacy_apk_path = os.path.join(get_plugin_dir(), "Magisk-v25.2.apk")
            
            if not os.path.exists(legacy_apk_path):
                self.log.emit("❌ Magisk-v25.2.apk not found in plugin directory")
                self.log.emit("   Please reinstall the plugin from the store to get the ARM32 compatible APK")
                self.log.emit("   Falling back to semi-automated patching...")
                self._patch_semi_automated(boot_path, apk_path, "magisk", device)
                return
            
            # Use the legacy APK for ARM32 devices
            magiskboot_apk = legacy_apk_path
            self.log.emit(f"   Using bundled Magisk v25.2 (has working ARM32 binary)")
        else:
            # Use current APK for ARM64/x86
            magiskboot_apk = apk_path
        
        # Create temp directory for extraction
        temp_dir = tempfile.mkdtemp(prefix="magisk_patch_")
        
        try:
            # Step 1: Extract required files from Magisk APK
            self.progress.emit(10, "Extracting magiskboot from APK...")
            self.log.emit("\n📦 Step 1: Extracting tools from Magisk APK...")
            
            # Magisk APK is a zip file
            with zipfile.ZipFile(magiskboot_apk, 'r') as apk:
                # List all files to find the architecture
                all_files = apk.namelist()
                
                # Find magiskboot binary (prefer device arch, then fallback)
                magiskboot_path = None
                arch_order = [target_arch] + [a for a in ['arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86'] if a != target_arch]
                
                for arch in arch_order:
                    candidate = f"lib/{arch}/libmagiskboot.so"
                    if candidate in all_files:
                        magiskboot_path = candidate
                        self.log.emit(f"   Found magiskboot for {arch}")
                        break
                
                if not magiskboot_path:
                    self.log.emit("❌ Could not find magiskboot in APK")
                    self.finished_signal.emit(False, "magiskboot not found in APK")
                    return
                
                # Extract magiskboot
                magiskboot_local = os.path.join(temp_dir, "magiskboot")
                with open(magiskboot_local, 'wb') as f:
                    f.write(apk.read(magiskboot_path))
                
                # Extract boot_patch.sh
                if 'assets/boot_patch.sh' in all_files:
                    boot_patch_local = os.path.join(temp_dir, "boot_patch.sh")
                    with open(boot_patch_local, 'wb') as f:
                        f.write(apk.read('assets/boot_patch.sh'))
                    self.log.emit("   Extracted boot_patch.sh")
                else:
                    self.log.emit("❌ boot_patch.sh not found in APK")
                    self.finished_signal.emit(False, "boot_patch.sh not found")
                    return
                
                # Extract util_functions.sh
                if 'assets/util_functions.sh' in all_files:
                    util_local = os.path.join(temp_dir, "util_functions.sh")
                    with open(util_local, 'wb') as f:
                        f.write(apk.read('assets/util_functions.sh'))
                    self.log.emit("   Extracted util_functions.sh")
                
                # Extract stub.apk if present (needed for hiding)
                if 'assets/stub.apk' in all_files:
                    stub_local = os.path.join(temp_dir, "stub.apk")
                    with open(stub_local, 'wb') as f:
                        f.write(apk.read('assets/stub.apk'))
                    self.log.emit("   Extracted stub.apk")
            
            self.log.emit("✅ Extraction complete!")
            
            # Step 2: Push files to device
            self.progress.emit(30, "Pushing tools to device...")
            self.log.emit("\n📤 Step 2: Pushing tools to device...")
            
            work_dir = "/data/local/tmp/magisk_patch"
            
            # Create work directory
            self._run_adb(["shell", "rm", "-rf", work_dir])
            self._run_adb(["shell", "mkdir", "-p", work_dir])
            
            # Push magiskboot
            success, output = self._run_adb(["push", magiskboot_local, f"{work_dir}/magiskboot"])
            if not success:
                self.finished_signal.emit(False, f"Failed to push magiskboot: {output}")
                return
            self.log.emit("   Pushed magiskboot")
            
            # Make magiskboot executable
            self._run_adb(["shell", "chmod", "755", f"{work_dir}/magiskboot"])
            
            # Push boot_patch.sh
            success, output = self._run_adb(["push", boot_patch_local, f"{work_dir}/boot_patch.sh"])
            if not success:
                self.finished_signal.emit(False, f"Failed to push boot_patch.sh: {output}")
                return
            self.log.emit("   Pushed boot_patch.sh")
            
            # Push util_functions.sh
            util_local = os.path.join(temp_dir, "util_functions.sh")
            if os.path.exists(util_local):
                self._run_adb(["push", util_local, f"{work_dir}/util_functions.sh"])
                self.log.emit("   Pushed util_functions.sh")
            
            # Push stub.apk
            stub_local = os.path.join(temp_dir, "stub.apk")
            if os.path.exists(stub_local):
                self._run_adb(["push", stub_local, f"{work_dir}/stub.apk"])
                self.log.emit("   Pushed stub.apk")
            
            # Push boot.img
            self.progress.emit(50, "Pushing boot image...")
            self.log.emit(f"\n📤 Pushing {os.path.basename(boot_path)}...")
            
            success, output = self._run_adb(["push", boot_path, f"{work_dir}/boot.img"])
            if not success:
                self.finished_signal.emit(False, f"Failed to push boot image: {output}")
                return
            self.log.emit("✅ Boot image pushed!")
            
            # Step 3: Run boot_patch.sh on device
            self.progress.emit(60, "Patching boot image...")
            self.log.emit("\n🔧 Step 3: Running boot_patch.sh on device...")
            self.log.emit("   This may take a minute...")
            
            # Get patch options from kwargs (defaults to safe values)
            keep_verity = self.kwargs.get('keep_verity', True)
            keep_encryption = self.kwargs.get('keep_encryption', True)
            patch_vbmeta = self.kwargs.get('patch_vbmeta', False)
            
            # Log the options being used
            self.log.emit(f"   Options: KEEPVERITY={keep_verity}, KEEPFORCEENCRYPT={keep_encryption}, PATCHVBMETAFLAG={patch_vbmeta}")
            
            # Set up environment and run patch script
            # The boot_patch.sh expects certain environment variables
            # KEEPVERITY=true means KEEP verity (don't disable it)
            # KEEPFORCEENCRYPT=true means KEEP encryption (don't disable it)
            # PATCHVBMETAFLAG=true means patch vbmeta flags in boot image
            patch_cmd = f'''
                cd {work_dir} && 
                export BOOTMODE=true && 
                export KEEPVERITY={'true' if keep_verity else 'false'} && 
                export KEEPFORCEENCRYPT={'true' if keep_encryption else 'false'} && 
                export PATCHVBMETAFLAG={'true' if patch_vbmeta else 'false'} &&
                export RECOVERYMODE=false &&
                sh boot_patch.sh boot.img 2>&1
            '''
            
            success, output = self._run_adb(["shell", patch_cmd], timeout=180)
            self.log.emit(f"   Patch output: {output[:500] if output else 'No output'}")
            
            # Check for CPU compatibility issues (Illegal instruction = binary not compatible with device CPU)
            if 'Illegal instruction' in output or 'SIGILL' in output:
                self.log.emit("")
                self.log.emit("⚠️ magiskboot binary incompatible with device CPU!")
                self.log.emit("   Falling back to semi-automated patching via Magisk app...")
                self._run_adb(["shell", "rm", "-rf", work_dir])
                shutil.rmtree(temp_dir, ignore_errors=True)
                # Fall back to semi-automated
                self._patch_semi_automated(boot_path, apk_path, "magisk", device)
                return
            
            # Check if patched file was created
            check_success, check_output = self._run_adb(["shell", f"ls -la {work_dir}/new-boot.img 2>/dev/null"])
            
            if 'new-boot.img' not in check_output and not check_success:
                self.log.emit("❌ Patching failed - no output file created")
                self.log.emit(f"   Full output: {output}")
                
                # Check if it's another known error that can fall back
                if 'Unable to unpack' in output or 'error' in output.lower():
                    self.log.emit("")
                    self.log.emit("⚠️ Falling back to semi-automated patching via Magisk app...")
                    self._run_adb(["shell", "rm", "-rf", work_dir])
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    self._patch_semi_automated(boot_path, apk_path, "magisk", device)
                    return
                
                self.finished_signal.emit(False, "Patching failed - check log for details")
                return
            
            self.log.emit("✅ Patching complete!")
            
            # Step 4: Pull patched boot image
            self.progress.emit(80, "Pulling patched image...")
            self.log.emit("\n📥 Step 4: Pulling patched boot image...")
            
            # Determine output path
            boot_dir = os.path.dirname(boot_path)
            boot_name = os.path.splitext(os.path.basename(boot_path))[0]
            patched_path = os.path.join(boot_dir, f"{boot_name}_magisk_patched.img")
            
            success, output = self._run_adb(["pull", f"{work_dir}/new-boot.img", patched_path])
            if not success:
                self.log.emit(f"❌ Failed to pull patched image: {output}")
                self.finished_signal.emit(False, f"Failed to pull patched image: {output}")
                return
            
            self.log.emit(f"✅ Patched image saved to: {patched_path}")
            
            # Cleanup on-device files
            self._run_adb(["shell", "rm", "-rf", work_dir])
            
            # Check if auto_flash is requested
            auto_flash = self.kwargs.get('auto_flash', False)
            
            if auto_flash:
                # Continue to flash automatically!
                self.log.emit("")
                self.log.emit("=" * 50)
                self.log.emit("⚡ AUTO-FLASH: Continuing to flash...")
                self.log.emit("=" * 50)
                
                # Step 5: Reboot to bootloader
                self.progress.emit(85, "Rebooting to bootloader...")
                self.log.emit("\n🔄 Step 5: Rebooting to bootloader...")
                
                success, output = self._run_adb(["reboot", "bootloader"])
                if not success:
                    self.log.emit(f"⚠️ Reboot command returned: {output}")
                
                # Wait for fastboot
                self.log.emit("⏳ Waiting for device in fastboot mode...")
                import time
                for i in range(30):
                    time.sleep(2)
                    success, output = run_fastboot(["devices"])
                    if success and output.strip():
                        self.log.emit("✅ Device detected in fastboot mode!")
                        break
                    self.log.emit(f"   Waiting... ({i+1}/30)")
                else:
                    self.log.emit("❌ Device did not enter fastboot mode")
                    self.log.emit(f"   Patched file saved at: {patched_path}")
                    self.log.emit("   You can flash manually with: fastboot flash boot <patched_file>")
                    self.finished_signal.emit(True, f"patched_only:{patched_path}")
                    return
                
                # Step 6: Flash the patched boot image
                self.progress.emit(90, "Flashing patched boot...")
                self.log.emit(f"\n⚡ Step 6: Flashing {os.path.basename(patched_path)}...")
                
                # Check for A/B slot
                success, output = self._run_fastboot(["getvar", "current-slot"])
                slot = ""
                if success:
                    for line in output.split('\n'):
                        if 'current-slot:' in line.lower():
                            slot_val = line.split(':')[-1].strip()
                            if slot_val and slot_val not in ['', 'none']:
                                slot = slot_val
                                break
                
                partition = f"boot_{slot}" if slot else "boot"
                self.log.emit(f"   Target partition: {partition}")
                
                success, output = self._run_fastboot(["flash", partition, patched_path], timeout=180)
                
                if success or "OKAY" in output.upper():
                    self.log.emit("✅ Boot image flashed successfully!")
                    
                    # Step 7: Reboot
                    self.progress.emit(98, "Rebooting...")
                    self.log.emit("\n🔄 Step 7: Rebooting device...")
                    self._run_fastboot(["reboot"])
                    
                    self.log.emit("")
                    self.log.emit("=" * 50)
                    self.log.emit("🎉 ROOT COMPLETE!")
                    self.log.emit("=" * 50)
                    self.log.emit("\nYour device is now rooted with Magisk!")
                    self.log.emit("Open the Magisk app after reboot to verify.")
                    
                    self.progress.emit(100, "Root complete!")
                    self.finished_signal.emit(True, f"rooted:{patched_path}")
                else:
                    self.log.emit(f"❌ Flash failed: {output}")
                    self.log.emit(f"   Patched file saved at: {patched_path}")
                    self.finished_signal.emit(False, f"Flash failed: {output}")
            else:
                # Manual mode - just report patching complete
                self.log.emit("")
                self.log.emit("=" * 50)
                self.log.emit("🎉 PATCHING COMPLETE!")
                self.log.emit("=" * 50)
                self.log.emit(f"\nPatched file: {patched_path}")
                self.log.emit("\nNext: Click 'Flash Patched Boot Image' or reboot to bootloader first")
                
                self.progress.emit(100, "Patching complete!")
                self.finished_signal.emit(True, patched_path)
            
        except Exception as e:
            import traceback
            self.log.emit(f"❌ Error: {str(e)}")
            traceback.print_exc()
            self.finished_signal.emit(False, str(e))
        finally:
            # Cleanup temp directory
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except:
                pass
    
    def _patch_semi_automated(self, boot_path: str, apk_path: str, method: str, device: str):
        """Semi-automated patching for KernelSU/APatch (requires manual app interaction)."""
        self.log.emit(f"\n⚠️ {method.title()} requires semi-automated patching...")
        
        # Step 1: Install APK
        self.progress.emit(10, "Installing APK...")
        self.log.emit(f"\n📦 Step 1: Installing {os.path.basename(apk_path)}...")
        
        success, output = self._run_adb(["install", "-r", apk_path], timeout=120)
        if not success:
            success, output = self._run_adb(["install", "-r", "-d", apk_path], timeout=120)
            if not success:
                self.finished_signal.emit(False, f"Failed to install APK: {output}")
                return
        
        self.log.emit("✅ APK installed!")
        
        # Step 2: Push boot.img
        self.progress.emit(40, "Pushing boot.img...")
        filename = os.path.basename(boot_path)
        remote_path = f"/sdcard/Download/{filename}"
        
        success, output = self._run_adb(["push", boot_path, remote_path], timeout=120)
        if not success:
            self.finished_signal.emit(False, f"Failed to push boot image: {output}")
            return
        
        self.log.emit(f"✅ Pushed to {remote_path}")
        
        # Step 3: Launch app
        packages = {
            'kernelsu': 'me.weishu.kernelsu',
            'apatch': 'me.bmax.apatch'
        }
        package = packages.get(method)
        
        self._run_adb(["shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"])
        
        self.log.emit("")
        self.log.emit("=" * 50)
        self.log.emit("📱 MANUAL STEP REQUIRED")
        self.log.emit("=" * 50)
        self.log.emit(f"\nPatch {filename} in the {method.title()} app")
        self.log.emit("Then click 'Pull Patched boot.img'")
        
        self.progress.emit(100, "Waiting for manual patch")
        self.finished_signal.emit(True, "ready_for_manual_patch")
    
    def _flash_boot(self):
        """Flash a boot image to the device via fastboot."""
        boot_path = self.kwargs.get('boot_path')
        device = self.kwargs.get('device')
        mode = self.kwargs.get('mode', 'fastboot')
        
        self.log.emit("=" * 50)
        self.log.emit("⚡ FLASHING BOOT IMAGE")
        self.log.emit("=" * 50)
        
        if not os.path.exists(boot_path):
            self.finished_signal.emit(False, f"Boot image not found: {boot_path}")
            return
        
        if mode == 'adb':
            # Need to reboot to bootloader first
            self.log.emit("🔄 Rebooting to bootloader...")
            self.progress.emit(20, "Rebooting to bootloader...")
            
            success, output = self._run_adb(["reboot", "bootloader"])
            if not success:
                self.log.emit(f"⚠️ Reboot command returned: {output}")
            
            # Wait for fastboot
            self.log.emit("⏳ Waiting for device in fastboot mode...")
            import time
            for i in range(30):
                time.sleep(2)
                success, output = run_fastboot(["devices"])
                if success and device in output:
                    self.log.emit("✅ Device detected in fastboot mode")
                    break
            else:
                self.finished_signal.emit(False, "Device did not enter fastboot mode")
                return
        
        # Flash the boot image
        self.progress.emit(50, "Flashing boot image...")
        self.log.emit(f"📦 Flashing: {os.path.basename(boot_path)}")
        
        # Check for A/B slot
        success, output = self._run_fastboot(["getvar", "current-slot"])
        slot = ""
        if success:
            for line in output.split('\n'):
                if 'current-slot:' in line.lower():
                    slot = line.split(':')[-1].strip()
                    break
        
        partition = f"boot_{slot}" if slot else "boot"
        self.log.emit(f"   Target partition: {partition}")
        
        success, output = self._run_fastboot(["flash", partition, boot_path], timeout=180)
        
        if success or "OKAY" in output:
            self.log.emit("✅ Boot image flashed successfully!")
            self.progress.emit(80, "Flash complete!")
            
            # Reboot
            self.log.emit("🔄 Rebooting device...")
            self._run_fastboot(["reboot"])
            
            self.progress.emit(100, "Done!")
            self.finished_signal.emit(True, "Boot image flashed and device rebooted")
        else:
            self.log.emit(f"❌ Flash failed: {output}")
            self.finished_signal.emit(False, f"Flash failed: {output}")
    
    def _full_root_process(self):
        """Run the complete root process: extract -> patch -> flash."""
        method = self.kwargs.get('method', 'magisk')
        device = self.kwargs.get('device')
        
        self.log.emit("=" * 60)
        self.log.emit("🚀 FULL AUTOMATED ROOT PROCESS")
        self.log.emit(f"   Method: {method.upper()}")
        self.log.emit("=" * 60)
        
        # Step 1: Extract boot.img
        output_dir = tempfile.mkdtemp(prefix="root_patcher_")
        boot_path = os.path.join(output_dir, "boot.img")
        
        self.kwargs['output_path'] = boot_path
        self._extract_boot()
        
        if not os.path.exists(boot_path):
            return  # Error already logged
        
        self.log.emit("")
        self.log.emit("📋 Next steps depend on selected method:")
        self.log.emit(f"   Boot image saved to: {boot_path}")
        
        if method == 'magisk':
            self.log.emit("")
            self.log.emit("For MAGISK:")
            self.log.emit("1. Transfer boot.img to an Android device with Magisk installed")
            self.log.emit("2. Use Magisk app to patch the boot.img")
            self.log.emit("3. Transfer patched boot back to PC")
            self.log.emit("4. Use the 'Flash Boot' button to flash it")
        elif method == 'kernelsu':
            self.log.emit("")
            self.log.emit("For KERNELSU:")
            self.log.emit("1. Download ksud from KernelSU releases")
            self.log.emit("2. Run: ksud boot-patch -b boot.img")
            self.log.emit("3. Use the 'Flash Boot' button to flash the patched image")
        
        self.finished_signal.emit(True, boot_path)


# =============================================================================
# Plugin Widget
# =============================================================================

class PluginWidget(QWidget):
    """Main plugin widget."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.current_boot_info = None
        self.worker = None
        self.device_worker = None
        self.active_workers = []  # Keep track of all active workers
        self.selected_device = None
        self.selected_device_mode = None
        self.extracted_boot_path = None
        self.current_device_info = None  # Store device info for compatibility checks
        self._setup_ui()
    
    def _cleanup_worker(self, worker):
        """Safely cleanup a finished worker."""
        if worker in self.active_workers:
            self.active_workers.remove(worker)
        worker.deleteLater()
    
    def _setup_ui(self):
        """Setup the UI with tabs for File and Device modes."""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("🔓 <b>Root Patcher</b> - Patch boot images for root access")
        header.setStyleSheet("font-size: 14px; padding: 5px;")
        layout.addWidget(header)
        
        # Tab widget for File vs Device mode
        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(self._create_device_tab(), "📱 Device Mode")
        self.tab_widget.addTab(self._create_file_tab(), "📄 File Mode")
        self.tab_widget.addTab(self._create_gsi_tab(), "🌐 Phh GSI")
        layout.addWidget(self.tab_widget)
        
        # Shared log output
        log_group = QGroupBox("📜 Output")
        log_layout = QVBoxLayout(log_group)
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(180)
        self.log_output.setStyleSheet("font-family: Consolas, monospace; font-size: 11px;")
        log_layout.addWidget(self.log_output)
        
        layout.addWidget(log_group)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
    
    def _create_device_tab(self) -> QWidget:
        """Create the Device Mode tab for automated rooting."""
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        
        # Scroll area for all content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        layout.setSpacing(10)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Device Connection Section
        connect_group = QGroupBox("🔌 Device Connection")
        connect_layout = QVBoxLayout(connect_group)
        
        # Scan row
        scan_row = QHBoxLayout()
        self.scan_btn = QPushButton("🔍 Scan for Devices")
        self.scan_btn.clicked.connect(self._scan_devices)
        scan_row.addWidget(self.scan_btn)
        
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(200)
        self.device_combo.currentIndexChanged.connect(self._on_device_selected)
        scan_row.addWidget(self.device_combo, 1)
        
        self.refresh_btn = QPushButton("🔄")
        self.refresh_btn.setMaximumWidth(40)
        self.refresh_btn.clicked.connect(self._scan_devices)
        scan_row.addWidget(self.refresh_btn)
        connect_layout.addLayout(scan_row)
        
        # Device info
        self.device_info_label = QLabel("No device connected")
        self.device_info_label.setWordWrap(True)
        self.device_info_label.setStyleSheet("color: #888; padding: 8px; background: #1a1a2e; border-radius: 5px;")
        connect_layout.addWidget(self.device_info_label)
        
        # Bootloader status
        self.bootloader_status = QLabel("⬜ Bootloader status: Unknown")
        self.bootloader_status.setStyleSheet("padding: 5px;")
        connect_layout.addWidget(self.bootloader_status)
        
        layout.addWidget(connect_group)
        
        # Boot Image Source Section
        boot_group = QGroupBox("📁 Step 1: Select Boot Image")
        boot_layout = QVBoxLayout(boot_group)
        
        # Source options
        source_row = QHBoxLayout()
        self.boot_source_group = QButtonGroup(self)
        
        self.boot_from_device_radio = QRadioButton("Extract from Device (requires root)")
        self.boot_from_file_radio = QRadioButton("Select Local File")
        self.boot_from_file_radio.setChecked(True)
        
        self.boot_source_group.addButton(self.boot_from_device_radio, 0)
        self.boot_source_group.addButton(self.boot_from_file_radio, 1)
        
        source_row.addWidget(self.boot_from_device_radio)
        source_row.addWidget(self.boot_from_file_radio)
        source_row.addStretch()
        boot_layout.addLayout(source_row)
        
        # Local file selection
        file_row = QHBoxLayout()
        self.device_boot_path_edit = QLineEdit()
        self.device_boot_path_edit.setPlaceholderText("Select boot.img or init_boot.img from your device firmware...")
        file_row.addWidget(self.device_boot_path_edit, 1)
        
        self.device_boot_browse_btn = QPushButton("📁 Browse")
        self.device_boot_browse_btn.clicked.connect(self._browse_device_boot)
        file_row.addWidget(self.device_boot_browse_btn)
        boot_layout.addLayout(file_row)
        
        # Extract from device button (for rooted devices)
        self.extract_btn = QPushButton("📥 Extract boot.img from Device")
        self.extract_btn.setEnabled(False)
        self.extract_btn.clicked.connect(self._extract_boot_from_device)
        self.extract_btn.setVisible(False)
        boot_layout.addWidget(self.extract_btn)
        
        self.boot_source_group.buttonToggled.connect(self._on_boot_source_changed)
        
        self.boot_step_status = QLabel("⬜ Select a boot image file")
        self.boot_step_status.setStyleSheet("color: #888; padding: 5px;")
        boot_layout.addWidget(self.boot_step_status)
        
        layout.addWidget(boot_group)
        
        # Patching Method Section
        patch_group = QGroupBox("🔧 Step 2: Select Patching Method & Patch")
        patch_layout = QVBoxLayout(patch_group)
        
        # Method selection dropdown
        method_row = QHBoxLayout()
        method_row.addWidget(QLabel("Method:"))
        self.device_method_combo = QComboBox()
        self.device_method_combo.setMinimumWidth(300)
        self.device_method_combo.addItem("⬜ Magisk - Scanning...", "magisk")
        self.device_method_combo.addItem("⬜ KernelSU - Scanning...", "kernelsu")
        self.device_method_combo.addItem("⬜ APatch - Scanning...", "apatch")
        self.device_method_combo.setEnabled(False)
        method_row.addWidget(self.device_method_combo, 1)
        patch_layout.addLayout(method_row)
        
        # Patch options (matching Magisk app options)
        options_row = QHBoxLayout()
        
        self.keep_verity_check = QCheckBox("Preserve AVB/dm-verity")
        self.keep_verity_check.setChecked(True)  # DEFAULT: Keep verity to avoid bootloops!
        self.keep_verity_check.setToolTip("Keep dm-verity intact. DISABLE only if you know your device supports it.\nDisabling on incompatible devices causes BOOTLOOP!")
        options_row.addWidget(self.keep_verity_check)
        
        self.keep_encryption_check = QCheckBox("Preserve force encryption")
        self.keep_encryption_check.setChecked(True)  # DEFAULT: Keep encryption
        self.keep_encryption_check.setToolTip("Keep force encryption flag. Disable to allow decrypted /data.")
        options_row.addWidget(self.keep_encryption_check)
        
        self.patch_vbmeta_check = QCheckBox("Patch vbmeta in boot")
        self.patch_vbmeta_check.setChecked(False)  # DEFAULT: Don't patch vbmeta
        self.patch_vbmeta_check.setToolTip("Patch vbmeta flags in boot image. Only enable if your device requires it.\nEnabling on incompatible devices causes BOOTLOOP!")
        options_row.addWidget(self.patch_vbmeta_check)
        
        options_row.addStretch()
        patch_layout.addLayout(options_row)
        
        # Warning label for options
        options_warning = QLabel("⚠️ <i>Change these only if patching fails or device bootloops. Defaults work for most devices.</i>")
        options_warning.setStyleSheet("color: #fa0; font-size: 11px; padding: 2px;")
        patch_layout.addWidget(options_warning)
        
        # Auto-flash checkbox
        self.auto_flash_check = QCheckBox("⚡ Auto-flash after patching (reboot to bootloader & flash)")
        self.auto_flash_check.setChecked(True)
        self.auto_flash_check.setStyleSheet("font-weight: bold; color: #4f4;")
        patch_layout.addWidget(self.auto_flash_check)
        
        # Patch action button
        self.auto_patch_btn = QPushButton("🚀 PATCH & ROOT DEVICE")
        self.auto_patch_btn.setMinimumHeight(45)
        self.auto_patch_btn.setEnabled(False)
        self.auto_patch_btn.setStyleSheet("font-weight: bold; font-size: 14px; background-color: #2a5a2a;")
        self.auto_patch_btn.clicked.connect(self._auto_patch_selected)
        patch_layout.addWidget(self.auto_patch_btn)
        
        self.patch_status = QLabel("⬜ Select boot image first")
        self.patch_status.setStyleSheet("color: #888; padding: 5px;")
        patch_layout.addWidget(self.patch_status)
        
        # Pull patched button
        self.pull_patched_btn = QPushButton("📤 Pull Patched boot.img from Device")
        self.pull_patched_btn.setEnabled(False)
        self.pull_patched_btn.clicked.connect(self._pull_patched_boot)
        patch_layout.addWidget(self.pull_patched_btn)
        
        layout.addWidget(patch_group)
        
        # Flash Section
        flash_group = QGroupBox("⚡ Step 3: Flash to Device")
        flash_layout = QVBoxLayout(flash_group)
        
        # Patched file path
        patched_row = QHBoxLayout()
        patched_row.addWidget(QLabel("Patched file:"))
        self.patched_path_edit = QLineEdit()
        self.patched_path_edit.setPlaceholderText("Patched boot image will appear here...")
        self.patched_path_edit.textChanged.connect(self._on_patched_path_changed)
        patched_row.addWidget(self.patched_path_edit, 1)
        browse_patched_btn = QPushButton("📁")
        browse_patched_btn.setMaximumWidth(40)
        browse_patched_btn.clicked.connect(self._browse_patched)
        patched_row.addWidget(browse_patched_btn)
        flash_layout.addLayout(patched_row)
        
        # Flash buttons row
        flash_btn_row = QHBoxLayout()
        
        self.reboot_bl_btn = QPushButton("🔄 Reboot to Bootloader")
        self.reboot_bl_btn.clicked.connect(self._reboot_bootloader)
        self.reboot_bl_btn.setEnabled(False)
        flash_btn_row.addWidget(self.reboot_bl_btn)
        
        self.flash_btn = QPushButton("⚡ Flash Patched Boot Image")
        self.flash_btn.setMinimumHeight(40)
        self.flash_btn.setEnabled(False)
        self.flash_btn.setStyleSheet("font-weight: bold;")
        self.flash_btn.clicked.connect(self._flash_patched_boot)
        flash_btn_row.addWidget(self.flash_btn)
        flash_layout.addLayout(flash_btn_row)
        
        self.flash_status = QLabel("⬜ Patch boot.img first")
        self.flash_status.setStyleSheet("color: #888; padding: 5px;")
        flash_layout.addWidget(self.flash_status)
        
        layout.addWidget(flash_group)
        
        # Quick Actions
        quick_group = QGroupBox("⚡ Quick Actions")
        quick_layout = QHBoxLayout(quick_group)
        
        reboot_btn = QPushButton("🔄 Reboot Device")
        reboot_btn.clicked.connect(self._reboot_device)
        quick_layout.addWidget(reboot_btn)
        
        layout.addWidget(quick_group)
        
        layout.addStretch()
        scroll.setWidget(scroll_content)
        tab_layout.addWidget(scroll)
        return tab
    
    def _browse_device_boot(self):
        """Browse for local boot.img file."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Boot Image",
            "", "Image Files (*.img);;All Files (*.*)"
        )
        if path:
            self.device_boot_path_edit.setText(path)
            self._on_device_boot_path_changed(path)
    
    def _on_device_boot_path_changed(self, path: str):
        """Handle boot image path change."""
        if path and os.path.isfile(path):
            filename = os.path.basename(path).lower()
            if 'init_boot' in filename:
                self.boot_step_status.setText(f"✅ Selected init_boot.img (for Android 13+ GKI)")
            else:
                self.boot_step_status.setText(f"✅ Selected: {os.path.basename(path)}")
            self.boot_step_status.setStyleSheet("color: #4f4; padding: 5px;")
            
            # Enable patching if device connected
            if self.selected_device:
                self.auto_patch_btn.setEnabled(True)
                self.patch_status.setText("✅ Ready to patch")
                self.patch_status.setStyleSheet("color: #4f4; padding: 5px;")
        else:
            self.boot_step_status.setText("⬜ Select a boot image file")
            self.boot_step_status.setStyleSheet("color: #888; padding: 5px;")
            self.auto_patch_btn.setEnabled(False)
    
    def _on_boot_source_changed(self, button, checked):
        """Handle boot source radio button change."""
        if not checked:
            return
        
        if button == self.boot_from_file_radio:
            self.device_boot_path_edit.setVisible(True)
            self.device_boot_browse_btn.setVisible(True)
            self.extract_btn.setVisible(False)
        else:
            self.device_boot_path_edit.setVisible(False)
            self.device_boot_browse_btn.setVisible(False)
            self.extract_btn.setVisible(True)
            # Enable extract if device is rooted
            if self.current_device_info and self.current_device_info.get('is_rooted'):
                self.extract_btn.setEnabled(True)
    
    def _create_file_tab(self) -> QWidget:
        """Create the File Mode tab (original functionality)."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(8)
        
        # Boot image selection
        select_group = QGroupBox("📱 Boot Image")
        select_layout = QVBoxLayout(select_group)
        
        file_row = QHBoxLayout()
        self.boot_path_edit = QLineEdit()
        self.boot_path_edit.setPlaceholderText("Select boot.img file...")
        self.boot_path_edit.textChanged.connect(self._on_boot_path_changed)
        file_row.addWidget(self.boot_path_edit, 1)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(self._browse_boot)
        file_row.addWidget(browse_btn)
        
        analyze_btn = QPushButton("🔍 Analyze")
        analyze_btn.clicked.connect(self._analyze_boot)
        file_row.addWidget(analyze_btn)
        select_layout.addLayout(file_row)
        
        layout.addWidget(select_group)
        
        # Boot image info
        info_group = QGroupBox("📊 Boot Image Analysis")
        info_layout = QVBoxLayout(info_group)
        
        self.info_label = QLabel("No boot image selected")
        self.info_label.setWordWrap(True)
        self.info_label.setStyleSheet("color: #888; padding: 10px;")
        info_layout.addWidget(self.info_label)
        
        layout.addWidget(info_group)
        
        # Compatibility status
        compat_group = QGroupBox("✅ Rooting Method Compatibility")
        compat_layout = QVBoxLayout(compat_group)
        
        self.magisk_status = QLabel("⬜ Magisk - Select a boot image first")
        self.apatch_status = QLabel("⬜ APatch - Select a boot image first")
        self.kernelsu_status = QLabel("⬜ KernelSU - Select a boot image first")
        self.gsi_status = QLabel("⬜ Phh GSI - Project Treble device required")
        
        for label in [self.magisk_status, self.apatch_status, self.kernelsu_status, self.gsi_status]:
            label.setStyleSheet("font-size: 12px; padding: 5px;")
            compat_layout.addWidget(label)
        
        layout.addWidget(compat_group)
        
        # Patching options
        patch_group = QGroupBox("🔧 Patch Boot Image")
        patch_layout = QVBoxLayout(patch_group)
        
        # Method selection
        method_row = QHBoxLayout()
        method_row.addWidget(QLabel("Method:"))
        
        self.method_group = QButtonGroup(self)
        self.magisk_radio = QRadioButton("Magisk")
        self.apatch_radio = QRadioButton("APatch")
        self.kernelsu_radio = QRadioButton("KernelSU")
        self.gsi_radio = QRadioButton("Phh GSI")
        self.magisk_radio.setChecked(True)
        
        self.method_group.addButton(self.magisk_radio, 0)
        self.method_group.addButton(self.apatch_radio, 1)
        self.method_group.addButton(self.kernelsu_radio, 2)
        self.method_group.addButton(self.gsi_radio, 3)
        
        method_row.addWidget(self.magisk_radio)
        method_row.addWidget(self.apatch_radio)
        method_row.addWidget(self.kernelsu_radio)
        method_row.addWidget(self.gsi_radio)
        method_row.addStretch()
        patch_layout.addLayout(method_row)
        
        # Info about selected method
        self.method_info = QLabel(
            "ℹ️ <b>Magisk</b>: Most compatible, works on almost all devices. "
            "Patches are done through the Magisk app on an Android device."
        )
        self.method_info.setWordWrap(True)
        self.method_info.setStyleSheet("color: #aaa; padding: 10px; background: #1a1a2e; border-radius: 5px;")
        patch_layout.addWidget(self.method_info)
        
        self.magisk_radio.toggled.connect(self._update_method_info)
        self.apatch_radio.toggled.connect(self._update_method_info)
        self.kernelsu_radio.toggled.connect(self._update_method_info)
        self.gsi_radio.toggled.connect(self._update_method_info)
        
        # Patch button
        self.patch_btn = QPushButton("📋 Show Patching Instructions")
        self.patch_btn.setMinimumHeight(40)
        self.patch_btn.setStyleSheet("font-weight: bold; font-size: 13px;")
        self.patch_btn.clicked.connect(self._start_patch)
        patch_layout.addWidget(self.patch_btn)
        
        layout.addWidget(patch_group)
        
        layout.addStretch()
        return tab
    
    def _create_gsi_tab(self) -> QWidget:
        """Create the Phh GSI tab for Generic System Image rooting."""
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        
        # Scroll area for all content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        layout.setSpacing(12)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Coming Soon Banner
        banner = QLabel("🚧 <b>Coming Soon</b> - Automated Phh GSI Flashing")
        banner.setStyleSheet("""
            font-size: 16px; 
            color: #ffa500; 
            padding: 15px; 
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2a2a3e, stop:1 #1a1a2e);
            border-radius: 8px;
            border: 1px solid #ffa500;
        """)
        banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        banner.setMinimumHeight(50)
        layout.addWidget(banner)
        
        # GSI Selection Section
        gsi_group = QGroupBox("🌐 GSI Image Selection")
        gsi_layout = QFormLayout(gsi_group)
        gsi_layout.setSpacing(8)
        gsi_layout.setContentsMargins(10, 15, 10, 10)
        
        self.gsi_source_combo = QComboBox()
        self.gsi_source_combo.addItems([
            "Phh Treble (Official)",
            "AndyYan LineageOS GSI",
            "ErfanGSI",
            "Custom GSI URL"
        ])
        self.gsi_source_combo.setEnabled(False)
        gsi_layout.addRow("GSI Source:", self.gsi_source_combo)
        
        self.gsi_arch_combo = QComboBox()
        self.gsi_arch_combo.addItems(["arm64-ab", "arm64-a", "arm-ab", "arm-a"])
        self.gsi_arch_combo.setEnabled(False)
        gsi_layout.addRow("Architecture:", self.gsi_arch_combo)
        
        self.gsi_version_combo = QComboBox()
        self.gsi_version_combo.addItems(["Android 14", "Android 13", "Android 12L", "Android 12", "Android 11"])
        self.gsi_version_combo.setEnabled(False)
        gsi_layout.addRow("Android Version:", self.gsi_version_combo)
        
        self.gsi_url_edit = QLineEdit()
        self.gsi_url_edit.setPlaceholderText("https://github.com/.../system.img.xz")
        self.gsi_url_edit.setEnabled(False)
        gsi_layout.addRow("Custom URL:", self.gsi_url_edit)
        
        self.gsi_download_btn = QPushButton("📥 Download GSI Image")
        self.gsi_download_btn.setMinimumHeight(38)
        self.gsi_download_btn.setEnabled(False)
        self.gsi_download_btn.setStyleSheet("font-weight: bold; font-size: 12px;")
        gsi_layout.addRow("", self.gsi_download_btn)
        
        layout.addWidget(gsi_group)
        
        # Root Options Section
        root_group = QGroupBox("🔓 Built-in Root Options")
        root_layout = QVBoxLayout(root_group)
        root_layout.setSpacing(10)
        root_layout.setContentsMargins(10, 15, 10, 10)
        
        self.gsi_root_check = QCheckBox("Enable Phh Superuser (built-in root)")
        self.gsi_root_check.setChecked(True)
        self.gsi_root_check.setEnabled(False)
        root_layout.addWidget(self.gsi_root_check)
        
        self.gsi_overlay_check = QCheckBox("Enable overlayfs for system modifications")
        self.gsi_overlay_check.setEnabled(False)
        root_layout.addWidget(self.gsi_overlay_check)
        
        self.gsi_signature_check = QCheckBox("Disable signature verification (dm-verity)")
        self.gsi_signature_check.setChecked(True)
        self.gsi_signature_check.setEnabled(False)
        root_layout.addWidget(self.gsi_signature_check)
        
        info_label = QLabel(
            "ℹ️ Phh GSI includes Phh Superuser which provides root access without "
            "needing Magisk. Root can be toggled via Developer Options → Phh Superuser."
        )
        info_label.setWordWrap(True)
        info_label.setMinimumHeight(45)
        info_label.setStyleSheet("color: #aaa; padding: 10px; background: #1a1a2e; border-radius: 5px;")
        root_layout.addWidget(info_label)
        
        layout.addWidget(root_group)
        
        # System Partition Operations
        system_group = QGroupBox("💾 System Partition Operations")
        system_layout = QVBoxLayout(system_group)
        system_layout.setSpacing(10)
        system_layout.setContentsMargins(10, 15, 10, 10)
        
        # Backup row
        backup_row = QHBoxLayout()
        self.gsi_backup_btn = QPushButton("📦 Backup Current System")
        self.gsi_backup_btn.setMinimumHeight(38)
        self.gsi_backup_btn.setMinimumWidth(180)
        self.gsi_backup_btn.setEnabled(False)
        backup_row.addWidget(self.gsi_backup_btn)
        
        self.gsi_backup_path = QLineEdit()
        self.gsi_backup_path.setPlaceholderText("Backup destination...")
        self.gsi_backup_path.setEnabled(False)
        self.gsi_backup_path.setMinimumHeight(32)
        backup_row.addWidget(self.gsi_backup_path, 1)
        
        backup_browse = QPushButton("📁")
        backup_browse.setFixedSize(40, 32)
        backup_browse.setEnabled(False)
        backup_row.addWidget(backup_browse)
        system_layout.addLayout(backup_row)
        
        # Flash row
        flash_row = QHBoxLayout()
        self.gsi_flash_btn = QPushButton("⚡ Flash GSI to System")
        self.gsi_flash_btn.setMinimumHeight(38)
        self.gsi_flash_btn.setMinimumWidth(180)
        self.gsi_flash_btn.setEnabled(False)
        self.gsi_flash_btn.setStyleSheet("font-weight: bold;")
        flash_row.addWidget(self.gsi_flash_btn)
        
        self.gsi_image_path = QLineEdit()
        self.gsi_image_path.setPlaceholderText("Select GSI system.img...")
        self.gsi_image_path.setEnabled(False)
        self.gsi_image_path.setMinimumHeight(32)
        flash_row.addWidget(self.gsi_image_path, 1)
        
        flash_browse = QPushButton("📁")
        flash_browse.setFixedSize(40, 32)
        flash_browse.setEnabled(False)
        flash_row.addWidget(flash_browse)
        system_layout.addLayout(flash_row)
        
        # Restore row
        restore_row = QHBoxLayout()
        self.gsi_restore_btn = QPushButton("🔄 Restore Original System")
        self.gsi_restore_btn.setMinimumHeight(38)
        self.gsi_restore_btn.setMinimumWidth(180)
        self.gsi_restore_btn.setEnabled(False)
        restore_row.addWidget(self.gsi_restore_btn)
        restore_row.addStretch()
        system_layout.addLayout(restore_row)
        
        layout.addWidget(system_group)
        
        # Treble Check Section
        treble_group = QGroupBox("🔍 Device Compatibility")
        treble_layout = QVBoxLayout(treble_group)
        treble_layout.setSpacing(10)
        treble_layout.setContentsMargins(10, 15, 10, 10)
        
        check_row = QHBoxLayout()
        self.gsi_treble_check_btn = QPushButton("🔍 Check Treble Support")
        self.gsi_treble_check_btn.setMinimumHeight(38)
        self.gsi_treble_check_btn.setMinimumWidth(180)
        self.gsi_treble_check_btn.setEnabled(False)
        check_row.addWidget(self.gsi_treble_check_btn)
        
        self.gsi_treble_status = QLabel("⬜ Connect device to check Treble/GSI compatibility")
        self.gsi_treble_status.setStyleSheet("padding-left: 10px;")
        check_row.addWidget(self.gsi_treble_status, 1)
        treble_layout.addLayout(check_row)
        
        # Compatibility info
        compat_info = QLabel(
            "<b>Requirements:</b> Project Treble support, unlocked bootloader, "
            "fastbootd support (A/B devices)"
        )
        compat_info.setWordWrap(True)
        compat_info.setMinimumHeight(30)
        compat_info.setStyleSheet("color: #888; padding: 8px;")
        treble_layout.addWidget(compat_info)
        
        layout.addWidget(treble_group)
        
        layout.addStretch()
        
        scroll.setWidget(scroll_content)
        tab_layout.addWidget(scroll)
        return tab
    
    # =========================================================================
    # Device Mode Methods
    # =========================================================================
    
    def _scan_devices(self):
        """Scan for connected ADB/Fastboot devices."""
        self.device_combo.clear()
        self.device_combo.addItem("Scanning...")
        self.scan_btn.setEnabled(False)
        
        worker = DevicePatcherWorker("detect_devices")
        worker.log.connect(self._log)
        worker.progress.connect(self._on_device_progress)
        worker.device_info.connect(self._on_devices_found)
        worker.finished_signal.connect(self._on_scan_complete)
        worker.finished_signal.connect(lambda s, m: self._cleanup_worker(worker))
        self.active_workers.append(worker)
        self.device_worker = worker
        worker.start()
    
    def _on_device_progress(self, value: int, msg: str):
        """Handle device operation progress."""
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(value)
    
    def _on_devices_found(self, devices: dict):
        """Handle device list received."""
        self.device_combo.clear()
        
        # Add ADB devices
        for dev in devices.get('adb', []):
            self.device_combo.addItem(
                f"📱 {dev['serial']} (ADB - {dev['state']})",
                {'serial': dev['serial'], 'mode': 'adb'}
            )
        
        # Add Fastboot devices
        for dev in devices.get('fastboot', []):
            self.device_combo.addItem(
                f"⚡ {dev['serial']} (Fastboot)",
                {'serial': dev['serial'], 'mode': 'fastboot'}
            )
        
        if self.device_combo.count() == 0:
            self.device_combo.addItem("No devices found")
    
    def _on_scan_complete(self, success: bool, msg: str):
        """Handle scan completion."""
        self.scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if self.device_combo.count() > 0 and "No devices" not in self.device_combo.currentText():
            self._on_device_selected(0)
    
    def _on_device_selected(self, index: int):
        """Handle device selection change."""
        if index < 0:
            return
        
        data = self.device_combo.currentData()
        if not data:
            self.device_info_label.setText("No device selected")
            self._update_device_buttons(False, False)
            return
        
        self.selected_device = data['serial']
        self.selected_device_mode = data['mode']
        
        # Get device info
        worker = DevicePatcherWorker(
            "get_device_info",
            device=self.selected_device,
            mode=self.selected_device_mode
        )
        worker.log.connect(self._log)
        worker.device_info.connect(self._on_device_info_received)
        worker.finished_signal.connect(lambda s, m: self._cleanup_worker(worker))
        self.active_workers.append(worker)
        self.device_worker = worker
        worker.start()
    
    def _on_device_info_received(self, info: dict):
        """Handle device info received."""
        # Store device info for compatibility checks
        self.current_device_info = info
        
        if info['mode'] == 'adb':
            text = f"""
<b>Device:</b> {info['manufacturer']} {info['model']}<br>
<b>Android:</b> {info['android_version']} (SDK {info['sdk_level']})<br>
<b>Architecture:</b> {info['arch']}<br>
<b>Root:</b> {'✅ Yes' if info['is_rooted'] else '❌ No'}<br>
<b>Treble:</b> {'✅ Yes' if info['has_treble'] else '❌ No'} | 
<b>A/B:</b> {'✅ Yes' if info['is_ab'] else '❌ No'}
{f"<br><b>Slot:</b> {info['boot_slot']}" if info['boot_slot'] else ''}
"""
            # Check bootloader status
            bootloader_unlocked = info.get('bootloader_unlocked', None)
            if bootloader_unlocked is True:
                self.bootloader_status.setText("✅ Bootloader: UNLOCKED - Ready to flash!")
                self.bootloader_status.setStyleSheet("color: #4f4; padding: 5px;")
            elif bootloader_unlocked is False:
                self.bootloader_status.setText("❌ Bootloader: LOCKED - Unlock required before flashing")
                self.bootloader_status.setStyleSheet("color: #f44; padding: 5px;")
            else:
                self.bootloader_status.setText("⚠️ Bootloader: Unknown (check in fastboot mode)")
                self.bootloader_status.setStyleSheet("color: #fa0; padding: 5px;")
        else:
            text = f"""
<b>Device:</b> {info['serial']} (Fastboot mode)<br>
<b>Model:</b> {info['model']}<br>
<b>A/B:</b> {'✅ Yes' if info['is_ab'] else '❌ No'}
{f"<br><b>Slot:</b> {info['boot_slot']}" if info['boot_slot'] else ''}
"""
            # In fastboot we can check bootloader status better
            bootloader_unlocked = info.get('bootloader_unlocked', None)
            if bootloader_unlocked is True:
                self.bootloader_status.setText("✅ Bootloader: UNLOCKED - Ready to flash!")
                self.bootloader_status.setStyleSheet("color: #4f4; padding: 5px;")
            elif bootloader_unlocked is False:
                self.bootloader_status.setText("❌ Bootloader: LOCKED - Cannot flash boot images")
                self.bootloader_status.setStyleSheet("color: #f44; padding: 5px;")
            else:
                self.bootloader_status.setText("⚠️ Bootloader: Unknown")
                self.bootloader_status.setStyleSheet("color: #fa0; padding: 5px;")
        
        self.device_info_label.setText(text)
        
        # Update method compatibility dropdown
        self._update_method_compatibility(info)
        
        # Update button states
        is_rooted = info.get('is_rooted', False)
        is_fastboot = info['mode'] == 'fastboot'
        self._update_device_buttons(is_rooted, is_fastboot)
        
        # Enable reboot to bootloader button if connected
        self.reboot_bl_btn.setEnabled(not is_fastboot)
        
        # Enable patching if boot image is selected
        if self.device_boot_path_edit.text() and os.path.isfile(self.device_boot_path_edit.text()):
            self.auto_patch_btn.setEnabled(not is_fastboot)
            self.patch_status.setText("✅ Ready to patch")
            self.patch_status.setStyleSheet("color: #4f4; padding: 5px;")
        
        # Enable extract if rooted
        if is_rooted and self.boot_from_device_radio.isChecked():
            self.extract_btn.setEnabled(True)
    
    def _update_method_compatibility(self, info: dict):
        """Update the method dropdown with compatibility status."""
        sdk_level = info.get('sdk_level', 0)
        try:
            sdk = int(sdk_level)
        except:
            sdk = 0
        
        kernel_version = info.get('kernel_version', '')
        arch = info.get('arch', '')
        
        # Magisk: Works on almost everything Android 5.0+ (SDK 21+)
        magisk_ok = sdk >= 21
        magisk_status = "✅" if magisk_ok else "❌"
        magisk_reason = "Fully Automated" if magisk_ok else "Requires Android 5.0+"
        
        # KernelSU: Requires GKI kernel (Android 12+ with 5.10+ kernel)
        # GKI kernels: 5.10, 5.15, 6.1, 6.6
        kernelsu_ok = False
        kernelsu_reason = "Semi-Auto (GKI kernel required)"
        if sdk >= 31:  # Android 12+
            for gki_ver in ['5.10', '5.15', '6.1', '6.6']:
                if kernel_version.startswith(gki_ver):
                    kernelsu_ok = True
                    kernelsu_reason = f"Semi-Auto (GKI {gki_ver})"
                    break
            if not kernelsu_ok and kernel_version:
                kernelsu_reason = f"Kernel {kernel_version[:10]} not GKI"
        else:
            kernelsu_reason = "Requires Android 12+"
        kernelsu_status = "✅" if kernelsu_ok else "❌"
        
        # APatch: Android 11+ (SDK 30+), arm64 only
        apatch_ok = sdk >= 30 and 'arm64' in arch.lower()
        apatch_status = "✅" if apatch_ok else "❌"
        if sdk < 30:
            apatch_reason = "Requires Android 11+"
        elif 'arm64' not in arch.lower():
            apatch_reason = "Requires arm64 architecture"
        else:
            apatch_reason = "Semi-Auto (arm64)"
        
        # Update dropdown items
        self.device_method_combo.clear()
        self.device_method_combo.addItem(f"{magisk_status} Magisk - {magisk_reason}", "magisk")
        self.device_method_combo.addItem(f"{kernelsu_status} KernelSU - {kernelsu_reason}", "kernelsu")
        self.device_method_combo.addItem(f"{apatch_status} APatch - {apatch_reason}", "apatch")
        
        # Select first compatible method
        if magisk_ok:
            self.device_method_combo.setCurrentIndex(0)
        elif kernelsu_ok:
            self.device_method_combo.setCurrentIndex(1)
        elif apatch_ok:
            self.device_method_combo.setCurrentIndex(2)
        
        self.device_method_combo.setEnabled(True)
    
    def _auto_patch_selected(self):
        """Patch with the selected method - full workflow."""
        method = self.device_method_combo.currentData()
        
        # Get boot image path (from local file or extracted)
        boot_path = self.device_boot_path_edit.text()
        if not boot_path or not os.path.isfile(boot_path):
            QMessageBox.warning(self, "Error", "Please select a boot.img file first")
            return
        
        if not self.selected_device:
            QMessageBox.warning(self, "Error", "No device connected")
            return
        
        # Find the APK for the selected method
        plugin_dir = get_plugin_dir()
        apk_patterns = {
            'magisk': 'Magisk*.apk',
            'kernelsu': 'KernelSU*.apk', 
            'apatch': 'APatch*.apk'
        }
        
        import glob
        pattern = os.path.join(plugin_dir, apk_patterns.get(method, ''))
        apk_files = glob.glob(pattern)
        
        if not apk_files:
            QMessageBox.warning(
                self, "Error", 
                f"No {method.title()} APK found in plugin directory.\n"
                "Please reinstall the plugin from the store."
            )
            return
        
        apk_path = apk_files[0]  # Use first match
        
        # Check if auto-flash is enabled
        auto_flash = self.auto_flash_check.isChecked()
        
        # Confirm with user - different message for Magisk (fully auto) vs others
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Question)
        msg.setWindowTitle("Confirm Rooting")
        msg.setText(f"Ready to root with {method.title()}")
        
        if method == 'magisk':
            if auto_flash:
                msg.setInformativeText(
                    f"This will FULLY AUTOMATICALLY:\n"
                    f"1. Extract magiskboot from APK\n"
                    f"2. Patch {os.path.basename(boot_path)} on device\n"
                    f"3. Pull patched image\n"
                    f"4. Reboot to bootloader\n"
                    f"5. Flash patched boot\n"
                    f"6. Reboot device\n\n"
                    f"⚠️ Your device will be ROOTED after this!\n\n"
                    f"Continue?"
                )
            else:
                msg.setInformativeText(
                    f"This will automatically:\n"
                    f"1. Extract magiskboot from APK\n"
                    f"2. Patch {os.path.basename(boot_path)} on device\n"
                    f"3. Pull patched image\n\n"
                    f"You'll need to flash manually after.\n\n"
                    f"Continue?"
                )
        else:
            msg.setInformativeText(
                f"This will:\n"
                f"1. Install {os.path.basename(apk_path)} on device\n"
                f"2. Push {os.path.basename(boot_path)} to device\n"
                f"3. Guide you to patch in the app\n"
                f"4. Pull the patched image back\n\n"
                f"Continue?"
            )
        msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if msg.exec() != QMessageBox.StandardButton.Yes:
            return
        
        # Get patch options
        keep_verity = self.keep_verity_check.isChecked()
        keep_encryption = self.keep_encryption_check.isChecked()
        patch_vbmeta = self.patch_vbmeta_check.isChecked()
        
        # Start the patching workflow
        self.auto_patch_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        
        worker = DevicePatcherWorker(
            "full_patch_workflow",
            device=self.selected_device,
            boot_path=boot_path,
            apk_path=apk_path,
            method=method,
            auto_flash=auto_flash,
            keep_verity=keep_verity,
            keep_encryption=keep_encryption,
            patch_vbmeta=patch_vbmeta
        )
        worker.log.connect(self._log)
        worker.progress.connect(self._on_device_progress)
        worker.finished_signal.connect(self._on_full_patch_complete)
        worker.finished_signal.connect(lambda s, m: self._cleanup_worker(worker))
        self.active_workers.append(worker)
        self.device_worker = worker
        worker.start()
    
    def _on_full_patch_complete(self, success: bool, result: str):
        """Handle full patch workflow completion."""
        self.progress_bar.setVisible(False)
        self.auto_patch_btn.setEnabled(True)
        
        if success:
            if result == "ready_for_manual_patch":
                # App is installed, boot.img pushed - user needs to patch manually
                self.patch_status.setText("⏳ Patch in app, then click Pull")
                self.patch_status.setStyleSheet("color: #fa0; padding: 5px;")
                self.pull_patched_btn.setEnabled(True)
                
                QMessageBox.information(
                    self, "Next Step",
                    "The root app has been installed and boot.img pushed to your device.\n\n"
                    "Now:\n"
                    "1. Open the app on your device\n"
                    "2. Select the boot.img from /sdcard/Download/\n"
                    "3. Patch it in the app\n"
                    "4. Click 'Pull Patched boot.img' when done"
                )
            elif result.startswith('rooted:'):
                # FULLY ROOTED! Auto-flash completed successfully
                patched_path = result.replace('rooted:', '')
                self.patched_path_edit.setText(patched_path)
                self.patch_status.setText("🎉 DEVICE ROOTED!")
                self.patch_status.setStyleSheet("color: #4f4; font-weight: bold; padding: 5px;")
                self.flash_status.setText("✅ Flash complete - device rebooting")
                self.flash_status.setStyleSheet("color: #4f4; padding: 5px;")
                
                QMessageBox.information(
                    self, "🎉 ROOT COMPLETE!",
                    f"Your device has been successfully rooted!\n\n"
                    f"Patched file: {os.path.basename(patched_path)}\n\n"
                    f"Your device is now rebooting.\n"
                    f"Open the Magisk app after boot to verify root status."
                )
            elif result.startswith('patched_only:'):
                # Patching done but flash failed/skipped
                patched_path = result.replace('patched_only:', '')
                self.patched_path_edit.setText(patched_path)
                self.patch_status.setText("✅ Patched (flash manually)")
                self.patch_status.setStyleSheet("color: #fa0; padding: 5px;")
                self.flash_btn.setEnabled(True)
                self.flash_status.setText("⚠️ Flash manually needed")
                self.flash_status.setStyleSheet("color: #fa0; padding: 5px;")
                
                QMessageBox.warning(
                    self, "Patching Complete - Flash Manually",
                    f"Boot image was patched but could not auto-flash.\n\n"
                    f"Patched file: {patched_path}\n\n"
                    f"Please flash manually:\n"
                    f"1. Reboot to bootloader\n"
                    f"2. Click 'Flash Patched Boot Image'"
                )
            elif result.endswith('.img'):
                # Got the patched file path - automated patching complete (no auto-flash)
                self.patched_path_edit.setText(result)
                self.patch_status.setText("✅ Patched image ready!")
                self.patch_status.setStyleSheet("color: #4f4; padding: 5px;")
                self.flash_btn.setEnabled(True)
                self.flash_status.setText("✅ Ready to flash")
                self.flash_status.setStyleSheet("color: #4f4; padding: 5px;")
                
                QMessageBox.information(
                    self, "Patching Complete",
                    f"Boot image patched successfully!\n\n"
                    f"Patched file saved to:\n{result}\n\n"
                    f"You can now flash the patched image to your device."
                )
        else:
            self.patch_status.setText(f"❌ {result}")
            self.patch_status.setStyleSheet("color: #f44; padding: 5px;")
            QMessageBox.warning(self, "Error", f"Patching failed: {result}")
    
    def _auto_patch_kernelsu(self):
        """Patch boot image with KernelSU."""
        self._auto_patch_selected()
    
    def _auto_patch_apatch(self):
        """Patch boot image with APatch."""
        self._auto_patch_selected()
    
    def _update_device_buttons(self, is_rooted: bool, is_fastboot: bool):
        """Update device mode button states."""
        # Extract requires root (only when using extract from device option)
        if hasattr(self, 'boot_from_device_radio') and self.boot_from_device_radio.isChecked():
            self.extract_btn.setEnabled(is_rooted and not is_fastboot)
        
        # Flash works in fastboot mode or ADB with unlocked bootloader
        if self.patched_path_edit.text():
            self.flash_btn.setEnabled(True)
            self.flash_status.setText("✅ Ready to flash")
            self.flash_status.setStyleSheet("color: #4f4; padding: 5px;")
        else:
            self.flash_btn.setEnabled(False)
            self.flash_status.setText("⬜ Patch boot.img first")
            self.flash_status.setStyleSheet("color: #888; padding: 5px;")
    
    def _extract_boot_from_device(self):
        """Extract boot.img from connected device."""
        if not self.selected_device:
            return
        
        # Ask where to save
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Extracted Boot Image",
            "boot.img", "Image Files (*.img)"
        )
        if not path:
            return
        
        self.extract_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        
        worker = DevicePatcherWorker(
            "extract_boot",
            device=self.selected_device,
            output_path=path
        )
        worker.log.connect(self._log)
        worker.progress.connect(self._on_device_progress)
        worker.finished_signal.connect(self._on_extract_complete)
        worker.finished_signal.connect(lambda s, m: self._cleanup_worker(worker))
        self.active_workers.append(worker)
        self.device_worker = worker
        worker.start()
    
    def _on_extract_complete(self, success: bool, result: str):
        """Handle boot extraction completion."""
        self.extract_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if success:
            self.extracted_boot_path = result
            self.extract_status.setText(f"✅ Extracted: {os.path.basename(result)}")
            self.extract_status.setStyleSheet("color: #4f4; padding-left: 60px;")
            
            # Enable patching
            self.auto_patch_btn.setEnabled(True)
            self.patch_status.setText("✅ Ready to patch")
            self.patch_status.setStyleSheet("color: #4f4; padding-left: 60px;")
            
            QMessageBox.information(self, "Success", f"Boot image extracted to:\n{result}")
        else:
            QMessageBox.warning(self, "Error", f"Extraction failed: {result}")
    
    def _auto_patch_magisk(self):
        """Start automated Magisk patching on device."""
        if not self.selected_device or not self.extracted_boot_path:
            return
        
        self.auto_patch_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        
        worker = DevicePatcherWorker(
            "patch_magisk_auto",
            device=self.selected_device,
            boot_path=self.extracted_boot_path
        )
        worker.log.connect(self._log)
        worker.progress.connect(self._on_device_progress)
        worker.finished_signal.connect(self._on_auto_patch_complete)
        worker.finished_signal.connect(lambda s, m: self._cleanup_worker(worker))
        self.active_workers.append(worker)
        self.device_worker = worker
        worker.start()
    
    def _on_auto_patch_complete(self, success: bool, result: str):
        """Handle auto patch completion."""
        self.progress_bar.setVisible(False)
        self.auto_patch_btn.setEnabled(True)
        
        if success and result == "ready_for_pull":
            # Enable pull button
            self.pull_patched_btn.setEnabled(True)
            self.patch_status.setText("⏳ Patch on device, then pull")
            self.patch_status.setStyleSheet("color: #fa0; padding-left: 60px;")
    
    def _pull_patched_boot(self):
        """Pull patched boot image from device."""
        if not self.selected_device:
            return
        
        # Find patched file
        success, output = run_adb(["shell", "ls", "/sdcard/Download/magisk_patched*.img"], self.selected_device)
        
        if not success or not output.strip():
            QMessageBox.warning(
                self, "Not Found",
                "No patched boot image found in /sdcard/Download/\n\n"
                "Make sure Magisk has finished patching."
            )
            return
        
        # Get the most recent patched file
        files = [f.strip() for f in output.strip().split('\n') if f.strip()]
        if not files:
            return
        
        remote_path = files[-1]  # Most recent
        
        # Ask where to save
        local_path, _ = QFileDialog.getSaveFileName(
            self, "Save Patched Boot Image",
            "magisk_patched.img", "Image Files (*.img)"
        )
        if not local_path:
            return
        
        self._log(f"📥 Pulling: {remote_path}")
        success, output = run_adb(["pull", remote_path, local_path], self.selected_device)
        
        if success:
            self._log(f"✅ Saved to: {local_path}")
            self.patched_path_edit.setText(local_path)
            self.patch_status.setText("✅ Patched boot ready")
            self.patch_status.setStyleSheet("color: #4f4; padding-left: 60px;")
            
            # Enable flash
            self.flash_btn.setEnabled(True)
            self.flash_status.setText("✅ Ready to flash")
            self.flash_status.setStyleSheet("color: #4f4; padding-left: 60px;")
        else:
            QMessageBox.warning(self, "Error", f"Failed to pull: {output}")
    
    def _browse_patched(self):
        """Browse for patched boot image."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Patched Boot Image",
            "", "Image Files (*.img);;All Files (*)"
        )
        if path:
            self.patched_path_edit.setText(path)
    
    def _on_patched_path_changed(self, path: str):
        """Handle patched path change."""
        if path and os.path.isfile(path):
            self.flash_btn.setEnabled(True)
            self.flash_status.setText("✅ Ready to flash")
            self.flash_status.setStyleSheet("color: #4f4; padding-left: 60px;")
    
    def _flash_patched_boot(self):
        """Flash patched boot image to device."""
        patched_path = self.patched_path_edit.text().strip()
        if not patched_path or not os.path.isfile(patched_path):
            QMessageBox.warning(self, "Error", "Please select a patched boot image")
            return
        
        if not self.selected_device:
            QMessageBox.warning(self, "Error", "No device selected")
            return
        
        # Confirm
        reply = QMessageBox.question(
            self, "Confirm Flash",
            f"Flash {os.path.basename(patched_path)} to device?\n\n"
            f"Device: {self.selected_device}\n\n"
            "This will reboot to bootloader and flash the boot partition.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.flash_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        
        worker = DevicePatcherWorker(
            "flash_boot",
            device=self.selected_device,
            mode=self.selected_device_mode,
            boot_path=patched_path
        )
        worker.log.connect(self._log)
        worker.progress.connect(self._on_device_progress)
        worker.finished_signal.connect(self._on_flash_complete)
        worker.finished_signal.connect(lambda s, m: self._cleanup_worker(worker))
        self.active_workers.append(worker)
        self.device_worker = worker
        worker.start()
    
    def _on_flash_complete(self, success: bool, msg: str):
        """Handle flash completion."""
        self.progress_bar.setVisible(False)
        self.flash_btn.setEnabled(True)
        
        if success:
            self.flash_status.setText("✅ Flash complete!")
            self.flash_status.setStyleSheet("color: #4f4; padding-left: 60px;")
            QMessageBox.information(self, "Success", "Boot image flashed successfully!\n\nDevice is rebooting.")
        else:
            QMessageBox.warning(self, "Error", f"Flash failed: {msg}")
    
    def _reboot_bootloader(self):
        """Reboot device to bootloader."""
        if not self.selected_device:
            return
        
        if self.selected_device_mode == 'adb':
            success, output = run_adb(["reboot", "bootloader"], self.selected_device)
        else:
            success, output = run_fastboot(["reboot", "bootloader"], self.selected_device)
        
        if success:
            self._log("🔄 Rebooting to bootloader...")
        else:
            self._log(f"❌ Reboot failed: {output}")
    
    def _reboot_device(self):
        """Reboot device normally."""
        if not self.selected_device:
            return
        
        if self.selected_device_mode == 'adb':
            success, output = run_adb(["reboot"], self.selected_device)
        else:
            success, output = run_fastboot(["reboot"], self.selected_device)
        
        if success:
            self._log("🔄 Rebooting device...")
        else:
            self._log(f"❌ Reboot failed: {output}")
    
    # =========================================================================
    # File Mode Methods (Original)
    # =========================================================================
    
    def _log(self, msg: str):
        """Add message to log."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_output.append(f"[{timestamp}] {msg}")
    
    def _browse_boot(self):
        """Browse for boot image."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Boot Image",
            "", "Image Files (*.img);;All Files (*)"
        )
        if path:
            self.boot_path_edit.setText(path)
    
    def _on_boot_path_changed(self, path: str):
        """Handle boot path change."""
        if path and os.path.isfile(path):
            self._analyze_boot()
    
    def _analyze_boot(self):
        """Analyze the selected boot image."""
        path = self.boot_path_edit.text().strip()
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "Error", "Please select a valid boot.img file")
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        self.worker = PatchWorker("analyze", path=path)
        self.worker.progress.connect(self._on_progress)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(self._on_analysis_complete)
        self.worker.start()
    
    def _on_progress(self, value: int, msg: str):
        """Handle progress update."""
        self.progress_bar.setValue(value)
    
    def _on_analysis_complete(self, success: bool, result: str):
        """Handle analysis completion."""
        self.progress_bar.setVisible(False)
        
        if not success:
            self._log(f"❌ Analysis failed: {result}")
            return
        
        try:
            info = json.loads(result)
            self.current_boot_info = info
            
            if not info['valid']:
                self.info_label.setText(f"❌ Invalid boot image: {info['error']}")
                self.info_label.setStyleSheet("color: #f44; padding: 10px;")
                return
            
            # Update info display
            info_text = f"""
<b>Header Version:</b> v{info['header_version']}<br>
<b>Kernel Size:</b> {info['kernel_size'] / 1024 / 1024:.2f} MB<br>
<b>Ramdisk Size:</b> {info['ramdisk_size'] / 1024:.2f} KB<br>
<b>Page Size:</b> {info['page_size']}<br>
<b>OS Version:</b> {info['os_version'] or 'Unknown'}<br>
<b>Patch Level:</b> {info['os_patch_level'] or 'Unknown'}<br>
<b>Kernel Version:</b> {info['kernel_version'] or 'Unknown'}<br>
<b>Kernel Compression:</b> {info['kernel_compression']}<br>
<b>GKI Kernel:</b> {'Yes' if info['is_gki'] else 'No'}
"""
            self.info_label.setText(info_text)
            self.info_label.setStyleSheet("color: #ddd; padding: 10px;")
            
            # Update compatibility status
            if info['magisk_compatible']:
                self.magisk_status.setText("✅ Magisk - Compatible (universal support)")
                self.magisk_status.setStyleSheet("color: #4f4; font-size: 12px; padding: 5px;")
            else:
                self.magisk_status.setText("❌ Magisk - Not compatible")
                self.magisk_status.setStyleSheet("color: #f44; font-size: 12px; padding: 5px;")
            
            if info['apatch_compatible']:
                self.apatch_status.setText(f"✅ APatch - Compatible (Android {info['os_version']})")
                self.apatch_status.setStyleSheet("color: #4f4; font-size: 12px; padding: 5px;")
            else:
                self.apatch_status.setText("❌ APatch - Requires Android 11+ with supported kernel")
                self.apatch_status.setStyleSheet("color: #f44; font-size: 12px; padding: 5px;")
            
            if info['kernelsu_compatible']:
                self.kernelsu_status.setText(f"✅ KernelSU - Compatible (GKI kernel {info['kernel_version']})")
                self.kernelsu_status.setStyleSheet("color: #4f4; font-size: 12px; padding: 5px;")
            else:
                reason = "Non-GKI kernel" if not info['is_gki'] else "Missing kprobes"
                self.kernelsu_status.setText(f"❌ KernelSU - Not compatible ({reason})")
                self.kernelsu_status.setStyleSheet("color: #f44; font-size: 12px; padding: 5px;")
            
            # GSI is always an option (for Treble devices)
            self.gsi_status.setText("⚠️ Phh GSI - Always available (Treble devices, replaces system)")
            self.gsi_status.setStyleSheet("color: #fa0; font-size: 12px; padding: 5px;")
            
            # Enable/disable radio buttons based on compatibility
            self.apatch_radio.setEnabled(info['apatch_compatible'])
            self.kernelsu_radio.setEnabled(info['kernelsu_compatible'])
            # GSI always enabled as fallback
            
            # Log compatibility notes
            for note in info['compatibility_notes']:
                self._log(note)
            
        except Exception as e:
            self._log(f"❌ Error parsing result: {e}")
    
    def _update_method_info(self):
        """Update method info based on selection."""
        if self.magisk_radio.isChecked():
            self.method_info.setText(
                "ℹ️ <b>Magisk</b>: Most compatible rooting solution. Works on virtually all Android devices. "
                "Patches are done through the Magisk app on an Android device. Supports MagiskHide/Zygisk "
                "for hiding root from apps."
            )
        elif self.apatch_radio.isChecked():
            self.method_info.setText(
                "ℹ️ <b>APatch</b>: Newer rooting solution based on KernelPatch. Requires Android 11+. "
                "Offers kernel-level patching with good hiding capabilities. Similar workflow to Magisk - "
                "patch through the APatch app."
            )
        elif self.kernelsu_radio.isChecked():
            self.method_info.setText(
                "ℹ️ <b>KernelSU</b>: Kernel-based root solution. <b>Requires GKI (Generic Kernel Image)</b> "
                "which is only available on Android 12+ devices with specific kernels. Most MTK devices "
                "do NOT have GKI kernels. Check compatibility before attempting!"
            )
        elif self.gsi_radio.isChecked():
            self.method_info.setText(
                "ℹ️ <b>Phh GSI</b>: Generic System Image with built-in root. <b>Replaces your system partition!</b> "
                "Best for devices where other methods fail or for testing. Requires Project Treble support "
                "(Android 8+). Includes Phh Treble Settings with easy su toggle."
            )
    
    def _start_patch(self):
        """Start the patching process."""
        # GSI doesn't require boot.img
        if self.gsi_radio.isChecked():
            self.log_output.clear()
            self.worker = PatchWorker("patch_gsi", path="")
            self.worker.log.connect(self._log)
            self.worker.finished_signal.connect(lambda s, m: self._log(f"\n{'✓' if s else '✗'} {m}"))
            self.worker.start()
            return
        
        path = self.boot_path_edit.text().strip()
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "Error", "Please select a valid boot.img file")
            return
        
        # Check compatibility
        if self.current_boot_info:
            if self.apatch_radio.isChecked() and not self.current_boot_info.get('apatch_compatible'):
                reply = QMessageBox.warning(
                    self, "Compatibility Warning",
                    "APatch may not be compatible with this boot image.\n\n"
                    "Continuing may result in a non-booting device.\n\n"
                    "Continue anyway?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return
            
            if self.kernelsu_radio.isChecked() and not self.current_boot_info.get('kernelsu_compatible'):
                reply = QMessageBox.warning(
                    self, "Compatibility Warning",
                    "KernelSU is NOT compatible with this boot image!\n\n"
                    "This kernel is not a GKI kernel. KernelSU will NOT work.\n\n"
                    "Use Magisk instead for this device.\n\n"
                    "Show instructions anyway?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return
        
        # Determine operation
        if self.magisk_radio.isChecked():
            operation = "patch_magisk"
        elif self.apatch_radio.isChecked():
            operation = "patch_apatch"
        else:
            operation = "patch_kernelsu"
        
        self.log_output.clear()
        self.worker = PatchWorker(operation, path=path)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(f"\n{'✓' if s else '✗'} {m}"))
        self.worker.start()


# =============================================================================
# Plugin Class
# =============================================================================

class Plugin:
    """Root Patcher plugin for Image Anarchy."""
    
    manifest = None
    
    def __init__(self):
        self.parent_window = None
        self.widget = None
    
    def get_name(self) -> str:
        return self.manifest.name if self.manifest else "Root Patcher"
    
    def get_icon(self) -> str:
        return self.manifest.icon if self.manifest else "🔓"
    
    def get_description(self) -> str:
        return self.manifest.description if self.manifest else ""
    
    def get_version(self) -> str:
        return self.manifest.version if self.manifest else "1.0.0"
    
    def get_author(self) -> str:
        return self.manifest.author if self.manifest else "Image Anarchy Team"
    
    def create_widget(self, parent=None) -> QWidget:
        """Create and return the plugin's UI widget."""
        self.parent_window = parent
        self.widget = PluginWidget(parent)
        return self.widget
    
    def on_load(self):
        """Called when plugin is loaded."""
        pass
    
    def on_unload(self):
        """Called when plugin is unloaded."""
        pass
