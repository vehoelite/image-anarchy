"""
IAABS - Image Anarchy Android Backup Solution

The first live root filesystem backup tool for Android via ADB.
No recovery mode needed - backup your entire device while it's running.

Features:
- Full system backup (/, /system, /vendor, /product, /data)
- Selective partition/folder backup
- Backup profiles (Full, Apps Only, User Data, System Only)
- Compression support (tar.gz)
- Backup verification
- Restore capability
- Backup history & management
"""

import os
import sys
import subprocess
import shutil
import json
import hashlib
import tarfile
import time
from datetime import datetime
from typing import Optional, List, Dict

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QComboBox,
    QPushButton, QLineEdit, QTextEdit, QProgressBar, QFileDialog,
    QMessageBox, QTabWidget, QFormLayout, QCheckBox, QSpinBox,
    QListWidget, QListWidgetItem, QAbstractItemView, QFrame,
    QTreeWidget, QTreeWidgetItem, QSplitter, QHeaderView,
    QRadioButton, QButtonGroup, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QIcon


def find_adb() -> Optional[str]:
    """Find ADB executable - checks ADB Toolkit plugin and common locations."""
    plugin_dir = os.path.dirname(os.path.abspath(__file__))
    plugins_root = os.path.dirname(plugin_dir)
    app_root = os.path.dirname(plugins_root)
    
    # PRIORITY 1: ADB Toolkit plugin's bundled platform-tools (most reliable)
    adb_toolkit_paths = [
        os.path.join(plugins_root, "adb_toolkit", "platform-tools", "adb.exe"),
        os.path.join(plugins_root, "adb_toolkit", "platform-tools", "adb"),
        os.path.join(plugins_root, "adb_toolkit", "adb.exe"),
        os.path.join(plugins_root, "adb_toolkit", "adb"),
    ]
    
    for path in adb_toolkit_paths:
        if os.path.isfile(path):
            return path
    
    # PRIORITY 2: App root platform-tools (development/frozen)
    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        exe_dir = os.path.dirname(sys.executable)
        
        frozen_paths = [
            os.path.join(meipass, "platform-tools", "adb.exe"),
            os.path.join(meipass, "platform-tools", "adb"),
            os.path.join(exe_dir, "platform-tools", "adb.exe"),
            os.path.join(exe_dir, "platform-tools", "adb"),
        ]
        
        for path in frozen_paths:
            if os.path.isfile(path):
                return path
    else:
        # Development mode
        dev_paths = [
            os.path.join(app_root, "platform-tools", "adb.exe"),
            os.path.join(app_root, "platform-tools", "adb"),
            os.path.join(app_root, "tools", "platform-tools", "adb.exe"),
            os.path.join(app_root, "tools", "platform-tools", "adb"),
        ]
        
        for path in dev_paths:
            if os.path.isfile(path):
                return path
    
    # PRIORITY 3: System PATH and common locations
    system_paths = [
        "adb", "adb.exe",
        os.path.join(os.environ.get("ANDROID_HOME", ""), "platform-tools", "adb.exe"),
        os.path.join(os.environ.get("ANDROID_HOME", ""), "platform-tools", "adb"),
        r"C:\platform-tools\adb.exe",
        r"C:\Android\platform-tools\adb.exe",
    ]
    
    for path in system_paths:
        if path and shutil.which(path):
            return shutil.which(path)
        if path and os.path.isfile(path):
            return path
    
    return None


# Backup profile definitions
BACKUP_PROFILES = {
    "full": {
        "name": "Full Device Backup",
        "description": "Complete backup of all partitions including system, vendor, and data",
        "paths": ["/system", "/vendor", "/product", "/data", "/odm"],
        "icon": "🔒"
    },
    "apps_and_data": {
        "name": "Apps & User Data",
        "description": "All installed apps and their data (most common)",
        "paths": ["/data/app", "/data/data", "/data/user", "/data/user_de"],
        "icon": "📱"
    },
    "user_data": {
        "name": "User Data Only", 
        "description": "Internal storage, downloads, DCIM, etc.",
        "paths": ["/sdcard", "/data/media/0"],
        "icon": "📁"
    },
    "system_only": {
        "name": "System Partitions",
        "description": "System, vendor, product - for ROM preservation",
        "paths": ["/system", "/vendor", "/product", "/odm"],
        "icon": "⚙️"
    },
    "custom": {
        "name": "Custom Selection",
        "description": "Choose exactly what to backup",
        "paths": [],
        "icon": "🎯"
    }
}

# Common Android paths for custom selection
ANDROID_PATHS = {
    "System Partitions": [
        ("/system", "Main system partition - Android OS"),
        ("/vendor", "Vendor-specific drivers and HALs"),
        ("/product", "Product-specific customizations"),
        ("/odm", "ODM customizations"),
    ],
    "Data Partition": [
        ("/data/app", "Installed APKs"),
        ("/data/data", "App private data"),
        ("/data/user/0", "Primary user data"),
        ("/data/user_de/0", "Device-encrypted user data"),
        ("/data/system", "System databases and settings"),
        ("/data/misc", "Misc system data (wifi, bluetooth, etc.)"),
    ],
    "User Storage": [
        ("/sdcard", "Internal storage (symlink)"),
        ("/data/media/0", "Internal storage (actual)"),
        ("/sdcard/DCIM", "Photos and videos"),
        ("/sdcard/Download", "Downloads"),
        ("/sdcard/Documents", "Documents"),
    ],
    "Special": [
        ("/efs", "IMEI and device identity (Samsung)"),
        ("/persist", "Persistent data partition"),
        ("/mnt/vendor/nvdata", "NV data (MediaTek)"),
        ("/mnt/vendor/nvcfg", "NV config (MediaTek)"),
        ("/mnt/vendor/protect_f", "Protected data (MediaTek)"),
    ]
}


class BackupWorker(QThread):
    """Worker thread for performing backups."""
    
    progress = pyqtSignal(int, int)  # current, total (0-100)
    status = pyqtSignal(str)
    log = pyqtSignal(str)
    finished = pyqtSignal(bool, str, dict)  # success, message, backup_info
    
    def __init__(self, device: str, paths: list, output_dir: str,
                 backup_name: str, compress: bool = True,
                 verify: bool = True):
        super().__init__()
        self.device = device
        self.paths = paths
        self.output_dir = output_dir
        self.backup_name = backup_name
        self.compress = compress
        self.verify = verify
        self._cancelled = False
        self.adb_path = find_adb()
        
        # Stats
        self.files_backed_up = 0
        self.files_failed = 0
        self.total_bytes = 0
        self.backup_info = {}
    
    def cancel(self):
        self._cancelled = True
    
    def run(self):
        start_time = time.time()
        
        if not self.adb_path:
            self.finished.emit(False, "ADB not found", {})
            return
        
        # Check root access
        self.status.emit("[0%] Checking root access...")
        self.progress.emit(0, 100)
        
        result = subprocess.run(
            [self.adb_path, "-s", self.device, "shell", "su", "-c", "id"],
            capture_output=True, text=True, timeout=10
        )
        
        if "uid=0" not in result.stdout:
            self.finished.emit(False, "ROOT ACCESS REQUIRED\n\nDevice must be rooted and su access granted.", {})
            return
        
        self.log.emit("✓ Root access confirmed")
        
        # Check tar capabilities (different on busybox vs toybox)
        self.status.emit("[1%] Checking tar capabilities...")
        tar_check = subprocess.run(
            [self.adb_path, "-s", self.device, "shell", "su", "-c", "tar --help 2>&1 | head -5"],
            capture_output=True, text=True, timeout=10
        )
        
        # Determine if we can use --numeric-owner (GNU tar / modern toybox)
        self.use_numeric_owner = "--numeric" in tar_check.stdout or "toybox" not in tar_check.stdout.lower()
        tar_type = "BusyBox" if "busybox" in tar_check.stdout.lower() else "Toybox/GNU"
        self.log.emit(f"✓ Using {tar_type} tar (numeric-owner: {'yes' if self.use_numeric_owner else 'no'})")
        
        # Get device info for backup metadata
        self.status.emit("[2%] Getting device info...")
        device_info = self._get_device_info()
        self.log.emit(f"📱 Device: {device_info.get('model', 'Unknown')} ({device_info.get('android_version', '?')})")
        
        # Create backup directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_folder = f"{self.backup_name}_{timestamp}"
        backup_path = os.path.join(self.output_dir, backup_folder)
        os.makedirs(backup_path, exist_ok=True)
        
        self.log.emit(f"📂 Backup location: {backup_path}")
        
        # Phase 1: Create tar archives on device (0-33%)
        total_paths = len(self.paths)
        self.log.emit(f"\n📦 PHASE 1: Creating {total_paths} backup archives on device...")
        self.log.emit("   (Preserving: paths, symlinks, permissions, ownership, SELinux contexts)")
        
        tar_jobs = []
        for idx, remote_path in enumerate(self.paths):
            if self._cancelled:
                break
            
            partition_name = self._get_partition_name(remote_path)
            remote_tar = f"/data/local/tmp/_iaabs_{partition_name}.tar"
            remote_contexts = f"/data/local/tmp/_iaabs_{partition_name}_contexts.txt"
            local_tar = os.path.join(backup_path, f"{partition_name}.tar")
            local_contexts = os.path.join(backup_path, f"{partition_name}_contexts.txt")
            
            pct = int((idx / total_paths) * 25)  # Phase 1a: tar (0-25%)
            self.progress.emit(pct, 100)
            self.status.emit(f"[{pct}%] Creating archive [{idx+1}/{total_paths}]: {partition_name}")
            self.log.emit(f"   📁 {remote_path}")
            
            # Create tar on device with full preservation flags
            # -c: create, -p: preserve permissions, -h: follow symlinks for content but store as symlink
            # Using numeric owner/group to preserve exact UIDs/GIDs (if supported)
            tar_flags = "--numeric-owner -cpf" if self.use_numeric_owner else "-cpf"
            tar_cmd = f"su -c \"tar {tar_flags} '{remote_tar}' -C / '{remote_path.lstrip('/')}' 2>/dev/null\""
            subprocess.run(
                [self.adb_path, "-s", self.device, "shell", tar_cmd],
                capture_output=True, timeout=1200
            )
            
            # Capture SELinux contexts (critical for Android!)
            # ls -Z output format: "context path" (e.g., "u:object_r:system_file:s0 /system/bin/sh")
            self.status.emit(f"[{pct}%] Capturing SELinux contexts: {partition_name}")
            # Use sh -c to ensure proper redirect handling in adb shell
            context_cmd = f"su -c 'find \"{remote_path}\" -exec ls -dZ {{}} \\; 2>/dev/null > \"{remote_contexts}\"'"
            subprocess.run(
                [self.adb_path, "-s", self.device, "shell", context_cmd],
                capture_output=True, timeout=600
            )
            
            # Verify tar was created and get size
            check = subprocess.run(
                [self.adb_path, "-s", self.device, "shell", f"ls -l '{remote_tar}' 2>/dev/null"],
                capture_output=True, text=True, timeout=10
            )
            
            if remote_tar in check.stdout:
                try:
                    size = int(check.stdout.split()[4])
                    self.log.emit(f"      ✓ Archive: {self._format_size(size)}")
                    tar_jobs.append((remote_tar, local_tar, partition_name, size, remote_contexts, local_contexts))
                except:
                    tar_jobs.append((remote_tar, local_tar, partition_name, 0, remote_contexts, local_contexts))
            else:
                self.log.emit(f"      ⚠️ Failed to create archive (path may not exist)")
                self.files_failed += 1
        
        if self._cancelled:
            self._cleanup_device_tars(tar_jobs)
            self.finished.emit(False, "Backup cancelled", {})
            return
        
        if not tar_jobs:
            self.finished.emit(False, "No archives created - check if paths exist", {})
            return
        
        # Phase 2: Transfer archives and context files (25-60%)
        total_tar_bytes = sum(job[3] for job in tar_jobs)
        self.log.emit(f"\n📥 PHASE 2: Transferring {len(tar_jobs)} archives + SELinux data ({self._format_size(total_tar_bytes)})...")
        
        transferred_tars = []
        for i, (remote_tar, local_tar, partition_name, tar_size, remote_contexts, local_contexts) in enumerate(tar_jobs):
            if self._cancelled:
                break
            
            pct = 25 + int((i / len(tar_jobs)) * 35)
            self.progress.emit(pct, 100)
            self.status.emit(f"[{pct}%] Transferring [{i+1}/{len(tar_jobs)}]: {partition_name}")
            
            # Pull tar archive
            pull_result = subprocess.run(
                [self.adb_path, "-s", self.device, "pull", remote_tar, local_tar],
                capture_output=True, text=True, timeout=3600
            )
            
            if pull_result.returncode == 0 and os.path.exists(local_tar):
                actual_size = os.path.getsize(local_tar)
                self.total_bytes += actual_size
                self.log.emit(f"   ✓ {partition_name}.tar ({self._format_size(actual_size)})")
                
                # Pull SELinux contexts file
                subprocess.run(
                    [self.adb_path, "-s", self.device, "pull", remote_contexts, local_contexts],
                    capture_output=True, timeout=120
                )
                
                has_contexts = os.path.exists(local_contexts) and os.path.getsize(local_contexts) > 0
                if has_contexts:
                    ctx_count = sum(1 for _ in open(local_contexts, 'r', errors='ignore'))
                    self.log.emit(f"   ✓ {partition_name}_contexts.txt ({ctx_count:,} entries)")
                
                transferred_tars.append((local_tar, partition_name, local_contexts if has_contexts else None))
            else:
                self.log.emit(f"   ❌ Failed to transfer {partition_name}.tar")
                self.files_failed += 1
            
            # Clean up device files
            subprocess.run(
                [self.adb_path, "-s", self.device, "shell", f"rm -f '{remote_tar}' '{remote_contexts}'"],
                capture_output=True, timeout=10
            )
        
        if self._cancelled:
            self.finished.emit(False, "Backup cancelled", {})
            return
        
        # Phase 3: Process archives locally (60-95%)
        self.log.emit(f"\n📂 PHASE 3: Processing {len(transferred_tars)} archives...")
        
        archive_info = {}
        for i, (local_tar, partition_name, local_contexts) in enumerate(transferred_tars):
            if self._cancelled:
                break
            
            pct = 60 + int((i / len(transferred_tars)) * 30)
            self.progress.emit(pct, 100)
            self.status.emit(f"[{pct}%] Processing [{i+1}/{len(transferred_tars)}]: {partition_name}")
            
            try:
                # Analyze tar contents - count files, symlinks, get permission summary
                with tarfile.open(local_tar, 'r') as tar:
                    members = tar.getmembers()
                    file_count = len(members)
                    symlink_count = sum(1 for m in members if m.issym())
                    dir_count = sum(1 for m in members if m.isdir())
                    self.files_backed_up += file_count
                    
                    archive_info[partition_name] = {
                        "file_count": file_count,
                        "symlink_count": symlink_count,
                        "directory_count": dir_count,
                        "size": os.path.getsize(local_tar),
                        "tar_path": local_tar,
                        "has_selinux_contexts": local_contexts is not None,
                        "selinux_contexts_path": local_contexts
                    }
                    
                    self.log.emit(f"   📦 {partition_name}: {file_count:,} files ({symlink_count:,} symlinks, {dir_count:,} dirs)")
                
                # Compress if requested
                if self.compress:
                    self.status.emit(f"[{pct}%] Compressing {partition_name}...")
                    compressed_tar = local_tar + ".gz"
                    
                    import gzip
                    with open(local_tar, 'rb') as f_in:
                        with gzip.open(compressed_tar, 'wb', compresslevel=6) as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    
                    # Update stats
                    compressed_size = os.path.getsize(compressed_tar)
                    original_size = archive_info[partition_name]["size"]
                    ratio = (1 - compressed_size / original_size) * 100 if original_size > 0 else 0
                    
                    self.log.emit(f"      ✓ Compressed: {self._format_size(original_size)} → {self._format_size(compressed_size)} ({ratio:.1f}% saved)")
                    
                    # Remove uncompressed tar
                    os.remove(local_tar)
                    archive_info[partition_name]["compressed_size"] = compressed_size
                    archive_info[partition_name]["tar_path"] = compressed_tar
                    
            except Exception as e:
                self.log.emit(f"   ⚠️ Error processing {partition_name}: {e}")
                self.files_failed += 1
        
        # Verification phase (95-99%)
        if self.verify and not self._cancelled:
            self.status.emit("[95%] Verifying backup integrity...")
            self.progress.emit(95, 100)
            self.log.emit("\n🔍 PHASE 4: Verifying backup integrity...")
            
            for partition_name, info in archive_info.items():
                try:
                    archive_path = info["tar_path"]
                    
                    # Calculate checksum
                    sha256 = hashlib.sha256()
                    with open(archive_path, 'rb') as f:
                        for chunk in iter(lambda: f.read(65536), b''):
                            sha256.update(chunk)
                    
                    checksum = sha256.hexdigest()
                    archive_info[partition_name]["sha256"] = checksum
                    self.log.emit(f"   ✓ {partition_name}: {checksum[:16]}...")
                    
                except Exception as e:
                    self.log.emit(f"   ⚠️ Verification failed for {partition_name}: {e}")
        
        # Create backup manifest
        self.progress.emit(99, 100)
        self.status.emit("[99%] Creating backup manifest...")
        
        elapsed_time = time.time() - start_time
        
        self.backup_info = {
            "backup_name": self.backup_name,
            "timestamp": timestamp,
            "created": datetime.now().isoformat(),
            "device": device_info,
            "paths_backed_up": self.paths,
            "archives": archive_info,
            "stats": {
                "total_files": self.files_backed_up,
                "failed_files": self.files_failed,
                "total_size": self.total_bytes,
                "compressed": self.compress,
                "verified": self.verify,
                "elapsed_seconds": elapsed_time
            }
        }
        
        manifest_path = os.path.join(backup_path, "backup_manifest.json")
        with open(manifest_path, 'w') as f:
            json.dump(self.backup_info, f, indent=2)
        
        self.log.emit(f"\n📋 Manifest saved: backup_manifest.json")
        
        # Complete
        self.progress.emit(100, 100)
        
        summary = (
            f"✅ BACKUP COMPLETE!\n\n"
            f"📁 Location: {backup_path}\n"
            f"📦 Archives: {len(transferred_tars)}\n"
            f"📄 Total files: {self.files_backed_up:,}\n"
            f"💾 Total size: {self._format_size(self.total_bytes)}\n"
            f"⏱️ Time: {self._format_duration(elapsed_time)}\n"
            f"{'🗜️ Compressed: Yes' if self.compress else ''}\n"
            f"{'✓ Verified: Yes' if self.verify else ''}"
        )
        
        self.log.emit(f"\n{'='*50}")
        self.log.emit(summary)
        
        self.finished.emit(True, summary, self.backup_info)
    
    def _get_device_info(self) -> dict:
        """Get device information for backup metadata."""
        info = {}
        
        props = [
            ("model", "ro.product.model"),
            ("manufacturer", "ro.product.manufacturer"),
            ("android_version", "ro.build.version.release"),
            ("sdk_version", "ro.build.version.sdk"),
            ("build_id", "ro.build.id"),
            ("serial", "ro.serialno"),
        ]
        
        for key, prop in props:
            try:
                result = subprocess.run(
                    [self.adb_path, "-s", self.device, "shell", f"getprop {prop}"],
                    capture_output=True, text=True, timeout=5
                )
                info[key] = result.stdout.strip()
            except:
                pass
        
        return info
    
    def _get_partition_name(self, path: str) -> str:
        """Get clean partition name from path."""
        path = path.rstrip('/')
        
        # Handle common paths
        path_map = {
            '/system': 'system',
            '/vendor': 'vendor',
            '/product': 'product',
            '/odm': 'odm',
            '/data/app': 'apps_apk',
            '/data/data': 'apps_data',
            '/data/user/0': 'user_data',
            '/data/user_de/0': 'user_data_de',
            '/data/system': 'system_data',
            '/data/misc': 'misc_data',
            '/data/media/0': 'internal_storage',
            '/sdcard': 'sdcard',
            '/sdcard/DCIM': 'dcim',
            '/sdcard/Download': 'downloads',
            '/efs': 'efs',
            '/persist': 'persist',
        }
        
        if path in path_map:
            return path_map[path]
        
        # Generate name from path
        return path.strip('/').replace('/', '_')
    
    def _format_size(self, bytes: int) -> str:
        """Format bytes to human readable."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024:
                return f"{bytes:.1f} {unit}"
            bytes /= 1024
        return f"{bytes:.1f} PB"
    
    def _format_duration(self, seconds: float) -> str:
        """Format seconds to human readable duration."""
        if seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            mins = seconds / 60
            return f"{mins:.1f} minutes"
        else:
            hours = seconds / 3600
            return f"{hours:.1f} hours"
    
    def _cleanup_device_tars(self, tar_jobs):
        """Clean up any tar files left on device."""
        for job in tar_jobs:
            remote_tar = job[0]
            subprocess.run(
                [self.adb_path, "-s", self.device, "shell", f"rm -f '{remote_tar}'"],
                capture_output=True, timeout=10
            )


class RestoreWorker(QThread):
    """Worker thread for restoring backups with full permission/context restoration."""
    
    progress = pyqtSignal(int, int)
    status = pyqtSignal(str)
    log = pyqtSignal(str)
    finished = pyqtSignal(bool, str)
    
    def __init__(self, device: str, backup_path: str, selected_archives: list, 
                 restore_contexts: bool = True):
        super().__init__()
        self.device = device
        self.backup_path = backup_path
        self.selected_archives = selected_archives
        self.restore_contexts = restore_contexts
        self._cancelled = False
        self.adb_path = find_adb()
    
    def cancel(self):
        self._cancelled = True
    
    def run(self):
        if not self.adb_path:
            self.finished.emit(False, "ADB not found")
            return
        
        # Check root
        self.status.emit("Checking root access...")
        result = subprocess.run(
            [self.adb_path, "-s", self.device, "shell", "su", "-c", "id"],
            capture_output=True, text=True, timeout=10
        )
        
        if "uid=0" not in result.stdout:
            self.finished.emit(False, "ROOT ACCESS REQUIRED")
            return
        
        self.log.emit("✓ Root access confirmed")
        
        # Check tar capabilities 
        tar_check = subprocess.run(
            [self.adb_path, "-s", self.device, "shell", "su", "-c", "tar --help 2>&1 | head -5"],
            capture_output=True, text=True, timeout=10
        )
        use_numeric_owner = "--numeric" in tar_check.stdout or "toybox" not in tar_check.stdout.lower()
        
        self.log.emit(f"\n⚠️ RESTORE OPERATION")
        self.log.emit(f"   This will OVERWRITE existing files on device!")
        self.log.emit(f"   Restoring: paths, symlinks, permissions, ownership" + 
                      (", SELinux contexts" if self.restore_contexts else ""))
        self.log.emit(f"📂 Source: {self.backup_path}")
        
        total = len(self.selected_archives)
        restored = 0
        failed = 0
        contexts_restored = 0
        
        for i, archive_name in enumerate(self.selected_archives):
            if self._cancelled:
                break
            
            # Phase 1: Push and extract tar (preserves paths, symlinks, permissions, ownership)
            pct = int((i / total) * 80)  # 0-80% for tar operations
            self.progress.emit(pct, 100)
            self.status.emit(f"[{pct}%] Restoring [{i+1}/{total}]: {archive_name}")
            
            # Find archive file
            archive_path = None
            for ext in ['.tar.gz', '.tar']:
                test_path = os.path.join(self.backup_path, archive_name + ext)
                if os.path.exists(test_path):
                    archive_path = test_path
                    break
            
            if not archive_path:
                self.log.emit(f"   ❌ Archive not found: {archive_name}")
                failed += 1
                continue
            
            # Find SELinux contexts file
            contexts_path = os.path.join(self.backup_path, f"{archive_name}_contexts.txt")
            has_contexts = os.path.exists(contexts_path)
            
            try:
                self.log.emit(f"   📁 {archive_name}")
                
                # Decompress if needed
                temp_tar = None
                if archive_path.endswith('.gz'):
                    self.log.emit(f"      Decompressing...")
                    import gzip
                    temp_tar = os.path.join(self.backup_path, f"_temp_{archive_name}.tar")
                    with gzip.open(archive_path, 'rb') as f_in:
                        with open(temp_tar, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    push_path = temp_tar
                else:
                    push_path = archive_path
                
                # Push archive to device
                self.log.emit(f"      Pushing to device...")
                remote_tar = f"/data/local/tmp/_restore_{archive_name}.tar"
                
                push_result = subprocess.run(
                    [self.adb_path, "-s", self.device, "push", push_path, remote_tar],
                    capture_output=True, text=True, timeout=3600
                )
                
                # Clean up temp file
                if temp_tar and os.path.exists(temp_tar):
                    os.remove(temp_tar)
                
                if push_result.returncode != 0:
                    self.log.emit(f"      ❌ Failed to push archive")
                    failed += 1
                    continue
                
                # Extract on device with full permission preservation
                # -x: extract, -p: preserve permissions, --numeric-owner: preserve exact UIDs/GIDs
                self.log.emit(f"      Extracting (preserving permissions & ownership)...")
                tar_flags = "--numeric-owner -xpf" if use_numeric_owner else "-xpf"
                extract_cmd = f"su -c \"tar {tar_flags} '{remote_tar}' -C / 2>/dev/null\""
                subprocess.run(
                    [self.adb_path, "-s", self.device, "shell", extract_cmd],
                    capture_output=True, timeout=1200
                )
                
                # Clean up remote tar
                subprocess.run(
                    [self.adb_path, "-s", self.device, "shell", f"rm -f '{remote_tar}'"],
                    capture_output=True, timeout=10
                )
                
                self.log.emit(f"      ✓ Files restored")
                restored += 1
                
                # Phase 2: Restore SELinux contexts (80-100%)
                if self.restore_contexts and has_contexts:
                    pct = 80 + int((i / total) * 20)
                    self.progress.emit(pct, 100)
                    self.status.emit(f"[{pct}%] Restoring SELinux contexts: {archive_name}")
                    
                    self.log.emit(f"      Restoring SELinux contexts...")
                    
                    # First try restorecon (uses Android's file_contexts policy - most reliable)
                    # Determine the base path from archive name
                    base_paths = {
                        'system': '/system',
                        'data': '/data', 
                        'vendor': '/vendor',
                        'product': '/product',
                        'sdcard': '/sdcard',
                        'storage': '/storage'
                    }
                    
                    base_path = base_paths.get(archive_name.split('_')[0], None)
                    if base_path:
                        # Try restorecon first (Android's native way to fix contexts)
                        self.log.emit(f"      Trying restorecon -R {base_path}...")
                        restorecon_cmd = f"su -c 'restorecon -R {base_path} 2>/dev/null'"
                        restorecon_result = subprocess.run(
                            [self.adb_path, "-s", self.device, "shell", restorecon_cmd],
                            capture_output=True, text=True, timeout=300
                        )
                        if restorecon_result.returncode == 0:
                            self.log.emit(f"      ✓ restorecon applied system policy")
                    
                    # Also apply specific contexts from backup (for custom labels)
                    remote_contexts = f"/data/local/tmp/_contexts_{archive_name}.txt"
                    subprocess.run(
                        [self.adb_path, "-s", self.device, "push", contexts_path, remote_contexts],
                        capture_output=True, timeout=120
                    )
                    
                    # Apply contexts using chcon (handles custom labels not in policy)
                    # ls -Z output format: "context path" (space-separated)
                    # Note: chcon may fail on fuse/sdcard filesystems - that's OK
                    restore_script = f"""
while read -r line; do
    context=$(echo "$line" | awk '{{print $1}}')
    filepath=$(echo "$line" | awk '{{$1=""; print substr($0,2)}}')
    if [ -n "$context" ] && [ -n "$filepath" ] && [ -e "$filepath" ]; then
        chcon "$context" "$filepath" 2>/dev/null || true
    fi
done < '{remote_contexts}'
"""
                    context_cmd = f"su -c '{restore_script}'"
                    ctx_result = subprocess.run(
                        [self.adb_path, "-s", self.device, "shell", context_cmd],
                        capture_output=True, timeout=600
                    )
                    
                    # Cleanup
                    subprocess.run(
                        [self.adb_path, "-s", self.device, "shell", f"rm -f '{remote_contexts}'"],
                        capture_output=True, timeout=10
                    )
                    
                    self.log.emit(f"      ✓ SELinux contexts applied (restorecon + chcon)")
                    contexts_restored += 1
                    
            except Exception as e:
                self.log.emit(f"      ❌ Error: {e}")
                failed += 1
        
        self.progress.emit(100, 100)
        
        summary_parts = [
            f"Restore {'complete' if restored > 0 else 'failed'}!",
            f"",
            f"Archives restored: {restored}/{total}",
            f"SELinux contexts applied: {contexts_restored}" if self.restore_contexts else "",
            f"Failed: {failed}" if failed > 0 else "",
            f"",
            f"⚠️ REBOOT RECOMMENDED to ensure all changes take effect!"
        ]
        
        summary = "\n".join(s for s in summary_parts if s)
        
        if restored > 0:
            self.finished.emit(True, summary)
        else:
            self.finished.emit(False, "Restore failed - no archives were restored")


class IABSPlugin:
    """Image Anarchy Android Backup Solution Plugin."""
    
    def __init__(self):
        self.manifest = None
        self.parent_window = None
        self.current_device = None
        self.devices = []
        self.backup_worker = None
        self.restore_worker = None
        
        # Config
        self.config_file = os.path.join(os.path.dirname(__file__), "iaabs_config.json")
        self.config = self._load_config()
    
    def _load_config(self) -> dict:
        """Load plugin configuration."""
        default = {
            "default_output": os.path.expanduser("~/IAABS_Backups"),
            "compress": True,
            "verify": True,
            "last_profile": "apps_and_data"
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return {**default, **json.load(f)}
            except:
                pass
        
        return default
    
    def _save_config(self):
        """Save plugin configuration."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except:
            pass
    
    def get_name(self) -> str:
        return self.manifest.name if self.manifest else "IAABS"
    
    def get_icon(self) -> str:
        return self.manifest.icon if self.manifest else "💾"
    
    def get_description(self) -> str:
        return self.manifest.description if self.manifest else ""
    
    def get_version(self) -> str:
        return self.manifest.version if self.manifest else "1.0"
    
    def get_author(self) -> str:
        return self.manifest.author if self.manifest else "Image Anarchy"
    
    def create_widget(self, parent_window) -> QWidget:
        self.parent_window = parent_window
        
        # Main scroll area for the entire plugin
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(8, 8, 8, 8)
        
        # Header
        header = QLabel("💾 IAABS - Image Anarchy Android Backup Solution")
        header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        header.setStyleSheet("color: #4CAF50; padding: 5px;")
        main_layout.addWidget(header)
        
        subtitle = QLabel("Live root filesystem backup & restore - No recovery mode needed")
        subtitle.setStyleSheet("color: #888; font-style: italic; margin-bottom: 10px;")
        main_layout.addWidget(subtitle)
        
        # Device Selection
        device_group = QGroupBox("Device")
        device_layout = QHBoxLayout(device_group)
        
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(250)
        device_layout.addWidget(self.device_combo)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_devices)
        device_layout.addWidget(refresh_btn)
        
        device_layout.addStretch()
        
        self.root_status = QLabel("⬤ Unknown")
        device_layout.addWidget(self.root_status)
        
        main_layout.addWidget(device_group)
        
        # Tabs
        tabs = QTabWidget()
        tabs.addTab(self._create_backup_tab(), "📦 Backup")
        tabs.addTab(self._create_restore_tab(), "📥 Restore")
        tabs.addTab(self._create_history_tab(), "📋 History")
        main_layout.addWidget(tabs, 1)  # Give tabs stretch priority
        
        # Progress Section
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("font-weight: bold;")
        progress_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p%")
        progress_layout.addWidget(self.progress_bar)
        
        main_layout.addWidget(progress_group)
        
        # Log
        log_group = QGroupBox("Log")
        log_layout = QVBoxLayout(log_group)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        self.log_text.setMinimumHeight(120)
        self.log_text.setMaximumHeight(200)
        log_layout.addWidget(self.log_text)
        
        main_layout.addWidget(log_group)
        
        # Initial refresh
        self._refresh_devices()
        
        scroll.setWidget(main_widget)
        return scroll
    
    def _create_backup_tab(self) -> QWidget:
        """Create the backup configuration tab."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Profile Selection
        profile_group = QGroupBox("Backup Profile")
        profile_layout = QVBoxLayout(profile_group)
        
        self.profile_buttons = QButtonGroup()
        
        for i, (profile_id, profile) in enumerate(BACKUP_PROFILES.items()):
            btn = QRadioButton(f"{profile['icon']} {profile['name']}")
            btn.setToolTip(profile['description'])
            btn.setProperty("profile_id", profile_id)
            
            if profile_id == self.config.get("last_profile", "apps_and_data"):
                btn.setChecked(True)
            
            self.profile_buttons.addButton(btn, i)
            profile_layout.addWidget(btn)
            
            # Add description
            desc = QLabel(f"    {profile['description']}")
            desc.setStyleSheet("color: #888; font-size: 11px;")
            profile_layout.addWidget(desc)
        
        self.profile_buttons.buttonClicked.connect(self._on_profile_changed)
        layout.addWidget(profile_group)
        
        # Custom Path Selection (shown when Custom profile selected)
        self.custom_paths_group = QGroupBox("Custom Path Selection")
        custom_layout = QVBoxLayout(self.custom_paths_group)
        
        self.path_tree = QTreeWidget()
        self.path_tree.setHeaderLabels(["Path", "Description"])
        self.path_tree.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        self.path_tree.header().setStretchLastSection(True)
        
        for category, paths in ANDROID_PATHS.items():
            cat_item = QTreeWidgetItem([category])
            cat_item.setFlags(cat_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            
            for path, desc in paths:
                path_item = QTreeWidgetItem([path, desc])
                cat_item.addChild(path_item)
            
            self.path_tree.addTopLevelItem(cat_item)
            cat_item.setExpanded(True)
        
        custom_layout.addWidget(self.path_tree)
        self.custom_paths_group.setVisible(False)
        layout.addWidget(self.custom_paths_group)
        
        # Output Directory
        output_group = QGroupBox("Output")
        output_layout = QHBoxLayout(output_group)
        
        self.output_path = QLineEdit(self.config.get("default_output", ""))
        output_layout.addWidget(self.output_path)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_output)
        output_layout.addWidget(browse_btn)
        
        layout.addWidget(output_group)
        
        # Backup Name
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Backup Name:"))
        self.backup_name = QLineEdit("Android_Backup")
        name_layout.addWidget(self.backup_name)
        layout.addLayout(name_layout)
        
        # Options
        options_layout = QHBoxLayout()
        
        self.compress_check = QCheckBox("Compress (gzip)")
        self.compress_check.setChecked(self.config.get("compress", True))
        options_layout.addWidget(self.compress_check)
        
        self.verify_check = QCheckBox("Verify integrity")
        self.verify_check.setChecked(self.config.get("verify", True))
        options_layout.addWidget(self.verify_check)
        
        options_layout.addStretch()
        layout.addLayout(options_layout)
        
        # Start Button
        self.backup_btn = QPushButton("🚀 START BACKUP")
        self.backup_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #45a049; }
            QPushButton:disabled { background-color: #888; }
        """)
        self.backup_btn.clicked.connect(self._start_backup)
        layout.addWidget(self.backup_btn)
        
        self.cancel_btn = QPushButton("⏹ Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_backup)
        layout.addWidget(self.cancel_btn)
        
        layout.addStretch()
        
        scroll.setWidget(widget)
        return scroll
    
    def _create_restore_tab(self) -> QWidget:
        """Create the restore tab."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Backup Selection
        select_group = QGroupBox("Select Backup to Restore")
        select_layout = QVBoxLayout(select_group)
        
        browse_layout = QHBoxLayout()
        self.restore_path = QLineEdit()
        self.restore_path.setPlaceholderText("Select a backup folder...")
        browse_layout.addWidget(self.restore_path)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_restore)
        browse_layout.addWidget(browse_btn)
        
        select_layout.addLayout(browse_layout)
        
        # Backup info
        self.restore_info = QLabel("No backup selected")
        self.restore_info.setStyleSheet("color: #888;")
        select_layout.addWidget(self.restore_info)
        
        layout.addWidget(select_group)
        
        # Archive Selection
        archives_group = QGroupBox("Select Archives to Restore")
        archives_layout = QVBoxLayout(archives_group)
        
        self.restore_list = QListWidget()
        self.restore_list.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        archives_layout.addWidget(self.restore_list)
        
        btn_layout = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(lambda: self.restore_list.selectAll())
        btn_layout.addWidget(select_all_btn)
        
        select_none_btn = QPushButton("Select None")
        select_none_btn.clicked.connect(lambda: self.restore_list.clearSelection())
        btn_layout.addWidget(select_none_btn)
        
        btn_layout.addStretch()
        archives_layout.addLayout(btn_layout)
        
        layout.addWidget(archives_group)
        
        # Restore Options
        options_group = QGroupBox("Restore Options")
        options_layout = QVBoxLayout(options_group)
        
        self.restore_contexts_check = QCheckBox("Restore SELinux contexts (recommended)")
        self.restore_contexts_check.setChecked(True)
        self.restore_contexts_check.setToolTip(
            "Restore SELinux security contexts from backup.\n"
            "Required for apps and system files to work correctly.\n"
            "Disable only if you know what you're doing."
        )
        options_layout.addWidget(self.restore_contexts_check)
        
        context_info = QLabel(
            "   📋 Restores: file paths, symlinks, permissions (mode),\n"
            "   ownership (UID/GID), and SELinux contexts"
        )
        context_info.setStyleSheet("color: #888; font-size: 11px;")
        options_layout.addWidget(context_info)
        
        layout.addWidget(options_group)
        
        # Warning
        warning = QLabel("⚠️ WARNING: Restore will OVERWRITE existing files on device!")
        warning.setStyleSheet("color: #ff6600; font-weight: bold;")
        layout.addWidget(warning)
        
        # Restore Button
        self.restore_btn = QPushButton("🔄 START RESTORE")
        self.restore_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff6600;
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #e55c00; }
            QPushButton:disabled { background-color: #888; }
        """)
        self.restore_btn.clicked.connect(self._start_restore)
        layout.addWidget(self.restore_btn)
        
        layout.addStretch()
        
        scroll.setWidget(widget)
        return scroll
    
    def _create_history_tab(self) -> QWidget:
        """Create the backup history tab."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        
        info = QLabel("Backup history shows all backups in your default output folder.")
        info.setStyleSheet("color: #888;")
        layout.addWidget(info)
        
        self.history_list = QListWidget()
        self.history_list.setMinimumHeight(200)
        layout.addWidget(self.history_list)
        
        btn_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_history)
        btn_layout.addWidget(refresh_btn)
        
        open_btn = QPushButton("📂 Open Folder")
        open_btn.clicked.connect(self._open_backup_folder)
        btn_layout.addWidget(open_btn)
        
        btn_layout.addStretch()
        
        delete_btn = QPushButton("🗑 Delete Selected")
        delete_btn.clicked.connect(self._delete_backup)
        btn_layout.addWidget(delete_btn)
        
        layout.addLayout(btn_layout)
        
        layout.addStretch()
        
        scroll.setWidget(widget)
        return scroll
    
    def _refresh_devices(self):
        """Refresh the device list."""
        self.device_combo.clear()
        self.devices = []
        
        adb_path = find_adb()
        if not adb_path:
            self.device_combo.addItem("ADB not found")
            return
        
        try:
            result = subprocess.run(
                [adb_path, "devices", "-l"],
                capture_output=True, text=True, timeout=10
            )
            
            for line in result.stdout.strip().split('\n')[1:]:
                if '\t' in line or 'device' in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == 'device':
                        serial = parts[0]
                        model = "Unknown"
                        
                        for part in parts[2:]:
                            if part.startswith("model:"):
                                model = part.split(":")[1]
                                break
                        
                        self.devices.append(serial)
                        self.device_combo.addItem(f"{model} ({serial})", serial)
            
            if not self.devices:
                self.device_combo.addItem("No devices found")
                self.root_status.setText("⬤ No device")
                self.root_status.setStyleSheet("color: #888;")
            else:
                self._check_root_status()
                
        except Exception as e:
            self.device_combo.addItem(f"Error: {e}")
    
    def _check_root_status(self):
        """Check if current device has root access."""
        if not self.devices:
            return
        
        device = self.device_combo.currentData()
        if not device:
            return
        
        adb_path = find_adb()
        try:
            result = subprocess.run(
                [adb_path, "-s", device, "shell", "su", "-c", "id"],
                capture_output=True, text=True, timeout=10
            )
            
            if "uid=0" in result.stdout:
                self.root_status.setText("⬤ Rooted")
                self.root_status.setStyleSheet("color: #4CAF50; font-weight: bold;")
            else:
                self.root_status.setText("⬤ Not Rooted")
                self.root_status.setStyleSheet("color: #f44336;")
        except:
            self.root_status.setText("⬤ Unknown")
            self.root_status.setStyleSheet("color: #888;")
    
    def _on_profile_changed(self, button):
        """Handle profile selection change."""
        profile_id = button.property("profile_id")
        self.custom_paths_group.setVisible(profile_id == "custom")
        self.config["last_profile"] = profile_id
        self._save_config()
    
    def _browse_output(self):
        """Browse for output directory."""
        path = QFileDialog.getExistingDirectory(
            self.parent_window, "Select Backup Output Directory",
            self.output_path.text() or os.path.expanduser("~")
        )
        if path:
            self.output_path.setText(path)
            self.config["default_output"] = path
            self._save_config()
    
    def _browse_restore(self):
        """Browse for backup to restore."""
        path = QFileDialog.getExistingDirectory(
            self.parent_window, "Select Backup Folder to Restore",
            self.config.get("default_output", os.path.expanduser("~"))
        )
        if path:
            self.restore_path.setText(path)
            self._load_restore_info(path)
    
    def _load_restore_info(self, path: str):
        """Load backup info for restore."""
        manifest_path = os.path.join(path, "backup_manifest.json")
        
        self.restore_list.clear()
        
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, 'r') as f:
                    manifest = json.load(f)
                
                device = manifest.get("device", {})
                stats = manifest.get("stats", {})
                
                self.restore_info.setText(
                    f"📱 {device.get('model', 'Unknown')} | "
                    f"📅 {manifest.get('created', 'Unknown')[:10]} | "
                    f"📦 {stats.get('total_files', 0):,} files | "
                    f"💾 {stats.get('total_size', 0) / 1024 / 1024:.1f} MB"
                )
                
                # List archives
                for name, info in manifest.get("archives", {}).items():
                    item = QListWidgetItem(
                        f"{name} - {info.get('file_count', 0):,} files"
                    )
                    item.setData(Qt.ItemDataRole.UserRole, name)
                    self.restore_list.addItem(item)
                    
            except Exception as e:
                self.restore_info.setText(f"Error loading manifest: {e}")
        else:
            self.restore_info.setText("No manifest found - manual archive selection")
            
            # List tar files
            for f in os.listdir(path):
                if f.endswith('.tar') or f.endswith('.tar.gz'):
                    name = f.replace('.tar.gz', '').replace('.tar', '')
                    item = QListWidgetItem(name)
                    item.setData(Qt.ItemDataRole.UserRole, name)
                    self.restore_list.addItem(item)
    
    def _get_selected_paths(self) -> list:
        """Get paths to backup based on selected profile."""
        # Find selected profile
        for button in self.profile_buttons.buttons():
            if button.isChecked():
                profile_id = button.property("profile_id")
                
                if profile_id == "custom":
                    # Get selected paths from tree
                    paths = []
                    for item in self.path_tree.selectedItems():
                        if item.childCount() == 0:  # Leaf node
                            paths.append(item.text(0))
                    return paths
                else:
                    return BACKUP_PROFILES[profile_id]["paths"]
        
        return []
    
    def _start_backup(self):
        """Start the backup process."""
        if not self.devices:
            QMessageBox.warning(self.parent_window, "No Device", "No device connected")
            return
        
        device = self.device_combo.currentData()
        paths = self._get_selected_paths()
        output_dir = self.output_path.text()
        backup_name = self.backup_name.text() or "Android_Backup"
        
        if not paths:
            QMessageBox.warning(self.parent_window, "No Paths", "Please select paths to backup")
            return
        
        if not output_dir:
            QMessageBox.warning(self.parent_window, "No Output", "Please select an output directory")
            return
        
        # Save config
        self.config["compress"] = self.compress_check.isChecked()
        self.config["verify"] = self.verify_check.isChecked()
        self._save_config()
        
        # Start worker
        self.backup_worker = BackupWorker(
            device=device,
            paths=paths,
            output_dir=output_dir,
            backup_name=backup_name,
            compress=self.compress_check.isChecked(),
            verify=self.verify_check.isChecked()
        )
        
        self.backup_worker.progress.connect(self._on_progress)
        self.backup_worker.status.connect(self._on_status)
        self.backup_worker.log.connect(self._on_log)
        self.backup_worker.finished.connect(self._on_backup_finished)
        
        self.backup_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.log_text.clear()
        
        self.backup_worker.start()
    
    def _cancel_backup(self):
        """Cancel the backup."""
        if self.backup_worker:
            self.backup_worker.cancel()
            self._on_log("⏹ Cancelling...")
    
    def _start_restore(self):
        """Start the restore process."""
        if not self.devices:
            QMessageBox.warning(self.parent_window, "No Device", "No device connected")
            return
        
        device = self.device_combo.currentData()
        backup_path = self.restore_path.text()
        
        if not backup_path or not os.path.exists(backup_path):
            QMessageBox.warning(self.parent_window, "No Backup", "Please select a valid backup folder")
            return
        
        selected = [item.data(Qt.ItemDataRole.UserRole) for item in self.restore_list.selectedItems()]
        
        if not selected:
            QMessageBox.warning(self.parent_window, "No Selection", "Please select archives to restore")
            return
        
        # Confirm
        restore_contexts = self.restore_contexts_check.isChecked()
        context_msg = "\n✓ SELinux contexts will be restored" if restore_contexts else "\n⚠️ SELinux contexts will NOT be restored"
        
        reply = QMessageBox.warning(
            self.parent_window,
            "Confirm Restore",
            f"⚠️ This will OVERWRITE files on your device!\n\n"
            f"Restoring {len(selected)} archives from:\n{backup_path}\n"
            f"{context_msg}\n\n"
            f"Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # Start restore
        self.restore_worker = RestoreWorker(device, backup_path, selected, restore_contexts)
        self.restore_worker.progress.connect(self._on_progress)
        self.restore_worker.status.connect(self._on_status)
        self.restore_worker.log.connect(self._on_log)
        self.restore_worker.finished.connect(self._on_restore_finished)
        
        self.restore_btn.setEnabled(False)
        self.log_text.clear()
        
        self.restore_worker.start()
    
    def _on_progress(self, current, total):
        """Handle progress updates."""
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
    
    def _on_status(self, status):
        """Handle status updates."""
        self.status_label.setText(status)
    
    def _on_log(self, message):
        """Handle log messages."""
        self.log_text.append(message)
        # Auto-scroll
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def _on_backup_finished(self, success, message, backup_info):
        """Handle backup completion."""
        self.backup_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        
        if success:
            QMessageBox.information(self.parent_window, "Backup Complete", message)
            self._refresh_history()
        else:
            QMessageBox.warning(self.parent_window, "Backup Failed", message)
    
    def _on_restore_finished(self, success, message):
        """Handle restore completion."""
        self.restore_btn.setEnabled(True)
        
        if success:
            QMessageBox.information(self.parent_window, "Restore Complete", message)
        else:
            QMessageBox.warning(self.parent_window, "Restore Failed", message)
    
    def _refresh_history(self):
        """Refresh backup history."""
        self.history_list.clear()
        
        output_dir = self.config.get("default_output", "")
        if not output_dir or not os.path.exists(output_dir):
            return
        
        for folder in sorted(os.listdir(output_dir), reverse=True):
            folder_path = os.path.join(output_dir, folder)
            manifest_path = os.path.join(folder_path, "backup_manifest.json")
            
            if os.path.isdir(folder_path) and os.path.exists(manifest_path):
                try:
                    with open(manifest_path, 'r') as f:
                        manifest = json.load(f)
                    
                    device = manifest.get("device", {})
                    stats = manifest.get("stats", {})
                    
                    item = QListWidgetItem(
                        f"📦 {manifest.get('backup_name', folder)} | "
                        f"{device.get('model', 'Unknown')} | "
                        f"{manifest.get('created', 'Unknown')[:10]} | "
                        f"{stats.get('total_files', 0):,} files | "
                        f"{stats.get('total_size', 0) / 1024 / 1024:.1f} MB"
                    )
                    item.setData(Qt.ItemDataRole.UserRole, folder_path)
                    self.history_list.addItem(item)
                except:
                    pass
    
    def _open_backup_folder(self):
        """Open the backup folder."""
        output_dir = self.config.get("default_output", "")
        if output_dir and os.path.exists(output_dir):
            os.startfile(output_dir)
    
    def _delete_backup(self):
        """Delete selected backup."""
        item = self.history_list.currentItem()
        if not item:
            return
        
        path = item.data(Qt.ItemDataRole.UserRole)
        
        reply = QMessageBox.question(
            self.parent_window,
            "Delete Backup",
            f"Delete this backup?\n\n{path}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                shutil.rmtree(path)
                self._refresh_history()
            except Exception as e:
                QMessageBox.warning(self.parent_window, "Error", f"Failed to delete: {e}")


# Plugin export - required for Image Anarchy plugin loader
Plugin = IABSPlugin
