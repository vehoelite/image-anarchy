"""
Visual Plugin Maker v2 - AST-Based Plugin Editor

This module provides a complete visual editor for Image Anarchy plugins.
It uses Python's AST module to parse plugin.py files into editable blocks,
allowing users to edit any part of a plugin while preserving all code.

Key Features:
- Parse any plugin.py into structured blocks (imports, functions, classes, etc.)
- Edit code directly with syntax highlighting
- Visual Mode: Edit individual blocks
- Code Mode: Edit full source with IDE-style editor
- Templates geared toward Image Anarchy's rebellious style
- Extended Function Library: ADB/Fastboot/MTK/Scrcpy with availability checks
- Validation: Code syntax and manifest validation
- Zero-loss roundtrip editing

UI Structure:
- Tab 1: manifest.json - Edit all manifest fields (sqlite3 compatible)
- Tab 2: plugin.py - Visual Mode with sub-tabs OR Code Mode
"""

import ast
import os
import json
import re
import sys
import zipfile
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTextEdit, QPlainTextEdit, QListWidget, QListWidgetItem, QTabWidget,
    QFrame, QSplitter, QScrollArea, QFileDialog, QMessageBox, QComboBox,
    QFormLayout, QGroupBox, QApplication, QSizePolicy, QStackedWidget,
    QDialog, QDialogButtonBox, QCheckBox, QRadioButton, QButtonGroup,
    QProgressBar, QSpinBox, QSlider, QTableWidget, QToolButton, QGridLayout,
    QTreeWidget, QTreeWidgetItem, QMenu
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize, QTimer
from PyQt6.QtGui import QFont, QColor, QSyntaxHighlighter, QTextCharFormat, QFontDatabase


# ═══════════════════════════════════════════════════════════════════════════════
# PLUGIN AVAILABILITY CHECKER
# ═══════════════════════════════════════════════════════════════════════════════

def get_plugins_dir() -> str:
    """Get the plugins directory."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'plugins')


def check_plugin_available(plugin_id: str) -> bool:
    """Check if a plugin is installed and available."""
    if not plugin_id:
        return True  # No requirement = always available
    plugin_path = os.path.join(get_plugins_dir(), plugin_id)
    manifest_path = os.path.join(plugin_path, 'manifest.json')
    return os.path.exists(manifest_path)


# ═══════════════════════════════════════════════════════════════════════════════
# MANIFEST SCHEMA - SQLite3 Compatible
# ═══════════════════════════════════════════════════════════════════════════════

MANIFEST_SCHEMA = {
    "id": {"type": "string", "required": True, "db_type": "TEXT PRIMARY KEY", "description": "Unique identifier (folder name)"},
    "name": {"type": "string", "required": True, "db_type": "TEXT NOT NULL", "description": "Display name"},
    "version": {"type": "string", "required": True, "db_type": "TEXT NOT NULL", "description": "Semantic version (e.g., 1.0.0)"},
    "description": {"type": "string", "required": False, "db_type": "TEXT", "description": "Brief description"},
    "author": {"type": "string", "required": False, "db_type": "TEXT", "description": "Developer name"},
    "icon": {"type": "string", "required": False, "db_type": "TEXT", "description": "Emoji icon"},
    "license_type": {"type": "string", "required": False, "db_type": "TEXT", "description": "free, paid, or donation", "enum": ["free", "paid", "donation"]},
    "website": {"type": "string", "required": False, "db_type": "TEXT", "description": "Project website URL"},
    "support_url": {"type": "string", "required": False, "db_type": "TEXT", "description": "Support/issues URL"},
    "min_version": {"type": "string", "required": False, "db_type": "TEXT", "description": "Minimum app version"},
    "requirements": {"type": "list", "required": False, "db_type": "TEXT", "description": "Pip packages (JSON array)"},
    "git_clone": {"type": "dict", "required": False, "db_type": "TEXT", "description": "Repository to clone (JSON object)"},
    "setup_commands": {"type": "list", "required": False, "db_type": "TEXT", "description": "Setup commands (JSON array)"},
    "bundled_binaries": {"type": "list", "required": False, "db_type": "TEXT", "description": "Binary files (JSON array)"},
    "post_install": {"type": "list", "required": False, "db_type": "TEXT", "description": "Post-install steps (JSON array)"},
    "enabled": {"type": "boolean", "required": False, "db_type": "INTEGER DEFAULT 1", "description": "Plugin enabled state"},
}


def validate_manifest(manifest: Dict) -> Tuple[bool, List[str]]:
    """Validate manifest against schema.

    Returns: (is_valid: bool, errors: list)
    """
    errors = []

    for field_name, spec in MANIFEST_SCHEMA.items():
        value = manifest.get(field_name)

        # Check required fields
        if spec['required'] and not value:
            errors.append(f"Required field '{field_name}' is missing")
            continue

        if value is None:
            continue

        # Type validation
        if spec['type'] == 'string' and not isinstance(value, str):
            errors.append(f"Field '{field_name}' must be a string")
        elif spec['type'] == 'list' and not isinstance(value, list):
            errors.append(f"Field '{field_name}' must be a list")
        elif spec['type'] == 'dict' and not isinstance(value, dict):
            errors.append(f"Field '{field_name}' must be an object")
        elif spec['type'] == 'boolean' and not isinstance(value, bool):
            errors.append(f"Field '{field_name}' must be a boolean")

        # Enum validation
        if 'enum' in spec and value and value not in spec['enum']:
            errors.append(f"Field '{field_name}' must be one of: {spec['enum']}")

    # ID format validation
    if manifest.get('id'):
        if not re.match(r'^[a-z][a-z0-9_]*$', manifest['id']):
            errors.append("ID must start with lowercase letter and contain only lowercase letters, numbers, underscores")

    # Version format validation
    if manifest.get('version'):
        if not re.match(r'^\d+\.\d+(\.\d+)?$', manifest['version']):
            errors.append("Version must be in format: X.Y or X.Y.Z")

    return len(errors) == 0, errors


# ═══════════════════════════════════════════════════════════════════════════════
# TEMPLATES - Image Anarchy Style
# ═══════════════════════════════════════════════════════════════════════════════

PLUGIN_TEMPLATES = {
    "basic": {
        "name": "Basic Plugin",
        "icon": "🔌",
        "description": "Simple plugin with UI - perfect for starting out",
        "manifest": {
            "id": "my_plugin",
            "name": "My Plugin",
            "version": "1.0",
            "description": "A powerful tool for Android enthusiasts",
            "author": "Your Name",
            "icon": "🔌",
            "license_type": "free",
            "requirements": [],
        },
        "code": '''"""
My Plugin - Unleash the Power

A custom tool for Image Anarchy.
"""

import os
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt6.QtCore import Qt


def get_plugin_dir():
    """Get the plugin directory."""
    return os.path.dirname(os.path.abspath(__file__))


class PluginWidget(QWidget):
    """Break free with your custom plugin."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("My Plugin")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #e91e63;")
        layout.addWidget(title)

        desc = QLabel("Unleash the power of your Android device")
        desc.setStyleSheet("color: #888;")
        layout.addWidget(desc)

        btn = QPushButton("Execute")
        btn.setStyleSheet("""
            QPushButton {
                background: #e91e63;
                color: white;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover { background: #c2185b; }
        """)
        btn.clicked.connect(self._on_execute)
        layout.addWidget(btn)

        layout.addStretch()

    def _on_execute(self):
        """Handle execute button click."""
        print("Anarchy unleashed!")


class MyPlugin:
    def __init__(self):
        self.manifest = None
        self.widget = None

    def get_name(self):
        return self.manifest.name if self.manifest else "My Plugin"

    def get_icon(self):
        return "🔌"

    def create_widget(self, parent):
        self.widget = PluginWidget(parent)
        return self.widget


Plugin = MyPlugin
'''
    },

    "device_tool": {
        "name": "Device Tool",
        "icon": "📱",
        "description": "Template with ADB/Fastboot integration ready",
        "manifest": {
            "id": "device_tool",
            "name": "Device Tool",
            "version": "1.0",
            "description": "Device operations made easy - break free from restrictions",
            "author": "Your Name",
            "icon": "📱",
            "license_type": "free",
            "requirements": [],
            "bundled_binaries": [
                "platform-tools/adb.exe",
                "platform-tools/fastboot.exe"
            ]
        },
        "code": '''"""
Device Tool - Anarchy for Your Device

Direct device operations via ADB/Fastboot.
No restrictions, no limits.
"""

import os
import sys
import subprocess
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QGroupBox, QComboBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread


def get_plugin_dir():
    """Get the plugin directory."""
    return os.path.dirname(os.path.abspath(__file__))


def find_adb():
    """Find ADB executable with priority order."""
    plugin_dir = get_plugin_dir()
    exe = "adb.exe" if sys.platform == "win32" else "adb"

    # Check plugin's platform-tools first
    local = os.path.join(plugin_dir, "platform-tools", exe)
    if os.path.exists(local):
        return local

    # Check app's platform-tools
    app_dir = os.path.dirname(os.path.dirname(plugin_dir))
    app_path = os.path.join(app_dir, "platform-tools", exe)
    if os.path.exists(app_path):
        return app_path

    # Check PyInstaller bundle
    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', None)
        if meipass:
            bundle = os.path.join(meipass, "platform-tools", exe)
            if os.path.exists(bundle):
                return bundle

    return "adb"


def find_fastboot():
    """Find Fastboot executable with priority order."""
    plugin_dir = get_plugin_dir()
    exe = "fastboot.exe" if sys.platform == "win32" else "fastboot"

    local = os.path.join(plugin_dir, "platform-tools", exe)
    if os.path.exists(local):
        return local

    app_dir = os.path.dirname(os.path.dirname(plugin_dir))
    app_path = os.path.join(app_dir, "platform-tools", exe)
    if os.path.exists(app_path):
        return app_path

    return "fastboot"


class CommandWorker(QThread):
    """Worker thread for running device commands."""

    output = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, command, cwd=None):
        super().__init__()
        self.command = command
        self.cwd = cwd

    def run(self):
        try:
            result = subprocess.run(
                self.command,
                capture_output=True,
                text=True,
                cwd=self.cwd
            )
            output = result.stdout + result.stderr
            self.output.emit(output)
            self.finished.emit(result.returncode == 0, output)
        except Exception as e:
            self.output.emit(f"Error: {e}")
            self.finished.emit(False, str(e))


class PluginWidget(QWidget):
    """Device operations made anarchic."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        title = QLabel("Device Tool")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #e91e63;")
        layout.addWidget(title)

        # Quick actions
        actions = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout(actions)

        devices_btn = QPushButton("Devices")
        devices_btn.clicked.connect(self._check_devices)
        actions_layout.addWidget(devices_btn)

        reboot_btn = QPushButton("Reboot")
        reboot_btn.clicked.connect(self._reboot_device)
        actions_layout.addWidget(reboot_btn)

        recovery_btn = QPushButton("Recovery")
        recovery_btn.clicked.connect(self._reboot_recovery)
        actions_layout.addWidget(recovery_btn)

        layout.addWidget(actions)

        # Output
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background: #1a1a1a; color: #0f0; font-family: monospace;")
        layout.addWidget(self.output)

    def _log(self, msg):
        self.output.append(msg)

    def _check_devices(self):
        adb = find_adb()
        self._run_command([adb, "devices", "-l"])

    def _reboot_device(self):
        adb = find_adb()
        self._run_command([adb, "reboot"])

    def _reboot_recovery(self):
        adb = find_adb()
        self._run_command([adb, "reboot", "recovery"])

    def _run_command(self, cmd):
        self._log(f"$ {' '.join(cmd)}")
        self.worker = CommandWorker(cmd)
        self.worker.output.connect(self._log)
        self.worker.start()


class DevicePlugin:
    def __init__(self):
        self.manifest = None
        self.widget = None

    def get_name(self):
        return self.manifest.name if self.manifest else "Device Tool"

    def get_icon(self):
        return "📱"

    def create_widget(self, parent):
        self.widget = PluginWidget(parent)
        return self.widget


Plugin = DevicePlugin
'''
    },

    "partition_tool": {
        "name": "Partition Tool",
        "icon": "💾",
        "description": "Read/Write partitions with proper threading",
        "manifest": {
            "id": "partition_tool",
            "name": "Partition Tool",
            "version": "1.0",
            "description": "Read and write Android partitions - break free from locks",
            "author": "Your Name",
            "icon": "💾",
            "license_type": "free",
            "requirements": [],
        },
        "code": '''"""
Partition Tool - Break Free From Restrictions

Read and write partitions like a true anarchist.
"""

import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QGroupBox, QComboBox, QProgressBar
)
from PyQt6.QtCore import Qt


def get_plugin_dir():
    return os.path.dirname(os.path.abspath(__file__))


PARTITIONS = [
    "boot", "recovery", "vbmeta", "vendor_boot",
    "system", "vendor", "product", "odm", "super"
]


class PluginWidget(QWidget):
    """Partition operations for the rebellious."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        title = QLabel("Partition Tool")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #e91e63;")
        layout.addWidget(title)

        subtitle = QLabel("Break free - read and write your partitions")
        subtitle.setStyleSheet("color: #888;")
        layout.addWidget(subtitle)

        # Partition selector
        select_group = QGroupBox("Select Partition")
        select_layout = QHBoxLayout(select_group)

        self.partition_combo = QComboBox()
        self.partition_combo.addItems(PARTITIONS)
        select_layout.addWidget(self.partition_combo)

        for p in ["boot", "recovery", "vbmeta"]:
            btn = QPushButton(p)
            btn.clicked.connect(lambda checked, part=p: self.partition_combo.setCurrentText(part))
            select_layout.addWidget(btn)

        layout.addWidget(select_group)

        # Actions
        actions = QGroupBox("Actions")
        actions_layout = QHBoxLayout(actions)

        read_btn = QPushButton("Read")
        read_btn.setStyleSheet("background: #4caf50; color: white; padding: 10px;")
        actions_layout.addWidget(read_btn)

        write_btn = QPushButton("Write")
        write_btn.setStyleSheet("background: #2196f3; color: white; padding: 10px;")
        actions_layout.addWidget(write_btn)

        layout.addWidget(actions)

        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        # Output
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background: #1a1a1a; color: #0f0; font-family: monospace;")
        layout.addWidget(self.output)


class PartitionPlugin:
    def __init__(self):
        self.manifest = None
        self.widget = None

    def get_name(self):
        return self.manifest.name if self.manifest else "Partition Tool"

    def get_icon(self):
        return "💾"

    def create_widget(self, parent):
        self.widget = PluginWidget(parent)
        return self.widget


Plugin = PartitionPlugin
'''
    },

    "firmware_decryptor": {
        "name": "Firmware Decryptor",
        "icon": "🔓",
        "description": "Decrypt OFP/OPS firmware with dependencies",
        "manifest": {
            "id": "firmware_decryptor",
            "name": "Firmware Decryptor",
            "version": "1.0",
            "description": "Decrypt OPPO/OnePlus/Realme firmware - no lock can hold you",
            "author": "Your Name",
            "icon": "🔓",
            "license_type": "free",
            "requirements": ["pycryptodome"],
        },
        "code": '''"""
Firmware Decryptor - No Lock Can Hold You

Decrypt proprietary firmware formats.
"""

import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QGroupBox, QFileDialog, QProgressBar
)
from PyQt6.QtCore import Qt


def get_plugin_dir():
    return os.path.dirname(os.path.abspath(__file__))


class PluginWidget(QWidget):
    """Decrypt firmware like a true rebel."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.selected_file = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        title = QLabel("Firmware Decryptor")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #e91e63;")
        layout.addWidget(title)

        subtitle = QLabel("No encryption can hold back anarchy")
        subtitle.setStyleSheet("color: #888;")
        layout.addWidget(subtitle)

        # File selection
        file_group = QGroupBox("Select Firmware")
        file_layout = QHBoxLayout(file_group)

        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("color: #666;")
        file_layout.addWidget(self.file_label, 1)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_file)
        file_layout.addWidget(browse_btn)

        layout.addWidget(file_group)

        formats = QLabel("Supported: .ofp (OPPO/Realme) | .ops (OnePlus) | .zip (encrypted)")
        formats.setStyleSheet("color: #666; font-size: 11px;")
        layout.addWidget(formats)

        # Decrypt button
        decrypt_btn = QPushButton("DECRYPT")
        decrypt_btn.setStyleSheet("""
            QPushButton {
                background: #e91e63;
                color: white;
                padding: 15px;
                font-size: 16px;
                font-weight: bold;
                border-radius: 8px;
            }
            QPushButton:hover { background: #c2185b; }
        """)
        layout.addWidget(decrypt_btn)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background: #1a1a1a; color: #0f0; font-family: monospace;")
        layout.addWidget(self.output)

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Firmware",
            "", "Firmware (*.ofp *.ops *.zip);;All Files (*.*)"
        )
        if path:
            self.selected_file = path
            self.file_label.setText(os.path.basename(path))
            self.file_label.setStyleSheet("color: #4caf50;")


class DecryptorPlugin:
    def __init__(self):
        self.manifest = None
        self.widget = None

    def get_name(self):
        return self.manifest.name if self.manifest else "Firmware Decryptor"

    def get_icon(self):
        return "🔓"

    def create_widget(self, parent):
        self.widget = PluginWidget(parent)
        return self.widget


Plugin = DecryptorPlugin
'''
    }
}


# ═══════════════════════════════════════════════════════════════════════════════
# EXTENDED FUNCTION LIBRARY - With plugin availability checks
# ═══════════════════════════════════════════════════════════════════════════════

FUNCTION_LIBRARY = {
    "adb": {
        "name": "ADB Functions",
        "icon": "📱",
        "plugin_check": "adb_toolkit",  # Check if this plugin exists
        "functions": {
            "find_adb": {
                "description": "Find ADB executable with fallback paths",
                "imports": ["os", "sys", "shutil"],
                "code": '''def find_adb():
    """Find ADB executable with priority order.

    Checks: plugin dir > app dir > PyInstaller bundle > PATH
    """
    plugin_dir = get_plugin_dir()
    exe = "adb.exe" if sys.platform == "win32" else "adb"

    local = os.path.join(plugin_dir, "platform-tools", exe)
    if os.path.exists(local):
        return local

    app_dir = os.path.dirname(os.path.dirname(plugin_dir))
    app_path = os.path.join(app_dir, "platform-tools", exe)
    if os.path.exists(app_path):
        return app_path

    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', None)
        if meipass:
            bundle = os.path.join(meipass, "platform-tools", exe)
            if os.path.exists(bundle):
                return bundle

    return "adb"'''
            },
            "run_adb_command": {
                "description": "Run an ADB command and return output",
                "imports": ["subprocess"],
                "requires": ["find_adb"],
                "code": '''def run_adb_command(args, timeout=60):
    """Run an ADB command with the given arguments.

    Args:
        args: List of arguments (without 'adb' prefix)
        timeout: Command timeout in seconds

    Returns:
        tuple: (success: bool, output: str)
    """
    adb = find_adb()
    cmd = [adb] + args

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        return result.returncode == 0, output.strip()
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)'''
            },
            "get_connected_devices": {
                "description": "Get list of connected ADB devices",
                "imports": [],
                "requires": ["run_adb_command"],
                "code": '''def get_connected_devices():
    """Get list of connected ADB devices.

    Returns:
        list: List of (serial, state, description) tuples
    """
    success, output = run_adb_command(["devices", "-l"])
    if not success:
        return []

    devices = []
    for line in output.split("\\n")[1:]:
        if line.strip():
            parts = line.split()
            if len(parts) >= 2:
                serial = parts[0]
                state = parts[1]
                desc = " ".join(parts[2:]) if len(parts) > 2 else ""
                devices.append((serial, state, desc))
    return devices'''
            }
        }
    },
    "fastboot": {
        "name": "Fastboot Functions",
        "icon": "⚡",
        "plugin_check": "fastboot_toolkit",
        "functions": {
            "find_fastboot": {
                "description": "Find Fastboot executable with fallback paths",
                "imports": ["os", "sys"],
                "code": '''def find_fastboot():
    """Find Fastboot executable with priority order."""
    plugin_dir = get_plugin_dir()
    exe = "fastboot.exe" if sys.platform == "win32" else "fastboot"

    local = os.path.join(plugin_dir, "platform-tools", exe)
    if os.path.exists(local):
        return local

    app_dir = os.path.dirname(os.path.dirname(plugin_dir))
    app_path = os.path.join(app_dir, "platform-tools", exe)
    if os.path.exists(app_path):
        return app_path

    return "fastboot"'''
            },
            "run_fastboot_command": {
                "description": "Run a Fastboot command and return output",
                "imports": ["subprocess"],
                "requires": ["find_fastboot"],
                "code": '''def run_fastboot_command(args, timeout=120):
    """Run a Fastboot command with the given arguments."""
    fastboot = find_fastboot()
    cmd = [fastboot] + args

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        return result.returncode == 0, output.strip()
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)'''
            }
        }
    },
    "mtk": {
        "name": "MTK Functions",
        "icon": "🔧",
        "plugin_check": "mtk_toolkit",
        "functions": {
            "get_mtkclient_dir": {
                "description": "Find mtkclient installation directory",
                "imports": ["os", "sys"],
                "code": '''def get_mtkclient_dir():
    """Find mtkclient installation directory."""
    plugin_dir = get_plugin_dir()

    possible_dirs = [
        os.path.join(plugin_dir, "mtkclient"),
        os.path.join(plugin_dir, "mtkclient", "mtkclient"),
        os.path.join(get_app_dir(), "mtkclient"),
    ]

    for dir_path in possible_dirs:
        mtk_py = os.path.join(dir_path, "mtk.py")
        library_dir = os.path.join(dir_path, "Library")
        if os.path.isfile(mtk_py) or os.path.isdir(library_dir):
            return dir_path

    return None'''
            },
            "run_mtk_command": {
                "description": "Run mtkclient command via CLI",
                "imports": ["subprocess", "sys"],
                "requires": ["get_mtkclient_dir"],
                "code": '''def run_mtk_command(args, callback=None, cwd=None):
    """Run an mtkclient command. Returns: (success, output)"""
    mtk_dir = get_mtkclient_dir()
    if not mtk_dir:
        return False, "mtkclient not found"

    mtk_py = os.path.join(mtk_dir, "mtk.py")
    cmd = [sys.executable, mtk_py] + args

    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=cwd or mtk_dir, text=True, bufsize=1
        )

        output_lines = []
        for line in iter(process.stdout.readline, ''):
            output_lines.append(line)
            if callback:
                callback(line.rstrip())

        process.wait()
        return process.returncode == 0, ''.join(output_lines)
    except Exception as e:
        return False, str(e)'''
            },
            "read_partition": {
                "description": "Read a partition from MTK device",
                "requires": ["run_mtk_command"],
                "code": '''def read_partition(partition, output_path, callback=None):
    """Read a partition from MTK device."""
    return run_mtk_command(["r", partition, output_path], callback=callback)'''
            },
            "write_partition": {
                "description": "Write a partition to MTK device",
                "requires": ["run_mtk_command"],
                "code": '''def write_partition(partition, input_path, callback=None):
    """Write a partition to MTK device."""
    return run_mtk_command(["w", partition, input_path], callback=callback)'''
            }
        }
    },
    "scrcpy": {
        "name": "Scrcpy Functions",
        "icon": "📺",
        "plugin_check": "scrcpy_toolkit",
        "functions": {
            "find_scrcpy": {
                "description": "Find scrcpy executable",
                "imports": ["os", "shutil"],
                "code": '''def find_scrcpy():
    """Find scrcpy executable."""
    plugin_dir = get_plugin_dir()
    exe = "scrcpy.exe" if sys.platform == "win32" else "scrcpy"

    paths = [
        os.path.join(plugin_dir, exe),
        os.path.join(plugin_dir, "tools", exe),
        os.path.join(get_app_dir(), "tools", exe),
    ]

    for path in paths:
        if os.path.exists(path):
            return path

    return shutil.which("scrcpy") or "scrcpy"'''
            },
            "start_mirror": {
                "description": "Start screen mirroring",
                "imports": ["subprocess"],
                "requires": ["find_scrcpy"],
                "code": '''def start_mirror(device=None, max_size=1024):
    """Start scrcpy screen mirroring. Returns Popen process."""
    cmd = [find_scrcpy(), "--max-size", str(max_size)]
    if device:
        cmd.extend(["--serial", device])
    return subprocess.Popen(cmd)'''
            }
        }
    },
    "threading": {
        "name": "Threading Utilities",
        "icon": "🔄",
        "plugin_check": None,  # Always available
        "functions": {
            "CommandWorker": {
                "description": "QThread worker for subprocess commands",
                "imports": ["subprocess"],
                "pyqt_imports": ["QThread", "pyqtSignal"],
                "code": '''class CommandWorker(QThread):
    """Worker thread for running shell commands without blocking UI."""

    output = pyqtSignal(str)
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)

    def __init__(self, command, cwd=None, shell=False):
        super().__init__()
        self.command = command
        self.cwd = cwd
        self.shell = shell
        self._cancelled = False

    def run(self):
        try:
            process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=self.cwd,
                shell=self.shell,
                text=True,
                bufsize=1
            )

            output_lines = []
            for line in iter(process.stdout.readline, ''):
                if self._cancelled:
                    process.terminate()
                    break
                self.output.emit(line.rstrip())
                output_lines.append(line)

            process.wait()
            full_output = ''.join(output_lines)
            self.finished.emit(process.returncode == 0, full_output)

        except Exception as e:
            self.output.emit(f"Error: {e}")
            self.finished.emit(False, str(e))

    def cancel(self):
        self._cancelled = True'''
            }
        }
    },
    "utils": {
        "name": "Plugin Utilities",
        "icon": "🛠️",
        "plugin_check": None,  # Always available
        "functions": {
            "get_plugin_dir": {
                "description": "Get the plugin's directory path",
                "imports": ["os"],
                "code": '''def get_plugin_dir():
    """Get the plugin directory."""
    return os.path.dirname(os.path.abspath(__file__))'''
            },
            "get_app_dir": {
                "description": "Get the main app's directory path",
                "imports": ["os"],
                "code": '''def get_app_dir():
    """Get the main app directory (parent of plugins folder)."""
    plugin_dir = get_plugin_dir()
    return os.path.dirname(os.path.dirname(plugin_dir))'''
            },
            "log_to_parent": {
                "description": "Log message to parent window's log area",
                "imports": [],
                "code": '''def log_to_parent(widget, message, level='info'):
    """Log a message to the parent window if available.

    Args:
        widget: The plugin widget (must have parent_window)
        message: Message to log
        level: 'info', 'warning', 'error', or 'success'
    """
    if hasattr(widget, 'parent_window') and widget.parent_window:
        if hasattr(widget.parent_window, '_log'):
            widget.parent_window._log(message, level)
        else:
            print(f"[{level.upper()}] {message}")
    else:
        print(f"[{level.upper()}] {message}")'''
            }
        }
    }
}


# ═══════════════════════════════════════════════════════════════════════════════
# DATA MODEL
# ═══════════════════════════════════════════════════════════════════════════════

class BlockType(Enum):
    """Types of code blocks that can be edited."""
    DOCSTRING = "docstring"
    IMPORT = "import"
    IMPORT_FROM = "import_from"
    FUNCTION = "function"
    CLASS = "class"
    ASSIGNMENT = "assignment"


@dataclass
class CodeBlock:
    """A block of code that can be edited."""
    block_type: BlockType
    name: str
    display_name: str
    source_code: str
    line_start: int
    line_end: int
    icon: str = "📄"
    metadata: Dict = field(default_factory=dict)

    is_modified: bool = False
    is_new: bool = False
    is_deleted: bool = False

    children: List['CodeBlock'] = field(default_factory=list)


@dataclass
class ManifestBlock:
    """A manifest.json field that can be edited."""
    key: str
    display_name: str
    value: Any
    field_type: str
    icon: str = "📋"
    description: str = ""
    required: bool = False


@dataclass
class PluginModel:
    """Complete parsed plugin structure."""
    manifest: Dict = field(default_factory=dict)
    manifest_blocks: List[ManifestBlock] = field(default_factory=list)

    docstring: Optional[CodeBlock] = None
    imports: List[CodeBlock] = field(default_factory=list)
    functions: List[CodeBlock] = field(default_factory=list)
    classes: List[CodeBlock] = field(default_factory=list)
    assignments: List[CodeBlock] = field(default_factory=list)

    _source_lines: List[str] = field(default_factory=list)
    _original_source: str = ""

    def get_blocks_by_category(self, category: str) -> List[CodeBlock]:
        """Get blocks for a specific category tab."""
        if category == "imports":
            return self.imports
        elif category == "functions":
            return self.functions
        elif category == "classes":
            return self.classes
        elif category == "widgets":
            return [c for c in self.classes
                    if any(b in c.metadata.get('bases', '')
                           for b in ['QWidget', 'QFrame', 'QMainWindow', 'QDialog'])]
        elif category == "variables":
            return self.assignments
        elif category == "all":
            all_blocks = []
            if self.docstring:
                all_blocks.append(self.docstring)
            all_blocks.extend(self.imports)
            all_blocks.extend(self.functions)
            all_blocks.extend(self.classes)
            all_blocks.extend(self.assignments)
            return sorted(all_blocks, key=lambda b: b.line_start)
        return []

    def reconstruct(self) -> str:
        """Reconstruct the full source code from all blocks."""
        parts = []

        if self.docstring and not self.docstring.is_deleted:
            parts.append(self.docstring.source_code)

        active_imports = [i for i in self.imports if not i.is_deleted]
        active_imports.sort(key=lambda x: (x.is_new, x.line_start))
        for imp in active_imports:
            parts.append(imp.source_code)

        plugin_assign = None
        for assign in self.assignments:
            if assign.is_deleted:
                continue
            if 'Plugin' in assign.name:
                plugin_assign = assign
            else:
                parts.append(assign.source_code)

        active_funcs = [f for f in self.functions if not f.is_deleted]
        active_funcs.sort(key=lambda x: (x.is_new, x.line_start))
        for func in active_funcs:
            parts.append(func.source_code)

        active_classes = [c for c in self.classes if not c.is_deleted]
        active_classes.sort(key=lambda x: (x.is_new, x.line_start))
        for cls in active_classes:
            parts.append(cls.source_code)

        if plugin_assign:
            parts.append(plugin_assign.source_code)

        return '\n\n\n'.join(parts) + '\n'

    def generate_manifest(self) -> Dict:
        """Generate manifest dict from blocks."""
        result = {}
        for block in self.manifest_blocks:
            if block.value or block.required:
                result[block.key] = block.value
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# PARSER
# ═══════════════════════════════════════════════════════════════════════════════

class PluginParser:
    """Parse a plugin.py into a structured PluginModel."""

    def __init__(self, source_code: str, manifest: Dict = None):
        self.source = source_code
        self.lines = source_code.split('\n')
        self.manifest = manifest or {}
        self.model = PluginModel(
            manifest=manifest or {},
            _source_lines=self.lines,
            _original_source=source_code
        )

    def parse(self) -> PluginModel:
        """Parse the source code and manifest into a PluginModel."""
        self._parse_manifest()
        self._parse_source()
        return self.model

    def _parse_manifest(self):
        """Parse manifest.json into editable blocks."""
        # Manifest fields matching CLAUDE.md format exactly
        manifest_fields = [
            ('id', 'Plugin ID', 'string', True, 'Unique identifier (becomes folder name in plugins/)'),
            ('name', 'Name', 'string', True, 'Display name'),
            ('version', 'Version', 'string', True, 'Semantic version (e.g., 1.0)'),
            ('description', 'Description', 'string', False, 'Brief description'),
            ('author', 'Author', 'string', False, 'Developer name'),
            ('icon', 'Icon', 'string', False, 'Emoji icon'),
            ('license_type', 'License', 'string', False, 'free, paid, or donation'),
            ('website', 'Website', 'string', False, 'Project website URL'),
            ('support_url', 'Support URL', 'string', False, 'Support/issues URL'),
            ('min_version', 'Min Version', 'string', False, 'Minimum Image Anarchy version'),
            ('requirements', 'Requirements', 'list', False, 'Pip packages (one per line)'),
            ('git_clone', 'Git Clone', 'dict', False, 'Repository to clone: {"repo": "url", "target": "folder"}'),
            ('setup_commands', 'Setup Commands', 'list', False, 'Commands to run after clone (e.g., pip install .)'),
            ('bundled_binaries', 'Binaries', 'list', False, 'Binary URLs or local paths'),
            ('post_install', 'Post-Install', 'list', False, 'Post-install steps (drivers, commands)'),
            ('enabled', 'Enabled', 'boolean', False, 'Plugin enabled state'),
        ]

        for key, display, ftype, required, desc in manifest_fields:
            if ftype == 'string':
                default = ''
            elif ftype == 'list':
                default = []
            elif ftype == 'dict':
                default = {}
            elif ftype == 'boolean':
                default = True
            else:
                default = ''
            value = self.manifest.get(key, default)
            self.model.manifest_blocks.append(ManifestBlock(
                key=key,
                display_name=display,
                value=value,
                field_type=ftype,
                icon='📋' if ftype == 'string' else '📦',
                description=desc,
                required=required
            ))

    def _parse_source(self):
        """Parse plugin.py source code into blocks."""
        try:
            tree = ast.parse(self.source)
        except SyntaxError as e:
            self.model.docstring = CodeBlock(
                block_type=BlockType.DOCSTRING,
                name="parse_error",
                display_name="⚠️ Parse Error",
                source_code=self.source,
                line_start=1,
                line_end=len(self.lines),
                icon="⚠️",
                metadata={'error': str(e)}
            )
            return

        for node in ast.iter_child_nodes(tree):
            self._process_node(node)

    def _get_source(self, node: ast.AST) -> str:
        """Extract original source code for a node."""
        start_line = node.lineno - 1
        end_line = node.end_lineno
        return '\n'.join(self.lines[start_line:end_line])

    def _process_node(self, node: ast.AST):
        """Process a top-level AST node into a CodeBlock."""

        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str) and node.lineno <= 10:
                self.model.docstring = CodeBlock(
                    block_type=BlockType.DOCSTRING,
                    name="module_docstring",
                    display_name="📝 Module Docstring",
                    source_code=self._get_source(node),
                    line_start=node.lineno,
                    line_end=node.end_lineno,
                    icon="📝"
                )

        elif isinstance(node, ast.Import):
            names = ', '.join(a.name for a in node.names)
            self.model.imports.append(CodeBlock(
                block_type=BlockType.IMPORT,
                name=f"import {names}",
                display_name=f"📥 import {names[:30]}",
                source_code=self._get_source(node),
                line_start=node.lineno,
                line_end=node.end_lineno,
                icon="📥",
                metadata={'modules': [a.name for a in node.names]}
            ))

        elif isinstance(node, ast.ImportFrom):
            names = [a.name for a in node.names]
            self.model.imports.append(CodeBlock(
                block_type=BlockType.IMPORT_FROM,
                name=f"from {node.module} import ...",
                display_name=f"📦 from {node.module}",
                source_code=self._get_source(node),
                line_start=node.lineno,
                line_end=node.end_lineno,
                icon="📦",
                metadata={'module': node.module, 'names': names}
            ))

        elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            args = ', '.join(a.arg for a in node.args.args)
            is_async = isinstance(node, ast.AsyncFunctionDef)

            self.model.functions.append(CodeBlock(
                block_type=BlockType.FUNCTION,
                name=f"def {node.name}({args})",
                display_name=f"⚡ {node.name}()",
                source_code=self._get_source(node),
                line_start=node.lineno,
                line_end=node.end_lineno,
                icon="⚡",
                metadata={
                    'name': node.name,
                    'args': args,
                    'docstring': ast.get_docstring(node),
                    'is_async': is_async
                }
            ))

        elif isinstance(node, ast.ClassDef):
            bases = ', '.join(ast.unparse(b) for b in node.bases) if node.bases else ''

            methods = []
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_args = ', '.join(a.arg for a in item.args.args)
                    methods.append(CodeBlock(
                        block_type=BlockType.FUNCTION,
                        name=f"def {item.name}({method_args})",
                        display_name=f"  └─ {item.name}()",
                        source_code=self._get_source(item),
                        line_start=item.lineno,
                        line_end=item.end_lineno,
                        icon="⚙️",
                        metadata={'name': item.name, 'is_method': True}
                    ))

            icon = "🏗️"
            if any(b in bases for b in ['QWidget', 'QFrame', 'QMainWindow', 'QDialog']):
                icon = "🖼️"
            elif any(b in bases for b in ['QThread', 'Thread']):
                icon = "🔄"
            elif any(b in bases for b in ['QPushButton', 'QLabel']):
                icon = "🔘"

            self.model.classes.append(CodeBlock(
                block_type=BlockType.CLASS,
                name=f"class {node.name}({bases})" if bases else f"class {node.name}",
                display_name=f"{icon} class {node.name}",
                source_code=self._get_source(node),
                line_start=node.lineno,
                line_end=node.end_lineno,
                icon=icon,
                metadata={
                    'name': node.name,
                    'bases': bases,
                    'docstring': ast.get_docstring(node)
                },
                children=methods
            ))

        elif isinstance(node, ast.Assign):
            targets = ', '.join(ast.unparse(t) for t in node.targets)

            self.model.assignments.append(CodeBlock(
                block_type=BlockType.ASSIGNMENT,
                name=targets,
                display_name=f"📊 {targets}",
                source_code=self._get_source(node),
                line_start=node.lineno,
                line_end=node.end_lineno,
                icon="📊",
                metadata={
                    'targets': [ast.unparse(t) for t in node.targets],
                    'value': ast.unparse(node.value)
                }
            ))


# ═══════════════════════════════════════════════════════════════════════════════
# SYNTAX HIGHLIGHTER
# ═══════════════════════════════════════════════════════════════════════════════

class PythonHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for Python code."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_formats()
        self._init_rules()

    def _init_formats(self):
        """Initialize text formats for different syntax elements."""
        self.keyword_format = QTextCharFormat()
        self.keyword_format.setForeground(QColor("#c678dd"))
        self.keyword_format.setFontWeight(QFont.Weight.Bold)

        self.string_format = QTextCharFormat()
        self.string_format.setForeground(QColor("#98c379"))

        self.comment_format = QTextCharFormat()
        self.comment_format.setForeground(QColor("#5c6370"))
        self.comment_format.setFontItalic(True)

        self.function_format = QTextCharFormat()
        self.function_format.setForeground(QColor("#61afef"))

        self.class_format = QTextCharFormat()
        self.class_format.setForeground(QColor("#e5c07b"))
        self.class_format.setFontWeight(QFont.Weight.Bold)

        self.number_format = QTextCharFormat()
        self.number_format.setForeground(QColor("#d19a66"))

        self.decorator_format = QTextCharFormat()
        self.decorator_format.setForeground(QColor("#e06c75"))

        self.self_format = QTextCharFormat()
        self.self_format.setForeground(QColor("#e06c75"))
        self.self_format.setFontItalic(True)

    def _init_rules(self):
        """Initialize highlighting rules."""
        self.rules = []

        keywords = [
            'and', 'as', 'assert', 'async', 'await', 'break', 'class', 'continue',
            'def', 'del', 'elif', 'else', 'except', 'finally', 'for', 'from',
            'global', 'if', 'import', 'in', 'is', 'lambda', 'nonlocal', 'not',
            'or', 'pass', 'raise', 'return', 'try', 'while', 'with', 'yield',
            'True', 'False', 'None'
        ]
        for keyword in keywords:
            pattern = rf'\b{keyword}\b'
            self.rules.append((pattern, self.keyword_format))

        self.rules.append((r'\bself\b', self.self_format))
        self.rules.append((r'\bclass\s+(\w+)', self.class_format))
        self.rules.append((r'\bdef\s+(\w+)', self.function_format))
        self.rules.append((r'@\w+', self.decorator_format))
        self.rules.append((r'\b\d+\.?\d*\b', self.number_format))
        self.rules.append((r'"[^"\\]*(\\.[^"\\]*)*"', self.string_format))
        self.rules.append((r"'[^'\\]*(\\.[^'\\]*)*'", self.string_format))
        self.rules.append((r'#[^\n]*', self.comment_format))

    def highlightBlock(self, text):
        """Apply syntax highlighting to a block of text."""
        for pattern, fmt in self.rules:
            for match in re.finditer(pattern, text):
                start = match.start()
                length = match.end() - start
                self.setFormat(start, length, fmt)


# ═══════════════════════════════════════════════════════════════════════════════
# CODE EDITOR WIDGET
# ═══════════════════════════════════════════════════════════════════════════════

class CodeEditor(QPlainTextEdit):
    """Code editor with syntax highlighting and line numbers."""

    code_changed = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_editor()
        self._highlighter = PythonHighlighter(self.document())

    def _setup_editor(self):
        """Setup the editor appearance."""
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        font.setPointSize(11)
        self.setFont(font)

        self.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #abb2bf;
                border: none;
                padding: 8px;
            }
        """)

        self.setTabStopDistance(self.fontMetrics().horizontalAdvance(' ') * 4)
        self.textChanged.connect(self._on_text_changed)

    def _on_text_changed(self):
        """Handle text changes."""
        self.code_changed.emit(self.toPlainText())

    def set_code(self, code: str):
        """Set the code without triggering change signal."""
        self.blockSignals(True)
        self.setPlainText(code)
        self.blockSignals(False)


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCK LIST WIDGET
# ═══════════════════════════════════════════════════════════════════════════════

class BlockListWidget(QListWidget):
    """List widget showing code blocks."""

    block_selected = pyqtSignal(object)  # Emits CodeBlock

    def __init__(self, parent=None):
        super().__init__(parent)
        self._blocks = []
        self._setup_style()
        self.currentItemChanged.connect(self._on_selection_changed)

    def _setup_style(self):
        """Setup the list style."""
        self.setStyleSheet("""
            QListWidget {
                background: #252525;
                border: none;
                outline: none;
            }
            QListWidget::item {
                padding: 8px 12px;
                border-bottom: 1px solid #333;
                color: #ddd;
            }
            QListWidget::item:selected {
                background: #e91e63;
                color: white;
            }
            QListWidget::item:hover:!selected {
                background: #333;
            }
        """)

    def set_blocks(self, blocks: List[CodeBlock]):
        """Set the blocks to display."""
        self._blocks = blocks
        self.clear()

        for block in blocks:
            if block.is_deleted:
                continue
            item = QListWidgetItem(block.display_name)
            item.setData(Qt.ItemDataRole.UserRole, block)

            tooltip = f"{block.name}\nLines {block.line_start}-{block.line_end}"
            if block.metadata.get('docstring'):
                tooltip += f"\n\n{block.metadata['docstring'][:100]}"
            item.setToolTip(tooltip)

            self.addItem(item)

            for child in block.children:
                child_item = QListWidgetItem(f"    {child.display_name}")
                child_item.setData(Qt.ItemDataRole.UserRole, child)
                self.addItem(child_item)

    def _on_selection_changed(self, current, previous):
        """Handle selection change."""
        if current:
            block = current.data(Qt.ItemDataRole.UserRole)
            if block:
                self.block_selected.emit(block)


# ═══════════════════════════════════════════════════════════════════════════════
# MANIFEST EDITOR
# ═══════════════════════════════════════════════════════════════════════════════

class ManifestEditor(QScrollArea):
    """Editor for manifest.json fields."""

    manifest_changed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._blocks = []
        self._widgets = {}
        self._setup_ui()

    def _setup_ui(self):
        """Setup the manifest editor UI."""
        self.setWidgetResizable(True)
        self.setStyleSheet("QScrollArea { border: none; background: #1a1a1a; }")

        container = QWidget()
        self._layout = QVBoxLayout(container)
        self._layout.setContentsMargins(16, 16, 16, 16)
        self._layout.setSpacing(16)

        self.setWidget(container)

    def set_manifest_blocks(self, blocks: List[ManifestBlock]):
        """Set the manifest blocks to edit."""
        self._blocks = blocks
        self._widgets.clear()

        while self._layout.count():
            item = self._layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for block in blocks:
            group = self._create_field_widget(block)
            self._layout.addWidget(group)

        self._layout.addStretch()

    def _create_field_widget(self, block: ManifestBlock) -> QWidget:
        """Create a widget for a manifest field."""
        group = QGroupBox(f"{block.icon} {block.display_name}")
        group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #444;
                border-radius: 4px;
                margin-top: 12px;
                padding-top: 8px;
                color: #e91e63;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
            }
        """)

        layout = QVBoxLayout(group)

        if block.description:
            desc = QLabel(block.description)
            desc.setStyleSheet("color: #888; font-size: 11px; font-weight: normal;")
            layout.addWidget(desc)

        if block.field_type == 'string':
            widget = QLineEdit()
            widget.setText(str(block.value) if block.value else '')
            widget.setStyleSheet("""
                QLineEdit {
                    background: #252525;
                    border: 1px solid #444;
                    border-radius: 4px;
                    padding: 8px;
                    color: white;
                }
            """)
            widget.textChanged.connect(lambda text, b=block: self._on_field_changed(b, text))
            layout.addWidget(widget)
            self._widgets[block.key] = widget

        elif block.field_type == 'list':
            widget = QTextEdit()
            if isinstance(block.value, list):
                widget.setText('\n'.join(str(v) for v in block.value))
            widget.setMaximumHeight(100)
            widget.setStyleSheet("""
                QTextEdit {
                    background: #252525;
                    border: 1px solid #444;
                    border-radius: 4px;
                    padding: 8px;
                    color: white;
                    font-family: monospace;
                }
            """)
            widget.textChanged.connect(lambda b=block: self._on_list_changed(b))
            layout.addWidget(widget)

            hint = QLabel("One item per line")
            hint.setStyleSheet("color: #666; font-size: 10px;")
            layout.addWidget(hint)
            self._widgets[block.key] = widget

        elif block.field_type == 'dict':
            widget = QTextEdit()
            if isinstance(block.value, dict):
                widget.setText(json.dumps(block.value, indent=2))
            widget.setMaximumHeight(120)
            widget.setStyleSheet("""
                QTextEdit {
                    background: #252525;
                    border: 1px solid #444;
                    border-radius: 4px;
                    padding: 8px;
                    color: white;
                    font-family: monospace;
                }
            """)
            widget.textChanged.connect(lambda b=block: self._on_dict_changed(b))
            layout.addWidget(widget)

            hint = QLabel("JSON format")
            hint.setStyleSheet("color: #666; font-size: 10px;")
            layout.addWidget(hint)
            self._widgets[block.key] = widget

        elif block.field_type == 'boolean':
            widget = QCheckBox("Enabled")
            widget.setChecked(block.value if isinstance(block.value, bool) else True)
            widget.setStyleSheet("color: #ddd;")
            widget.stateChanged.connect(lambda state, b=block: self._on_bool_changed(b, state))
            layout.addWidget(widget)
            self._widgets[block.key] = widget

        return group

    def _on_field_changed(self, block: ManifestBlock, value: str):
        block.value = value
        self._emit_manifest()

    def _on_list_changed(self, block: ManifestBlock):
        widget = self._widgets.get(block.key)
        if widget:
            text = widget.toPlainText()
            block.value = [line.strip() for line in text.split('\n') if line.strip()]
            self._emit_manifest()

    def _on_dict_changed(self, block: ManifestBlock):
        widget = self._widgets.get(block.key)
        if widget:
            try:
                block.value = json.loads(widget.toPlainText())
            except json.JSONDecodeError:
                pass
            self._emit_manifest()

    def _on_bool_changed(self, block: ManifestBlock, state: int):
        block.value = state == 2  # Qt.CheckState.Checked = 2
        self._emit_manifest()

    def _emit_manifest(self):
        result = {}
        for block in self._blocks:
            if block.value or block.required:
                result[block.key] = block.value
        self.manifest_changed.emit(result)

    def get_manifest(self) -> Dict:
        result = {}
        for block in self._blocks:
            if block.value or block.required:
                result[block.key] = block.value
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# TEMPLATE SELECTOR DIALOG
# ═══════════════════════════════════════════════════════════════════════════════

class TemplateDialog(QDialog):
    """Dialog for selecting a plugin template."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_template = None
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("Select Template")
        self.setMinimumWidth(500)
        self.setStyleSheet("QDialog { background: #1a1a1a; }")

        layout = QVBoxLayout(self)

        title = QLabel("🎨 Choose Your Template")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #e91e63;")
        layout.addWidget(title)

        subtitle = QLabel("Start your plugin with a solid foundation")
        subtitle.setStyleSheet("color: #888;")
        layout.addWidget(subtitle)

        # Template list
        self.template_list = QListWidget()
        self.template_list.setStyleSheet("""
            QListWidget {
                background: #252525;
                border: 1px solid #444;
                border-radius: 4px;
            }
            QListWidget::item {
                padding: 12px;
                border-bottom: 1px solid #333;
                color: white;
            }
            QListWidget::item:selected {
                background: #e91e63;
            }
        """)

        for key, template in PLUGIN_TEMPLATES.items():
            item = QListWidgetItem(f"{template['icon']} {template['name']}")
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setToolTip(template['description'])
            self.template_list.addItem(item)

        self.template_list.itemDoubleClicked.connect(self._on_double_click)
        layout.addWidget(self.template_list)

        # Description
        self.desc_label = QLabel("Select a template above")
        self.desc_label.setStyleSheet("color: #888; padding: 8px;")
        self.desc_label.setWordWrap(True)
        layout.addWidget(self.desc_label)

        self.template_list.currentItemChanged.connect(self._on_selection_changed)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_selection_changed(self, current, previous):
        if current:
            key = current.data(Qt.ItemDataRole.UserRole)
            template = PLUGIN_TEMPLATES.get(key, {})
            self.desc_label.setText(template.get('description', ''))

    def _on_double_click(self, item):
        self.accept()

    def accept(self):
        current = self.template_list.currentItem()
        if current:
            self.selected_template = current.data(Qt.ItemDataRole.UserRole)
        super().accept()


# ═══════════════════════════════════════════════════════════════════════════════
# FUNCTION LIBRARY DIALOG
# ═══════════════════════════════════════════════════════════════════════════════

class FunctionLibraryDialog(QDialog):
    """Dialog for browsing and importing functions from the library."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_functions = []
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("Function Library")
        self.setMinimumSize(600, 500)
        self.setStyleSheet("QDialog { background: #1a1a1a; }")

        layout = QVBoxLayout(self)

        title = QLabel("📚 Function Library")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #e91e63;")
        layout.addWidget(title)

        subtitle = QLabel("Import ready-to-use functions from existing plugins")
        subtitle.setStyleSheet("color: #888;")
        layout.addWidget(subtitle)

        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Categories
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)

        cat_label = QLabel("Categories")
        cat_label.setStyleSheet("font-weight: bold; color: #ddd;")
        left_layout.addWidget(cat_label)

        self.category_list = QListWidget()
        self.category_list.setStyleSheet("""
            QListWidget { background: #252525; border: none; }
            QListWidget::item { padding: 8px; color: #ddd; }
            QListWidget::item:selected { background: #e91e63; }
            QListWidget::item:disabled { color: #555; }
        """)

        for cat_id, cat_data in FUNCTION_LIBRARY.items():
            plugin_check = cat_data.get('plugin_check')
            is_available = check_plugin_available(plugin_check)

            if is_available:
                item = QListWidgetItem(f"{cat_data['icon']} {cat_data['name']}")
            else:
                item = QListWidgetItem(f"{cat_data['icon']} {cat_data['name']} (Not Installed)")
                item.setForeground(QColor("#666"))
                item.setToolTip(f"Requires plugin: {plugin_check}")

            item.setData(Qt.ItemDataRole.UserRole, cat_id)
            item.setData(Qt.ItemDataRole.UserRole + 1, is_available)  # Store availability
            self.category_list.addItem(item)

        self.category_list.currentItemChanged.connect(self._on_category_changed)
        left_layout.addWidget(self.category_list)

        splitter.addWidget(left_panel)

        # Right: Functions with checkboxes
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)

        func_label = QLabel("Functions")
        func_label.setStyleSheet("font-weight: bold; color: #ddd;")
        right_layout.addWidget(func_label)

        self.function_scroll = QScrollArea()
        self.function_scroll.setWidgetResizable(True)
        self.function_scroll.setStyleSheet("QScrollArea { border: none; background: #252525; }")

        self.function_container = QWidget()
        self.function_layout = QVBoxLayout(self.function_container)
        self.function_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.function_scroll.setWidget(self.function_container)

        right_layout.addWidget(self.function_scroll)

        # Code preview
        preview_label = QLabel("Preview")
        preview_label.setStyleSheet("font-weight: bold; color: #ddd;")
        right_layout.addWidget(preview_label)

        self.code_preview = CodeEditor()
        self.code_preview.setMaximumHeight(150)
        self.code_preview.setReadOnly(True)
        right_layout.addWidget(self.code_preview)

        splitter.addWidget(right_panel)
        splitter.setSizes([200, 400])

        layout.addWidget(splitter)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._collect_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        # Select first category
        if self.category_list.count() > 0:
            self.category_list.setCurrentRow(0)

    def _on_category_changed(self, current, previous):
        if not current:
            return

        # Clear existing
        while self.function_layout.count():
            item = self.function_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        cat_id = current.data(Qt.ItemDataRole.UserRole)
        is_available = current.data(Qt.ItemDataRole.UserRole + 1)
        cat_data = FUNCTION_LIBRARY.get(cat_id, {})

        # Show warning if plugin not available
        if not is_available:
            plugin_check = cat_data.get('plugin_check', 'unknown')
            warning = QLabel(f"⚠️ Plugin '{plugin_check}' is not installed.\n\n"
                           f"You can still import these functions, but they\n"
                           f"may not work without the plugin installed.\n\n"
                           f"Install from Plugin Store for full functionality.")
            warning.setStyleSheet("color: #ff9800; padding: 12px; background: #332700; border-radius: 4px;")
            warning.setWordWrap(True)
            self.function_layout.addWidget(warning)

        for func_name, func_data in cat_data.get('functions', {}).items():
            checkbox = QCheckBox(func_name)
            if is_available:
                checkbox.setStyleSheet("color: #ddd;")
            else:
                checkbox.setStyleSheet("color: #888;")
            checkbox.setProperty('func_id', f"{cat_id}.{func_name}")
            checkbox.stateChanged.connect(lambda state, fn=func_name, fd=func_data:
                                          self._on_function_hover(fn, fd))

            desc = QLabel(func_data.get('description', ''))
            desc.setStyleSheet("color: #888; font-size: 11px; margin-left: 20px;")

            self.function_layout.addWidget(checkbox)
            self.function_layout.addWidget(desc)

        self.function_layout.addStretch()

    def _on_function_hover(self, func_name, func_data):
        self.code_preview.set_code(func_data.get('code', '# No code available'))

    def _collect_and_accept(self):
        self.selected_functions = []
        for i in range(self.function_layout.count()):
            item = self.function_layout.itemAt(i)
            if item and item.widget():
                widget = item.widget()
                if isinstance(widget, QCheckBox) and widget.isChecked():
                    func_id = widget.property('func_id')
                    if func_id:
                        self.selected_functions.append(func_id)
        self.accept()

    def get_function_code(self, func_id: str) -> tuple:
        """Get the code and imports for a function.

        Returns: (code, imports_list, requires_list)
        """
        parts = func_id.split('.')
        if len(parts) != 2:
            return '', [], []

        cat_id, func_name = parts
        cat_data = FUNCTION_LIBRARY.get(cat_id, {})
        func_data = cat_data.get('functions', {}).get(func_name, {})

        return (
            func_data.get('code', ''),
            func_data.get('imports', []),
            func_data.get('requires', [])
        )


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN VISUAL PLUGIN MAKER v2
# ═══════════════════════════════════════════════════════════════════════════════

class VisualPluginMakerV2(QWidget):
    """
    Visual Plugin Maker v2 - AST-Based Plugin Editor

    A complete visual editor for Image Anarchy plugins that can:
    - Import any plugin.py and parse it into editable blocks
    - Edit manifest.json fields
    - Edit any code block (imports, functions, classes, etc.)
    - Advanced Code Mode for full source editing
    - Templates for Image Anarchy style plugins
    - Function library import
    - Export without losing any code
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.model: Optional[PluginModel] = None
        self.current_block: Optional[CodeBlock] = None
        self.plugin_path: Optional[str] = None
        self.is_code_mode = False

        self._setup_ui()

    def _setup_ui(self):
        """Setup the main UI."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Header
        self._create_header(main_layout)

        # Main content
        self.main_tabs = QTabWidget()
        self.main_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background: #1a1a1a;
            }
            QTabBar::tab {
                background: #252525;
                color: #888;
                padding: 12px 24px;
                border: none;
                border-bottom: 2px solid transparent;
            }
            QTabBar::tab:selected {
                color: #e91e63;
                border-bottom: 2px solid #e91e63;
            }
            QTabBar::tab:hover:!selected {
                color: #ddd;
            }
        """)

        # Tab 1: manifest.json
        self.manifest_editor = ManifestEditor()
        self.main_tabs.addTab(self.manifest_editor, "📋 manifest.json")

        # Tab 2: plugin.py
        self.plugin_tab = QWidget()
        self.plugin_tab_layout = QVBoxLayout(self.plugin_tab)
        self.plugin_tab_layout.setContentsMargins(0, 0, 0, 0)
        self.plugin_tab_layout.setSpacing(0)

        # Mode stack for Visual/Code mode
        self.mode_stack = QStackedWidget()

        # Visual mode content
        self.visual_mode_widget = self._create_visual_mode()
        self.mode_stack.addWidget(self.visual_mode_widget)

        # Code mode content
        self.code_mode_widget = self._create_code_mode()
        self.mode_stack.addWidget(self.code_mode_widget)

        self.plugin_tab_layout.addWidget(self.mode_stack)
        self.main_tabs.addTab(self.plugin_tab, "🐍 plugin.py")

        main_layout.addWidget(self.main_tabs)

        # Start with empty state
        self._show_empty_state()

    def _create_header(self, parent_layout):
        """Create the header bar."""
        header = QFrame()
        header.setStyleSheet("background: #1e1e1e; border-bottom: 1px solid #444;")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 10, 16, 10)

        # Title
        title = QLabel("🎨 Visual Plugin Maker v2")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #e91e63;")
        header_layout.addWidget(title)

        header_layout.addStretch()

        btn_style = """
            QPushButton {
                background: #333;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                color: white;
            }
            QPushButton:hover {
                background: #444;
            }
        """

        # New button (dropdown with templates)
        new_btn = QPushButton("📄 New")
        new_btn.setStyleSheet(btn_style)
        new_btn.clicked.connect(self._show_template_dialog)
        header_layout.addWidget(new_btn)

        # Import button
        import_btn = QPushButton("📥 Import")
        import_btn.setStyleSheet(btn_style)
        import_btn.clicked.connect(self._import_plugin)
        header_layout.addWidget(import_btn)

        # Function library button
        lib_btn = QPushButton("📚 Functions")
        lib_btn.setStyleSheet(btn_style)
        lib_btn.clicked.connect(self._show_function_library)
        header_layout.addWidget(lib_btn)

        # Mode toggle
        self.mode_btn = QPushButton("📝 Visual Mode")
        self.mode_btn.setStyleSheet("""
            QPushButton {
                background: #2196f3;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                color: white;
            }
            QPushButton:hover { background: #1976d2; }
        """)
        self.mode_btn.clicked.connect(self._toggle_mode)
        header_layout.addWidget(self.mode_btn)

        # Export button
        export_btn = QPushButton("📤 Export")
        export_btn.setStyleSheet(btn_style.replace("#333", "#e91e63").replace("#444", "#c2185b"))
        export_btn.clicked.connect(self._export_plugin)
        header_layout.addWidget(export_btn)

        parent_layout.addWidget(header)

    def _create_visual_mode(self) -> QWidget:
        """Create the visual mode editing widget."""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Left panel: Sub-tabs with block lists
        left_panel = QWidget()
        left_panel.setMaximumWidth(350)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        # Sub-tabs for categories
        self.category_tabs = QTabWidget()
        self.category_tabs.setStyleSheet("""
            QTabWidget::pane { border: none; background: #252525; }
            QTabBar::tab {
                background: #1a1a1a;
                color: #666;
                padding: 8px 12px;
                font-size: 11px;
            }
            QTabBar::tab:selected { color: #61afef; background: #252525; }
        """)

        self.block_lists = {}
        categories = [
            ("all", "📄 All"),
            ("imports", "📥 Imports"),
            ("functions", "⚡ Functions"),
            ("classes", "🏗️ Classes"),
            ("widgets", "🖼️ Widgets"),
            ("variables", "📊 Variables"),
        ]

        for cat_id, cat_name in categories:
            list_widget = BlockListWidget()
            list_widget.block_selected.connect(self._on_block_selected)
            self.block_lists[cat_id] = list_widget
            self.category_tabs.addTab(list_widget, cat_name)

        left_layout.addWidget(self.category_tabs)

        # Add/Delete buttons
        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(8, 8, 8, 8)

        add_btn = QPushButton("+ Add Block")
        add_btn.setStyleSheet("""
            QPushButton {
                background: #4caf50;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #66bb6a; }
        """)
        add_btn.clicked.connect(self._add_block_to_current_category)
        btn_row.addWidget(add_btn)

        del_btn = QPushButton("Delete")
        del_btn.setStyleSheet("""
            QPushButton {
                background: #f44336;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #ef5350; }
        """)
        del_btn.clicked.connect(self._delete_current_block)
        btn_row.addWidget(del_btn)

        left_layout.addLayout(btn_row)
        layout.addWidget(left_panel)

        # Right panel: Single shared code editor
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        # Editor header
        editor_header = QFrame()
        editor_header.setStyleSheet("background: #252525;")
        editor_header_layout = QHBoxLayout(editor_header)
        editor_header_layout.setContentsMargins(12, 8, 12, 8)

        self.block_title = QLabel("Select a block to edit")
        self.block_title.setStyleSheet("color: #888; font-size: 13px;")
        editor_header_layout.addWidget(self.block_title)

        editor_header_layout.addStretch()

        right_layout.addWidget(editor_header)

        # SINGLE shared code editor
        self.block_editor = CodeEditor()
        self.block_editor.code_changed.connect(self._on_block_code_changed)
        right_layout.addWidget(self.block_editor)

        layout.addWidget(right_panel, 1)

        return widget

    def _create_code_mode(self) -> QWidget:
        """Create the advanced code mode editing widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QFrame()
        header.setStyleSheet("background: #252525;")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 8, 12, 8)

        code_label = QLabel("📝 Full Source Code Editor")
        code_label.setStyleSheet("color: #61afef; font-weight: bold;")
        header_layout.addWidget(code_label)

        header_layout.addStretch()

        # Validate button
        validate_btn = QPushButton("✓ Validate Syntax")
        validate_btn.setStyleSheet("""
            QPushButton {
                background: #4caf50;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #66bb6a; }
        """)
        validate_btn.clicked.connect(self._validate_code)
        header_layout.addWidget(validate_btn)

        layout.addWidget(header)

        # Full source code editor
        self.full_code_editor = CodeEditor()
        self.full_code_editor.code_changed.connect(self._on_full_code_changed)
        layout.addWidget(self.full_code_editor)

        return widget

    def _toggle_mode(self):
        """Toggle between Visual and Code mode."""
        if self.is_code_mode:
            # Switching to Visual mode - re-parse the code
            if self.model:
                code = self.full_code_editor.toPlainText()
                try:
                    ast.parse(code)
                    # Re-parse
                    parser = PluginParser(code, self.model.generate_manifest())
                    self.model = parser.parse()
                    self._refresh_block_lists()
                except SyntaxError as e:
                    QMessageBox.warning(
                        self, "Syntax Error",
                        f"Cannot switch to Visual mode - code has syntax error:\n{e}\n\n"
                        "Fix the error first or your changes may be lost."
                    )
                    return

            self.mode_stack.setCurrentIndex(0)
            self.mode_btn.setText("📝 Visual Mode")
            self.mode_btn.setStyleSheet("""
                QPushButton {
                    background: #2196f3;
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                }
                QPushButton:hover { background: #1976d2; }
            """)
            self.is_code_mode = False
        else:
            # Switching to Code mode - sync full source
            if self.model:
                full_source = self.model.reconstruct()
                self.full_code_editor.set_code(full_source)

            self.mode_stack.setCurrentIndex(1)
            self.mode_btn.setText("🔧 Code Mode")
            self.mode_btn.setStyleSheet("""
                QPushButton {
                    background: #ff9800;
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                }
                QPushButton:hover { background: #f57c00; }
            """)
            self.is_code_mode = True

    def _validate_code(self):
        """Validate the code syntax."""
        code = self.full_code_editor.toPlainText()
        try:
            ast.parse(code)
            QMessageBox.information(self, "Valid", "✓ Code syntax is valid!")
        except SyntaxError as e:
            QMessageBox.warning(self, "Syntax Error", f"Syntax error at line {e.lineno}:\n{e.msg}")

    def _show_template_dialog(self):
        """Show the template selection dialog."""
        dialog = TemplateDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.selected_template:
            self._apply_template(dialog.selected_template)

    def _apply_template(self, template_key: str):
        """Apply a selected template."""
        template = PLUGIN_TEMPLATES.get(template_key)
        if not template:
            return

        parser = PluginParser(template['code'], template['manifest'])
        self.model = parser.parse()
        self.plugin_path = None

        self._refresh_ui()

        QMessageBox.information(
            self, "Template Applied",
            f"Template '{template['name']}' loaded!\n\n"
            "Edit the manifest and code, then click Export to save."
        )

    def _show_function_library(self):
        """Show the function library dialog."""
        if not self.model:
            QMessageBox.warning(self, "No Plugin", "Create or import a plugin first.")
            return

        dialog = FunctionLibraryDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            for func_id in dialog.selected_functions:
                self._import_function(dialog, func_id)

    def _import_function(self, dialog: FunctionLibraryDialog, func_id: str):
        """Import a function from the library."""
        code, imports, requires = dialog.get_function_code(func_id)
        if not code:
            return

        # Add imports if needed
        for imp in imports:
            exists = any(imp in i.name for i in self.model.imports)
            if not exists:
                new_import = CodeBlock(
                    block_type=BlockType.IMPORT,
                    name=f"import {imp}",
                    display_name=f"📥 import {imp}",
                    source_code=f"import {imp}",
                    line_start=9999,
                    line_end=9999,
                    icon="📥",
                    is_new=True
                )
                self.model.imports.append(new_import)

        # Add the function/class
        func_name = func_id.split('.')[-1]
        if code.strip().startswith('class '):
            new_block = CodeBlock(
                block_type=BlockType.CLASS,
                name=f"class {func_name}",
                display_name=f"🏗️ class {func_name}",
                source_code=code,
                line_start=9999,
                line_end=9999,
                icon="🏗️",
                is_new=True
            )
            self.model.classes.append(new_block)
        else:
            new_block = CodeBlock(
                block_type=BlockType.FUNCTION,
                name=f"def {func_name}",
                display_name=f"⚡ {func_name}()",
                source_code=code,
                line_start=9999,
                line_end=9999,
                icon="⚡",
                is_new=True
            )
            self.model.functions.append(new_block)

        self._refresh_block_lists()
        QMessageBox.information(self, "Imported", f"Function '{func_name}' imported!")

    def _show_empty_state(self):
        """Show the empty state when no plugin is loaded."""
        self.model = None
        self.current_block = None

        for list_widget in self.block_lists.values():
            list_widget.clear()

        self.block_editor.set_code(
            "# No plugin loaded\n"
            "# Click 'New' to create from template\n"
            "# Or 'Import' to load an existing plugin"
        )
        self.full_code_editor.set_code("")

    def _import_plugin(self):
        """Import an existing plugin."""
        plugins_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'plugins')

        path, _ = QFileDialog.getOpenFileName(
            self, "Select manifest.json",
            plugins_dir, "Manifest (manifest.json);;All Files (*.*)"
        )

        if not path:
            return

        try:
            with open(path, 'r', encoding='utf-8') as f:
                manifest = json.load(f)

            plugin_dir = os.path.dirname(path)
            plugin_py = os.path.join(plugin_dir, 'plugin.py')

            if os.path.exists(plugin_py):
                with open(plugin_py, 'r', encoding='utf-8') as f:
                    source_code = f.read()
            else:
                source_code = '# No plugin.py found'

            parser = PluginParser(source_code, manifest)
            self.model = parser.parse()
            self.plugin_path = plugin_dir

            self._refresh_ui()

            stats = (
                f"Imports: {len(self.model.imports)}\n"
                f"Functions: {len(self.model.functions)}\n"
                f"Classes: {len(self.model.classes)}\n"
                f"Variables: {len(self.model.assignments)}"
            )

            QMessageBox.information(
                self, "Plugin Imported",
                f"Successfully imported: {manifest.get('name', 'Unknown')}\n\n{stats}"
            )

        except Exception as e:
            QMessageBox.critical(self, "Import Error", f"Failed to import plugin:\n{e}")

    def _export_plugin(self):
        """Export the current plugin."""
        if not self.model:
            QMessageBox.warning(self, "No Plugin", "No plugin to export. Create or import one first.")
            return

        # If in code mode, use the full editor content
        if self.is_code_mode:
            source_code = self.full_code_editor.toPlainText()
        else:
            source_code = self.model.reconstruct()

        # Validate syntax
        try:
            ast.parse(source_code)
        except SyntaxError as e:
            QMessageBox.critical(
                self, "Syntax Error",
                f"Cannot export - code has syntax error at line {e.lineno}:\n{e.msg}"
            )
            return

        manifest = self.model.generate_manifest()
        plugin_id = manifest.get('id', 'my_plugin')

        plugins_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'plugins')

        # Loop until user picks a valid name or cancels
        while True:
            export_dir = os.path.join(plugins_dir, plugin_id)

            if os.path.exists(export_dir):
                # Ask overwrite or rename
                msg = QMessageBox(self)
                msg.setWindowTitle("Plugin Exists")
                msg.setText(f"Plugin folder '{plugin_id}' already exists.")
                msg.setInformativeText("What would you like to do?")
                overwrite_btn = msg.addButton("Overwrite", QMessageBox.ButtonRole.AcceptRole)
                rename_btn = msg.addButton("Save As...", QMessageBox.ButtonRole.ActionRole)
                cancel_btn = msg.addButton(QMessageBox.StandardButton.Cancel)
                msg.exec()

                clicked = msg.clickedButton()
                if clicked == cancel_btn:
                    return
                elif clicked == rename_btn:
                    # Ask for new plugin ID
                    from PyQt6.QtWidgets import QInputDialog
                    new_id, ok = QInputDialog.getText(
                        self, "Save As",
                        "Enter new plugin ID (folder name):",
                        text=plugin_id + "_copy"
                    )
                    if ok and new_id.strip():
                        plugin_id = new_id.strip()
                        # Update manifest with new ID
                        manifest['id'] = plugin_id
                        # Update the model's manifest blocks too
                        for block in self.model.manifest_blocks:
                            if block.key == 'id':
                                block.value = plugin_id
                                break
                        continue  # Loop to check if new name exists
                    else:
                        return
                # else: overwrite - proceed to export
                break
            else:
                os.makedirs(export_dir, exist_ok=True)
                break

        try:
            manifest_path = os.path.join(export_dir, 'manifest.json')
            with open(manifest_path, 'w', encoding='utf-8') as f:
                json.dump(manifest, f, indent=2)

            plugin_path = os.path.join(export_dir, 'plugin.py')
            with open(plugin_path, 'w', encoding='utf-8') as f:
                f.write(source_code)

            self.plugin_path = export_dir

            QMessageBox.information(
                self, "Export Complete",
                f"Plugin exported to:\n{export_dir}\n\n"
                f"Files created:\n"
                f"• manifest.json\n"
                f"• plugin.py ({len(source_code)} chars)"
            )

        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export plugin:\n{e}")

    def _refresh_ui(self):
        """Refresh the UI with current model data."""
        if not self.model:
            return

        self.manifest_editor.set_manifest_blocks(self.model.manifest_blocks)
        self._refresh_block_lists()

        self.current_block = None
        self.block_editor.set_code("# Select a block from the list to edit")
        self.block_title.setText("Select a block to edit")

        # Update full code editor
        source_code = self.model.reconstruct()
        self.full_code_editor.set_code(source_code)

    def _refresh_block_lists(self):
        """Refresh all block lists."""
        if not self.model:
            return

        for category, list_widget in self.block_lists.items():
            blocks = self.model.get_blocks_by_category(category)
            list_widget.set_blocks(blocks)

    def _on_block_selected(self, block: CodeBlock):
        """Handle block selection from any list."""
        self.current_block = block
        self.block_title.setText(block.display_name)
        self.block_editor.set_code(block.source_code)

    def _on_block_code_changed(self, code: str):
        """Handle code changes in the block editor."""
        if self.current_block:
            self.current_block.source_code = code
            self.current_block.is_modified = True

    def _on_full_code_changed(self, code: str):
        """Handle changes in full code mode."""
        # Updates are applied when switching back to visual mode
        pass

    def _add_block_to_current_category(self):
        """Add a new block to the current category."""
        if not self.model:
            QMessageBox.warning(self, "No Plugin", "Create or import a plugin first.")
            return

        current_index = self.category_tabs.currentIndex()
        categories = ["all", "imports", "functions", "classes", "widgets", "variables"]
        category = categories[current_index] if current_index < len(categories) else "functions"

        self._add_block(category)

    def _add_block(self, category: str):
        """Add a new block to the specified category."""
        if category in ("imports", "all"):
            new_block = CodeBlock(
                block_type=BlockType.IMPORT,
                name="import new_module",
                display_name="📥 import new_module",
                source_code="import new_module",
                line_start=9999,
                line_end=9999,
                icon="📥",
                is_new=True
            )
            self.model.imports.append(new_block)

        elif category == "functions":
            new_block = CodeBlock(
                block_type=BlockType.FUNCTION,
                name="def new_function()",
                display_name="⚡ new_function()",
                source_code='def new_function():\n    """New function."""\n    pass',
                line_start=9999,
                line_end=9999,
                icon="⚡",
                is_new=True
            )
            self.model.functions.append(new_block)

        elif category in ("classes", "widgets"):
            base = "QWidget" if category == "widgets" else ""
            code = f'class NewClass({base}):\n    """New class."""\n    \n    def __init__(self):\n        {"super().__init__()" if base else "pass"}'
            new_block = CodeBlock(
                block_type=BlockType.CLASS,
                name=f"class NewClass({base})" if base else "class NewClass",
                display_name="🏗️ class NewClass",
                source_code=code,
                line_start=9999,
                line_end=9999,
                icon="🏗️" if not base else "🖼️",
                is_new=True,
                metadata={'bases': base}
            )
            self.model.classes.append(new_block)

        elif category == "variables":
            new_block = CodeBlock(
                block_type=BlockType.ASSIGNMENT,
                name="NEW_VAR",
                display_name="📊 NEW_VAR",
                source_code="NEW_VAR = None",
                line_start=9999,
                line_end=9999,
                icon="📊",
                is_new=True
            )
            self.model.assignments.append(new_block)
        else:
            return

        self._refresh_block_lists()

    def _delete_current_block(self):
        """Delete the currently selected block."""
        if not self.current_block:
            QMessageBox.warning(self, "No Selection", "Select a block to delete.")
            return

        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Delete '{self.current_block.display_name}'?\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.current_block.is_deleted = True
            self.current_block = None
            self.block_title.setText("Select a block to edit")
            self.block_editor.set_code("# Block deleted")
            self._refresh_block_lists()
