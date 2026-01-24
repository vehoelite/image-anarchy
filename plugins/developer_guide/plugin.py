"""
Plugin Developer Guide for Image Anarchy
Learn how to create plugins and monetize your skills!
"""

from __main__ import PluginBase
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QTextEdit, QGroupBox, QScrollArea, QFrame, QTabWidget
)
from PyQt6.QtCore import Qt
import webbrowser
import os
import subprocess
import sys


class DeveloperGuidePlugin(PluginBase):
    """Interactive developer guide for creating Image Anarchy plugins."""
    
    def create_widget(self, parent_window):
        """Create the developer guide widget."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Hero Section
        hero = QLabel("🛠️ Create Plugins for Image Anarchy")
        hero.setStyleSheet("font-size: 24px; font-weight: bold; color: #4fc3f7;")
        hero.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(hero)
        
        subtitle = QLabel("Build powerful tools for Android enthusiasts - and earn money doing it!")
        subtitle.setStyleSheet("font-size: 14px; color: #aaa; margin-bottom: 20px;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)
        
        # Create tabs for organization
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #444; border-radius: 4px; }
            QTabBar::tab { padding: 8px 16px; }
            QTabBar::tab:selected { background: #4fc3f7; color: #000; }
        """)
        
        # Tab 1: Getting Started
        tab1 = self._create_getting_started_tab()
        tabs.addTab(tab1, "🚀 Getting Started")
        
        # Tab 2: Manifest.json Guide
        tab2 = self._create_manifest_tab()
        tabs.addTab(tab2, "📋 manifest.json")
        
        # Tab 3: Advanced Features
        tab3 = self._create_advanced_tab()
        tabs.addTab(tab3, "⚡ Advanced")
        
        # Tab 4: Monetization
        tab4 = self._create_monetization_tab()
        tabs.addTab(tab4, "💰 Monetization")
        
        layout.addWidget(tabs)
        
        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        docs_btn = QPushButton("📖 Documentation")
        docs_btn.setStyleSheet("padding: 10px 20px;")
        docs_btn.clicked.connect(lambda: webbrowser.open("https://github.com/vehoelite/image-anarchy"))
        btn_layout.addWidget(docs_btn)
        
        folder_btn = QPushButton("📁 Open Plugins Folder")
        folder_btn.setStyleSheet("padding: 10px 20px;")
        folder_btn.clicked.connect(self._open_folder)
        btn_layout.addWidget(folder_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        # Footer
        footer = QLabel("Questions? Join our community on GitHub or XDA!")
        footer.setStyleSheet("color: #666; font-style: italic; margin-top: 20px;")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(footer)
        
        layout.addStretch()
        scroll.setWidget(widget)
        return scroll
    
    def _create_getting_started_tab(self):
        """Create the getting started tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(12)
        
        # Why Create Plugins
        why_group = QGroupBox("Why Create Plugins?")
        why_layout = QVBoxLayout(why_group)
        why_items = [
            "🌍 Reach thousands of users - Image Anarchy is used by Android enthusiasts worldwide",
            "💵 Monetize your skills - Set your price, accept donations, or keep it free",
            "✨ Incredibly easy - Just 2 files: manifest.json + plugin.py",
            "🎨 Full PyQt6 power - Create any UI you can imagine",
            "🔧 Access core features - Use Image Anarchy extractors, packers, and utilities"
        ]
        for item in why_items:
            lbl = QLabel(item)
            lbl.setWordWrap(True)
            lbl.setStyleSheet("font-size: 12px; padding: 4px 0;")
            why_layout.addWidget(lbl)
        layout.addWidget(why_group)
        
        # How Easy Section
        easy_group = QGroupBox("Just 3 Steps!")
        easy_layout = QVBoxLayout(easy_group)
        
        steps = [
            ("Step 1:", "Create a folder in the plugins directory (folder name = plugin ID)"),
            ("Step 2:", "Add manifest.json with your plugin info"),
            ("Step 3:", "Add plugin.py - implement create_widget() to return your UI"),
        ]
        for title, desc in steps:
            step_lbl = QLabel(f"<b>{title}</b> {desc}")
            step_lbl.setTextFormat(Qt.TextFormat.RichText)
            step_lbl.setStyleSheet("font-size: 12px; padding: 6px 0;")
            easy_layout.addWidget(step_lbl)
        layout.addWidget(easy_group)
        
        # Code Example
        code_group = QGroupBox("Minimal Plugin Example (plugin.py)")
        code_layout = QVBoxLayout(code_group)
        
        code_text = QTextEdit()
        code_text.setReadOnly(True)
        code_text.setMaximumHeight(220)
        code_text.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a2e;
                color: #4fc3f7;
                font-family: Consolas, Courier New, monospace;
                font-size: 11px;
                padding: 10px;
                border: 1px solid #333;
            }
        """)
        code_text.setPlainText("""# plugin.py - This is ALL you need!

from __main__ import PluginBase
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton

class MyPlugin(PluginBase):
    
    def create_widget(self, parent_window):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        layout.addWidget(QLabel("Hello from my plugin!"))
        
        btn = QPushButton("Do Something Cool")
        btn.clicked.connect(self.do_something)
        layout.addWidget(btn)
        
        return widget
    
    def do_something(self):
        print("Plugin is working!")""")
        code_layout.addWidget(code_text)
        layout.addWidget(code_group)
        
        layout.addStretch()
        return widget
    
    def _create_manifest_tab(self):
        """Create the manifest.json guide tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(12)
        
        intro = QLabel(
            "<b>manifest.json</b> tells Image Anarchy everything about your plugin. "
            "All dependencies, settings, and metadata go here for seamless installation."
        )
        intro.setTextFormat(Qt.TextFormat.RichText)
        intro.setWordWrap(True)
        intro.setStyleSheet("font-size: 12px; padding: 8px; background: #2a2a2a; border-radius: 4px;")
        layout.addWidget(intro)
        
        # Complete manifest example
        manifest_group = QGroupBox("📋 Complete manifest.json Example")
        manifest_layout = QVBoxLayout(manifest_group)
        
        manifest_text = QTextEdit()
        manifest_text.setReadOnly(True)
        manifest_text.setMinimumHeight(380)
        manifest_text.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a2e;
                color: #4fc3f7;
                font-family: Consolas, Courier New, monospace;
                font-size: 11px;
                padding: 10px;
                border: 1px solid #333;
            }
        """)
        manifest_text.setPlainText("""{
  "id": "my_plugin",
  "name": "My Awesome Plugin",
  "version": "1.0.0",
  "description": "Short description for store listing",
  "author": "Your Name",
  "icon": "🔧",
  "category": "tools",
  "license_type": "free",
  "website": "https://github.com/you/plugin",
  "support_url": "https://github.com/you/plugin/issues",
  "min_version": "2.0",
  
  "requirements": [
    "requests",
    "pillow>=9.0",
    "pyusb",
    "pycryptodome"
  ],
  
  "git_clone": {
    "repo": "https://github.com/user/tool.git",
    "target": "tool"
  },
  
  "bundled_binaries": [
    "platform-tools/adb.exe",
    "platform-tools/fastboot.exe"
  ],
  
  "post_install": [
    {"type": "driver", "file": "drivers/usb_driver.msi"}
  ]
}""")
        manifest_layout.addWidget(manifest_text)
        layout.addWidget(manifest_group)
        
        # Field explanations
        fields_group = QGroupBox("📖 Field Reference")
        fields_layout = QVBoxLayout(fields_group)
        
        fields = [
            ("<b>requirements</b>", "List ALL pip packages your plugin needs. Installed automatically."),
            ("<b>git_clone</b>", "Clone a Git repo at install time. Perfect for tools like mtkclient."),
            ("<b>bundled_binaries</b>", "Binary files included in your plugin ZIP (adb.exe, etc.)"),
            ("<b>post_install</b>", "Run commands or install drivers after setup."),
            ("<b>icon</b>", "Emoji displayed in the plugin store (🔧, ⚡, 🚀, etc.)"),
            ("<b>category</b>", "tools, extraction, modification, adb, fastboot, utilities, other"),
        ]
        for field, desc in fields:
            lbl = QLabel(f"{field}: {desc}")
            lbl.setTextFormat(Qt.TextFormat.RichText)
            lbl.setWordWrap(True)
            lbl.setStyleSheet("font-size: 11px; padding: 3px 0;")
            fields_layout.addWidget(lbl)
        layout.addWidget(fields_group)
        
        layout.addStretch()
        return widget
    
    def _create_advanced_tab(self):
        """Create the advanced features tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(12)
        
        # Git Clone Feature
        git_group = QGroupBox("📦 Git Repository Clone")
        git_layout = QVBoxLayout(git_group)
        
        git_info = QLabel(
            "If your plugin needs to clone a Git repository (like mtkclient), use the <b>git_clone</b> field:<br><br>"
            "<code style='background:#1a1a1a;padding:4px;'>"
            '"git_clone": {<br>'
            '&nbsp;&nbsp;"repo": "https://github.com/bkerler/mtkclient.git",<br>'
            '&nbsp;&nbsp;"target": "mtkclient"<br>'
            "}</code><br><br>"
            "<span style='color:#ff9800;'>⚠️ Important:</span> List ALL pip packages in <b>requirements</b>, not in the cloned repo's requirements.txt!"
        )
        git_info.setTextFormat(Qt.TextFormat.RichText)
        git_info.setWordWrap(True)
        git_info.setStyleSheet("font-size: 11px;")
        git_layout.addWidget(git_info)
        layout.addWidget(git_group)
        
        # Bundled Binaries
        bin_group = QGroupBox("📁 Bundled Binaries")
        bin_layout = QVBoxLayout(bin_group)
        
        bin_info = QLabel(
            "Include executables (adb, fastboot, custom tools) in your plugin ZIP:<br><br>"
            "<code style='background:#1a1a1a;padding:4px;'>"
            '"bundled_binaries": ["platform-tools/adb.exe", "tools/mytool.exe"]'
            "</code><br><br>"
            "These files should be in your plugin ZIP at the paths specified."
        )
        bin_info.setTextFormat(Qt.TextFormat.RichText)
        bin_info.setWordWrap(True)
        bin_info.setStyleSheet("font-size: 11px;")
        bin_layout.addWidget(bin_info)
        layout.addWidget(bin_group)
        
        # Access Core Features
        core_group = QGroupBox("🔧 Accessing Image Anarchy Features")
        core_layout = QVBoxLayout(core_group)
        
        core_text = QTextEdit()
        core_text.setReadOnly(True)
        core_text.setMaximumHeight(150)
        core_text.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a2e;
                color: #4fc3f7;
                font-family: Consolas, monospace;
                font-size: 11px;
                padding: 8px;
            }
        """)
        core_text.setPlainText("""# Access the main window
main_window = parent_window

# Use Image Anarchy's utilities
from __main__ import PayloadFile, detect_image_type

# Run ADB/Fastboot commands
import subprocess
adb_path = os.path.join(plugin_dir, "platform-tools", "adb.exe")
result = subprocess.run([adb_path, "devices"], capture_output=True)""")
        core_layout.addWidget(core_text)
        layout.addWidget(core_group)
        
        layout.addStretch()
        return widget
    
    def _create_monetization_tab(self):
        """Create the monetization tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(12)
        
        intro = QLabel(
            "💰 <b>Turn your skills into income!</b> Set your license type in manifest.json."
        )
        intro.setTextFormat(Qt.TextFormat.RichText)
        intro.setStyleSheet("font-size: 14px; padding: 10px;")
        layout.addWidget(intro)
        
        # License Types
        license_group = QGroupBox("License Types")
        license_layout = QVBoxLayout(license_group)
        
        licenses = [
            ("🆓 free", "Open to everyone, no strings attached"),
            ("☕ donation", "Free with optional tip jar shown to users"),
            ("💵 paid", "Users see your price before using (coming soon)"),
        ]
        for lic, desc in licenses:
            lbl = QLabel(f"<b>{lic}</b> - {desc}")
            lbl.setTextFormat(Qt.TextFormat.RichText)
            lbl.setStyleSheet("font-size: 12px; padding: 6px 0;")
            license_layout.addWidget(lbl)
        layout.addWidget(license_group)
        
        # Payment Methods
        payment_group = QGroupBox("Supported Payment Methods")
        payment_layout = QVBoxLayout(payment_group)
        
        payments = [
            "₿ Bitcoin (BTC) - Direct wallet address",
            "💳 PayPal - Payment links", 
            "☕ Ko-fi - Creator support",
            "🎁 Patreon - Subscriptions",
            "❤️ GitHub Sponsors"
        ]
        for p in payments:
            lbl = QLabel(p)
            lbl.setStyleSheet("font-size: 12px; padding: 4px 0;")
            payment_layout.addWidget(lbl)
        layout.addWidget(payment_group)
        
        # Plugin Ideas
        ideas_group = QGroupBox("💡 Plugin Ideas to Get You Started")
        ideas_layout = QVBoxLayout(ideas_group)
        
        ideas = [
            "🔧 Build.prop Editor - Visual editor for system properties",
            "🎬 Boot Animation Creator - Design custom boot animations", 
            "📊 Partition Analyzer - Deep analysis of partition contents",
            "💾 Device Profiles - Save/restore device configurations",
            "📦 Batch Processor - Process multiple images at once",
            "⬇️ OTA Downloader - Download OTAs from manufacturers",
        ]
        for idea in ideas:
            lbl = QLabel(idea)
            lbl.setStyleSheet("font-size: 12px; padding: 3px 0;")
            ideas_layout.addWidget(lbl)
        layout.addWidget(ideas_group)
        
        layout.addStretch()
        return widget
    
    def _open_folder(self):
        plugins_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if sys.platform == "win32":
            os.startfile(plugins_dir)
        elif sys.platform == "darwin":
            subprocess.run(["open", plugins_dir])
        else:
            subprocess.run(["xdg-open", plugins_dir])


# Export the plugin class
Plugin = DeveloperGuidePlugin
