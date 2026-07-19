"""Qualcomm EDL Toolkit — Image Anarchy plugin (Phase 1: comms foundation)."""
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel

manifest = None  # set by PluginManager


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
