# 🔓 Image Anarchy

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/icon.png?raw=true" alt="Image Anarchy Logo" width="200">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.1-blue?style=for-the-badge" alt="Version 1.1">
  <img src="https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-orange?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-purple?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/GUI-PyQt6-red?style=for-the-badge" alt="PyQt6">
</p>

<p align="center">
  <b>The All-in-One Android Image Swiss Army Knife with Extensible Plugin System</b>
</p>

---

## 🆕 What's New in v1.1

### Plugin System 🔌
- **Extensible Architecture** - Add new features without modifying core code
- **Monetization Support** - Plugins can be free, paid, or donation-based
- **Auto-Dependency Install** - Plugins can specify pip requirements that auto-install
- **Hot-Reload Ready** - Discover new plugins without restarting

### Bundled Platform Tools
- **ADB & Fastboot Included** - No need to install Android SDK separately
- **Zero Configuration** - Works out of the box

### New Plugins Included
- **ADB Toolkit** - Comprehensive device management (7 tools)
- **Fastboot Toolkit** - Complete bootloader operations (8 tools)
- **Plugin Developer Guide** - Tutorial for creating your own plugins

---

## ✨ Features

### Core Functionality
| Feature | Description |
|---------|-------------|
| 📦 **Payload Extract** | Extract images from Android OTA `payload.bin` files |
| 📦 **Payload Repack** | Repack modified images back into `payload.bin` |
| 🖼️ **Image Extract** | Unpack `system.img`, `vendor.img`, and other sparse/raw images |
| 🖼️ **Image Repack** | Rebuild ext4/sparse images from extracted folders |
| 🔄 **Recovery Porter** | Port recovery/boot images between devices (kernel/ramdisk swap) |
| 🔌 **Plugin System** | Extend functionality with community plugins |

### Plugin System
| Feature | Description |
|---------|-------------|
| 📁 **Folder-Based Discovery** | Drop plugin folders into `plugins/` directory |
| 💰 **Monetization Support** | Free, paid, or donation-based licensing |
| 📋 **Auto-Requirements** | Plugins can auto-install their pip dependencies |
| 🎨 **Full GUI Integration** | Plugins get their own tabs in the main window |
| 📖 **Developer Guide** | Built-in tutorial for plugin developers |

---

## 🔌 Included Plugins

### ADB Toolkit
Complete Android Debug Bridge management with 7 specialized tabs:

| Tab | Features |
|-----|----------|
| **📱 Info** | Device details, properties, battery status, display info |
| **💾 Partitions** | List, pull, and backup device partitions |
| **📁 Files** | Browse, push, pull, and delete files on device |
| **📦 Apps** | List, install, uninstall, backup, and restore APKs |
| **🖥️ Shell** | Interactive ADB shell with command history |
| **🛠️ Tools** | Screenshots, screen recording, logcat, reboot options |
| **🔄 Reboot** | System, recovery, bootloader, fastboot, EDL modes |

### Fastboot Toolkit  
Complete bootloader operations with 8 specialized tabs:

| Tab | Features |
|-----|----------|
| **📱 Info** | Device info, all variables, partition list |
| **⚡ Flash** | Flash any image to any partition with safety checks |
| **🚀 Boot** | Temporarily boot images without flashing |
| **📥 Fetch** | Pull partitions from device (device support required) |
| **🗑️ Erase** | Erase partitions with confirmation dialogs |
| **🔐 OEM** | OEM unlock/lock, critical operations |
| **🔀 Slot** | A/B slot management for dual-slot devices |
| **🔄 Reboot** | Bootloader, recovery, system, EDL modes |

### Plugin Developer Guide
Interactive tutorial showing how to create your own plugins with:
- Plugin structure and manifest format
- Monetization options (free, paid, donation)
- GUI integration examples
- Best practices and tips

---

## 📋 Requirements

### System Requirements
- Python 3.8 or higher
- 4GB+ RAM recommended for large images
- Windows, Linux, or macOS

### Python Dependencies
```bash
pip install PyQt6 protobuf bsdiff4 lz4
```

### Optional (for advanced features)
- `simg2img` / `img2simg` - For sparse image conversion (included in platform-tools)
- `e2fsdroid` / `mke2fs` - For ext4 image packing (Linux)

---

## 🚀 Installation

### Quick Start
```bash
# Clone the repository
git clone https://github.com/vehoelite/image-anarchy.git
cd image-anarchy

# Install dependencies
pip install PyQt6 protobuf bsdiff4 lz4

# Run Image Anarchy
python image_anarchy.py
```

### From Release
1. Download the latest release from [Releases](https://github.com/vehoelite/image-anarchy/releases)
2. Extract the archive
3. Install dependencies: `pip install PyQt6 protobuf bsdiff4 lz4`
4. Run: `python image_anarchy.py`

---

## 📖 Usage

### Payload Extract
1. Go to the **Extract** tab
2. Click **Browse** to select a `payload.bin` file
3. Choose output directory
4. Select which partitions to extract (or leave all checked)
5. Click **Extract**

### Payload Repack
1. Go to the **Repack** tab
2. Select the original `payload.bin` as reference
3. Add modified images
4. Click **Repack** to create new payload

### Image Extract
1. Go to the **Image Extract** tab
2. Select a system/vendor/product `.img` file
3. Choose extraction directory
4. Click **Extract** - handles both sparse and raw images

### Image Repack
1. Go to the **Image Repack** tab
2. Select the extracted folder
3. Configure image settings (size, label, etc.)
4. Click **Repack** to create new image

### Recovery Porter
1. Go to the **Recovery Porter** tab
2. Select source recovery/boot image (from donor device)
3. Select target recovery/boot image (your device)
4. Choose what to port (kernel, ramdisk, or both)
5. Click **Port** to create hybrid image

### Using Plugins
1. Go to the **Plugins** tab
2. Click on any plugin to open it in a new window
3. For ADB/Fastboot: Connect your device and click **Refresh Devices**

---

## 🔌 Creating Plugins

### Plugin Structure
```
plugins/
└── my_plugin/
    ├── manifest.json    # Plugin metadata
    └── plugin.py        # Plugin code
```

### manifest.json
```json
{
    "id": "my-plugin",
    "name": "My Awesome Plugin",
    "version": "1.0.0",
    "description": "What my plugin does",
    "author": "Your Name",
    "min_app_version": "1.1",
    "license_type": "free",
    "requirements": ["requests", "pillow"]
}
```

### License Types
| Type | Description |
|------|-------------|
| `free` | Completely free to use |
| `donation` | Free with donation option |
| `paid` | Requires purchase |

### plugin.py Template
```python
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel

class Plugin(QWidget):
    """Your plugin must export a 'Plugin' class"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Hello from my plugin!"))
```

See the **Plugin Developer Guide** in the Plugins tab for a complete tutorial!

---

## 📁 Project Structure

```
image-anarchy/
├── image_anarchy.py      # Main application (~11,000 lines)
├── update_metadata_pb2.py # Protobuf definitions for OTA
├── README.md
├── platform-tools/        # Bundled ADB & Fastboot
│   ├── adb.exe
│   ├── fastboot.exe
│   └── ...
└── plugins/               # Plugin directory
    ├── adb_toolkit/       # ADB Toolkit plugin
    ├── fastboot_toolkit/  # Fastboot Toolkit plugin
    └── developer_guide/   # Plugin development tutorial
```

---

## 🖼️ Screenshots

<details>
<summary>Click to expand screenshots</summary>

### Main Interface
![Payload Extract Tab](screenshots/extract.png)

### Plugin System
![Plugins Tab](screenshots/plugins.png)

### ADB Toolkit
![ADB Toolkit](screenshots/adb_toolkit.png)

### Fastboot Toolkit
![Fastboot Toolkit](screenshots/fastboot_toolkit.png)

</details>

---

## 📜 Changelog

### v1.1 - Plugin System Release
- ✨ **New:** Extensible plugin system with folder-based discovery
- ✨ **New:** Plugin monetization support (free/paid/donation)
- ✨ **New:** Auto pip requirements installation for plugins
- ✨ **New:** ADB Toolkit plugin with 7 comprehensive tools
- ✨ **New:** Fastboot Toolkit plugin with 8 comprehensive tools
- ✨ **New:** Plugin Developer Guide with complete tutorial
- ✨ **New:** Bundled platform-tools (ADB & Fastboot) - zero setup needed
- 🔧 **Improved:** Expanded window size (1200x900 default)
- 🔧 **Improved:** Better error handling throughout

### v1.0 - Initial Release
- 📦 Payload extraction from OTA files
- 📦 Payload repacking
- 🖼️ Sparse/raw image extraction
- 🖼️ Image repacking with ext4 support
- 🔄 Recovery/boot image porting
- 🎨 Dark-themed PyQt6 GUI
- 🚀 Multi-threaded operations

---

## ⚠️ Disclaimer

**USE AT YOUR OWN RISK!**

This tool modifies Android system images and interacts with device partitions. Improper use can:
- Brick your device
- Void your warranty
- Cause data loss

Always:
- ✅ Backup your device before making changes
- ✅ Understand what you're doing
- ✅ Have a recovery method ready
- ✅ Test on non-critical devices first

The developers are not responsible for any damage to your devices.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Plugin Contributions
Want to share your plugin? 
1. Create your plugin following the structure above
2. Test thoroughly
3. Submit a PR adding your plugin to the `plugins/` directory

---

## 💖 Support

If you find Image Anarchy useful, consider supporting development:

**Bitcoin:** `bc1qx5kp5sx67qe2fd32h6ne7jvw6xpzy2xhnph0rs`

Or star ⭐ the repository to show your appreciation!

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Credits

- **bsdiff4** - Binary diff/patch algorithms
- **protobuf** - Protocol buffer support for OTA metadata
- **PyQt6** - Modern GUI framework
- **lz4** - Fast compression for payload data
- **Android Open Source Project** - Platform tools and documentation

---

<p align="center">
  Made with ❤️ for the Android modding community
</p>

<p align="center">
  <a href="https://github.com/vehoelite/image-anarchy">⭐ Star on GitHub</a> •
  <a href="https://github.com/vehoelite/image-anarchy/issues">🐛 Report Bug</a> •
  <a href="https://github.com/vehoelite/image-anarchy/issues">💡 Request Feature</a>
</p>
