```
    ___                                  ___                        __         
   /   |  ____  ____ ___________  ___   /   |  ____  ____ _____ ___/ /_  __  __
  / /| | / __ \/ __ `/ ___/ ___/ / _ \ / /| | / __ \/ __ `/ __ `/ __ / / / / /
 / ___ |/ / / / /_/ / /  / /__  /  __// ___ |/ / / / /_/ / /_/ / /_/ / /_/ /  
/_/  |_/_/ /_/\__,_/_/   \___/  \___//_/  |_/_/ /_/\__,_/\__, /\__,_/\__, /   
                                                        /____/      /____/    
```

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/icon.png?raw=true" alt="Image Anarchy Logo" width="150">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.1-blue" alt="Version">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.9+-green" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
  <img src="https://img.shields.io/github/stars/vehoelite/image-anarchy?style=social" alt="Stars">
</p>

<h1 align="center">Ⓐ Image Anarchy Ⓐ</h1>
<h3 align="center">Android Image Swiss Army Knife</h3>

<p align="center">
  <i>Break free from restrictive tools. Extract, create, and manipulate Android images with anarchic freedom.</i>
</p>

---

## 🆕 What's New in v1.1

### 🔌 Plugin System
- **Extensible Architecture** - Add new features without modifying core code
- **Monetization Support** - Plugins can be free, paid, or donation-based
- **Auto-Dependency Install** - Plugins can specify pip requirements that auto-install
- **Hot-Reload Ready** - Discover new plugins without restarting

### 📦 Bundled Platform Tools
- **ADB & Fastboot Included** - No need to install Android SDK separately
- **Zero Configuration** - Works out of the box

### 🛠️ New Plugins Included
- **ADB Toolkit** - Comprehensive device management (7 tools)
- **Fastboot Toolkit** - Complete bootloader operations (8 tools)
- **Plugin Developer Guide** - Tutorial for creating your own plugins

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/plugin.png?raw=true" alt="Plugin System" width="700">
</p>

---

## 🔥 Features

### 📦 Payload Operations
- **Extract** partitions from `payload.bin` OTA files
- **Create** new `payload.bin` from partition images
- Support for **differential OTA** (incremental updates)
- Multiple compression: **ZSTD**, **XZ**, **BZ2**, **Brotli**
- Remote file support: HTTP, HTTPS, S3, Google Cloud Storage

### 🔍 Image Extraction
| Format | Capabilities |
|--------|-------------|
| **Sparse** | Convert to raw images |
| **Boot/Recovery/Vendor Boot** | Extract kernel, ramdisk, DTB (v0-v4) |
| **Super (Dynamic)** | Extract all logical partitions |
| **vbmeta** | Parse, patch (disable verity/verification), re-sign |
| **ABL (Android Bootloader)** | Deep analysis, unlock checks, LG LAF mode |
| **ext4** | Extract filesystem contents |
| **FAT** | Extract filesystem contents |
| **ELF/Bootloader** | Analyze XBL, TZ, firmware |

### 🔨 Image Repacking
- **Boot/Recovery images** (v0, v1, v2, v3, v4) - custom kernel/ramdisk
- **Vendor boot images** (v3, v4)
- **Sparse images** from raw (for faster flashing)
- **vbmeta images** with AVB disabled
- **Ramdisk** from directory (cpio + compression)

### 🔄 Recovery Porter
- **Analyze** TWRP, OrangeFox, SHRP, PitchBlack, LineageOS recovery
- **Extract** kernel, DTB, ramdisk, cmdline
- **Browse** ramdisk contents (view fstab, init scripts)
- **Swap** kernel/DTB from another device
- **Modify** cmdline and rebuild
- **Port** custom recoveries between devices
- **Educational comments** explaining recovery internals

### 🔐 Security Features
- **vbmeta patching**: Disable dm-verity and AVB verification
- **Custom AVB signing**: Re-sign with your own keys
- Key generation (RSA-2048/4096/8192)

### 🎨 User Experience
- Modern **dark-themed GUI** (PyQt6)
- **Drag & drop** support
- **Non-blocking** threaded operations
- Real-time progress and logging
- CLI mode for scripting/automation

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

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/adb.png?raw=true" alt="ADB Toolkit" width="700">
</p>

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

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/fastboot.png?raw=true" alt="Fastboot Toolkit" width="700">
</p>

### Plugin Developer Guide
Interactive tutorial showing how to create your own plugins with:
- Plugin structure and manifest format
- Monetization options (free, paid, donation)
- GUI integration examples
- Best practices and tips

---

## 📥 Installation

### Prerequisites
- Python 3.9 or higher
- pip (Python package manager)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/vehoelite/image-anarchy.git
cd image-anarchy

# Create virtual environment (recommended)
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

**Required:**
```bash
pip install PyQt6 bsdiff4 brotli zstandard fsspec protobuf
```

**Optional (for AVB signing & LZ4 ramdisks):**
```bash
pip install cryptography lz4
```

### requirements.txt
```
PyQt6>=6.4.0
bsdiff4>=1.2.0
brotli>=1.0.9
zstandard>=0.19.0
fsspec>=2023.1.0
protobuf>=4.21.0
cryptography>=40.0.0  # Optional: for AVB key signing
lz4>=4.0.0            # Optional: for LZ4 ramdisk compression
```

---

## 🚀 Usage

### GUI Mode (Default)

```bash
python image_anarchy.py
```

The GUI provides 6 tabs:
1. **📦 Extract** - Extract partitions from payload.bin
2. **🔧 Repack** - Create new payload.bin from images
3. **🔍 Image Extract** - Analyze and extract Android images
4. **🔨 Image Repack** - Create boot, sparse, vbmeta images
5. **🔄 Recovery Porter** - Port/modify custom recoveries
6. **🔌 Plugins** - ADB Toolkit, Fastboot Toolkit, and more

### CLI Mode

#### Extract Payload
```bash
# Extract all partitions
python image_anarchy.py --extract payload.bin

# Extract specific partitions
python image_anarchy.py --extract payload.bin -i boot,system,vendor

# Extract from OTA zip
python image_anarchy.py --extract ota_update.zip -o ./extracted/

# Extract from URL
python image_anarchy.py --extract https://example.com/payload.bin
```

#### Create Payload
```bash
# Create payload from images directory
python image_anarchy.py --create ./images/ -o new_payload.bin

# With compression
python image_anarchy.py --create ./images/ -o payload.bin --compression zstd --level 9

# With block size
python image_anarchy.py --create ./images/ -o payload.bin --block-size 262144
```

#### Process Images
```bash
# Convert sparse to raw
python image_anarchy.py --image system.img

# Extract boot image components
python image_anarchy.py --image boot.img

# Extract super partition
python image_anarchy.py --image super.img

# Analyze only (don't extract)
python image_anarchy.py --image vbmeta.img --analyze
```

---

## 📖 Examples

### Extract and Modify Boot Image

```bash
# 1. Extract boot.img from payload
python image_anarchy.py --extract payload.bin -i boot

# 2. Extract boot image components (GUI: Image Extract tab)
#    This gives you: kernel, ramdisk.cpio.gz, dtb, etc.

# 3. Modify ramdisk contents
#    Unpack: gunzip ramdisk.cpio.gz && cpio -idv < ramdisk.cpio
#    Make changes...
#    Repack using GUI: Image Repack tab -> Ramdisk

# 4. Create new boot.img (GUI: Image Repack tab -> Boot Image)
```

### Disable AVB for Custom ROM

```bash
# Using GUI:
# 1. Image Extract tab -> Load vbmeta.img
# 2. Check "Disable dm-verity" and "Disable AVB verification"  
# 3. Optionally check "Re-sign with custom key"
# 4. Extract

# Or create fresh disabled vbmeta:
# Image Repack tab -> vbmeta Image -> Check both disable options -> Create
```

### Port TWRP to Another Device

```bash
# GUI: Recovery Porter tab
# 1. Load source TWRP recovery.img (working on similar device)
# 2. Click "Analyze" to see recovery structure
# 3. Replace kernel with target device's kernel
# 4. Replace DTB if needed (device tree for hardware)
# 5. Click "Extract All" to extract ramdisk
# 6. Edit fstab to match target device partitions
# 7. Set output path and click "Build Recovery"
# 8. Flash: fastboot flash recovery recovery_ported.img
```

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

## 🏗️ Project Structure

```
image-anarchy/
├── image_anarchy.py       # Main application (single file, batteries included)
├── requirements.txt       # Python dependencies
├── README.md              # This file
├── LICENSE                # MIT License
├── platform-tools/        # Bundled ADB & Fastboot
│   ├── adb.exe
│   ├── fastboot.exe
│   └── ...
└── plugins/               # Plugin directory
    ├── adb_toolkit/       # ADB Toolkit plugin
    ├── fastboot_toolkit/  # Fastboot Toolkit plugin
    └── developer_guide/   # Plugin development tutorial
```

The entire application is contained in a single Python file with embedded protobuf definitions - no external proto files needed!

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
- 📦 Payload repacking with multiple compression formats
- 🖼️ Sparse/raw image extraction and conversion
- 🖼️ Boot/recovery image extraction (v0-v4)
- 🖼️ Super partition extraction
- 🖼️ vbmeta parsing, patching, and re-signing
- 🖼️ ABL/bootloader analysis
- 🔨 Boot/recovery image repacking
- 🔨 Sparse image creation
- 🔨 vbmeta image creation
- 🔄 Recovery porting between devices
- 🎨 Dark-themed PyQt6 GUI
- 🚀 Multi-threaded operations
- 📡 Remote file support (HTTP, S3, GCS)

---

## 🤝 Contributing

Contributions are welcome! Feel free to:

- 🐛 Report bugs
- 💡 Suggest features
- 🔧 Submit pull requests
- 🔌 Create and share plugins

### Plugin Contributions
Want to share your plugin? 
1. Create your plugin following the structure above
2. Test thoroughly
3. Submit a PR adding your plugin to the `plugins/` directory

---

## ⚠️ Disclaimer

This tool is provided for **educational and development purposes**. 

- Modifying device images may void your warranty
- Always backup your data before flashing modified images
- Disabling AVB/dm-verity reduces device security
- Use at your own risk

---

## 💖 Support

If you find Image Anarchy useful, consider supporting development:

**Bitcoin:** `bc1qx5kp5sx67qe2fd32h6ne7jvw6xpzy2xhnph0rs`

Or star ⭐ the repository to show your appreciation!

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- Android Open Source Project
- Chromium OS update_engine
- The Android modding community

---

<p align="center">
  <b>Ⓐ Break the chains. Free your images. Ⓐ</b>
</p>

<p align="center">
  Made with ☕ and rebellion
</p>
