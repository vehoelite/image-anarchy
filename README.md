```
    ___                                  ___                        __         
   /   |  ____  ____ ___________  ___   /   |  ____  ____ _____ ___/ /_  __  __
  / /| | / __ \/ __ `/ ___/ ___/ / _ \ / /| | / __ \/ __ `/ __ `/ __ / / / / /
 / ___ |/ / / / /_/ / /  / /__  /  __// ___ |/ / / / /_/ / /_/ / /_/ / /_/ /  
/_/  |_/_/ /_/\__,_/_/   \___/  \___//_/  |_/_/ /_/\__,_/\__, /\__,_/\__, /   
                                                        /____/      /____/    
```
<h2>Announcement: XDA for tyrants not for phones. A bunch of n00bs are at xdaforums.com (AVOID AT ALL COSTS!)</h2>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/icon.png?raw=true" alt="Image Anarchy Logo" width="150">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.5-red" alt="Version">
  <img src="https://img.shields.io/badge/MAJOR-Release-orange" alt="MAJOR">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.9+-green" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
  <img src="https://img.shields.io/github/stars/vehoelite/image-anarchy?style=social" alt="Stars">
</p>

<h1 align="center">Ⓐ Image Anarchy Ⓐ</h1>
<h3 align="center">Android Image Swiss Army Knife</h3>
<h3 align="center"><a href="https://imageanarchy.com" border=0>https://imageanarchy.com</a></h3>

<p align="center">
  <i>Break free from restrictive tools. Extract, create, and manipulate Android images with anarchic freedom.</i>
</p>

---

## 🔥 What's New in v2.5 - MAJOR RELEASE

### 🎨 Visual Plugin Maker (NEW!)
Create plugins without writing code! Drag-and-drop interface for building custom plugins:
- **📦 Block Palette** - Drag building blocks for dependencies, tools, and UI elements
- **🎯 Tool Detection** - Automatically scans for available tools and capabilities
- **🔧 5 Block Categories** - Dependencies, Built-in Tools, External Tools, Plugin Tools, UI Elements
- **🔌 30+ Blocks** - From pip packages to ADB commands, EROFS extraction to MTK flashing
- **💾 Export** - Generate manifest.json and plugin.py from your visual design
- **🔒 Smart Availability** - Blocks show locked status if required tools aren't installed

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/vpm1.png?raw=true" alt="Visual Plugin Maker - Block Palette" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/vpm2.png?raw=true" alt="Visual Plugin Maker - Canvas" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/vpm3.png?raw=true" alt="Visual Plugin Maker - Properties" width="700">
</p>
<h1> 🎨 Visual Plugin Maker V2</h1>

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/vpmv2.png?raw=true" alt="Visual Plugin Maker V2 - More Advanced" width="700">
</p>

### 🧪 Plugin Playground (NEW!)
Test and validate your plugins in a dedicated sandbox environment:
- **🔄 Hot Reload** - Automatically reload plugin when files change
- **✅ 11-Point Validation** - Comprehensive checklist ensures plugin quality
- **🖼️ Live Preview** - See your plugin widget rendered in real-time
- **🐛 Console Output** - View logs, errors, and debug messages
- **📦 Dependency Check** - Verify all requirements are available

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/vpm4.png?raw=true" alt="Plugin Playground - Validation" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/vpm5.png?raw=true" alt="Plugin Playground - Preview" width="700">
</p>

### 🔄 Auto-Update System (NEW!)
Never miss an update with automatic version checking:
- **🔔 Background Check** - Silently checks for updates on startup
- **📊 Update Dialog** - Shows changelog and download size
- **⬇️ One-Click Download** - Download updates directly in the app
- **📋 Progress Tracking** - See download progress in real-time
- **🔄 Easy Install** - Replaces exe automatically on Windows

### 📱 OPPO/OnePlus/Realme Firmware Decryption
- **OFP Decryption** - Decrypt OPPO/Realme .ofp firmware files
- **Auto-Detect Chipset** - Automatically detects Qualcomm vs MediaTek firmware
- **OPS Support** - Decrypt OnePlus .ops firmware packages
- **ZIP Password Cracking** - Extract password-protected OPPO/Realme ZIPs
- **Multiple Key Tables** - Supports wide range of firmware versions (V1.4.17 to V2.0.3+)
- Based on [bkerler's oppo_decrypt](https://github.com/bkerler/oppo_decrypt)

### 🌞 Allwinner Firmware Support
- **Unpack LiveSuit/PhoenixSuit** - Extract Allwinner .img firmware
- **Repack Firmware** - Create new Allwinner firmware images
- **Chipset Support** - SC8600/9800, A10-A80, A133, H2/H3/H5/H6/H313/H616/H618

### 🪨 Rockchip Firmware Support
- **Unpack RKFW/RKAF** - Extract Rockchip update.img firmware
- **Repack Firmware** - Create new Rockchip firmware images
- **Chipset Support** - RK28xx through RK35xx series

### 🗂️ EROFS Support (Android 13+)
- **Full EROFS Extraction** - Extract files from Enhanced Read-Only File System images
- **EROFS Repacking** - Create EROFS images from directories with LZ4/LZMA compression
- **Superblock Analysis** - View block size, inode count, UUID, compression algorithms
- **Modern Android Support** - Works with system/vendor/product partitions from Android 13+
- **Compression Options** - LZ4 (fast), LZ4HC (balanced), LZMA (best compression)

### 📺 NEW: Scrcpy Toolkit Plugin
- **Live Screen Mirroring** - Mirror your Android screen in real-time
- **Screenshot Capture** - Take high-quality screenshots with one click
- **Screen Recording** - Record device screen with audio support
- **WiFi Mirroring** - Connect wirelessly after initial USB setup
- **Multiple Quality Options** - Adjust bitrate, resolution, and framerate
- **Always-On-Top Window** - Keep mirror visible while working
- **Zero Dependencies** - Uses bundled scrcpy executable

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/scrcpy1.png?raw=true" alt="Scrcpy Mirror" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/scrcpy2.png?raw=true" alt="Scrcpy Screenshot" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/scrcpy3.png?raw=true" alt="Scrcpy Recording" width="700">
</p>

### 🛒 Online Plugin Store
- **Browse & Download** - Discover plugins directly from the app
- **One-Click Install** - Download, extract, and activate plugins instantly
- **Plugin Ratings & Reviews** - See what the community thinks
- **Version Management** - Check for updates to installed plugins
- **Featured Plugins** - Curated selection of the best tools

### 🔌 Premium Plugins Available
- **ADB Toolkit** - Complete Android Debug Bridge management (7 tools + Run as Root)
- **Fastboot Toolkit** - Comprehensive bootloader operations (8 tools + vbmeta patching)
- **MTK Toolkit** - MediaTek device support with BROM exploit
- **Scrcpy Toolkit** - Screen mirroring, screenshots, and recording

### 📦 Bundled Platform Tools
- **ADB & Fastboot Included** - No need to install Android SDK separately
- **Zero Configuration** - Works out of the box
- **Driver Pack** - Common USB drivers bundled for Windows

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/plugin_store.png?raw=true" alt="Plugin Store" width="700">
</p>

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/upload.png?raw=true" alt="Plugin Upload" width="700">
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
| **EROFS** | Extract Android 13+ read-only filesystem (LZ4/LZMA) |
| **FAT** | Extract filesystem contents |
| **ELF/Bootloader** | Analyze XBL, TZ, firmware |

### 🔨 Image Repacking
- **Boot/Recovery images** (v0, v1, v2, v3, v4) - custom kernel/ramdisk
- **Vendor boot images** (v3, v4)
- **Sparse images** from raw (for faster flashing)
- **EROFS images** from directory (LZ4/LZ4HC/LZMA compression)
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

## 🔌 Available Plugins (from Store)

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
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/adbpull.png?raw=true" alt="ADB Partition Pull" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/apps.png?raw=true" alt="ADB Apps" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/shell.png?raw=true" alt="ADB Shell" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/makedir.png?raw=true" alt="ADB File Browser" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/oem.png?raw=true" alt="ADB OEM Commands" width="700">
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
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/fastboot1.png?raw=true" alt="Fastboot Info" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/fastboot2.png?raw=true" alt="Fastboot Flash" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/fastboot3.png?raw=true" alt="Fastboot Boot" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/fastboot4.png?raw=true" alt="Fastboot OEM" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/fastboot5.png?raw=true" alt="Fastboot Slot" width="700">
</p>

### MTK Toolkit
MediaTek device support with advanced operations:

| Feature | Description |
|---------|-------------|
| **🔌 BROM Mode** | Connect to devices in BROM/Preloader mode |
| **📥 Read Partitions** | Dump partitions via BROM exploit |
| **⚡ Write Partitions** | Flash images to MediaTek devices |
| **🔐 Bypass Auth** | DA authentication bypass for secured devices |
| **📊 Device Info** | Hardware ID, chip info, EMMC/UFS details |

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/mtk1.png?raw=true" alt="MTK Connect" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/mtk2.png?raw=true" alt="MTK Read" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/mtk3.png?raw=true" alt="MTK Write" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/mtk4.png?raw=true" alt="MTK Erase" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/mtk5.png?raw=true" alt="MTK Tools" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/v2.0/mtkclient.png?raw=true" alt="MTK Client Console" width="700">
</p>

### Scrcpy Toolkit
Real-time screen mirroring and capture for Android devices:

| Feature | Description |
|---------|-------------|
| **📺 Screen Mirror** | Live mirroring with customizable quality settings |
| **📸 Screenshot** | Capture device screen as PNG with timestamp |
| **🎬 Screen Record** | Record screen with adjustable bitrate and duration |
| **📶 WiFi Mode** | Connect wirelessly for untethered mirroring |
| **⚙️ Quality Control** | Adjust resolution, bitrate, and framerate |
| **📌 Always-On-Top** | Keep mirror window visible (default: enabled) |

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/scrcpy1.png?raw=true" alt="Scrcpy Mirror Tab" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/scrcpy2.png?raw=true" alt="Scrcpy Screenshot Tab" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/scrcpy3.png?raw=true" alt="Scrcpy Recording Tab" width="700">
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

### GUI Mode (Default) (Build from Windows)
You need Microsoft Visual C++ Redis pack
https://imageanarchy.com/VC_redist.x64.exe

You need the Microsoft C++ Build Tools. (or bsdiff4 will fail during pip install)
https://imageanarchy.com/vs_BuildTools.exe

Select Desktop development with C++ --> Goto Individual components Tab and select -->
MSVC Build Tools for x64/x86 (Latest)

Windows 11 SDK (10.0.26100.7175)

C++ CMake tools for Windows

MTesting tools core features - Build Tools

MSVC AddressSanitizer

vcpkg package manager

Confirm version here*
Windows 11 SDK (10.0.22621.0) 

Then select Install

```bash
python -m venv venv
venv/Scripts/activate.ps1
pip install -r requirements.txt
python image_anarchy.py
```

The GUI provides 8+ tabs:
1. **📦 Extract** - Extract partitions from payload.bin
2. **🔧 Repack** - Create new payload.bin from images
3. **🔍 Image Extract** - Analyze and extract Android images
4. **🔨 Image Repack** - Create boot, sparse, vbmeta images
5. **🔄 Recovery Porter** - Port/modify custom recoveries
6. **🔌 Plugins** - ADB Toolkit, Fastboot Toolkit, and more
7. **🌞 Allwinner** - Allwinner firmware unpack/repack
8. **🪨 Rockchip** - Rockchip firmware unpack/repack
9. **📱 OPPO/OnePlus** - OPPO/Realme/OnePlus firmware decryption

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

### manifest.json - Complete Reference
```json
{
    "id": "my-plugin",
    "name": "My Awesome Plugin",
    "version": "1.0.0",
    "description": "What my plugin does",
    "author": "Your Name",
    "icon": "🔧",
    "min_app_version": "2.0",
    "license_type": "free",
    "website": "https://example.com",
    "support_url": "https://example.com/support",
    "enabled": true,
    
    "requirements": [
        "requests",
        "pillow"
    ],
    
    "git_clone": {
        "repo": "https://github.com/user/repo.git",
        "target": "repo_folder_name"
    },
    
    "setup_commands": [
        "pip install ."
    ],
    
    "bundled_binaries": [
        "https://example.com/tool.exe",
        {
            "url": "https://example.com/file.zip",
            "target_path": "tools/file.zip",
            "sha256": "abc123..."
        }
    ],
    
    "post_install": [
        {"type": "driver", "file": "driver.msi"},
        {"type": "command", "cmd": ["setup.exe", "/silent"]}
    ]
}
```

### Manifest Fields Reference

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique plugin identifier (folder name) |
| `name` | string | Display name shown in UI |
| `version` | string | Plugin version (semver recommended) |
| `description` | string | Short description |
| `author` | string | Developer name |
| `icon` | string | Emoji icon for UI |
| `license_type` | string | `free`, `donation`, or `paid` |
| `min_app_version` | string | Minimum Image Anarchy version required |
| `enabled` | bool | Whether plugin is active |
| `website` | string | Plugin homepage URL |
| `support_url` | string | Support/docs URL |
| `requirements` | array | Pip packages to install |
| `git_clone` | object | Repository to clone (see below) |
| `setup_commands` | array | Commands to run after clone |
| `bundled_binaries` | array | Files/URLs to download |
| `post_install` | array | Final setup steps (drivers, etc.) |

### Dependency Installation Flow

When a plugin is installed, dependencies are set up in this order:

1. **Git Clone** (`git_clone`) - Clone repository to plugin directory
2. **Download Binaries** (`bundled_binaries`) - Download any required files
3. **Pip Packages** (`requirements`) - Install Python dependencies
4. **Setup Commands** (`setup_commands`) - Run in cloned repo directory
5. **Post Install** (`post_install`) - Final steps like driver installation

### git_clone Object
```json
{
    "repo": "https://github.com/user/repo.git",
    "target": "local_folder_name"
}
```
- `repo`: Git repository URL
- `target`: Folder name within plugin directory to clone into

### setup_commands Array
```json
["pip install .", "python setup.py build"]
```
- Commands run **inside the git_clone target directory**
- Use `pip install .` to install a cloned Python package
- Supports any shell command

### bundled_binaries Array
```json
[
    "https://example.com/simple.exe",
    {
        "url": "https://example.com/tool.zip",
        "target_path": "tools/tool.zip",
        "sha256": "checksum_for_verification"
    }
]
```
- Simple string: URL downloaded to plugin root
- Object: Allows custom path and optional SHA256 verification

### License Types
| Type | Description |
|------|-------------|
| `free` | Completely free to use |
| `donation` | Free with optional donation |
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

### Example: Plugin with Git Clone

For plugins that wrap existing Python libraries:

```json
{
    "id": "mtk_toolkit",
    "name": "MTK Toolkit",
    "version": "1.0",
    "description": "MediaTek device toolkit",
    "author": "Image Anarchy",
    "icon": "📱",
    "license_type": "free",
    
    "requirements": [
        "pyusb", "pycryptodome", "colorama", "pyserial"
    ],
    
    "git_clone": {
        "repo": "https://github.com/bkerler/mtkclient.git",
        "target": "mtkclient"
    },
    
    "setup_commands": [
        "pip install ."
    ]
}
```

**Flow:**
1. Clone mtkclient repo → `plugins/mtk_toolkit/mtkclient/`
2. Install pip requirements
3. Run `pip install .` inside the cloned repo
4. Plugin ready to use!

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
├── tools/                 # CLI tools
│   ├── *.erofs.exe        # EROFS utilities
│   ├── Allwinner/         # imgRePacker for Allwinner
│   └── Rockchip/          # imgRePackerRK for Rockchip
└── plugins/               # Plugin directory
    ├── adb_toolkit/       # ADB Toolkit plugin
    ├── fastboot_toolkit/  # Fastboot Toolkit plugin
    └── developer_guide/   # Plugin development tutorial
```

The entire application is contained in a single Python file with embedded protobuf definitions - no external proto files needed!

---

## 📜 Changelog

### v2.1 - HOT UPDATE: Multi-Platform Firmware Support
- 🔥 **New:** OPPO/Realme .ofp firmware decryption (Qualcomm & MediaTek)
- 🔥 **New:** OnePlus .ops firmware decryption
- 🔥 **New:** Allwinner firmware unpack/repack (LiveSuit, PhoenixSuit)
- 🔥 **New:** Rockchip firmware unpack/repack (RKFW, RKAF)
- 🔥 **New:** Full EROFS filesystem extraction (Android 13+ system/vendor/product images)
- 🔥 **New:** EROFS image creation from directories with LZ4/LZ4HC/LZMA compression
- 🔥 **New:** EROFS superblock analysis (UUID, block size, features, compression)
- ✨ **New:** Scrcpy Toolkit plugin for screen mirroring
- ✨ **New:** Screenshot capture with one-click save
- ✨ **New:** Screen recording with audio support
- ✨ **New:** WiFi mirroring mode for wireless connection
- ✨ **New:** "Run as Root" checkbox in ADB Shell tab
- ✨ **New:** Password-protected OPPO/Realme ZIP extraction
- 🔧 **Improved:** Shell prompt shows # for root mode, $ for normal
- 🔧 **Improved:** Scrcpy defaults to always-on-top and half-size window
- 🔧 **Improved:** Better error handling for EROFS compressed blocks
- 🔧 **Improved:** Auto-detect QC vs MTK firmware variants

### v2.0 - Plugin Store & Advanced Dependencies
- ✨ **New:** Online Plugin Store with browse, install, ratings & reviews
- ✨ **New:** One-click plugin installation with automatic dependency setup
- ✨ **New:** Git clone support for plugins (`git_clone` manifest field)
- ✨ **New:** Setup commands for complex installations (`setup_commands` field)
- ✨ **New:** Bundled binary downloads (`bundled_binaries` field)
- ✨ **New:** Post-install actions for drivers & commands (`post_install` field)
- ✨ **New:** MTK Toolkit plugin with BROM exploit support
- ✨ **New:** System tray with minimize-to-tray functionality
- ✨ **New:** 4-phase plugin setup progress with clear "Step X/N" display
- 🔧 **Improved:** Plugin dependencies work in frozen exe (PyInstaller)
- 🔧 **Improved:** Better plugin manifest validation
- 🔧 **Improved:** Proper application quit from system tray

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







