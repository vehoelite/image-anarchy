<h1>This project is completely created by A.I. As they upgrade, so does the program.</h1>
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
  <img src="https://img.shields.io/badge/Version-3.0-red" alt="Version">
  <img src="https://img.shields.io/badge/REVOLUTIONARY-Release-orange" alt="REVOLUTIONARY">
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

## 🔥 What's New in v3.0 - REVOLUTIONARY RELEASE

### 📋 Community Forum (NOW LIVE!)
A full phpBB forum integrated directly into Image Anarchy!

- **📋 Dedicated Forum Tab** - Browse and post without leaving the app
- **🔗 Unified Login** - Same account for app, chat, and forum
- **💬 Device Support** - Get help with your specific device
- **📖 Guides & Tutorials** - Community-created content
- **🌐 Web Access** - Also available at [forum.imageanarchy.com](https://forum.imageanarchy.com)

### 🗄️ Backend Overhaul (NOW LIVE!)
Major infrastructure upgrades powering v3.0:

- **🐬 MySQL Database** - Upgraded from SQLite3 to MySQL for scalability
- **⚡ Redis Integration** - Lightning-fast caching and session management
- **🔗 Unified Auth System** - Single sign-on across app, chatrooms, and forum
- **📧 Email Integration** - Account invites, notifications, password recovery

### 💾 IAABS - Image Anarchy Android Backup Solution (WORLD FIRST!)
The first-ever live root filesystem backup tool for Android via ADB. **No recovery mode needed** - backup your entire device while it's running!

- **🔓 Live Root Backup** - Backup system partitions while your phone is ON and running
- **📱 Multiple Backup Profiles** - Full Device, Apps & Data, User Data Only, System Only, Custom
- **📦 Tar-Based Extraction** - Blazing fast 3-phase backup (create → pull → compress)
- **🔒 SELinux Context Preservation** - Captures and restores security contexts for proper functionality
- **♻️ Full Restore Capability** - Restore backups with paths, symlinks, permissions, ownership intact
- **📊 Progress Tracking** - Real-time percentage indicators throughout all phases
- **🗂️ Backup History** - Manage and browse previous backups with one-click restore

<p align="center">
  <img src="https://imageanarchy.com/screenshots/iaabs1.png" alt="IAABS - Backup Profiles" width="700">
</p>
<p align="center">
  <img src="https://imageanarchy.com/screenshots/iaabs2.png" alt="IAABS - Restore" width="700">
</p>

**Why IAABS is Revolutionary:**
| Traditional Methods | IAABS |
|---------------------|-------|
| Requires recovery mode (TWRP) | Works while phone is running |
| Device must be offline | Phone stays connected and usable |
| Complex multi-step process | One-click backup with profiles |
| Loses SELinux contexts | Preserves and restores security contexts |
| Manual partition selection | Intelligent preset profiles |

### 🔓 Root Patcher Plugin (NEW!)
Fully automated boot.img patching - no manual interaction required!

- **🪄 Magisk Auto-Patch** - Extracts magiskboot from APK and patches on device automatically
- **🔧 KernelSU Support** - Semi-automated patching for GKI kernels
- **⚡ APatch Support** - Semi-automated patching with KernelPatch
- **📥 Extract Boot from Device** - Pull boot.img directly from connected device
- **🔙 Patch & Flash Back** - Complete round-trip patching workflow
- **📱 Bundled APKs** - Includes latest Magisk, KernelSU, and APatch APKs
- **✅ Compatibility Checks** - Warns before bricking with incompatible methods

<p align="center">
  <img src="https://imageanarchy.com/screenshots/rootpatcher1.png" alt="Root Patcher - Main" width="700">
</p>
<p align="center">
  <img src="https://imageanarchy.com/screenshots/rootpatcher2.png" alt="Root Patcher - Patching" width="700">
</p>

| Root Method | Automation Level | Requirements |
|-------------|------------------|--------------|
| Magisk | 🟢 Fully Automated | Any Android device |
| KernelSU | 🟡 Semi-Automated | GKI kernel (Android 12+) |
| APatch | 🟡 Semi-Automated | Android 11+ |

### 🛡️ Enhanced Plugin Security
- **🔍 VirusTotal Integration** - All plugin uploads scanned with 70+ AV engines
- **🦠 ClamAV Support** - Optional local scanning for instant threat detection
- **📦 Dependency Scanning** - External binaries scanned before packaging
- **🚨 Automatic Quarantine** - Detected threats isolated automatically
- **📧 Admin Alerts** - Email notifications on threat detection
- **📋 Full Audit Logging** - Complete security event history

### 🎯 Plugin Store Improvements
- **📊 Better Statistics** - Enhanced plugin analytics and download tracking
- **🔄 Improved Updates** - More reliable plugin update notifications
- **🔐 Stricter Validation** - 20-point validation for all plugin submissions
- **⚡ Redis Caching** - Faster plugin listings and searches

### 💬 Integrated Chatrooms & Community (🔜 COMING SOON)
Connect with the anarchy community directly from the app!

- **💬 Dedicated Chatroom Tab** - Real-time chat built into Image Anarchy
- **🏠 Create Your Own Rooms** - Make public or private chatrooms
- **🔒 Private Rooms** - Invite-only rooms for your crew
- **📧 Invite System** - Invite anyone via email with automatic account creation
- **🚀 Auto-Join on Register** - New users automatically join chatrooms from invites
- **🔗 Unified Accounts** - One login for app, chatrooms, and forum

### 🛠️ Professional Remote Support (🔜 COMING SOON)
Get help from experts without leaving your chair!

- **🖥️ Remote Desktop** - Allow professionals to see and control your screen
- **📱 Remote ADB/Fastboot** - Experts can run commands on your connected device
- **🔐 Secure Connections** - End-to-end encrypted remote sessions
- **👨‍🔧 Verified Professionals** - Connect with trusted community helpers

### 🔧 Quality of Life Improvements
- **📜 Scrollable Plugin UIs** - All plugins now have proper scroll areas
- **🎨 Improved Layouts** - Better spacing and responsive design
- **🔗 Better ADB Detection** - Plugins share ADB from ADB Toolkit automatically
- **📝 Enhanced Logging** - More detailed progress and error messages

---

## 🔥 Previous Release Highlights (v2.5)

### 🎨 Visual Plugin Maker
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

<h3>🎨 Visual Plugin Maker V2</h3>

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/vpmv2.png?raw=true" alt="Visual Plugin Maker V2 - More Advanced" width="700">
</p>

### 🧪 Plugin Playground
Test and validate your plugins in a dedicated sandbox environment:
- **🔄 Hot Reload** - Automatically reload plugin when files change
- **✅ 20-Point Validation** - Validates ALL 15 manifest fields plus plugin files
- **🖼️ Live Preview** - See your plugin widget rendered in real-time
- **🐛 Console Output** - View logs, errors, and debug messages
- **📦 Dependency Check** - Verify all requirements are available

<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/vpm4.png?raw=true" alt="Plugin Playground - Validation" width="700">
</p>
<p align="center">
  <img src="https://github.com/vehoelite/image-anarchy/blob/main/screenshots/vpm5.png?raw=true" alt="Plugin Playground - Preview" width="700">
</p>

### 🔄 Auto-Update System
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

### 🛒 Online Plugin Store
- **Browse & Download** - Discover plugins directly from the app
- **One-Click Install** - Download, extract, and activate plugins instantly
- **Plugin Ratings & Reviews** - See what the community thinks
- **Version Management** - Check for updates to installed plugins
- **Featured Plugins** - Curated selection of the best tools

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

### 💾 IAABS - Android Backup Solution (NEW in v3.0!)
Revolutionary live root filesystem backup - the first of its kind:

| Feature | Description |
|---------|-------------|
| **🔓 Live Backup** | Backup while device is running - no recovery needed |
| **📱 Smart Profiles** | Full, Apps & Data, User Data, System Only, Custom |
| **🔒 SELinux Contexts** | Preserves and restores security labels |
| **📊 3-Phase Process** | Create tars → Pull to PC → Compress & verify |
| **♻️ Full Restore** | Restore with all metadata intact |
| **📋 History** | Browse and manage all previous backups |

### 🔓 Root Patcher (NEW in v3.0!)
One-click root patching with Magisk, KernelSU, and APatch:

| Feature | Description |
|---------|-------------|
| **🪄 Auto-Patch** | Fully automated Magisk patching on device |
| **📥 Extract Boot** | Pull boot.img directly from device |
| **🔧 Multi-Method** | Magisk, KernelSU, APatch support |
| **✅ Safety Checks** | Compatibility verification before patching |
| **📱 Bundled APKs** | Latest rooting tools included |

### 📱 ADB Toolkit
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

### ⚡ Fastboot Toolkit  
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

### 🔥 MTK Toolkit
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

### 📺 Scrcpy Toolkit
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

### 📖 Plugin Developer Guide
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
You need Microsoft Visual C++ Redist pack
https://imageanarchy.com/VC_redist.x64.exe

You need the Microsoft C++ Build Tools. (or bsdiff4 will fail during pip install)
https://imageanarchy.com/vs_BuildTools.exe

Select Desktop development with C++ --> Goto Individual components Tab and select -->
MSVC Build Tools for x64/x86 (Latest)

Windows 11 SDK (10.0.26100.7175)

C++ CMake tools for Windows

Testing tools core features - Build Tools

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

The GUI provides 9+ tabs:
1. **📦 Extract** - Extract partitions from payload.bin
2. **🔧 Repack** - Create new payload.bin from images
3. **🔍 Image Extract** - Analyze and extract Android images
4. **🔨 Image Repack** - Create boot, sparse, vbmeta images
5. **🔄 Recovery Porter** - Port/modify custom recoveries
6. **🔌 Plugins** - IAABS, Root Patcher, ADB, Fastboot, MTK, Scrcpy
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
    ├── manifest.json    # Plugin metadata (ALL 15 fields required!)
    └── plugin.py        # Plugin code
```

### ⚠️ STRICT manifest.json Format

**All 15 fields are REQUIRED in the exact order shown below. Missing fields will cause your plugin to be rejected.**

```json
{
    "id": "my_plugin",
    "name": "My Awesome Plugin",
    "version": "1.0.0",
    "description": "What my plugin does",
    "author": "Your Name",
    "icon": "🔧",
    "license_type": "free",
    "website": "https://example.com",
    "support_url": "https://example.com/issues",
    "min_version": "2.0",
    "git_clone": null,
    "requirements": [],
    "bundled_binaries": [],
    "setup_commands": [],
    "enabled": true
}
```

### Manifest Fields Reference (All 15 Required)

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | **MUST match folder name.** Lowercase letters, numbers, underscores only. Start with letter. |
| `name` | string | Human-readable display name |
| `version` | string | Format: `X.Y` or `X.Y.Z` (e.g., "1.0" or "1.0.0") |
| `description` | string | Brief description shown in plugin list |
| `author` | string | Developer or team name |
| `icon` | string | Single emoji (🔧, ⚡, 📱, etc.) |
| `license_type` | string | Must be: `"free"`, `"paid"`, or `"donation"` |
| `website` | string | Project homepage URL (can be empty `""`) |
| `support_url` | string | Issues/support URL (can be empty `""`) |
| `min_version` | string | Minimum Image Anarchy version required |
| `git_clone` | object/null | Repository to clone, or `null` if not needed |
| `requirements` | array | Pip packages to install (can be empty `[]`) |
| `bundled_binaries` | array | Binary URLs to download (can be empty `[]`) |
| `setup_commands` | array | Shell commands to run (can be empty `[]`) |
| `enabled` | boolean | `true` or `false` |

### Dependency Installation Flow

When a plugin is installed, dependencies are set up in this order:

1. **Git Clone** (`git_clone`) - Clone repository to plugin directory
2. **Download Binaries** (`bundled_binaries`) - Download any required files
3. **Pip Packages** (`requirements`) - Install Python dependencies
4. **Setup Commands** (`setup_commands`) - Run in cloned repo directory

### git_clone Object
```json
"git_clone": {
    "repo": "https://github.com/user/repo.git",
    "target": "local_folder_name"
}
```
When not using git_clone, set to `null`:
```json
"git_clone": null
```

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
        "path": "tools/tool.zip",
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

### Example: Plugin with Git Clone (Complete Manifest)

For plugins that wrap existing Python libraries, here's a **complete** manifest with all 15 required fields:

```json
{
    "id": "mtk_toolkit",
    "name": "MTK Toolkit",
    "version": "1.2",
    "description": "Advanced MediaTek device toolkit - BROM exploit, flash read/write, unlock bootloader",
    "author": "Image Anarchy Team",
    "icon": "⚡",
    "license_type": "free",
    "website": "https://imageanarchy.com",
    "support_url": "https://github.com/vehoelite/image-anarchy/issues",
    "min_version": "2.0",
    "git_clone": {
        "repo": "https://github.com/bkerler/mtkclient.git",
        "target": "mtkclient"
    },
    "requirements": ["pyusb", "pyserial"],
    "bundled_binaries": [],
    "setup_commands": ["pip install ."],
    "enabled": true
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
    ├── iaabs/             # IAABS backup plugin (NEW!)
    ├── root_patcher/      # Root Patcher plugin (NEW!)
    ├── adb_toolkit/       # ADB Toolkit plugin
    ├── fastboot_toolkit/  # Fastboot Toolkit plugin
    ├── mtk_toolkit/       # MTK Toolkit plugin
    ├── scrcpy_toolkit/    # Scrcpy Toolkit plugin
    └── developer_guide/   # Plugin development tutorial
```

The entire application is contained in a single Python file with embedded protobuf definitions - no external proto files needed!

---

## 📜 Changelog

### v3.0 - REVOLUTIONARY RELEASE 🔥
- 📋 **NOW LIVE:** Community Forum
  - Dedicated Forum tab with full phpBB integration
  - Also available at [forum.imageanarchy.com](https://forum.imageanarchy.com)
  - Unified login system (app + chat + forum)
  - Device support and community guides
- 🗄️ **NOW LIVE:** Backend Overhaul
  - Migrated from SQLite3 to MySQL database
  - Redis integration for caching and sessions
  - Unified authentication across all services
- 🔥 **NEW:** IAABS - Image Anarchy Android Backup Solution (World First!)
  - Live root filesystem backup via ADB - no recovery mode needed
  - Multiple backup profiles (Full, Apps, User Data, System, Custom)
  - 3-phase tar-based backup with progress tracking
  - SELinux context preservation and restoration
  - Full restore capability with metadata intact
  - Backup history and management
- 🔥 **NEW:** Root Patcher Plugin
  - Fully automated Magisk patching (no manual steps)
  - KernelSU support for GKI kernels
  - APatch support with KernelPatch
  - Extract boot.img directly from device
  - Bundled latest APKs (Magisk, APatch, KernelSU)
- 🛡️ **Enhanced Security:** VirusTotal + ClamAV scanning for plugins
- 🛡️ **Enhanced Security:** Automatic threat quarantine
- 🛡️ **Enhanced Security:** Full audit logging
- 🔧 **Improved:** All plugins now have scrollable UIs
- 🔧 **Improved:** Better ADB detection across plugins
- 🔧 **Improved:** Enhanced progress indicators
- 🔧 **Improved:** Plugin Store performance with Redis caching
- 🔜 **COMING SOON:** Integrated Chatrooms
  - Dedicated Chatroom tab in the app
  - Create public or private rooms
  - Invite system with email-based account signup
  - Automatic room join after registration
- 🔜 **COMING SOON:** Professional Remote Support
  - Remote Desktop for expert assistance
  - Remote ADB/Fastboot command execution
  - Secure end-to-end encrypted sessions

### v2.5 - MAJOR RELEASE
- 🎨 **New:** Visual Plugin Maker - Create plugins without code
- 🧪 **New:** Plugin Playground - Test plugins with hot reload
- 🔄 **New:** Auto-Update System with one-click install
- 📱 **New:** OPPO/OnePlus/Realme firmware decryption
- 🌞 **New:** Allwinner firmware support
- 🪨 **New:** Rockchip firmware support
- 🗂️ **New:** Full EROFS extraction and repacking
- 📺 **New:** Scrcpy Toolkit plugin

### v2.0 - Plugin Store & Dependencies
- ✨ **New:** Online Plugin Store
- ✨ **New:** Git clone support for plugins
- ✨ **New:** Setup commands and bundled binaries
- ✨ **New:** MTK Toolkit plugin
- ✨ **New:** System tray support

### v1.0-1.1 - Foundation
- 📦 Payload extraction and repacking
- 🖼️ Image extraction (boot, super, vbmeta, sparse, etc.)
- 🔨 Image repacking
- 🔄 Recovery porter
- 🔌 Plugin system with ADB/Fastboot toolkits

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
  <b>Ⓐ Break the chains. Free your images. Join the rebellion. Ⓐ</b>
</p>

<p align="center">
  Made with ☕ and rebellion
</p>


