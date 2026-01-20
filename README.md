```
    ___                                  ___                        __         
   /   |  ____  ____ ___________  ___   /   |  ____  ____ _____ ___/ /_  __  __
  / /| | / __ \/ __ `/ ___/ ___/ / _ \ / /| | / __ \/ __ `/ __ `/ __ / / / / /
 / ___ |/ / / / /_/ / /  / /__  /  __// ___ |/ / / / /_/ / /_/ / /_/ / /_/ /  
/_/  |_/_/ /_/\__,_/_/   \___/  \___//_/  |_/_/ /_/\__,_/\__, /\__,_/\__, /   
                                                        /____/      /____/    
```

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.9+-green" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
  <img src="https://img.shields.io/github/stars/vehoelite/image-anarchy?style=social" alt="Stars">
</p>

<h1 align="center">Ⓐ Image Anarchy</h1>
<h3 align="center">Android Image Swiss Army Knife</h3>

<p align="center">
  <i>Break free from restrictive tools. Extract, create, and manipulate Android images with anarchic freedom.</i>
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
| **Boot/Vendor Boot** | Extract kernel, ramdisk, DTB (v0-v4) |
| **Super (Dynamic)** | Extract all logical partitions |
| **vbmeta** | Parse, patch (disable verity/verification), re-sign |
| **ext4** | Extract filesystem contents |
| **FAT** | Extract filesystem contents |
| **ELF/Bootloader** | Analyze XBL, ABL, TZ, firmware |

### 🔨 Image Repacking
- **Boot images** (v0, v1, v2, v3, v4) - custom kernel/ramdisk
- **Vendor boot images** (v3, v4)
- **Sparse images** from raw (for faster flashing)
- **vbmeta images** with AVB disabled
- **Ramdisk** from directory (cpio + compression)

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

**Optional (for AVB signing):**
```bash
pip install cryptography
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
```

---

## 🚀 Usage

### GUI Mode (Default)

```bash
python image_anarchy.py
```

The GUI provides 4 tabs:
1. **📦 Extract** - Extract partitions from payload.bin
2. **🔧 Repack** - Create new payload.bin from images
3. **🔍 Image Extract** - Analyze and extract Android images
4. **🔨 Image Repack** - Create boot, sparse, vbmeta images

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

### Create Sparse Image for Flashing

```bash
# GUI: Image Repack tab
# 1. Select "Sparse Image (from raw)"
# 2. Browse for your raw system.img
# 3. Set output path
# 4. Create Image

# Results in smaller file that flashes faster via fastboot
```

---

## 🏗️ Project Structure

```
image-anarchy/
├── image_anarchy.py    # Main application (single file, batteries included)
├── requirements.txt    # Python dependencies
├── README.md          # This file
├── LICENSE            # MIT License
└── .gitignore         # Git ignore rules
```

The entire application is contained in a single Python file with embedded protobuf definitions - no external proto files needed!

---

## 🤝 Contributing

Contributions are welcome! Feel free to:

- 🐛 Report bugs
- 💡 Suggest features
- 🔧 Submit pull requests

---

## ⚠️ Disclaimer

This tool is provided for **educational and development purposes**. 

- Modifying device images may void your warranty
- Always backup your data before flashing modified images
- Disabling AVB/dm-verity reduces device security
- Use at your own risk

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
