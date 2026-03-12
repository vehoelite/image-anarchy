"""
Fastboot Toolkit Plugin for Image Anarchy

Comprehensive Fastboot tools including:
- Device Info (getvar all)
- Flash Partitions
- Boot Image (temporary)
- Boot Image Mods (ADB fix, prop editing, SELinux, fstab patching)
- Erase Partitions
- OEM Unlock/Lock
- Fetch Partitions
- Reboot Options
- Format Data
- Set Active Slot
"""

import os
import sys
import subprocess
import shutil
import struct
import gzip
import io
import re
import tempfile
import time
from typing import Optional, List, Dict, Tuple, BinaryIO
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QComboBox,
    QPushButton, QLineEdit, QTextEdit, QListWidget, QListWidgetItem,
    QProgressBar, QFileDialog, QMessageBox, QAbstractItemView, QTabWidget,
    QFormLayout, QCheckBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QRadioButton, QButtonGroup, QScrollArea, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer


# =============================================================================
# VBMETA PATCHER - Inline implementation for self-contained plugin
# =============================================================================

AVB_MAGIC = b'AVB0'

class VbmetaPatcher:
    """
    Patches vbmeta images to disable dm-verity and/or AVB verification.
    
    This allows booting with modified system/boot partitions.
    Note: Bootloader must be unlocked to use patched vbmeta.
    """
    
    FLAG_DISABLE_VERITY = 0x01        # AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED
    FLAG_DISABLE_VERIFICATION = 0x02  # AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED
    FLAGS_OFFSET = 120  # Offset of flags field in vbmeta header
    
    def __init__(self, input_path: str):
        self.input_path = Path(input_path)
    
    def get_info(self) -> dict:
        """Get vbmeta info including current flags."""
        try:
            with open(self.input_path, 'rb') as f:
                data = f.read(256)  # Just need header
            
            if data[:4] != AVB_MAGIC:
                return {'valid': False, 'error': 'Invalid vbmeta magic'}
            
            flags = struct.unpack('>I', data[self.FLAGS_OFFSET:self.FLAGS_OFFSET+4])[0]
            
            return {
                'valid': True,
                'size': self.input_path.stat().st_size,
                'flags': flags,
                'verity_disabled': bool(flags & self.FLAG_DISABLE_VERITY),
                'verification_disabled': bool(flags & self.FLAG_DISABLE_VERIFICATION),
            }
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def patch(self, output_path: str, disable_verity: bool = False, 
              disable_verification: bool = False) -> tuple[bool, str]:
        """
        Patch vbmeta flags.
        
        Returns:
            (success, message)
        """
        if not disable_verity and not disable_verification:
            return False, "No patches selected"
        
        try:
            with open(self.input_path, 'rb') as f:
                data = bytearray(f.read())
            
            if data[:4] != AVB_MAGIC:
                return False, "Invalid vbmeta magic - not a valid vbmeta image"
            
            # Read current flags
            current_flags = struct.unpack('>I', data[self.FLAGS_OFFSET:self.FLAGS_OFFSET+4])[0]
            
            # Apply new flags
            new_flags = current_flags
            if disable_verity:
                new_flags |= self.FLAG_DISABLE_VERITY
            if disable_verification:
                new_flags |= self.FLAG_DISABLE_VERIFICATION
            
            # Write new flags
            data[self.FLAGS_OFFSET:self.FLAGS_OFFSET+4] = struct.pack('>I', new_flags)
            
            # Save patched vbmeta
            with open(output_path, 'wb') as f:
                f.write(data)
            
            changes = []
            if disable_verity:
                changes.append("verity disabled")
            if disable_verification:
                changes.append("verification disabled")
            
            return True, f"Patched: {', '.join(changes)} (flags: 0x{current_flags:02X} → 0x{new_flags:02X})"
            
        except Exception as e:
            return False, f"Patch failed: {e}"


# =============================================================================
# BOOT IMAGE MODIFIER - Pure Python boot.img unpack/modify/repack
# =============================================================================

@dataclass
class CpioEntry:
    """A single entry in a CPIO newc archive."""
    name: str
    mode: int
    uid: int
    gid: int
    nlink: int
    mtime: int
    data: bytes
    dev_major: int = 0
    dev_minor: int = 0
    rdev_major: int = 0
    rdev_minor: int = 0

    @property
    def is_dir(self) -> bool:
        return (self.mode & 0o170000) == 0o040000

    @property
    def is_file(self) -> bool:
        return (self.mode & 0o170000) == 0o100000

    @property
    def is_symlink(self) -> bool:
        return (self.mode & 0o170000) == 0o120000


class CpioArchive:
    """Pure Python CPIO newc format parser and writer."""
    
    CPIO_NEWC_MAGIC = b'070701'
    CPIO_TRAILER = 'TRAILER!!!'
    
    def __init__(self):
        self.entries: List[CpioEntry] = []
    
    def parse(self, data: bytes):
        """Parse a CPIO newc archive from raw bytes."""
        self.entries = []
        offset = 0
        
        while offset < len(data):
            # Check magic
            magic = data[offset:offset + 6]
            if magic != self.CPIO_NEWC_MAGIC:
                break
            
            # Parse header (110 bytes total)
            # Format: magic(6) ino(8) mode(8) uid(8) gid(8) nlink(8) mtime(8)
            #         filesize(8) devmajor(8) devminor(8) rdevmajor(8) rdevminor(8)
            #         namesize(8) check(8)
            hdr = data[offset:offset + 110]
            if len(hdr) < 110:
                break
            
            ino = int(hdr[6:14], 16)
            mode = int(hdr[14:22], 16)
            uid = int(hdr[22:30], 16)
            gid = int(hdr[30:38], 16)
            nlink = int(hdr[38:46], 16)
            mtime = int(hdr[46:54], 16)
            filesize = int(hdr[54:62], 16)
            dev_major = int(hdr[62:70], 16)
            dev_minor = int(hdr[70:78], 16)
            rdev_major = int(hdr[78:86], 16)
            rdev_minor = int(hdr[86:94], 16)
            namesize = int(hdr[94:102], 16)
            # check = int(hdr[102:110], 16)
            
            # Name starts at offset + 110, padded to 4-byte boundary
            name_start = offset + 110
            name_end = name_start + namesize
            name = data[name_start:name_end].rstrip(b'\x00').decode('utf-8', errors='replace')
            
            # Data starts after name, padded to 4-byte boundary
            data_start = (name_end + 3) & ~3
            data_end = data_start + filesize
            file_data = data[data_start:data_end]
            
            # Next entry starts after data, padded to 4-byte boundary
            offset = (data_end + 3) & ~3
            
            if name == self.CPIO_TRAILER:
                break
            
            self.entries.append(CpioEntry(
                name=name,
                mode=mode,
                uid=uid,
                gid=gid,
                nlink=nlink,
                mtime=mtime,
                data=file_data,
                dev_major=dev_major,
                dev_minor=dev_minor,
                rdev_major=rdev_major,
                rdev_minor=rdev_minor,
            ))
    
    def serialize(self) -> bytes:
        """Serialize back to CPIO newc format."""
        buf = io.BytesIO()
        ino_counter = 300000  # Start at a safe inode number
        
        for entry in self.entries:
            ino_counter += 1
            name_bytes = entry.name.encode('utf-8') + b'\x00'
            namesize = len(name_bytes)
            filesize = len(entry.data)
            
            # Write header
            hdr = (
                f"070701"
                f"{ino_counter:08X}"
                f"{entry.mode:08X}"
                f"{entry.uid:08X}"
                f"{entry.gid:08X}"
                f"{entry.nlink:08X}"
                f"{entry.mtime:08X}"
                f"{filesize:08X}"
                f"{entry.dev_major:08X}"
                f"{entry.dev_minor:08X}"
                f"{entry.rdev_major:08X}"
                f"{entry.rdev_minor:08X}"
                f"{namesize:08X}"
                f"00000000"
            ).encode('ascii')
            
            buf.write(hdr)
            buf.write(name_bytes)
            
            # Pad name to 4-byte boundary
            name_total = 110 + namesize
            pad = (4 - (name_total % 4)) % 4
            buf.write(b'\x00' * pad)
            
            # Write data
            buf.write(entry.data)
            
            # Pad data to 4-byte boundary
            data_pad = (4 - (filesize % 4)) % 4
            buf.write(b'\x00' * data_pad)
        
        # Write trailer
        trailer_name = self.CPIO_TRAILER.encode('utf-8') + b'\x00'
        ino_counter += 1
        trailer_hdr = (
            f"070701"
            f"{ino_counter:08X}"
            f"00000000"
            f"00000000"
            f"00000000"
            f"00000001"
            f"00000000"
            f"00000000"
            f"00000000"
            f"00000000"
            f"00000000"
            f"00000000"
            f"{len(trailer_name):08X}"
            f"00000000"
        ).encode('ascii')
        
        buf.write(trailer_hdr)
        buf.write(trailer_name)
        
        # Pad trailer to 4-byte boundary
        total = 110 + len(trailer_name)
        pad = (4 - (total % 4)) % 4
        buf.write(b'\x00' * pad)
        
        # Pad entire archive to 256-byte boundary (required by some bootloaders)
        result = buf.getvalue()
        final_pad = (256 - (len(result) % 256)) % 256
        result += b'\x00' * final_pad
        
        return result
    
    def find_entry(self, name: str) -> Optional[CpioEntry]:
        """Find an entry by name (with or without leading ./)."""
        for entry in self.entries:
            entry_clean = entry.name.lstrip('./')
            name_clean = name.lstrip('./')
            if entry_clean == name_clean:
                return entry
        return None
    
    def get_prop_files(self) -> List[CpioEntry]:
        """Find all property files in the ramdisk."""
        prop_names = [
            'default.prop', 'prop.default', 'build.prop',
            'system/build.prop', 'vendor/build.prop',
            'system/etc/prop.default',
        ]
        found = []
        for entry in self.entries:
            name_clean = entry.name.lstrip('./')
            if name_clean in prop_names or name_clean.endswith('.prop') or name_clean.endswith('prop.default'):
                found.append(entry)
        return found
    
    def get_fstab_files(self) -> List[CpioEntry]:
        """Find all fstab files in the ramdisk."""
        found = []
        for entry in self.entries:
            name_clean = entry.name.lstrip('./')
            basename = os.path.basename(name_clean)
            if basename.startswith('fstab.') or basename == 'fstab':
                found.append(entry)
        return found
    
    def add_or_replace_entry(self, name: str, data: bytes, mode: int = 0o100644, 
                              uid: int = 0, gid: int = 0):
        """Add a new entry or replace an existing one."""
        existing = self.find_entry(name)
        if existing:
            existing.data = data
        else:
            self.entries.append(CpioEntry(
                name=name,
                mode=mode,
                uid=uid,
                gid=gid,
                nlink=1,
                mtime=int(time.time()),
                data=data,
            ))


class BootImageModifier:
    """
    Pure Python boot.img unpacker/modifier/repacker.
    
    Supports Android boot image header v0-v2 (v3/v4 have a different structure
    where ramdisk props live in vendor_boot, but we handle them gracefully).
    
    Common modifications:
    - Enable ADB without authorization (ro.adb.secure=0, ro.debuggable=1)
    - Set SELinux permissive via cmdline
    - Patch fstab to remove dm-verity
    - Inject ADB public keys into ramdisk
    - Set USB config to enable ADB by default
    """
    
    BOOT_MAGIC = b'ANDROID!'
    VENDOR_BOOT_MAGIC = b'VNDRBOOT'
    
    def __init__(self, boot_img_path: str):
        self.path = boot_img_path
        self.header_version = 0
        self.page_size = 4096
        self.kernel_data = b''
        self.ramdisk_data = b''
        self.second_data = b''
        self.dtb_data = b''
        self.recovery_dtbo_data = b''
        self.cmdline = ''
        self.extra_cmdline = ''
        self.kernel_addr = 0x00008000
        self.ramdisk_addr = 0x01000000
        self.second_addr = 0x00F00000
        self.tags_addr = 0x00000100
        self.os_version_raw = 0
        self.product_name = b''
        self.sha_hash = b''
        self.ramdisk_compression = 'gzip'  # gzip, lz4, zstd, lzma, or none
        self.cpio = CpioArchive()
        self._parsed = False
        # Vendor boot specific
        self.is_vendor_boot = False
        self.vendor_name = b''
        self.vendor_header_size = 0
        self.dtb_addr = 0
        self.vendor_ramdisk_table_size = 0
        self.vendor_ramdisk_table_entry_num = 0
        self.vendor_ramdisk_table_entry_size = 0
        self.vendor_ramdisk_table_data = b''
        self.bootconfig_data = b''
        self.bootconfig_size = 0
    
    def parse(self) -> dict:
        """Parse boot image and extract all components."""
        with open(self.path, 'rb') as f:
            magic = f.read(8)
            
            if magic == self.VENDOR_BOOT_MAGIC:
                return self._parse_vendor_boot(f)
            
            if magic != self.BOOT_MAGIC:
                raise ValueError(
                    f"Not a valid boot/vendor_boot image (magic: {magic!r}).\n"
                    f"Expected ANDROID! or VNDRBOOT header."
                )
            
            f.seek(40)
            self.header_version = struct.unpack('<I', f.read(4))[0]
            if self.header_version > 10:
                self.header_version = 0
            
            f.seek(8)
            
            if self.header_version >= 3:
                return self._parse_v3_v4(f)
            else:
                return self._parse_v0_v2(f)
    
    def _parse_v0_v2(self, f: BinaryIO) -> dict:
        """Parse v0/v1/v2 boot image."""
        kernel_size = struct.unpack('<I', f.read(4))[0]
        self.kernel_addr = struct.unpack('<I', f.read(4))[0]
        ramdisk_size = struct.unpack('<I', f.read(4))[0]
        self.ramdisk_addr = struct.unpack('<I', f.read(4))[0]
        second_size = struct.unpack('<I', f.read(4))[0]
        self.second_addr = struct.unpack('<I', f.read(4))[0]
        self.tags_addr = struct.unpack('<I', f.read(4))[0]
        self.page_size = struct.unpack('<I', f.read(4))[0]
        
        if self.page_size == 0 or self.page_size > 65536:
            self.page_size = 4096
        
        f.read(4)  # header_version (already read)
        self.os_version_raw = struct.unpack('<I', f.read(4))[0]
        self.product_name = f.read(16)
        self.cmdline = f.read(512).rstrip(b'\x00').decode('utf-8', errors='ignore')
        self.sha_hash = f.read(32)
        self.extra_cmdline = f.read(1024).rstrip(b'\x00').decode('utf-8', errors='ignore')
        
        # Recovery DTBO for v1/v2
        recovery_dtbo_size = 0
        if self.header_version >= 1:
            recovery_dtbo_size = struct.unpack('<I', f.read(4))[0]
            f.read(8)  # recovery_dtbo_offset (64-bit)
            f.read(4)  # header_size
        
        dtb_size = 0
        if self.header_version >= 2:
            dtb_size = struct.unpack('<I', f.read(4))[0]
            f.read(8)  # dtb_addr (64-bit)
        
        def align(size):
            return ((size + self.page_size - 1) // self.page_size) * self.page_size
        
        # Extract components
        offset = self.page_size
        
        f.seek(offset)
        self.kernel_data = f.read(kernel_size)
        offset += align(kernel_size)
        
        f.seek(offset)
        self.ramdisk_data = f.read(ramdisk_size)
        offset += align(ramdisk_size)
        
        if second_size > 0:
            f.seek(offset)
            self.second_data = f.read(second_size)
            offset += align(second_size)
        
        if self.header_version >= 1 and recovery_dtbo_size > 0:
            f.seek(offset)
            self.recovery_dtbo_data = f.read(recovery_dtbo_size)
            offset += align(recovery_dtbo_size)
        
        if self.header_version >= 2 and dtb_size > 0:
            f.seek(offset)
            self.dtb_data = f.read(dtb_size)
        
        # Decompress and parse ramdisk
        if ramdisk_size > 0:
            self._parse_ramdisk()
        
        self._parsed = True
        
        return {
            'header_version': self.header_version,
            'page_size': self.page_size,
            'kernel_size': kernel_size,
            'ramdisk_size': ramdisk_size,
            'second_size': second_size,
            'dtb_size': dtb_size,
            'cmdline': self.cmdline,
            'ramdisk_compression': self.ramdisk_compression,
            'ramdisk_entries': len(self.cpio.entries),
        }
    
    def _parse_v3_v4(self, f: BinaryIO) -> dict:
        """Parse v3/v4 boot image."""
        kernel_size = struct.unpack('<I', f.read(4))[0]
        ramdisk_size = struct.unpack('<I', f.read(4))[0]
        self.os_version_raw = struct.unpack('<I', f.read(4))[0]
        header_size = struct.unpack('<I', f.read(4))[0]
        f.read(16)  # reserved
        f.read(4)   # header_version again
        self.cmdline = f.read(1536).rstrip(b'\x00').decode('utf-8', errors='ignore')
        
        self.page_size = 4096
        
        def align(size):
            return ((size + 4095) // 4096) * 4096
        
        f.seek(4096)
        self.kernel_data = f.read(kernel_size)
        
        f.seek(4096 + align(kernel_size))
        self.ramdisk_data = f.read(ramdisk_size)
        
        if ramdisk_size > 0:
            self._parse_ramdisk()
        
        self._parsed = True
        
        return {
            'header_version': self.header_version,
            'page_size': self.page_size,
            'kernel_size': kernel_size,
            'ramdisk_size': ramdisk_size,
            'second_size': 0,
            'dtb_size': 0,
            'cmdline': self.cmdline,
            'ramdisk_compression': self.ramdisk_compression,
            'ramdisk_entries': len(self.cpio.entries),
        }
    
    @staticmethod
    def _decompress_lz4_legacy(data: bytes) -> bytes:
        """Decompress LZ4 legacy format (magic: 02 21 4c 18).
        
        Android commonly uses this format for ramdisks.
        Format: 4-byte magic, then sequence of [4-byte compressed_size, compressed_block].
        Each block decompresses to up to 8MB (default block size).
        """
        try:
            import lz4.block
        except ImportError:
            raise ValueError(
                "Ramdisk is LZ4 legacy compressed. Install lz4: pip install lz4\n"
                "Or use: pip install image-anarchy[all]"
            )
        
        LEGACY_MAGIC = b'\x02\x21\x4c\x18'
        if data[:4] != LEGACY_MAGIC:
            raise ValueError("Not LZ4 legacy format")
        
        output = bytearray()
        pos = 4  # Skip magic
        
        while pos < len(data):
            if pos + 4 > len(data):
                break
            block_size = struct.unpack('<I', data[pos:pos + 4])[0]
            pos += 4
            
            if block_size == 0:
                break
            if pos + block_size > len(data):
                break
            
            block_data = data[pos:pos + block_size]
            pos += block_size
            
            try:
                decompressed_block = lz4.block.decompress(
                    block_data, uncompressed_size=8 * 1024 * 1024  # 8MB max per block
                )
                output.extend(decompressed_block)
            except Exception:
                # Try with larger output buffer
                decompressed_block = lz4.block.decompress(
                    block_data, uncompressed_size=16 * 1024 * 1024
                )
                output.extend(decompressed_block)
        
        return bytes(output)
    
    @staticmethod
    def _compress_lz4_legacy(data: bytes) -> bytes:
        """Compress data in LZ4 legacy format (magic: 02 21 4c 18).
        
        Matches the format Android expects for boot ramdisks.
        """
        try:
            import lz4.block
        except ImportError:
            raise ValueError("lz4 not installed: pip install lz4")
        
        LEGACY_MAGIC = b'\x02\x21\x4c\x18'
        BLOCK_SIZE = 8 * 1024 * 1024  # 8MB blocks
        
        output = bytearray(LEGACY_MAGIC)
        pos = 0
        
        while pos < len(data):
            chunk = data[pos:pos + BLOCK_SIZE]
            pos += len(chunk)
            
            compressed = lz4.block.compress(chunk, store_size=False)
            output.extend(struct.pack('<I', len(compressed)))
            output.extend(compressed)
        
        # End marker
        output.extend(struct.pack('<I', 0))
        
        return bytes(output)
    
    def _parse_ramdisk(self):
        """Decompress ramdisk and parse CPIO."""
        rd = self.ramdisk_data
        
        if rd[:2] == b'\x1f\x8b':
            self.ramdisk_compression = 'gzip'
            decompressed = gzip.decompress(rd)
        elif rd[:4] == b'\x02\x21\x4c\x18':
            # LZ4 legacy format — very common on Android!
            self.ramdisk_compression = 'lz4_legacy'
            decompressed = self._decompress_lz4_legacy(rd)
        elif rd[:4] == b'\x04\x22\x4d\x18':
            # LZ4 frame format
            self.ramdisk_compression = 'lz4'
            try:
                import lz4.frame
                decompressed = lz4.frame.decompress(rd)
            except ImportError:
                raise ValueError(
                    "Ramdisk is LZ4 compressed. Install lz4: pip install lz4\n"
                    "Or use: pip install image-anarchy[all]"
                )
        elif rd[:4] == b'\x28\xb5\x2f\xfd':
            self.ramdisk_compression = 'zstd'
            try:
                import zstandard as zstd
                decompressor = zstd.ZstdDecompressor()
                decompressed = decompressor.decompress(rd, max_output_size=256 * 1024 * 1024)
            except ImportError:
                raise ValueError(
                    "Ramdisk is ZSTD compressed. Install zstandard: pip install zstandard\n"
                    "Or use: pip install image-anarchy[all]"
                )
        elif rd[:6] == b'070701' or rd[:6] == b'070702':
            self.ramdisk_compression = 'none'
            decompressed = rd
        else:
            # Try gzip anyway (some have non-standard headers)
            try:
                decompressed = gzip.decompress(rd)
                self.ramdisk_compression = 'gzip'
            except:
                raise ValueError(
                    f"Unknown ramdisk compression format: {rd[:8].hex()}\n"
                    f"Header bytes: {rd[:16].hex()}"
                )
        
        self.cpio.parse(decompressed)
    
    def _compress_ramdisk(self, cpio_data: bytes) -> bytes:
        """Recompress ramdisk data using the original compression."""
        if self.ramdisk_compression == 'gzip':
            return gzip.compress(cpio_data, compresslevel=9)
        elif self.ramdisk_compression == 'lz4_legacy':
            return self._compress_lz4_legacy(cpio_data)
        elif self.ramdisk_compression == 'lz4':
            try:
                import lz4.frame
                return lz4.frame.compress(cpio_data)
            except ImportError:
                raise ValueError("lz4 not installed: pip install lz4")
        elif self.ramdisk_compression == 'zstd':
            try:
                import zstandard as zstd
                compressor = zstd.ZstdCompressor(level=19)
                return compressor.compress(cpio_data)
            except ImportError:
                raise ValueError("zstandard not installed: pip install zstandard")
        elif self.ramdisk_compression == 'none':
            return cpio_data
        else:
            return gzip.compress(cpio_data, compresslevel=9)
    
    def modify_props(self, modifications: Dict[str, str]) -> List[str]:
        """
        Modify properties in ramdisk prop files.
        
        Args:
            modifications: dict of {property_name: new_value}
            
        Returns:
            List of changes made
        """
        if not self._parsed:
            raise ValueError("Must call parse() first")
        
        changes = []
        prop_files = self.cpio.get_prop_files()
        
        if not prop_files:
            # No prop files found — create default.prop
            prop_files = [CpioEntry(
                name='default.prop',
                mode=0o100644,
                uid=0, gid=0, nlink=1, mtime=int(time.time()),
                data=b'# Created by Image Anarchy Boot Mods\n',
            )]
            self.cpio.entries.insert(0, prop_files[0])
            changes.append("Created default.prop (none existed)")
        
        for prop_entry in prop_files:
            content = prop_entry.data.decode('utf-8', errors='replace')
            modified = False
            
            for key, value in modifications.items():
                # Check if property already exists
                pattern = re.compile(rf'^(\s*){re.escape(key)}\s*=\s*(.*)$', re.MULTILINE)
                match = pattern.search(content)
                
                if match:
                    old_val = match.group(2).strip()
                    if old_val != value:
                        content = pattern.sub(rf'\g<1>{key}={value}', content)
                        changes.append(f"{prop_entry.name}: {key}={old_val} → {value}")
                        modified = True
                    else:
                        changes.append(f"{prop_entry.name}: {key}={value} (already set)")
                else:
                    # Add at the end
                    if not content.endswith('\n'):
                        content += '\n'
                    content += f"{key}={value}\n"
                    changes.append(f"{prop_entry.name}: added {key}={value}")
                    modified = True
            
            if modified:
                prop_entry.data = content.encode('utf-8')
        
        return changes
    
    def modify_cmdline(self, additions: List[str] = None, removals: List[str] = None) -> List[str]:
        """Modify the kernel command line."""
        if not self._parsed:
            raise ValueError("Must call parse() first")
        
        changes = []
        
        if removals:
            for removal in removals:
                if removal in self.cmdline:
                    self.cmdline = self.cmdline.replace(removal, '').strip()
                    changes.append(f"Removed from cmdline: {removal}")
        
        if additions:
            for addition in additions:
                if addition not in self.cmdline:
                    self.cmdline = (self.cmdline + ' ' + addition).strip()
                    changes.append(f"Added to cmdline: {addition}")
                else:
                    changes.append(f"Already in cmdline: {addition}")
        
        return changes
    
    def patch_fstab_verity(self) -> List[str]:
        """Remove dm-verity and verification from fstab files in ramdisk."""
        if not self._parsed:
            raise ValueError("Must call parse() first")
        
        changes = []
        fstab_files = self.cpio.get_fstab_files()
        
        for entry in fstab_files:
            content = entry.data.decode('utf-8', errors='replace')
            original = content
            
            # Remove verify flag
            content = re.sub(r',verify\b', '', content)
            content = re.sub(r'\bverify,', '', content)
            content = re.sub(r'\bverify\b', '', content)
            
            # Remove avb flags  
            content = re.sub(r',avb=.*?(?=,|\s|$)', '', content)
            content = re.sub(r',avb\b', '', content)
            content = re.sub(r'\bavb,', '', content)
            content = re.sub(r'\bavb\b', '', content)
            
            # Remove support_scfs
            content = re.sub(r',support_scfs\b', '', content)
            
            if content != original:
                entry.data = content.encode('utf-8')
                changes.append(f"Patched {entry.name}: removed verity/avb flags")
            else:
                changes.append(f"{entry.name}: no verity/avb flags found")
        
        if not fstab_files:
            changes.append("No fstab files found in ramdisk")
        
        return changes
    
    def inject_init_rc_props(self, props: Dict[str, str]) -> List[str]:
        """Inject setprop commands into init.rc for reliable property override.
        
        This is the nuclear option for Android 13+ GKI devices where:
        - Bootloader sets androidboot.adb.secure=1 in kernel cmdline
        - ro.boot.adb.secure=1 takes priority over prop file values
        - init_boot cmdline is ignored by bootloader (only boot.img cmdline used)
        
        By adding setprop commands to an early init trigger, we can override
        properties after the cmdline is processed but before adbd starts.
        """
        if not self._parsed:
            raise ValueError("Must call parse() first")
        
        changes = []
        
        # Build the setprop block
        prop_lines = []
        for key, value in props.items():
            prop_lines.append(f"    setprop {key} {value}")
        
        inject_block = (
            "\n# Image Anarchy Boot Mods - property overrides\n"
            "on early-init\n"
            + "\n".join(prop_lines) + "\n"
            "\n# Image Anarchy Boot Mods - post-fs override\n"
            "on post-fs\n"
            + "\n".join(prop_lines) + "\n"
            "\n# Image Anarchy Boot Mods - enable ADB & skip setup wizard after boot\n"
            "on property:sys.boot_completed=1\n"
            "    exec -- /system/bin/settings put global adb_enabled 1\n"
            "    exec -- /system/bin/settings put global development_settings_enabled 1\n"
            "    exec -- /system/bin/settings put global setup_wizard_has_run 1\n"
            "    exec -- /system/bin/settings put secure user_setup_complete 1\n"
            "    exec -- /system/bin/settings put global device_provisioned 1\n"
            "    exec -- /system/bin/settings put global adb_allowed_connection_time 0\n"
        )
        
        # Find init.rc in the ramdisk
        init_rc = self.cpio.find_entry('init.rc')
        if init_rc:
            content = init_rc.data.decode('utf-8', errors='replace')
            # Check if we already injected
            if 'Image Anarchy Boot Mods' not in content:
                # Insert at the very beginning so our on early-init runs first
                init_rc.data = (inject_block + "\n" + content).encode('utf-8')
                changes.append(f"init.rc: injected {len(props)} setprop overrides (early-init + post-fs)")
            else:
                changes.append("init.rc: Image Anarchy overrides already present")
        else:
            # No init.rc — create a supplementary init script
            # Android init reads all .rc files in the ramdisk root
            self.cpio.entries.append(CpioEntry(
                name='init.anarchy.rc',
                mode=0o100644,
                uid=0, gid=0, nlink=1, mtime=int(time.time()),
                data=inject_block.encode('utf-8'),
            ))
            changes.append(f"Created init.anarchy.rc with {len(props)} setprop overrides")
        
        return changes
    
    def inject_adb_key(self, pubkey_path: str) -> List[str]:
        """Inject an ADB public key into the ramdisk.
        
        Places key in multiple locations for maximum compatibility:
        - /adb_keys (ramdisk root — some ROMs check here)
        - /data/misc/adb/adb_keys (standard Android path)
        Also injects an init.rc command to copy the key at boot time.
        """
        if not self._parsed:
            raise ValueError("Must call parse() first")
        
        changes = []
        
        if not os.path.isfile(pubkey_path):
            raise ValueError(f"ADB public key not found: {pubkey_path}")
        
        with open(pubkey_path, 'r') as f:
            key_data = f.read().strip() + '\n'
        
        # === Location 1: /adb_keys at ramdisk root ===
        root_keys = self.cpio.find_entry('adb_keys')
        if root_keys:
            existing = root_keys.data.decode('utf-8', errors='replace')
            if key_data.strip() not in existing:
                root_keys.data = (existing.rstrip('\n') + '\n' + key_data).encode('utf-8')
                root_keys.mtime = int(time.time())
                changes.append("Appended ADB key to /adb_keys")
            else:
                changes.append("/adb_keys: key already present")
        else:
            self.cpio.entries.append(CpioEntry(
                name='adb_keys',
                mode=0o100644,
                uid=0, gid=2000,  # shell group
                nlink=1, mtime=int(time.time()),
                data=key_data.encode('utf-8'),
            ))
            changes.append("Created /adb_keys in ramdisk root")
        
        # === Location 2: /data/misc/adb/adb_keys (classic path) ===
        data_keys = self.cpio.find_entry('data/misc/adb/adb_keys')
        if data_keys:
            existing = data_keys.data.decode('utf-8', errors='replace')
            if key_data.strip() not in existing:
                data_keys.data = (existing.rstrip('\n') + '\n' + key_data).encode('utf-8')
                changes.append("Appended ADB key to data/misc/adb/adb_keys")
            else:
                changes.append("data/misc/adb/adb_keys: key already present")
        else:
            now = int(time.time())
            for dir_path in ['data', 'data/misc', 'data/misc/adb']:
                if not self.cpio.find_entry(dir_path):
                    self.cpio.entries.append(CpioEntry(
                        name=dir_path,
                        mode=0o040750,
                        uid=0, gid=1007 if 'adb' in dir_path else 0,
                        nlink=2, mtime=now, data=b'',
                    ))
            self.cpio.entries.append(CpioEntry(
                name='data/misc/adb/adb_keys',
                mode=0o100640,
                uid=1000, gid=1007,
                nlink=1, mtime=now,
                data=key_data.encode('utf-8'),
            ))
            changes.append("Created data/misc/adb/adb_keys")
        
        # === Location 3: init.rc commands for key + ADB + setup wizard ===
        # - Copy key to /data so it persists after /data mounts over ramdisk
        # - Enable ADB in settings database (required after factory reset)
        # - Skip setup wizard (critical for broken screen)
        key_install_block = (
            "\n# Image Anarchy - ADB key installer & post-reset setup\n"
            "on post-fs-data\n"
            "    mkdir /data/misc/adb 0750 system shell\n"
            "    copy /adb_keys /data/misc/adb/adb_keys\n"
            "    chmod 0640 /data/misc/adb/adb_keys\n"
            "    chown system shell /data/misc/adb/adb_keys\n"
            "    restorecon /data/misc/adb/adb_keys\n"
            "\n# Image Anarchy - Enable ADB & skip setup wizard after boot\n"
            "on property:sys.boot_completed=1\n"
            "    exec -- /system/bin/settings put global adb_enabled 1\n"
            "    exec -- /system/bin/settings put global development_settings_enabled 1\n"
            "    exec -- /system/bin/settings put global setup_wizard_has_run 1\n"
            "    exec -- /system/bin/settings put secure user_setup_complete 1\n"
            "    exec -- /system/bin/settings put global device_provisioned 1\n"
            "    exec -- /system/bin/settings put global adb_allowed_connection_time 0\n"
            "    setprop persist.sys.usb.config mtp,adb\n"
            "    setprop sys.usb.config mtp,adb\n"
        )
        
        init_rc = self.cpio.find_entry('init.rc')
        if init_rc:
            content = init_rc.data.decode('utf-8', errors='replace')
            if 'ADB key installer' not in content:
                init_rc.data = (content + key_install_block).encode('utf-8')
                changes.append("init.rc: added post-fs-data ADB key copy command")
        else:
            # Append to our supplementary rc file or create new
            anarchy_rc = self.cpio.find_entry('init.anarchy.rc')
            if anarchy_rc:
                existing = anarchy_rc.data.decode('utf-8', errors='replace')
                if 'ADB key installer' not in existing:
                    anarchy_rc.data = (existing + key_install_block).encode('utf-8')
                    changes.append("init.anarchy.rc: added post-fs-data ADB key copy command")
            else:
                self.cpio.entries.append(CpioEntry(
                    name='init.anarchy.rc',
                    mode=0o100644,
                    uid=0, gid=0, nlink=1, mtime=int(time.time()),
                    data=key_install_block.encode('utf-8'),
                ))
                changes.append("Created init.anarchy.rc with ADB key copy command")
        
        return changes
    
    def get_current_props(self) -> Dict[str, str]:
        """Get all current properties from ramdisk prop files."""
        props = {}
        for entry in self.cpio.get_prop_files():
            content = entry.data.decode('utf-8', errors='replace')
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, _, value = line.partition('=')
                    props[key.strip()] = value.strip()
        return props
    
    def list_ramdisk_files(self) -> List[str]:
        """List all files in the ramdisk."""
        return [e.name for e in self.cpio.entries]
    
    def save(self, output_path: str) -> str:
        """Repack and save modified boot image."""
        if not self._parsed:
            raise ValueError("Must call parse() first")
        
        # Recompress ramdisk
        cpio_data = self.cpio.serialize()
        new_ramdisk = self._compress_ramdisk(cpio_data)
        
        if self.is_vendor_boot:
            return self._save_vendor_boot(output_path, new_ramdisk)
        elif self.header_version >= 3:
            return self._save_v3_v4(output_path, new_ramdisk)
        else:
            return self._save_v0_v2(output_path, new_ramdisk)
    
    def _save_v0_v2(self, output_path: str, new_ramdisk: bytes) -> str:
        """Repack v0/v1/v2 boot image."""
        ps = self.page_size
        
        def align(size):
            return ((size + ps - 1) // ps) * ps
        
        with open(output_path, 'wb') as f:
            # Write header
            header = bytearray(ps)
            
            # Magic
            header[0:8] = self.BOOT_MAGIC
            # kernel_size
            struct.pack_into('<I', header, 8, len(self.kernel_data))
            # kernel_addr
            struct.pack_into('<I', header, 12, self.kernel_addr)
            # ramdisk_size
            struct.pack_into('<I', header, 16, len(new_ramdisk))
            # ramdisk_addr
            struct.pack_into('<I', header, 20, self.ramdisk_addr)
            # second_size
            struct.pack_into('<I', header, 24, len(self.second_data))
            # second_addr
            struct.pack_into('<I', header, 28, self.second_addr)
            # tags_addr
            struct.pack_into('<I', header, 32, self.tags_addr)
            # page_size
            struct.pack_into('<I', header, 36, ps)
            # header_version
            struct.pack_into('<I', header, 40, self.header_version)
            # os_version
            struct.pack_into('<I', header, 44, self.os_version_raw)
            # product_name
            header[48:48 + len(self.product_name)] = self.product_name[:16]
            # cmdline (512 bytes)
            cmdline_bytes = self.cmdline.encode('utf-8')[:512]
            header[64:64 + len(cmdline_bytes)] = cmdline_bytes
            # sha (32 bytes at offset 576)
            header[576:576 + len(self.sha_hash)] = self.sha_hash[:32]
            # extra_cmdline (1024 bytes at offset 608)
            extra_bytes = self.extra_cmdline.encode('utf-8')[:1024]
            header[608:608 + len(extra_bytes)] = extra_bytes
            
            # v1 fields
            if self.header_version >= 1:
                struct.pack_into('<I', header, 1632, len(self.recovery_dtbo_data))
                # recovery_dtbo_offset (64-bit) - calculated later
                # header_size
                if self.header_version == 1:
                    struct.pack_into('<I', header, 1648, 1648)
                elif self.header_version == 2:
                    struct.pack_into('<I', header, 1648, 1660)
            
            if self.header_version >= 2:
                struct.pack_into('<I', header, 1652, len(self.dtb_data))
                # dtb_addr (64-bit)
            
            f.write(header)
            
            # Kernel (page-aligned)
            f.write(self.kernel_data)
            f.write(b'\x00' * (align(len(self.kernel_data)) - len(self.kernel_data)))
            
            # Ramdisk (page-aligned)
            f.write(new_ramdisk)
            f.write(b'\x00' * (align(len(new_ramdisk)) - len(new_ramdisk)))
            
            # Second (page-aligned)
            if len(self.second_data) > 0:
                f.write(self.second_data)
                f.write(b'\x00' * (align(len(self.second_data)) - len(self.second_data)))
            
            # Recovery DTBO
            if self.header_version >= 1 and len(self.recovery_dtbo_data) > 0:
                f.write(self.recovery_dtbo_data)
                f.write(b'\x00' * (align(len(self.recovery_dtbo_data)) - len(self.recovery_dtbo_data)))
            
            # DTB
            if self.header_version >= 2 and len(self.dtb_data) > 0:
                f.write(self.dtb_data)
                f.write(b'\x00' * (align(len(self.dtb_data)) - len(self.dtb_data)))
        
        return output_path
    
    def _save_v3_v4(self, output_path: str, new_ramdisk: bytes) -> str:
        """Repack v3/v4 boot image."""
        def align(size):
            return ((size + 4095) // 4096) * 4096
        
        with open(output_path, 'wb') as f:
            # v3/v4 header (4096 bytes)
            header = bytearray(4096)
            
            header[0:8] = self.BOOT_MAGIC
            struct.pack_into('<I', header, 8, len(self.kernel_data))
            struct.pack_into('<I', header, 12, len(new_ramdisk))
            struct.pack_into('<I', header, 16, self.os_version_raw)
            struct.pack_into('<I', header, 20, 4096)  # header_size
            # reserved (16 bytes at 24)
            struct.pack_into('<I', header, 40, self.header_version)
            cmdline_bytes = self.cmdline.encode('utf-8')[:1536]
            header[44:44 + len(cmdline_bytes)] = cmdline_bytes
            
            f.write(header)
            
            # Kernel
            f.write(self.kernel_data)
            f.write(b'\x00' * (align(len(self.kernel_data)) - len(self.kernel_data)))
            
            # Ramdisk
            f.write(new_ramdisk)
            f.write(b'\x00' * (align(len(new_ramdisk)) - len(new_ramdisk)))
        
        return output_path
    
    def _parse_vendor_boot(self, f: BinaryIO) -> dict:
        """Parse vendor_boot image (v3/v4) with VNDRBOOT magic."""
        self.is_vendor_boot = True
        
        # After 8-byte magic already consumed
        self.header_version = struct.unpack('<I', f.read(4))[0]
        self.page_size = struct.unpack('<I', f.read(4))[0]
        self.kernel_addr = struct.unpack('<I', f.read(4))[0]
        self.ramdisk_addr = struct.unpack('<I', f.read(4))[0]
        vendor_ramdisk_size = struct.unpack('<I', f.read(4))[0]
        self.cmdline = f.read(2048).rstrip(b'\x00').decode('utf-8', errors='ignore')
        self.tags_addr = struct.unpack('<I', f.read(4))[0]
        self.vendor_name = f.read(16).rstrip(b'\x00')
        self.vendor_header_size = struct.unpack('<I', f.read(4))[0]
        dtb_size = struct.unpack('<I', f.read(4))[0]
        self.dtb_addr = struct.unpack('<Q', f.read(8))[0]
        
        # V4 extra fields
        if self.header_version >= 4:
            self.vendor_ramdisk_table_size = struct.unpack('<I', f.read(4))[0]
            self.vendor_ramdisk_table_entry_num = struct.unpack('<I', f.read(4))[0]
            self.vendor_ramdisk_table_entry_size = struct.unpack('<I', f.read(4))[0]
            self.bootconfig_size = struct.unpack('<I', f.read(4))[0]
        
        ps = self.page_size
        def align(size):
            return ((size + ps - 1) // ps) * ps
        
        # Vendor ramdisk starts at page-aligned offset after header
        header_start = align(self.vendor_header_size) if self.vendor_header_size else ps
        f.seek(header_start)
        self.ramdisk_data = f.read(vendor_ramdisk_size)
        
        # DTB follows ramdisk
        dtb_offset = header_start + align(vendor_ramdisk_size)
        f.seek(dtb_offset)
        if dtb_size > 0:
            self.dtb_data = f.read(dtb_size)
        
        # V4: vendor ramdisk table and bootconfig
        if self.header_version >= 4:
            vrt_offset = dtb_offset + align(dtb_size)
            f.seek(vrt_offset)
            if self.vendor_ramdisk_table_size > 0:
                self.vendor_ramdisk_table_data = f.read(self.vendor_ramdisk_table_size)
            
            bc_offset = vrt_offset + align(self.vendor_ramdisk_table_size)
            f.seek(bc_offset)
            if self.bootconfig_size > 0:
                self.bootconfig_data = f.read(self.bootconfig_size)
        
        # Parse ramdisk CPIO
        if vendor_ramdisk_size > 0:
            self._parse_ramdisk()
        
        self._parsed = True
        
        return {
            'header_version': self.header_version,
            'page_size': self.page_size,
            'kernel_size': 0,
            'ramdisk_size': vendor_ramdisk_size,
            'second_size': 0,
            'dtb_size': dtb_size,
            'cmdline': self.cmdline,
            'ramdisk_compression': self.ramdisk_compression,
            'ramdisk_entries': len(self.cpio.entries),
            'vendor_boot': True,
            'vendor_name': self.vendor_name.decode('utf-8', errors='ignore'),
            'bootconfig_size': self.bootconfig_size if self.header_version >= 4 else 0,
        }
    
    def _save_vendor_boot(self, output_path: str, new_ramdisk: bytes) -> str:
        """Repack vendor_boot image (v3/v4)."""
        ps = self.page_size
        
        def align(size):
            return ((size + ps - 1) // ps) * ps
        
        # Use stored header size or calculate it
        hdr_data_size = 8 + 4 + 4 + 4 + 4 + 4 + 2048 + 4 + 16 + 4 + 4 + 8
        if self.header_version >= 4:
            hdr_data_size += 16  # 4 extra uint32 fields
        header_size = self.vendor_header_size if self.vendor_header_size else hdr_data_size
        
        header = bytearray(align(header_size))
        
        off = 0
        header[off:off + 8] = self.VENDOR_BOOT_MAGIC; off += 8
        struct.pack_into('<I', header, off, self.header_version); off += 4
        struct.pack_into('<I', header, off, self.page_size); off += 4
        struct.pack_into('<I', header, off, self.kernel_addr); off += 4
        struct.pack_into('<I', header, off, self.ramdisk_addr); off += 4
        struct.pack_into('<I', header, off, len(new_ramdisk)); off += 4
        cmd = self.cmdline.encode('utf-8')[:2048]
        header[off:off + len(cmd)] = cmd; off += 2048
        struct.pack_into('<I', header, off, self.tags_addr); off += 4
        vname = self.vendor_name[:16] if isinstance(self.vendor_name, bytes) else self.vendor_name.encode('utf-8')[:16]
        header[off:off + len(vname)] = vname; off += 16
        struct.pack_into('<I', header, off, header_size); off += 4
        struct.pack_into('<I', header, off, len(self.dtb_data)); off += 4
        struct.pack_into('<Q', header, off, self.dtb_addr); off += 8
        
        vrt_data = b''
        bc_data = b''
        if self.header_version >= 4:
            vrt_data = self.vendor_ramdisk_table_data or b''
            bc_data = self.bootconfig_data or b''
            struct.pack_into('<I', header, off, len(vrt_data)); off += 4
            struct.pack_into('<I', header, off, self.vendor_ramdisk_table_entry_num); off += 4
            struct.pack_into('<I', header, off, self.vendor_ramdisk_table_entry_size); off += 4
            struct.pack_into('<I', header, off, len(bc_data)); off += 4
        
        with open(output_path, 'wb') as f:
            # Header (page-aligned)
            f.write(header)
            
            # Vendor ramdisk (page-aligned)
            f.write(new_ramdisk)
            pad = align(len(new_ramdisk)) - len(new_ramdisk)
            if pad > 0:
                f.write(b'\x00' * pad)
            
            # DTB (page-aligned)
            if len(self.dtb_data) > 0:
                f.write(self.dtb_data)
                pad = align(len(self.dtb_data)) - len(self.dtb_data)
                if pad > 0:
                    f.write(b'\x00' * pad)
            
            # V4: vendor ramdisk table + bootconfig
            if self.header_version >= 4:
                if len(vrt_data) > 0:
                    f.write(vrt_data)
                    pad = align(len(vrt_data)) - len(vrt_data)
                    if pad > 0:
                        f.write(b'\x00' * pad)
                if len(bc_data) > 0:
                    f.write(bc_data)
                    pad = align(len(bc_data)) - len(bc_data)
                    if pad > 0:
                        f.write(b'\x00' * pad)
        
        return output_path


def get_plugin_dir() -> str:
    """Get the directory where this plugin is installed."""
    return os.path.dirname(os.path.abspath(__file__))


def find_fastboot() -> Optional[str]:
    """Find Fastboot executable - checks plugin directory first for self-contained plugins."""
    plugin_dir = get_plugin_dir()
    
    # PRIORITY 1: Plugin's own bundled platform-tools (for Plugin Store downloads)
    plugin_fb_paths = [
        os.path.join(plugin_dir, "platform-tools", "fastboot.exe"),
        os.path.join(plugin_dir, "platform-tools", "fastboot"),
        os.path.join(plugin_dir, "fastboot.exe"),
        os.path.join(plugin_dir, "fastboot"),
    ]
    
    for path in plugin_fb_paths:
        if os.path.isfile(path):
            return path
    
    # PRIORITY 2: PyInstaller frozen exe bundled files
    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        app_dir = os.path.dirname(sys.executable)
        
        frozen_paths = [
            os.path.join(meipass, "platform-tools", "fastboot.exe"),
            os.path.join(meipass, "platform-tools", "fastboot"),
            os.path.join(app_dir, "platform-tools", "fastboot.exe"),
            os.path.join(app_dir, "platform-tools", "fastboot"),
        ]
        
        for path in frozen_paths:
            if os.path.isfile(path):
                return path
    else:
        # Development mode - check app root
        app_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        dev_paths = [
            os.path.join(app_dir, "platform-tools", "fastboot.exe"),
            os.path.join(app_dir, "platform-tools", "fastboot"),
        ]
        
        for path in dev_paths:
            if os.path.isfile(path):
                return path
    
    # PRIORITY 3: System PATH and common locations
    system_paths = [
        "fastboot", "fastboot.exe",
        os.path.join(os.environ.get("ANDROID_HOME", ""), "platform-tools", "fastboot"),
        os.path.join(os.environ.get("ANDROID_HOME", ""), "platform-tools", "fastboot.exe"),
        r"C:\platform-tools\fastboot.exe",
        r"C:\Android\platform-tools\fastboot.exe",
    ]
    
    for path in system_paths:
        if path and shutil.which(path):
            return shutil.which(path)
        if path and os.path.isfile(path):
            return path
    
    return None


def run_fastboot(args: List[str], device: Optional[str] = None, timeout: int = 60) -> tuple:
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
        # Fastboot often returns success info in stderr
        return result.returncode == 0 or "OKAY" in output or "Finished" in output, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def find_adb() -> Optional[str]:
    """Find ADB executable - checks plugin directory first for self-contained plugins."""
    plugin_dir = get_plugin_dir()

    # PRIORITY 1: Plugin's own bundled platform-tools
    plugin_paths = [
        os.path.join(plugin_dir, "platform-tools", "adb.exe"),
        os.path.join(plugin_dir, "platform-tools", "adb"),
    ]
    for path in plugin_paths:
        if os.path.isfile(path):
            return path

    # PRIORITY 2: PyInstaller frozen exe
    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        app_dir = os.path.dirname(sys.executable)
        for d in (meipass, app_dir):
            for fn in ("adb.exe", "adb"):
                p = os.path.join(d, "platform-tools", fn)
                if os.path.isfile(p):
                    return p
    else:
        app_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        for fn in ("adb.exe", "adb"):
            p = os.path.join(app_dir, "platform-tools", fn)
            if os.path.isfile(p):
                return p

    # PRIORITY 3: System PATH / common locations
    system_paths = [
        "adb", "adb.exe",
        os.path.join(os.environ.get("ANDROID_HOME", ""), "platform-tools", "adb"),
        os.path.join(os.environ.get("ANDROID_HOME", ""), "platform-tools", "adb.exe"),
    ]
    for path in system_paths:
        if path and shutil.which(path):
            return shutil.which(path)
    return None


def run_adb(args: List[str], device: Optional[str] = None, timeout: int = 60) -> tuple:
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
        output = result.stdout + result.stderr
        return result.returncode == 0, output.strip()
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def run_adb_shell(cmd_str: str, device: Optional[str] = None, timeout: int = 60) -> tuple:
    """Run ADB shell command and return (success, output)."""
    return run_adb(["shell", cmd_str], device=device, timeout=timeout)


# =============================================================================
# LP METADATA (super partition) PARSER
# =============================================================================

# Constants from Android's liblp/metadata_format.h
LP_METADATA_GEOMETRY_MAGIC = 0x616c4467  # "gDla"
LP_METADATA_HEADER_MAGIC   = 0x414c5030  # "0PLA"
LP_PARTITION_ATTR_READONLY  = (1 << 0)
LP_PARTITION_ATTR_SLOT_SUFFIXED = (1 << 1)

LP_TARGET_TYPE_LINEAR = 0
LP_TARGET_TYPE_ZERO   = 1


@dataclass
class LpPartitionExtent:
    """A linear extent mapping logical → physical sectors within super."""
    target_type: int       # 0 = linear, 1 = zero
    num_sectors: int       # in 512-byte sectors
    target_source: int     # index into block_devices table
    physical_sector: int   # start sector on physical device


@dataclass
class LpPartition:
    """A logical partition inside the super image."""
    name: str
    group_index: int
    attributes: int
    first_extent_index: int
    num_extents: int
    extents: List[LpPartitionExtent]

    @property
    def readonly(self) -> bool:
        return bool(self.attributes & LP_PARTITION_ATTR_READONLY)

    @property
    def total_size(self) -> int:
        return sum(e.num_sectors * 512 for e in self.extents)


@dataclass
class LpBlockDevice:
    """A physical block device hosting the super partition."""
    first_logical_sector: int
    alignment: int
    alignment_offset: int
    size: int
    partition_name: str


class LpMetadata:
    """Parsed LP (Logical Partitions) metadata from a super partition."""

    def __init__(self, raw_geometry: bytes, raw_metadata: bytes):
        self.partitions: List[LpPartition] = []
        self.block_devices: List[LpBlockDevice] = []
        self._parse_geometry(raw_geometry)
        self._parse_metadata(raw_metadata)

    # -- geometry ----------------------------------------------------------
    def _parse_geometry(self, data: bytes):
        if len(data) < 52:
            raise ValueError("LP geometry too short")
        magic = struct.unpack_from('<I', data, 0)[0]
        if magic != LP_METADATA_GEOMETRY_MAGIC:
            raise ValueError(f"Bad geometry magic: 0x{magic:08x}")
        # struct_size  = struct.unpack_from('<I', data, 4)[0]
        # checksum     = data[8:40]  # SHA-256
        self.metadata_max_size  = struct.unpack_from('<I', data, 40)[0]
        self.metadata_slot_count = struct.unpack_from('<I', data, 44)[0]
        self.logical_block_size  = struct.unpack_from('<I', data, 48)[0]

    # -- metadata header + tables -----------------------------------------
    def _parse_metadata(self, data: bytes):
        if len(data) < 128:
            raise ValueError("LP metadata header too short")
        magic = struct.unpack_from('<I', data, 0)[0]
        if magic != LP_METADATA_HEADER_MAGIC:
            raise ValueError(f"Bad metadata magic: 0x{magic:08x}")

        header_size = struct.unpack_from('<I', data, 8)[0]

        # Table descriptors (offset, num_entries, entry_size) — all relative to header_size
        tables_off = 12
        part_off, part_n, part_sz   = struct.unpack_from('<III', data, tables_off)
        ext_off,  ext_n,  ext_sz    = struct.unpack_from('<III', data, tables_off + 12)
        grp_off,  grp_n,  grp_sz   = struct.unpack_from('<III', data, tables_off + 24)
        blk_off,  blk_n,  blk_sz   = struct.unpack_from('<III', data, tables_off + 36)

        base = header_size  # all table offsets are relative to this

        # Block devices
        for i in range(blk_n):
            o = base + blk_off + i * blk_sz
            fls  = struct.unpack_from('<Q', data, o)[0]
            aln  = struct.unpack_from('<I', data, o + 8)[0]
            alo  = struct.unpack_from('<I', data, o + 12)[0]
            sz   = struct.unpack_from('<Q', data, o + 16)[0]
            name = data[o + 24: o + 24 + 36].split(b'\x00')[0].decode('ascii', errors='replace')
            self.block_devices.append(LpBlockDevice(fls, aln, alo, sz, name))

        # Extents
        all_extents: List[LpPartitionExtent] = []
        for i in range(ext_n):
            o = base + ext_off + i * ext_sz
            tt   = struct.unpack_from('<I', data, o)[0]       # target_type
            ns   = struct.unpack_from('<Q', data, o + 4)[0]   # num_sectors
            ts   = struct.unpack_from('<I', data, o + 12)[0]  # target_source
            ps   = struct.unpack_from('<Q', data, o + 16)[0]  # physical_sector
            all_extents.append(LpPartitionExtent(tt, ns, ts, ps))

        # Partitions
        for i in range(part_n):
            o = base + part_off + i * part_sz
            name = data[o: o + 36].split(b'\x00')[0].decode('ascii', errors='replace')
            attrs = struct.unpack_from('<I', data, o + 36)[0]
            fei   = struct.unpack_from('<I', data, o + 40)[0]
            ne    = struct.unpack_from('<I', data, o + 44)[0]
            gi    = struct.unpack_from('<I', data, o + 48)[0]
            exts  = all_extents[fei:fei + ne] if ne > 0 else []
            self.partitions.append(LpPartition(name, gi, attrs, fei, ne, exts))

    def find_partition(self, name: str) -> Optional[LpPartition]:
        """Find a partition by name (exact match)."""
        for p in self.partitions:
            if p.name == name:
                return p
        return None

    def find_partition_fuzzy(self, base_name: str) -> Optional[LpPartition]:
        """Find partition by base name, trying base_name, base_name_a, base_name-a."""
        for suffix in ('', '_a', '-a'):
            p = self.find_partition(base_name + suffix)
            if p and p.total_size > 0:
                return p
        return None


def parse_lp_metadata_from_super(device_serial: str, super_block: str = '/dev/block/sda30') -> LpMetadata:
    """Read LP metadata from the super partition on a device via ADB shell.

    Requires root ADB (recovery mode).
    Reads geometry at offset 4096 and first metadata slot.
    """
    # Read geometry (4096 bytes at offset 4096)
    ok, geo_b64 = run_adb_shell(
        f"dd if={super_block} bs=4096 skip=1 count=1 2>/dev/null | base64",
        device=device_serial, timeout=30
    )
    if not ok or not geo_b64.strip():
        raise RuntimeError(f"Failed to read LP geometry from {super_block}: {geo_b64}")

    import base64
    geo_data = base64.b64decode(geo_b64.strip().replace('\n', '').replace('\r', ''))

    # Parse geometry to find metadata size
    if len(geo_data) < 52:
        raise RuntimeError("LP geometry data too small")
    magic = struct.unpack_from('<I', geo_data, 0)[0]
    if magic != LP_METADATA_GEOMETRY_MAGIC:
        raise RuntimeError(f"Bad LP geometry magic: 0x{magic:08x} (expected 0x{LP_METADATA_GEOMETRY_MAGIC:08x})")

    meta_max_size = struct.unpack_from('<I', geo_data, 40)[0]
    # Metadata starts at offset 2 * 4096 (two geometry copies) = 8192
    meta_blocks = (meta_max_size + 4095) // 4096

    ok, meta_b64 = run_adb_shell(
        f"dd if={super_block} bs=4096 skip=2 count={meta_blocks} 2>/dev/null | base64",
        device=device_serial, timeout=30
    )
    if not ok or not meta_b64.strip():
        raise RuntimeError(f"Failed to read LP metadata: {meta_b64}")

    meta_data = base64.b64decode(meta_b64.strip().replace('\n', '').replace('\r', ''))
    return LpMetadata(geo_data, meta_data)


# =============================================================================
# PRODUCT PARTITION ADB KEY INJECTOR
# =============================================================================

class ProductKeyInjector:
    """Injects ADB public key into the product partition via recovery root shell.

    This is THE breakthrough method for enabling ADB on broken-screen devices
    without ANY screen interaction. It works because:

    1. On Pixel / GKI devices, /adb_keys is a symlink → /product/etc/security/adb_keys
    2. adbd reads /adb_keys at startup and trusts any key found there
    3. The product partition is a dynamic partition inside super
    4. In recovery (with root), we can parse LP metadata, map the partition
       via losetup, resize the ext4 filesystem, mount RW, and write the key

    This survives factory resets and reboots — the key persists in product.

    Requirements:
    - Device in recovery with root ADB shell (LineageOS recovery, TWRP, etc.)
    - Bootloader unlocked (to flash custom recovery)
    - ADB public key file on the host PC
    """

    def __init__(self, device_serial: str, log_fn=None):
        self.serial = device_serial
        self.log = log_fn or (lambda msg: None)
        self.super_block = None   # detected super block device
        self.loop_dev = None      # created loop device
        self.mount_point = '/mnt/product_ia'
        self._mounted = False

    def _sh(self, cmd: str, timeout: int = 30) -> str:
        """Run shell command on device, return output. Raises on failure."""
        ok, out = run_adb_shell(cmd, device=self.serial, timeout=timeout)
        if not ok:
            raise RuntimeError(f"Shell command failed: {cmd}\nOutput: {out}")
        return out

    def _sh_rc(self, cmd: str, timeout: int = 30) -> tuple:
        """Run shell command, return (success, output) without raising."""
        return run_adb_shell(cmd, device=self.serial, timeout=timeout)

    # -- Step 1: Detect super partition ------------------------------------
    def detect_super_block(self) -> str:
        """Find the super partition block device."""
        self.log("🔍 Detecting super partition...")

        # Method 1: Check by-name symlinks (most reliable)
        for path in ('/dev/block/by-name/super', '/dev/block/bootdevice/by-name/super'):
            ok, target = self._sh_rc(f"readlink -f {path} 2>/dev/null")
            if ok and target.startswith('/dev/block/'):
                self.super_block = target.strip()
                self.log(f"  Found via by-name: {self.super_block}")
                return self.super_block

        # Method 2: Search in /dev/block/platform/*/by-name/super
        ok, out = self._sh_rc("ls -la /dev/block/platform/*/by-name/super 2>/dev/null")
        if ok and '/dev/block/' in out:
            for line in out.split('\n'):
                if '->' in line:
                    target = line.split('->')[-1].strip()
                    if target.startswith('/dev/block/') or target.startswith('../'):
                        ok2, resolved = self._sh_rc(f"readlink -f /dev/block/platform/*/by-name/super 2>/dev/null")
                        if ok2 and resolved.startswith('/dev/block/'):
                            self.super_block = resolved.strip()
                            self.log(f"  Found via platform: {self.super_block}")
                            return self.super_block

        # Method 3: Try common paths
        for blk in ('/dev/block/sda30', '/dev/block/sda17', '/dev/block/mmcblk0p32'):
            ok, _ = self._sh_rc(f"test -b {blk}")
            if ok:
                # Verify it has LP metadata magic
                ok2, out2 = self._sh_rc(f"dd if={blk} bs=4096 skip=1 count=1 2>/dev/null | head -c 4 | xxd -p")
                if ok2 and '67446c61' in out2.replace(' ', ''):  # gDla in LE
                    self.super_block = blk
                    self.log(f"  Found via probe: {self.super_block}")
                    return self.super_block

        raise RuntimeError(
            "Could not find super partition.\n"
            "This device may not use dynamic partitions, or the recovery\n"
            "doesn't have the necessary block devices mounted."
        )

    # -- Step 2: Parse LP metadata and find product_a ----------------------
    def find_product_extent(self) -> Tuple[int, int]:
        """Parse LP metadata and return (byte_offset, byte_size) of product_a in super.

        Returns the offset and size for use with losetup.
        """
        if not self.super_block:
            self.detect_super_block()

        self.log("📊 Parsing LP metadata...")
        lp = parse_lp_metadata_from_super(self.serial, self.super_block)

        product = lp.find_partition_fuzzy('product')
        if not product:
            available = [p.name for p in lp.partitions if p.total_size > 0]
            raise RuntimeError(
                f"No 'product' partition found in LP metadata.\n"
                f"Available partitions: {', '.join(available)}\n\n"
                "This device may not have a product partition, or it uses\n"
                "a different layout. The ADB key symlink method won't work here."
            )

        if not product.extents:
            raise RuntimeError(f"Product partition '{product.name}' has no extents (empty)")

        # Use the first linear extent
        ext = product.extents[0]
        if ext.target_type != LP_TARGET_TYPE_LINEAR:
            raise RuntimeError(f"Product extent is type {ext.target_type}, not linear")

        byte_offset = ext.physical_sector * 512
        byte_size = ext.num_sectors * 512

        self.log(f"  Found '{product.name}': offset=0x{byte_offset:X} ({byte_offset // 1048576} MB), "
                 f"size={byte_size // 1048576} MB")
        self.log(f"  Extents: {len(product.extents)}, total={product.total_size // 1048576} MB")
        return byte_offset, byte_size

    # -- Step 3: Create loop device ----------------------------------------
    def setup_loop_device(self, offset: int, size: int) -> str:
        """Create a loop device over the product extent in super."""
        self.log("🔧 Creating loop device...")

        # Clean up any previous loop
        self._sh_rc("losetup -d /dev/block/loop7 2>/dev/null")
        self._sh_rc(f"umount {self.mount_point} 2>/dev/null")

        # Use loop7 to avoid conflicts (loop0-6 may be in use)
        self._sh(
            f"losetup /dev/block/loop7 {self.super_block} "
            f"-o {offset} --sizelimit {size}"
        )
        self.loop_dev = '/dev/block/loop7'

        # Verify
        ok, info = self._sh_rc("losetup -a 2>/dev/null")
        if ok and 'loop7' in info:
            self.log(f"  Loop device: {self.loop_dev} → {self.super_block} @ offset {offset}")
        else:
            self.log(f"  Loop device created (losetup -a not available for verify)")

        return self.loop_dev

    # -- Step 4: Fix filesystem (shared_blocks + resize) -------------------
    def fix_filesystem(self) -> bool:
        """Run e2fsck and resize2fs to fix shared_blocks and grow the filesystem.

        Google's product partition uses ext4 with shared_blocks dedup, which makes
        every block appear shared. We need to:
        1. e2fsck -fy to fix block counts (shared→real free count)
        2. resize2fs to grow into any unused partition extent space
        """
        if not self.loop_dev:
            raise RuntimeError("No loop device — call setup_loop_device first")

        self.log("🔧 Checking and fixing filesystem...")

        # First, check if it's actually ext4
        ok, magic = self._sh_rc(f"dd if={self.loop_dev} bs=1 skip=1080 count=2 2>/dev/null | xxd -p")
        if ok and '53ef' in magic.replace(' ', ''):
            self.log("  Confirmed: ext4 filesystem")
        else:
            self.log(f"  ⚠️ Filesystem magic doesn't look like ext4: {magic}")

        # Step 4a: Clear shared_blocks feature flag from superblock
        # ro_compat field at superblock offset 0x64 (100 bytes)
        self.log("  Patching shared_blocks feature flag...")
        ok, sb_hex = self._sh_rc(
            f"dd if={self.loop_dev} bs=1 skip=100 count=4 2>/dev/null | xxd -p"
        )
        if ok and sb_hex.strip():
            ro_compat_bytes = bytes.fromhex(sb_hex.strip())
            ro_compat = struct.unpack('<I', ro_compat_bytes)[0]
            SHARED_BLOCKS_FLAG = 0x4000
            if ro_compat & SHARED_BLOCKS_FLAG:
                new_ro_compat = ro_compat & ~SHARED_BLOCKS_FLAG
                new_bytes = struct.pack('<I', new_ro_compat)
                hex_str = new_bytes.hex()
                self._sh(
                    f"printf '\\x{hex_str[0:2]}\\x{hex_str[2:4]}\\x{hex_str[4:6]}\\x{hex_str[6:8]}' "
                    f"| dd of={self.loop_dev} bs=1 seek=100 conv=notrunc 2>/dev/null"
                )
                self.log(f"  Cleared shared_blocks flag: 0x{ro_compat:08x} → 0x{new_ro_compat:08x}")
            else:
                self.log(f"  shared_blocks not set (ro_compat=0x{ro_compat:08x})")

        # Step 4b: e2fsck to fix counts
        self.log("  Running e2fsck -fy (this may take a moment)...")
        ok, out = self._sh_rc(f"e2fsck -fy {self.loop_dev} 2>&1", timeout=300)
        if 'FILE SYSTEM WAS MODIFIED' in (out or ''):
            self.log("  Filesystem was repaired")
        elif 'clean' in (out or '').lower():
            self.log("  Filesystem is clean")
        else:
            self.log(f"  e2fsck output: {(out or '')[-200:]}")

        # Step 4c: resize2fs to grow into unused partition extent space
        self.log("  Running resize2fs to maximize available space...")
        ok, out = self._sh_rc(f"resize2fs {self.loop_dev} 2>&1", timeout=120)
        if ok and 'is now' in (out or ''):
            # Parse the new block count
            m = re.search(r'now (\d+)', out)
            if m:
                self.log(f"  Filesystem resized to {int(m.group(1))} blocks")
        elif 'Nothing to do' in (out or ''):
            self.log("  Filesystem already at maximum size")
        else:
            self.log(f"  resize2fs: {(out or '')[-200:]}")

        return True

    # -- Step 5: Mount read-write ------------------------------------------
    def mount_product_rw(self) -> str:
        """Mount the product partition read-write."""
        if not self.loop_dev:
            raise RuntimeError("No loop device")

        self.log("📂 Mounting product partition RW...")

        # Create mount point
        self._sh_rc(f"mkdir -p {self.mount_point}")

        # Try RW mount
        ok, out = self._sh_rc(f"mount -t ext4 -o rw {self.loop_dev} {self.mount_point}")
        if not ok:
            raise RuntimeError(f"Failed to mount product partition RW: {out}")

        self._mounted = True

        # Verify we have free space
        ok, df_out = self._sh_rc(f"df -h {self.mount_point}")
        if ok:
            self.log(f"  Mounted at {self.mount_point}")
            for line in df_out.split('\n'):
                if 'loop' in line or self.mount_point in line:
                    self.log(f"  {line.strip()}")
        return self.mount_point

    # -- Step 6: Write ADB key ---------------------------------------------
    def write_adb_key(self, pubkey_content: str) -> bool:
        """Write the ADB public key to /product/etc/security/adb_keys."""
        if not self._mounted:
            raise RuntimeError("Product partition not mounted")

        target_dir = f"{self.mount_point}/etc/security"
        target_file = f"{target_dir}/adb_keys"

        self.log("🔑 Writing ADB public key...")

        # Ensure directory exists
        self._sh_rc(f"mkdir -p {target_dir}")

        # Write key via echo (avoids needing to push a file)
        # Use base64 to safely transfer the key content
        import base64
        key_b64 = base64.b64encode(pubkey_content.encode()).decode()
        self._sh(f"echo '{key_b64}' | base64 -d > {target_file}")

        # Set proper permissions
        self._sh(f"chmod 644 {target_file}")
        self._sh(f"chown root:root {target_file}")

        # Verify
        ok, verify = self._sh_rc(f"wc -c < {target_file}")
        if ok:
            size = verify.strip()
            self.log(f"  Written: {target_file} ({size} bytes)")
            if int(size) < 10:
                raise RuntimeError(f"Key file too small ({size} bytes) — write may have failed")
        else:
            raise RuntimeError(f"Could not verify key file: {verify}")

        # Also verify symlink chain exists
        ok, symlink = self._sh_rc("ls -la /adb_keys 2>/dev/null")
        if ok and 'product' in symlink:
            self.log(f"  Symlink chain: {symlink.strip()}")
        else:
            self.log("  ⚠️ /adb_keys symlink not found — key will only work if adbd checks product path")

        return True

    # -- Step 7: Cleanup ---------------------------------------------------
    def cleanup(self):
        """Unmount and detach loop device."""
        self.log("🧹 Cleaning up...")
        if self._mounted:
            self._sh_rc("sync")
            self._sh_rc(f"umount {self.mount_point}")
            self._mounted = False
        if self.loop_dev:
            self._sh_rc(f"losetup -d {self.loop_dev} 2>/dev/null")
            self.loop_dev = None
        self.log("  Done")

    # -- Full pipeline -----------------------------------------------------
    def inject(self, pubkey_content: str) -> List[str]:
        """Full pipeline: detect → parse → mount → write → cleanup.

        Returns a list of step descriptions.
        """
        steps = []
        try:
            # Step 1: Find super
            self.detect_super_block()
            steps.append(f"Found super: {self.super_block}")

            # Step 2: Parse LP metadata
            offset, size = self.find_product_extent()
            steps.append(f"Product partition: offset=0x{offset:X}, size={size // 1048576} MB")

            # Step 3: Loop device
            self.setup_loop_device(offset, size)
            steps.append(f"Loop device: {self.loop_dev}")

            # Step 4: Fix filesystem
            self.fix_filesystem()
            steps.append("Filesystem fixed (shared_blocks cleared, resized)")

            # Step 5: Mount
            self.mount_product_rw()
            steps.append(f"Mounted RW at {self.mount_point}")

            # Step 6: Write key
            self.write_adb_key(pubkey_content)
            steps.append("ADB key written to /product/etc/security/adb_keys")

            return steps

        finally:
            self.cleanup()


class FastbootWorkerThread(QThread):
    """Worker thread for Fastboot operations."""
    progress = pyqtSignal(int, int, str)
    log = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)
    result_data = pyqtSignal(object)
    
    def __init__(self, operation: str, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
        self._cancelled = False
        self.fb_path = find_fastboot()
    
    def cancel(self):
        self._cancelled = True
    
    def run(self):
        # ADB-only operations don't require fastboot
        adb_only_ops = {"inject_product_key"}
        if not self.fb_path and self.operation not in adb_only_ops:
            self.finished_signal.emit(False, "Fastboot not found. Please ensure platform-tools is available.")
            return
        
        try:
            if self.operation == "list_devices":
                self._list_devices()
            elif self.operation == "device_info":
                self._get_device_info()
            elif self.operation == "flash":
                self._flash_partition()
            elif self.operation == "boot":
                self._boot_image()
            elif self.operation == "erase":
                self._erase_partition()
            elif self.operation == "fetch":
                self._fetch_partition()
            elif self.operation == "oem_unlock":
                self._oem_unlock()
            elif self.operation == "oem_lock":
                self._oem_lock()
            elif self.operation == "flashing_unlock":
                self._flashing_unlock()
            elif self.operation == "flashing_lock":
                self._flashing_lock()
            elif self.operation == "set_active":
                self._set_active_slot()
            elif self.operation == "format":
                self._format_partition()
            elif self.operation == "reboot":
                self._reboot()
            elif self.operation == "getvar":
                self._getvar()
            elif self.operation == "list_partitions":
                self._list_partitions()
            elif self.operation == "boot_mod":
                self._boot_mod()
            elif self.operation == "inject_product_key":
                self._inject_product_key()
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.finished_signal.emit(False, str(e))
    
    def _list_partitions(self):
        """List partitions using getvar all - extracts partition info."""
        device = self.kwargs.get('device')
        lg_safe = self.kwargs.get('lg_safe', False)
        
        partitions = []
        seen = set()
        
        if lg_safe:
            # LG Safe Mode: Provide common partition names without querying
            # This avoids 'getvar all' which causes LG devices to reboot
            common_partitions = [
                'boot', 'boot_a', 'boot_b', 'recovery', 'system', 'system_a', 'system_b',
                'vendor', 'vendor_a', 'vendor_b', 'userdata', 'cache', 'dtbo', 'dtbo_a', 'dtbo_b',
                'vbmeta', 'vbmeta_a', 'vbmeta_b', 'abl', 'abl_a', 'abl_b', 'xbl', 'xbl_a', 'xbl_b',
                'modem', 'modem_a', 'modem_b', 'super', 'laf', 'laf_a', 'laf_b'
            ]
            for p in common_partitions:
                partitions.append({'name': p, 'size': '(LG Safe Mode)', 'size_bytes': 0})
            
            self.result_data.emit(partitions)
            self.finished_signal.emit(True, f"Common partitions listed (LG Safe Mode - no query)")
            return
        
        success, output = run_fastboot(["getvar", "all"], device, timeout=30)
        
        # Parse getvar all output for partition info
        # Formats vary by device but common patterns:
        # (bootloader) partition-size:boot: 0x4000000
        # (bootloader) partition-type:boot: raw
        # partition-size:boot_a: 0x6000000
        for line in output.split('\n'):
            line = line.replace('(bootloader)', '').strip()
            
            # Look for partition-size entries
            if 'partition-size:' in line.lower():
                try:
                    # Extract partition name and size
                    parts = line.split(':')
                    if len(parts) >= 2:
                        part_name = parts[1].strip()
                        size_hex = parts[2].strip() if len(parts) > 2 else '0'
                        
                        if part_name and part_name not in seen:
                            seen.add(part_name)
                            # Convert hex size to human readable
                            try:
                                size_bytes = int(size_hex, 16)
                                if size_bytes >= 1024*1024*1024:
                                    size_str = f"{size_bytes / (1024*1024*1024):.1f} GB"
                                elif size_bytes >= 1024*1024:
                                    size_str = f"{size_bytes / (1024*1024):.1f} MB"
                                elif size_bytes >= 1024:
                                    size_str = f"{size_bytes / 1024:.1f} KB"
                                else:
                                    size_str = f"{size_bytes} B"
                            except:
                                size_str = size_hex
                            
                            partitions.append({
                                'name': part_name,
                                'size': size_str,
                                'size_bytes': size_bytes if 'size_bytes' in dir() else 0
                            })
                except:
                    continue
            
            # Also check for has-slot entries to find A/B partitions
            elif 'has-slot:' in line.lower():
                try:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        part_name = parts[1].strip()
                        if part_name and part_name not in seen and parts[-1].strip().lower() == 'yes':
                            # This partition has slots, add _a and _b versions if not already present
                            for suffix in ['_a', '_b']:
                                slot_name = part_name + suffix
                                if slot_name not in seen:
                                    seen.add(slot_name)
                                    partitions.append({'name': slot_name, 'size': 'A/B slot', 'size_bytes': 0})
                except:
                    continue
        
        # Sort by name
        partitions.sort(key=lambda x: x['name'])
        
        self.result_data.emit(partitions)
        self.finished_signal.emit(True, f"Found {len(partitions)} partitions")
    
    def _list_devices(self):
        lg_safe = self.kwargs.get('lg_safe', False)
        
        # LG Safe Mode: Use simple 'fastboot devices' without -l flag
        # The -l flag can cause issues on some devices
        if lg_safe:
            success, output = run_fastboot(["devices"], timeout=10)
        else:
            success, output = run_fastboot(["devices", "-l"], timeout=10)
        
        devices = []
        for line in output.strip().split('\n'):
            if line.strip() and ('fastboot' in line.lower() or '\t' in line):
                parts = line.split()
                if len(parts) >= 1:
                    serial = parts[0]
                    # Check it's not an error message
                    if serial and not serial.startswith('*') and not serial.lower().startswith('error'):
                        devices.append({'serial': serial, 'state': 'fastboot'})
        
        self.result_data.emit(devices)
        self.finished_signal.emit(True, f"Found {len(devices)} device(s) in fastboot")
    
    def _get_device_info(self):
        device = self.kwargs.get('device')
        lg_safe = self.kwargs.get('lg_safe', False)
        
        info = {}
        
        if lg_safe:
            # LG Safe Mode: Query individual variables instead of 'getvar all'
            # 'getvar all' causes LG devices to reboot!
            safe_vars = [
                'product', 'serialno', 'secure', 'unlocked', 
                'variant', 'slot-count', 'current-slot'
            ]
            for var in safe_vars:
                success, output = run_fastboot(["getvar", var], device, timeout=5)
                if success:
                    for line in output.split('\n'):
                        if ':' in line and var in line.lower():
                            line = line.replace('(bootloader)', '').strip()
                            key, _, value = line.partition(':')
                            value = value.strip()
                            if value and value not in ['OKAY', 'Finished']:
                                info[var] = value
                                break
            
            self.result_data.emit(info)
            self.finished_signal.emit(True, f"Device info retrieved (LG Safe Mode - {len(info)} vars)")
        else:
            # Normal mode: use getvar all
            success, output = run_fastboot(["getvar", "all"], device, timeout=30)
            
            for line in output.split('\n'):
                if ':' in line and line.startswith('(bootloader)') or ':' in line:
                    line = line.replace('(bootloader)', '').strip()
                    if ':' in line:
                        key, _, value = line.partition(':')
                        key = key.strip()
                        value = value.strip()
                        if key and value and key not in ['OKAY', 'Finished']:
                            info[key] = value
            
            self.result_data.emit(info)
            self.finished_signal.emit(True, "Device info retrieved")
    
    def _flash_partition(self):
        device = self.kwargs.get('device')
        partition = self.kwargs.get('partition')
        image_path = self.kwargs.get('image_path')
        
        if not os.path.exists(image_path):
            self.finished_signal.emit(False, f"Image not found: {image_path}")
            return
        
        self.log.emit(f"Flashing {partition}...")
        self.progress.emit(0, 100, f"Flashing {partition}...")
        
        success, output = run_fastboot(["flash", partition, image_path], device, timeout=300)
        
        self.progress.emit(100, 100, "Done")
        if success or "OKAY" in output:
            self.log.emit(f"✓ {partition} flashed successfully")
            self.finished_signal.emit(True, f"Flashed {partition}")
        else:
            self.log.emit(f"✗ Failed: {output}")
            self.finished_signal.emit(False, output)
    
    def _boot_image(self):
        device = self.kwargs.get('device')
        image_path = self.kwargs.get('image_path')
        
        if not os.path.exists(image_path):
            self.finished_signal.emit(False, f"Image not found: {image_path}")
            return
        
        self.log.emit(f"Booting {os.path.basename(image_path)}...")
        
        success, output = run_fastboot(["boot", image_path], device, timeout=120)
        
        if success or "OKAY" in output:
            self.log.emit("✓ Boot image sent, device should be booting...")
            self.finished_signal.emit(True, "Booted")
        else:
            self.finished_signal.emit(False, output)
    
    def _erase_partition(self):
        device = self.kwargs.get('device')
        partition = self.kwargs.get('partition')
        
        self.log.emit(f"Erasing {partition}...")
        
        success, output = run_fastboot(["erase", partition], device, timeout=60)
        
        if success or "OKAY" in output:
            self.log.emit(f"✓ {partition} erased")
            self.finished_signal.emit(True, f"Erased {partition}")
        else:
            self.finished_signal.emit(False, output)
    
    def _fetch_partition(self):
        device = self.kwargs.get('device')
        partition = self.kwargs.get('partition')
        output_path = self.kwargs.get('output_path')
        
        # Ensure partition subfolder exists (UI should have created it, but be safe)
        output_dir = os.path.dirname(output_path)
        os.makedirs(output_dir, exist_ok=True)

        self.log.emit(f"Fetching {partition}...")
        self.progress.emit(0, 100, f"Fetching {partition}...")
        
        success, output = run_fastboot(["fetch", partition, output_path], device, timeout=300)
        
        self.progress.emit(100, 100, "Done")
        
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            size = os.path.getsize(output_path)
            size_str = f"{size / (1024*1024):.1f} MB"
            self.log.emit(f"✓ {partition} saved ({size_str})")
            self.finished_signal.emit(True, output_path)
        else:
            # Fetch might not be supported, try alternative
            self.log.emit("Fetch not supported, try using ADB in recovery mode")
            self.finished_signal.emit(False, "Fetch not supported on this device")
    
    def _oem_unlock(self):
        device = self.kwargs.get('device')
        
        self.log.emit("Sending OEM unlock command...")
        success, output = run_fastboot(["oem", "unlock"], device, timeout=30)
        
        if success or "OKAY" in output:
            self.log.emit("✓ OEM unlock command sent")
            self.log.emit("Check device screen to confirm unlock")
            self.finished_signal.emit(True, "OEM unlock sent")
        else:
            self.finished_signal.emit(False, output)
    
    def _oem_lock(self):
        device = self.kwargs.get('device')
        
        self.log.emit("Sending OEM lock command...")
        success, output = run_fastboot(["oem", "lock"], device, timeout=30)
        
        if success or "OKAY" in output:
            self.log.emit("✓ OEM lock command sent")
            self.finished_signal.emit(True, "OEM locked")
        else:
            self.finished_signal.emit(False, output)
    
    def _flashing_unlock(self):
        device = self.kwargs.get('device')
        
        self.log.emit("Sending flashing unlock command...")
        success, output = run_fastboot(["flashing", "unlock"], device, timeout=30)
        
        if success or "OKAY" in output:
            self.log.emit("✓ Flashing unlock command sent")
            self.log.emit("Check device screen to confirm")
            self.finished_signal.emit(True, "Flashing unlock sent")
        else:
            self.finished_signal.emit(False, output)
    
    def _flashing_lock(self):
        device = self.kwargs.get('device')
        
        self.log.emit("Sending flashing lock command...")
        success, output = run_fastboot(["flashing", "lock"], device, timeout=30)
        
        if success or "OKAY" in output:
            self.log.emit("✓ Bootloader locked")
            self.finished_signal.emit(True, "Bootloader locked")
        else:
            self.finished_signal.emit(False, output)
    
    def _set_active_slot(self):
        device = self.kwargs.get('device')
        slot = self.kwargs.get('slot')
        
        self.log.emit(f"Setting active slot to {slot}...")
        success, output = run_fastboot(["set_active", slot], device)
        
        if success or "OKAY" in output:
            self.log.emit(f"✓ Active slot set to {slot}")
            self.finished_signal.emit(True, f"Active: {slot}")
        else:
            self.finished_signal.emit(False, output)
    
    def _format_partition(self):
        device = self.kwargs.get('device')
        partition = self.kwargs.get('partition')
        fs_type = self.kwargs.get('fs_type', 'ext4')
        
        self.log.emit(f"Formatting {partition} as {fs_type}...")
        success, output = run_fastboot(["format", f"{partition}:{fs_type}"], device, timeout=120)
        
        if success or "OKAY" in output:
            self.log.emit(f"✓ {partition} formatted")
            self.finished_signal.emit(True, f"Formatted {partition}")
        else:
            self.finished_signal.emit(False, output)
    
    def _reboot(self):
        device = self.kwargs.get('device')
        mode = self.kwargs.get('mode', '')
        
        self.log.emit(f"Rebooting{' to ' + mode if mode else ''}...")
        
        if mode == 'bootloader':
            success, output = run_fastboot(["reboot-bootloader"], device)
        elif mode == 'fastbootd':
            success, output = run_fastboot(["reboot-fastboot"], device)
        elif mode == 'recovery':
            success, output = run_fastboot(["reboot-recovery"], device)
        elif mode == 'edl':
            success, output = run_fastboot(["oem", "edl"], device)
        else:
            success, output = run_fastboot(["reboot"], device)
        
        self.finished_signal.emit(True, f"Rebooting{' to ' + mode if mode else ''}")
    
    def _getvar(self):
        device = self.kwargs.get('device')
        var = self.kwargs.get('var', 'all')
        
        success, output = run_fastboot(["getvar", var], device)
        self.result_data.emit(output)
        self.finished_signal.emit(success, output)
    
    def _boot_mod(self):
        """Perform boot image modification operations."""
        mod_type = self.kwargs.get('mod_type')
        input_path = self.kwargs.get('input_path')
        output_path = self.kwargs.get('output_path')
        
        try:
            self.log.emit(f"Loading boot image: {os.path.basename(input_path)}")
            modifier = BootImageModifier(input_path)
            info = modifier.parse()
            
            self.log.emit(f"  Header v{info['header_version']}, page={info['page_size']}, "
                         f"ramdisk={info['ramdisk_compression']}, "
                         f"{info['ramdisk_entries']} files in ramdisk")
            
            all_changes = []
            
            if mod_type == 'fix_adb':
                # The main use case: fix ADB access on a phone with broken screen
                self.log.emit("🔧 Applying ADB fix modifications...")
                
                # 1. Prop file modifications (works when bootloader doesn't set cmdline override)
                adb_props = {
                    'ro.adb.secure': '0',
                    'ro.debuggable': '1',
                    'persist.sys.usb.config': 'mtp,adb',
                    'ro.secure': '0',
                    'ro.boot.adb.secure': '0',
                    # Skip setup wizard — critical for broken screen after factory reset
                    'ro.setupwizard.mode': 'OPTIONAL',
                    'ro.setupwizard.testharness': 'true',
                    'setupwizard.feature.baseline_setupwizard_enabled': 'false',
                }
                changes = modifier.modify_props(adb_props)
                all_changes.extend(changes)
                for c in changes:
                    self.log.emit(f"  ✓ {c}")
                
                # 2. init.rc injection — CRITICAL for Android 13+ GKI devices
                # Bootloader often sets androidboot.adb.secure=1 in kernel cmdline
                # which becomes ro.boot.adb.secure=1 and overrides prop files.
                # setprop in init.rc runs after cmdline processing and CAN override.
                self.log.emit("📜 Injecting init.rc property overrides...")
                rc_changes = modifier.inject_init_rc_props(adb_props)
                all_changes.extend(rc_changes)
                for c in rc_changes:
                    self.log.emit(f"  ✓ {c}")
                
                # 3. Cmdline (helps on non-GKI or if bootloader reads init_boot cmdline)
                cmd_changes = modifier.modify_cmdline(
                    additions=['androidboot.adb.secure=0'],
                    removals=['androidboot.adb.secure=1']
                )
                all_changes.extend(cmd_changes)
                for c in cmd_changes:
                    self.log.emit(f"  ✓ {c}")
                
                # 4. ADB key — THE critical step for production devices
                # On production builds, ALLOW_ADBD_NO_AUTH=false at compile time,
                # meaning ro.adb.secure=0 is completely ignored by adbd.
                # The only way to authorize ADB is injecting the user's public key.
                adb_key_path = self.kwargs.get('adb_key_path')
                if adb_key_path and os.path.isfile(adb_key_path):
                    self.log.emit("🔑 Injecting ADB public key (CRITICAL for production devices)...")
                    key_changes = modifier.inject_adb_key(adb_key_path)
                    all_changes.extend(key_changes)
                    for c in key_changes:
                        self.log.emit(f"  ✓ {c}")
                else:
                    self.log.emit("")
                    self.log.emit("⚠️" + "═" * 60)
                    self.log.emit("⚠️ WARNING: NO ADB KEY PROVIDED!")
                    self.log.emit("⚠️ On production devices (Pixel, Samsung, etc.),")
                    self.log.emit("⚠️ ro.adb.secure=0 is COMPILED OUT of adbd.")
                    self.log.emit("⚠️ Without your adbkey.pub, ADB auth WILL FAIL.")
                    self.log.emit("⚠️ Properties were set but they have NO EFFECT on production firmware.")
                    self.log.emit("⚠️" + "═" * 60)
                    self.log.emit("")
                
            elif mod_type == 'enable_adb':
                self.log.emit("🔓 Enabling ADB without authorization...")
                changes = modifier.modify_props({
                    'ro.adb.secure': '0',
                    'ro.debuggable': '1',
                })
                all_changes.extend(changes)
                for c in changes:
                    self.log.emit(f"  ✓ {c}")
                    
            elif mod_type == 'usb_adb_default':
                self.log.emit("🔌 Setting USB config to ADB by default...")
                changes = modifier.modify_props({
                    'persist.sys.usb.config': 'mtp,adb',
                    'sys.usb.config': 'mtp,adb',
                    'sys.usb.configfs': '1',
                })
                all_changes.extend(changes)
                for c in changes:
                    self.log.emit(f"  ✓ {c}")
                    
            elif mod_type == 'selinux_permissive':
                self.log.emit("🛡️ Setting SELinux to permissive...")
                changes = modifier.modify_cmdline(
                    additions=['androidboot.selinux=permissive'],
                    removals=['androidboot.selinux=enforcing']
                )
                all_changes.extend(changes)
                # Also set in props
                prop_changes = modifier.modify_props({
                    'ro.boot.selinux': 'permissive',
                })
                all_changes.extend(prop_changes)
                for c in changes + prop_changes:
                    self.log.emit(f"  ✓ {c}")
                    
            elif mod_type == 'patch_verity':
                self.log.emit("🔓 Patching fstab to remove dm-verity...")
                changes = modifier.patch_fstab_verity()
                all_changes.extend(changes)
                for c in changes:
                    self.log.emit(f"  ✓ {c}")
                    
            elif mod_type == 'inject_key':
                adb_key_path = self.kwargs.get('adb_key_path')
                if not adb_key_path:
                    self.finished_signal.emit(False, "No ADB key path provided")
                    return
                self.log.emit("🔑 Injecting ADB public key...")
                changes = modifier.inject_adb_key(adb_key_path)
                all_changes.extend(changes)
                for c in changes:
                    self.log.emit(f"  ✓ {c}")
                    
            elif mod_type == 'custom_props':
                custom = self.kwargs.get('custom_props', {})
                self.log.emit(f"📝 Applying {len(custom)} custom property changes...")
                changes = modifier.modify_props(custom)
                all_changes.extend(changes)
                for c in changes:
                    self.log.emit(f"  ✓ {c}")
                    
            elif mod_type == 'full_rescue':
                # The nuclear option: everything at once
                self.log.emit("🚨 Applying FULL RESCUE modifications...")
                
                # 1. All prop files
                rescue_props = {
                    'ro.adb.secure': '0',
                    'ro.debuggable': '1',
                    'ro.secure': '0',
                    'ro.boot.adb.secure': '0',
                    'persist.sys.usb.config': 'mtp,adb',
                    'sys.usb.config': 'mtp,adb',
                    'sys.usb.configfs': '1',
                    'ro.boot.selinux': 'permissive',
                    # Skip setup wizard — critical for broken screen after factory reset
                    'ro.setupwizard.mode': 'OPTIONAL',
                    'ro.setupwizard.testharness': 'true',
                    'setupwizard.feature.baseline_setupwizard_enabled': 'false',
                }
                changes = modifier.modify_props(rescue_props)
                all_changes.extend(changes)
                
                # 2. init.rc injection — CRITICAL for GKI ADB auth bypass
                self.log.emit("📜 Injecting init.rc property overrides...")
                rc_changes = modifier.inject_init_rc_props(rescue_props)
                all_changes.extend(rc_changes)
                
                # 3. Kernel cmdline
                cmdline_changes = modifier.modify_cmdline(
                    additions=[
                        'androidboot.selinux=permissive',
                        'androidboot.adb.secure=0',
                    ],
                    removals=[
                        'androidboot.selinux=enforcing',
                        'androidboot.adb.secure=1',
                    ]
                )
                all_changes.extend(cmdline_changes)
                
                # 4. Fstab verity removal
                fstab_changes = modifier.patch_fstab_verity()
                all_changes.extend(fstab_changes)
                
                # 5. ADB key — THE critical step for production devices
                adb_key_path = self.kwargs.get('adb_key_path')
                if adb_key_path and os.path.isfile(adb_key_path):
                    self.log.emit("🔑 Injecting ADB public key (CRITICAL for production devices)...")
                    key_changes = modifier.inject_adb_key(adb_key_path)
                    all_changes.extend(key_changes)
                else:
                    self.log.emit("")
                    self.log.emit("⚠️" + "═" * 60)
                    self.log.emit("⚠️ WARNING: NO ADB KEY PROVIDED!")
                    self.log.emit("⚠️ On production devices, ADB auth WILL FAIL without your key.")
                    self.log.emit("⚠️" + "═" * 60)
                    self.log.emit("")
                
                for c in all_changes:
                    self.log.emit(f"  ✓ {c}")
            
            # Save
            self.log.emit(f"💾 Repacking boot image...")
            modifier.save(output_path)
            
            file_size = os.path.getsize(output_path)
            size_str = f"{file_size / (1024*1024):.1f} MB" if file_size >= 1024*1024 else f"{file_size / 1024:.1f} KB"
            
            self.log.emit(f"✅ Saved: {output_path} ({size_str})")
            
            result = {
                'output_path': output_path,
                'changes': all_changes,
                'info': info,
            }
            self.result_data.emit(result)
            self.finished_signal.emit(True, f"Boot image modified ({len(all_changes)} changes)")
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.log.emit(f"❌ Error: {e}")
            self.finished_signal.emit(False, str(e))

    def _inject_product_key(self):
        """Inject ADB public key into product partition via recovery root shell.

        This is the 'nuclear option' for enabling ADB on broken-screen devices.
        Runs the full ProductKeyInjector pipeline.
        """
        pubkey_content = self.kwargs.get('pubkey_content', '')
        device = self.kwargs.get('device', '')
        reboot_after = self.kwargs.get('reboot_after', False)

        if not pubkey_content:
            self.finished_signal.emit(False, "No ADB public key content provided")
            return

        if not device:
            self.finished_signal.emit(False, "No device serial provided")
            return

        self.log.emit("")
        self.log.emit("🔓" + "═" * 60)
        self.log.emit("🔓  ADB RESCUE — Product Partition Key Injection")
        self.log.emit("🔓" + "═" * 60)
        self.log.emit("")
        self.log.emit("This injects your ADB public key directly into the product")
        self.log.emit("partition's /etc/security/adb_keys file. On Pixel/GKI devices,")
        self.log.emit("/adb_keys is a symlink to this location. After reboot, your PC")
        self.log.emit("is automatically trusted for USB ADB — no screen interaction needed.")
        self.log.emit("")

        try:
            # Verify we have root ADB in recovery
            self.log.emit("🔍 Verifying recovery root shell...")
            ok, id_out = run_adb_shell("id", device=device, timeout=10)
            if not ok or 'uid=0' not in id_out:
                self.finished_signal.emit(False,
                    "Root ADB shell not available.\n\n"
                    "This feature requires the device to be in RECOVERY mode with\n"
                    "a root shell (LineageOS recovery, TWRP, OrangeFox, etc.).\n\n"
                    f"Got: {id_out}\n\n"
                    "Steps:\n"
                    "1. Flash a custom recovery (LineageOS, TWRP)\n"
                    "2. Boot into recovery\n"
                    "3. Ensure ADB is enabled in recovery\n"
                    "4. Try again"
                )
                return
            self.log.emit(f"  ✓ Root shell confirmed: {id_out.strip()}")

            injector = ProductKeyInjector(device, log_fn=self.log.emit)
            steps = injector.inject(pubkey_content)

            self.log.emit("")
            self.log.emit("✅" + "═" * 60)
            self.log.emit("✅  KEY INJECTION SUCCESSFUL!")
            self.log.emit("✅" + "═" * 60)
            for step in steps:
                self.log.emit(f"  ✓ {step}")
            self.log.emit("")

            if reboot_after:
                self.log.emit("🔄 Rebooting to Android...")
                run_adb(["reboot"], device=device, timeout=10)
                self.log.emit("  Device is rebooting. Wait ~60 seconds, then try 'adb devices'.")
                self.log.emit("  Your device should show as 'device' (authorized) — no screen needed!")

            self.result_data.emit({'steps': steps, 'success': True})
            self.finished_signal.emit(True,
                "ADB key injected successfully! "
                + ("Device is rebooting..." if reboot_after else "Reboot to Android to test.")
            )

        except Exception as e:
            import traceback
            traceback.print_exc()
            self.log.emit(f"")
            self.log.emit(f"❌ INJECTION FAILED: {e}")
            self.log.emit(f"")
            self.log.emit("Troubleshooting:")
            self.log.emit("  1. Ensure device is in recovery with root ADB")
            self.log.emit("  2. Check that bootloader is unlocked")
            self.log.emit("  3. Try a different recovery (TWRP, LineageOS)")
            self.log.emit("  4. Some devices don't have a product partition")
            self.finished_signal.emit(False, str(e))


class FastbootToolkitPlugin:
    """Comprehensive Fastboot Toolkit Plugin."""
    
    def __init__(self):
        self.manifest = None
        self.parent_window = None
        self.current_device = None
        self.devices = []
        self.worker = None
    
    def get_name(self) -> str:
        return self.manifest.name if self.manifest else "Fastboot Toolkit"
    
    def get_icon(self) -> str:
        return self.manifest.icon if self.manifest else "⚡"
    
    def get_description(self) -> str:
        return self.manifest.description if self.manifest else ""
    
    def get_version(self) -> str:
        return self.manifest.version if self.manifest else "1.0"
    
    def get_author(self) -> str:
        return self.manifest.author if self.manifest else "Image Anarchy"
    
    def create_widget(self, parent_window) -> QWidget:
        self.parent_window = parent_window
        
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(8, 8, 8, 8)
        
        # Warning banner
        warning = QLabel("⚠️ Fastboot operations can brick your device. Proceed with caution!")
        warning.setStyleSheet("background: #442200; color: #ffaa00; padding: 8px; border-radius: 4px;")
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(warning)
        
        # LG Safe Mode checkbox (LG devices reboot on certain fastboot commands)
        self.lg_safe_mode = QCheckBox("🛡️ LG Safe Mode (prevents reboots on LG/quirky devices)")
        self.lg_safe_mode.setToolTip(
            "Enable this for LG devices that randomly reboot when using fastboot.\n"
            "LG's fastboot implementation is buggy and reboots on 'getvar all' and other commands.\n"
            "Safe mode uses minimal commands to avoid triggering reboots."
        )
        self.lg_safe_mode.setStyleSheet("color: #88ccff; padding: 4px;")
        main_layout.addWidget(self.lg_safe_mode)
        
        # Device Selection
        device_group = QGroupBox("Device (Fastboot Mode)")
        device_layout = QHBoxLayout(device_group)
        
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(300)
        device_layout.addWidget(QLabel("Device:"))
        device_layout.addWidget(self.device_combo, 1)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_devices)
        device_layout.addWidget(refresh_btn)
        
        self.device_status = QLabel("No device in fastboot")
        self.device_status.setStyleSheet("color: #888;")
        device_layout.addWidget(self.device_status)
        
        main_layout.addWidget(device_group)
        
        # Tools Tabs
        self.tabs = QTabWidget()
        
        self.tabs.addTab(self._create_info_tab(), "📋 Info")
        self.tabs.addTab(self._create_flash_tab(), "⚡ Flash")
        self.tabs.addTab(self._create_boot_tab(), "🚀 Boot")
        self.tabs.addTab(self._create_boot_mods_tab(), "🛠️ Boot Mods")
        self.tabs.addTab(self._create_fetch_tab(), "📥 Fetch")
        self.tabs.addTab(self._create_erase_tab(), "🗑️ Erase")
        self.tabs.addTab(self._create_patch_tab(), "🔧 Patch")
        self.tabs.addTab(self._create_oem_tab(), "🔓 OEM")
        self.tabs.addTab(self._create_slot_tab(), "🔀 Slot")
        self.tabs.addTab(self._create_shell_tab(), "💻 Shell")
        self.tabs.addTab(self._create_adb_rescue_tab(), "🔓 ADB Rescue")
        self.tabs.addTab(self._create_reboot_tab(), "🔄 Reboot")
        
        main_layout.addWidget(self.tabs)
        
        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(120)
        self.log_output.setStyleSheet("font-family: Consolas; font-size: 11px;")
        main_layout.addWidget(self.log_output)
        
        # Initial device scan (with delay, and no auto-scan to avoid LG issues)
        # User must click refresh manually to be safe for LG devices
        self._log("Click 'Refresh' to scan for fastboot devices")
        
        return main_widget
    
    def _log(self, msg: str):
        self.log_output.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        self.log_output.verticalScrollBar().setValue(self.log_output.verticalScrollBar().maximum())
    
    def _refresh_devices(self):
        lg_safe = self.lg_safe_mode.isChecked()
        self._log(f"Scanning for fastboot devices...{' (LG Safe Mode)' if lg_safe else ''}")
        self.worker = FastbootWorkerThread("list_devices", lg_safe=lg_safe)
        self.worker.result_data.connect(self._on_devices_found)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _on_devices_found(self, devices):
        self.devices = devices
        self.device_combo.clear()
        
        if not devices:
            self.device_combo.addItem("No fastboot devices found")
            self.device_status.setText("Boot to bootloader with: adb reboot bootloader")
            self.device_status.setStyleSheet("color: #f84;")
        else:
            for dev in devices:
                self.device_combo.addItem(f"{dev['serial']} (fastboot)", dev['serial'])
            self.device_status.setText("✓ Connected")
            self.device_status.setStyleSheet("color: #4f4;")
    
    def _get_device(self):
        if not self.devices:
            return None
        return self.device_combo.currentData()
    
    # ===== INFO TAB =====
    def _create_info_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.info_table = QTableWidget()
        self.info_table.setColumnCount(2)
        self.info_table.setHorizontalHeaderLabels(["Variable", "Value"])
        self.info_table.horizontalHeader().setStretchLastSection(True)
        self.info_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.info_table)
        
        btn = QPushButton("🔄 Get Device Info (getvar all)")
        btn.setToolTip("Use LG Safe Mode checkbox if your device reboots when clicking this")
        btn.clicked.connect(self._get_info)
        layout.addWidget(btn)
        
        return tab
    
    def _get_info(self):
        device = self._get_device()
        if not device:
            return
        
        lg_safe = self.lg_safe_mode.isChecked()
        self._log(f"Getting device variables...{' (LG Safe Mode)' if lg_safe else ''}")
        self.worker = FastbootWorkerThread("device_info", device=device, lg_safe=lg_safe)
        self.worker.result_data.connect(self._on_info_received)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _on_info_received(self, info: dict):
        self.info_table.setRowCount(len(info))
        for i, (key, value) in enumerate(sorted(info.items())):
            self.info_table.setItem(i, 0, QTableWidgetItem(key))
            self.info_table.setItem(i, 1, QTableWidgetItem(str(value)))
    
    # ===== FLASH TAB =====
    def _create_flash_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Quick flash presets
        presets_group = QGroupBox("Quick Flash")
        presets_layout = QVBoxLayout(presets_group)
        
        preset_row1 = QHBoxLayout()
        for name, partition in [("Boot", "boot"), ("Recovery", "recovery"), ("Vendor Boot", "vendor_boot")]:
            btn = QPushButton(f"⚡ {name}")
            btn.clicked.connect(lambda c, p=partition: self._quick_flash(p))
            preset_row1.addWidget(btn)
        presets_layout.addLayout(preset_row1)
        
        preset_row2 = QHBoxLayout()
        for name, partition in [("DTBO", "dtbo"), ("Vbmeta", "vbmeta"), ("Init Boot", "init_boot")]:
            btn = QPushButton(f"⚡ {name}")
            btn.clicked.connect(lambda c, p=partition: self._quick_flash(p))
            preset_row2.addWidget(btn)
        presets_layout.addLayout(preset_row2)
        
        layout.addWidget(presets_group)
        
        # Custom flash
        custom_group = QGroupBox("Custom Flash")
        custom_layout = QFormLayout(custom_group)
        
        self.flash_partition = QLineEdit()
        self.flash_partition.setPlaceholderText("e.g., boot, recovery, vbmeta")
        custom_layout.addRow("Partition:", self.flash_partition)
        
        self.flash_image = QLineEdit()
        flash_browse = QPushButton("Browse...")
        flash_browse.clicked.connect(lambda: self._browse_file(self.flash_image, "Image Files (*.img)"))
        flash_row = QHBoxLayout()
        flash_row.addWidget(self.flash_image)
        flash_row.addWidget(flash_browse)
        custom_layout.addRow("Image:", flash_row)
        
        self.flash_progress = QProgressBar()
        custom_layout.addRow("Progress:", self.flash_progress)
        
        flash_btn = QPushButton("⚡ Flash Partition")
        flash_btn.setStyleSheet("background: #c62828; font-weight: bold;")
        flash_btn.clicked.connect(self._flash_partition)
        custom_layout.addRow("", flash_btn)
        
        layout.addWidget(custom_group)
        layout.addStretch()
        
        return tab
    
    def _quick_flash(self, partition):
        path, _ = QFileDialog.getOpenFileName(
            self.parent_window, f"Select {partition}.img", "", "Image Files (*.img)"
        )
        if path:
            self.flash_partition.setText(partition)
            self.flash_image.setText(path)
            self._flash_partition()
    
    def _flash_partition(self):
        device = self._get_device()
        partition = self.flash_partition.text()
        image = self.flash_image.text()
        
        if not device or not partition or not image:
            QMessageBox.warning(self.parent_window, "Error", "Device, partition, and image are required")
            return
        
        reply = QMessageBox.question(
            self.parent_window, "Confirm Flash",
            f"Flash {partition} with:\n{os.path.basename(image)}\n\nThis cannot be undone!"
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = FastbootWorkerThread("flash", device=device, partition=partition, image_path=image)
        self.worker.log.connect(self._log)
        self.worker.progress.connect(lambda c, t, m: self.flash_progress.setValue(c))
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== BOOT TAB =====
    def _create_boot_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        layout.addWidget(QLabel("Boot an image without flashing (temporary).\nDevice will return to normal on reboot."))
        
        boot_group = QGroupBox("Boot Image")
        boot_layout = QFormLayout(boot_group)
        
        self.boot_image = QLineEdit()
        boot_browse = QPushButton("Browse...")
        boot_browse.clicked.connect(lambda: self._browse_file(self.boot_image, "Image Files (*.img)"))
        boot_row = QHBoxLayout()
        boot_row.addWidget(self.boot_image)
        boot_row.addWidget(boot_browse)
        boot_layout.addRow("Image:", boot_row)
        
        boot_btn = QPushButton("🚀 Boot Image")
        boot_btn.setStyleSheet("background: #1565c0; font-weight: bold;")
        boot_btn.clicked.connect(self._boot_image)
        boot_layout.addRow("", boot_btn)
        
        layout.addWidget(boot_group)
        
        # Common boot images info
        info = QLabel(
            "Common uses:\n"
            "• Boot patched boot.img to test Magisk root\n"
            "• Boot TWRP recovery without installing\n"
            "• Boot custom kernels for testing\n"
            "• Boot LineageOS recovery for sideloading"
        )
        info.setStyleSheet("color: #888; padding: 10px;")
        layout.addWidget(info)
        
        layout.addStretch()
        return tab
    
    def _boot_image(self):
        device = self._get_device()
        image = self.boot_image.text()
        
        if not device or not image:
            return
        
        self.worker = FastbootWorkerThread("boot", device=device, image_path=image)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== BOOT MODS TAB =====
    def _create_boot_mods_tab(self):
        """Create boot image modification tab — ADB fix, prop editing, etc."""
        tab = QWidget()
        main_layout = QVBoxLayout(tab)
        
        # Scroll area for all the content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        
        scroll_widget = QWidget()
        layout = QVBoxLayout(scroll_widget)
        
        # Hero header
        hero = QLabel(
            "🛠️ <b style='font-size: 14px;'>Boot Image Mods</b> — "
            "<span style='color: #4fc3f7;'>Modify boot / init_boot / vendor_boot without leaving fastboot</span><br>"
            "<span style='color: #888;'>Unpack → Modify ramdisk → Repack → Flash. "
            "Pure Python, no external tools needed.</span>"
        )
        hero.setWordWrap(True)
        hero.setStyleSheet("padding: 8px; background: #1a2a3a; border-radius: 6px; margin-bottom: 4px;")
        layout.addWidget(hero)
        
        # ── Partition Type Selector ──
        ptype_group = QGroupBox("🎯 Partition Type")
        ptype_layout = QVBoxLayout(ptype_group)
        
        ptype_row = QHBoxLayout()
        ptype_row.addWidget(QLabel("Image type:"))
        self.bootmod_ptype_combo = QComboBox()
        self.bootmod_ptype_combo.addItem("🔧 boot — Standard boot image", "boot")
        self.bootmod_ptype_combo.addItem("⭐ init_boot — Android 13+ GKI (ramdisk lives here!)", "init_boot")
        self.bootmod_ptype_combo.addItem("📦 vendor_boot — Vendor ramdisk (drivers/config)", "vendor_boot")
        self.bootmod_ptype_combo.setStyleSheet("font-size: 12px; padding: 4px;")
        self.bootmod_ptype_combo.currentIndexChanged.connect(self._on_partition_type_changed)
        ptype_row.addWidget(self.bootmod_ptype_combo, 1)
        ptype_layout.addLayout(ptype_row)
        
        self.bootmod_ptype_desc = QLabel(
            "<span style='color: #888;'>Standard boot.img — Contains kernel + ramdisk. "
            "Works for most devices pre-Android 13.</span>"
        )
        self.bootmod_ptype_desc.setWordWrap(True)
        self.bootmod_ptype_desc.setStyleSheet("padding: 2px 4px;")
        ptype_layout.addWidget(self.bootmod_ptype_desc)
        
        ptype_tip = QLabel(
            "<span style='color: #f84;'>💡 <b>Not sure?</b> If your boot.img ramdisk has only ~5 files, "
            "your device uses <b>init_boot</b> (Android 13+ with GKI). "
            "Try fetching init_boot instead!</span>"
        )
        ptype_tip.setWordWrap(True)
        ptype_tip.setStyleSheet("padding: 4px; background: rgba(255,152,0,0.1); border-radius: 4px;")
        ptype_layout.addWidget(ptype_tip)
        
        layout.addWidget(ptype_group)
        
        # ── Input boot.img ──
        input_group = QGroupBox("📁 Input Boot Image")
        input_layout = QVBoxLayout(input_group)
        
        file_row = QHBoxLayout()
        self.bootmod_input = QLineEdit()
        self.bootmod_input.setPlaceholderText("Select your boot.img file...")
        self.bootmod_input.textChanged.connect(self._on_bootmod_input_changed)
        file_row.addWidget(self.bootmod_input, 1)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(lambda: self._browse_file(self.bootmod_input, "Image Files (*.img);;All Files (*)"))
        file_row.addWidget(browse_btn)
        
        fetch_btn = QPushButton("📥 Fetch from Device")
        fetch_btn.setToolTip("Fetch boot partition from connected device via fastboot")
        fetch_btn.clicked.connect(self._fetch_boot_for_mod)
        file_row.addWidget(fetch_btn)
        
        input_layout.addLayout(file_row)
        
        # Boot image info display
        self.bootmod_info_label = QLabel("No boot image loaded")
        self.bootmod_info_label.setStyleSheet("color: #888; padding: 4px;")
        input_layout.addWidget(self.bootmod_info_label)
        
        layout.addWidget(input_group)
        
        # ── ADB Key ──
        key_group = QGroupBox("🔑 ADB Public Key (REQUIRED for broken screen)")
        key_layout = QVBoxLayout(key_group)
        
        key_row = QHBoxLayout()
        self.bootmod_adbkey = QLineEdit()
        # Auto-detect default location
        default_key = os.path.join(os.path.expanduser('~'), '.android', 'adbkey.pub')
        if os.path.isfile(default_key):
            self.bootmod_adbkey.setText(default_key)
            self.bootmod_adbkey.setStyleSheet("color: #4f4;")
        else:
            self.bootmod_adbkey.setPlaceholderText("Path to adbkey.pub — NOT FOUND (connect device via adb once to generate)")
            self.bootmod_adbkey.setStyleSheet("color: #f44;")
        key_row.addWidget(self.bootmod_adbkey, 1)
        
        key_browse = QPushButton("📁")
        key_browse.setMaximumWidth(40)
        key_browse.clicked.connect(lambda: self._browse_file(self.bootmod_adbkey, "Public Keys (*.pub);;All Files (*)"))
        key_row.addWidget(key_browse)
        key_layout.addLayout(key_row)
        
        key_info = QLabel(
            "⚠️ CRITICAL: On production devices (Pixel, Samsung, etc.), this is the ONLY way to authorize ADB\n"
            "without the on-screen dialog. The ro.adb.secure=0 trick does NOT work on production firmware.\n"
            "Your PC's public key is injected into the ramdisk so the device recognizes your ADB client."
        )
        key_info.setWordWrap(True)
        key_info.setStyleSheet("color: #ff8; font-size: 11px; padding: 4px;")
        key_layout.addWidget(key_info)
        
        layout.addWidget(key_group)
        
        # ── Quick Actions (the main attraction) ──
        actions_group = QGroupBox("⚡ Quick Actions")
        actions_layout = QVBoxLayout(actions_group)
        
        # Row 1: THE big one
        row1 = QHBoxLayout()
        
        self.btn_fix_adb = QPushButton("🔧 Fix ADB Access\n(Dead Screen / Post-Reset)")
        self.btn_fix_adb.setMinimumHeight(60)
        self.btn_fix_adb.setStyleSheet(
            "background: #c62828; font-weight: bold; font-size: 13px; "
            "border-radius: 8px; padding: 8px;"
        )
        self.btn_fix_adb.setToolTip(
            "THE button for when you factory reset with a broken screen.\n\n"
            "What it does:\n"
            "• Injects your ADB public key → device auto-trusts your PC\n"
            "• Sets properties: ro.debuggable=1, persist.sys.usb.config=mtp,adb\n"
            "• Patches kernel cmdline (for boot.img)\n\n"
            "⚠️ IMPORTANT: The ADB key (above) is REQUIRED on production devices.\n"
            "The ro.adb.secure=0 property is compiled out of production adbd —\n"
            "your public key is the only way to bypass the auth dialog."
        )
        self.btn_fix_adb.clicked.connect(lambda: self._run_boot_mod('fix_adb'))
        self.btn_fix_adb.setEnabled(False)
        row1.addWidget(self.btn_fix_adb)
        
        self.btn_full_rescue = QPushButton("🚨 Full Rescue\n(ADB + SELinux + Verity)")
        self.btn_full_rescue.setMinimumHeight(60)
        self.btn_full_rescue.setStyleSheet(
            "background: #b71c1c; font-weight: bold; font-size: 13px; "
            "border-radius: 8px; padding: 8px;"
        )
        self.btn_full_rescue.setToolTip(
            "Nuclear option: Fix ADB + SELinux permissive + Remove dm-verity + Inject key.\n"
            "Use when nothing else works and you need maximum access."
        )
        self.btn_full_rescue.clicked.connect(lambda: self._run_boot_mod('full_rescue'))
        self.btn_full_rescue.setEnabled(False)
        row1.addWidget(self.btn_full_rescue)
        
        actions_layout.addLayout(row1)
        
        # Row 2: Individual mods
        row2 = QHBoxLayout()
        
        self.btn_enable_adb = QPushButton("🔓 Enable ADB\n(No Auth)")
        self.btn_enable_adb.setMinimumHeight(45)
        self.btn_enable_adb.setToolTip("Set ro.adb.secure=0 and ro.debuggable=1")
        self.btn_enable_adb.clicked.connect(lambda: self._run_boot_mod('enable_adb'))
        self.btn_enable_adb.setEnabled(False)
        row2.addWidget(self.btn_enable_adb)
        
        self.btn_usb_adb = QPushButton("🔌 USB = ADB\n(Default Config)")
        self.btn_usb_adb.setMinimumHeight(45)
        self.btn_usb_adb.setToolTip("Set persist.sys.usb.config=mtp,adb so ADB is on at boot")
        self.btn_usb_adb.clicked.connect(lambda: self._run_boot_mod('usb_adb_default'))
        self.btn_usb_adb.setEnabled(False)
        row2.addWidget(self.btn_usb_adb)
        
        self.btn_selinux = QPushButton("🛡️ SELinux\nPermissive")
        self.btn_selinux.setMinimumHeight(45)
        self.btn_selinux.setToolTip("Add androidboot.selinux=permissive to kernel cmdline")
        self.btn_selinux.clicked.connect(lambda: self._run_boot_mod('selinux_permissive'))
        self.btn_selinux.setEnabled(False)
        row2.addWidget(self.btn_selinux)
        
        self.btn_verity = QPushButton("🔓 Disable\ndm-verity")
        self.btn_verity.setMinimumHeight(45)
        self.btn_verity.setToolTip("Strip verify and avb flags from fstab files in ramdisk")
        self.btn_verity.clicked.connect(lambda: self._run_boot_mod('patch_verity'))
        self.btn_verity.setEnabled(False)
        row2.addWidget(self.btn_verity)
        
        self.btn_inject_key = QPushButton("🔑 Inject\nADB Key")
        self.btn_inject_key.setMinimumHeight(45)
        self.btn_inject_key.setToolTip("Add your PC's ADB public key into the boot ramdisk")
        self.btn_inject_key.clicked.connect(lambda: self._run_boot_mod('inject_key'))
        self.btn_inject_key.setEnabled(False)
        row2.addWidget(self.btn_inject_key)
        
        actions_layout.addLayout(row2)
        
        layout.addWidget(actions_group)
        
        # ── Custom Property Editor ──
        custom_group = QGroupBox("📝 Custom Property Editor")
        custom_layout = QVBoxLayout(custom_group)
        
        custom_info = QLabel("Edit boot image properties directly. One per line: key=value")
        custom_info.setStyleSheet("color: #888;")
        custom_layout.addWidget(custom_info)
        
        self.bootmod_custom_props = QTextEdit()
        self.bootmod_custom_props.setMaximumHeight(100)
        self.bootmod_custom_props.setPlaceholderText(
            "ro.adb.secure=0\n"
            "ro.debuggable=1\n"
            "persist.sys.usb.config=mtp,adb"
        )
        self.bootmod_custom_props.setStyleSheet("font-family: Consolas; font-size: 11px;")
        custom_layout.addWidget(self.bootmod_custom_props)
        
        custom_btn_row = QHBoxLayout()
        
        self.btn_apply_custom = QPushButton("📝 Apply Custom Props")
        self.btn_apply_custom.clicked.connect(self._apply_custom_props)
        self.btn_apply_custom.setEnabled(False)
        custom_btn_row.addWidget(self.btn_apply_custom)
        
        self.btn_view_props = QPushButton("👁️ View Current Props")
        self.btn_view_props.clicked.connect(self._view_current_props)
        self.btn_view_props.setEnabled(False)
        custom_btn_row.addWidget(self.btn_view_props)
        
        self.btn_view_ramdisk = QPushButton("📂 List Ramdisk Files")
        self.btn_view_ramdisk.clicked.connect(self._view_ramdisk_files)
        self.btn_view_ramdisk.setEnabled(False)
        custom_btn_row.addWidget(self.btn_view_ramdisk)
        
        custom_layout.addLayout(custom_btn_row)
        
        layout.addWidget(custom_group)
        
        # ── Output & Flash Options ──
        output_group = QGroupBox("💾 Output & Flash Target")
        output_layout = QVBoxLayout(output_group)
        
        output_row = QHBoxLayout()
        self.bootmod_output = QLineEdit()
        self.bootmod_output.setPlaceholderText("Output path (auto-set when input is selected)")
        output_row.addWidget(self.bootmod_output, 1)
        
        output_browse = QPushButton("📁")
        output_browse.setMaximumWidth(40)
        output_browse.clicked.connect(lambda: self._browse_file(self.bootmod_output, "Image Files (*.img)"))
        output_row.addWidget(output_browse)
        output_layout.addLayout(output_row)
        
        # A/B Partition target selector
        ab_group = QGroupBox("🔀 Target Partition (A/B Slot)")
        ab_layout = QVBoxLayout(ab_group)
        
        ab_info = QLabel(
            "<span style='color: #888;'>Modern devices have A/B slots. "
            "Select which partition(s) to flash. If unsure, use "
            "<b>Detect from Device</b>.</span>"
        )
        ab_info.setWordWrap(True)
        ab_layout.addWidget(ab_info)
        
        target_row = QHBoxLayout()
        target_row.addWidget(QLabel("Partition:"))
        self.bootmod_partition = QComboBox()
        self.bootmod_partition.addItems(["boot", "boot_a", "boot_b"])
        self.bootmod_partition.setEditable(True)
        self.bootmod_partition.setToolTip(
            "The partition to flash the modified image to.\n"
            "Auto-updates based on partition type above.\n"
            "Use _a/_b suffixes for A/B devices."
        )
        target_row.addWidget(self.bootmod_partition, 1)
        
        detect_btn = QPushButton("🔍 Detect from Device")
        detect_btn.setToolTip("Query device for current slot and auto-configure")
        detect_btn.clicked.connect(self._detect_ab_slot)
        target_row.addWidget(detect_btn)
        ab_layout.addLayout(target_row)
        
        # A/B options row
        ab_opts_row = QHBoxLayout()
        self.bootmod_flash_both = QCheckBox("⚡ Flash BOTH slots (A and B)")
        self.bootmod_flash_both.setToolTip(
            "Flash the same modified image to both boot_a AND boot_b.\n"
            "Recommended when you want the mod regardless of which slot boots."
        )
        self.bootmod_flash_both.setStyleSheet("color: #f84; font-weight: bold;")
        ab_opts_row.addWidget(self.bootmod_flash_both)
        ab_opts_row.addStretch()
        ab_layout.addLayout(ab_opts_row)
        
        # Slot status label
        self.bootmod_slot_label = QLabel("")
        self.bootmod_slot_label.setStyleSheet("color: #888; padding: 2px;")
        ab_layout.addWidget(self.bootmod_slot_label)
        
        output_layout.addWidget(ab_group)
        
        # Flash after mod checkbox
        flash_row = QHBoxLayout()
        self.bootmod_auto_flash = QCheckBox("⚡ Flash to device after modification")
        self.bootmod_auto_flash.setToolTip("Automatically flash the modified boot.img to the selected partition via fastboot")
        self.bootmod_auto_flash.setStyleSheet("color: #4fc3f7;")
        flash_row.addWidget(self.bootmod_auto_flash)
        flash_row.addStretch()
        output_layout.addLayout(flash_row)
        
        layout.addWidget(output_group)
        
        # How it works info
        how_it_works = QLabel(
            "<b>How it works:</b><br>"
            "1. Detect image type (ANDROID! or VNDRBOOT magic) → unpack header<br>"
            "2. Extract and decompress ramdisk (gzip/lz4/zstd) → parse CPIO archive<br>"
            "3. Modify property files (default.prop), fstab, kernel cmdline, inject keys<br>"
            "4. Repack CPIO → recompress → rebuild image → optionally flash<br><br>"
            "<b>Which partition?</b><br>"
            "• <b>boot</b> — Most devices (pre-Android 13), kernel + init ramdisk<br>"
            "• <b>init_boot</b> — Android 13+ GKI devices, ramdisk moved here<br>"
            "• <b>vendor_boot</b> — Vendor ramdisk with device drivers/config<br><br>"
            "<span style='color: #f84;'>⚠️ Only works with unlocked bootloader. "
            "If Magisk is installed, use <b>your Magisk-patched image</b> as input!</span>"
        )
        how_it_works.setWordWrap(True)
        how_it_works.setStyleSheet("color: #888; padding: 8px; background: #1a1a2e; border-radius: 4px;")
        layout.addWidget(how_it_works)
        
        layout.addStretch()
        scroll.setWidget(scroll_widget)
        main_layout.addWidget(scroll)
        
        return tab
    
    def _on_partition_type_changed(self, idx):
        """Update UI when partition type selector changes."""
        ptype = self.bootmod_ptype_combo.currentData() or 'boot'
        
        # Update partition combo items
        self.bootmod_partition.clear()
        self.bootmod_partition.addItems([ptype, f"{ptype}_a", f"{ptype}_b"])
        
        # Update description based on selection
        descriptions = {
            'boot': (
                "<span style='color: #888;'>Standard boot.img — Contains kernel + ramdisk. "
                "Works for most devices pre-Android 13.</span>"
            ),
            'init_boot': (
                "<span style='color: #4fc3f7;'>⭐ <b>Init Boot (Android 13+ GKI)</b> — "
                "The REAL init ramdisk lives here on GKI devices.<br>"
                "If your boot.img ramdisk had only ~5 files, <b>this is what you need!</b></span>"
            ),
            'vendor_boot': (
                "<span style='color: #ff9800;'>📦 <b>Vendor Boot</b> — "
                "Vendor-specific ramdisk with device drivers and config.<br>"
                "Uses VNDRBOOT header format. For device-specific modifications.</span>"
            ),
        }
        self.bootmod_ptype_desc.setText(descriptions.get(ptype, descriptions['boot']))
        
        # Update input placeholder
        self.bootmod_input.setPlaceholderText(f"Select your {ptype}.img file...")
        
        # If A/B was previously detected, auto-update the partition selection
        if hasattr(self, '_bootmod_is_ab') and self._bootmod_is_ab and self._bootmod_current_slot:
            target = f"{ptype}_{self._bootmod_current_slot}"
            idx_t = self.bootmod_partition.findText(target)
            if idx_t >= 0:
                self.bootmod_partition.setCurrentIndex(idx_t)
    
    def _on_bootmod_input_changed(self, path):
        """Handle boot mod input file change — validate and pre-parse."""
        buttons = [
            self.btn_fix_adb, self.btn_full_rescue, self.btn_enable_adb,
            self.btn_usb_adb, self.btn_selinux, self.btn_verity,
            self.btn_inject_key, self.btn_apply_custom, self.btn_view_props,
            self.btn_view_ramdisk,
        ]
        
        if not path or not os.path.isfile(path):
            self.bootmod_info_label.setText("No boot image loaded")
            self.bootmod_info_label.setStyleSheet("color: #888; padding: 4px;")
            for btn in buttons:
                btn.setEnabled(False)
            return
        
        try:
            # Quick validation — check magic
            with open(path, 'rb') as f:
                magic = f.read(8)
            
            if magic not in (b'ANDROID!', b'VNDRBOOT'):
                self.bootmod_info_label.setText(f"❌ Not a valid boot/vendor_boot image (magic: {magic[:8].hex()})")
                self.bootmod_info_label.setStyleSheet("color: #f44; padding: 4px;")
                for btn in buttons:
                    btn.setEnabled(False)
                return
            
            # Try to parse to get info
            modifier = BootImageModifier(path)
            info = modifier.parse()
            
            size_kb = os.path.getsize(path) / 1024
            size_str = f"{size_kb / 1024:.1f} MB" if size_kb >= 1024 else f"{size_kb:.1f} KB"
            
            prop_count = len(modifier.get_current_props())
            fstab_count = len(modifier.cpio.get_fstab_files())
            
            img_type = "vendor_boot" if info.get('vendor_boot') else "boot"
            extra_info = ""
            if info.get('vendor_boot'):
                vname = info.get('vendor_name', '')
                bc_size = info.get('bootconfig_size', 0)
                extra_info = f", vendor={vname}" if vname else ""
                if bc_size > 0:
                    extra_info += f", bootconfig={bc_size}B"
            elif info['ramdisk_entries'] <= 5 and info['header_version'] >= 4:
                extra_info = " ⚠️ STUB RAMDISK — try init_boot instead!"
            
            self.bootmod_info_label.setText(
                f"✅ Valid {img_type} image ({size_str}) — "
                f"Header v{info['header_version']}, "
                f"{info['ramdisk_compression']} ramdisk, "
                f"{info['ramdisk_entries']} files, "
                f"{prop_count} props, "
                f"{fstab_count} fstab files{extra_info}"
            )
            self.bootmod_info_label.setStyleSheet("color: #4f4; padding: 4px;")
            
            # Enable all buttons
            for btn in buttons:
                btn.setEnabled(True)
            
            # Auto-set output path — ALWAYS update when input changes
            # to prevent stale output from previous image (e.g. boot_modded.img
            # lingering when user switches to init_boot.img)
            base = os.path.splitext(path)[0]
            self.bootmod_output.setText(f"{base}_modded.img")
            
            # Store parsed modifier for view operations
            self._bootmod_modifier = modifier
            
        except Exception as e:
            self.bootmod_info_label.setText(f"❌ Parse error: {e}")
            self.bootmod_info_label.setStyleSheet("color: #f44; padding: 4px;")
            for btn in buttons:
                btn.setEnabled(False)
    
    def _detect_ab_slot(self):
        """Detect A/B slot configuration from connected device."""
        device = self._get_device()
        if not device:
            QMessageBox.warning(self.parent_window, "Error", "No device connected in fastboot")
            return
        
        self._log("🔍 Detecting A/B slot configuration...")
        self.worker = FastbootWorkerThread("device_info", device=device, lg_safe=self.lg_safe_mode.isChecked())
        self.worker.result_data.connect(self._on_ab_detected)
        self.worker.finished_signal.connect(lambda s, m: None)
        self.worker.start()
    
    def _on_ab_detected(self, info: dict):
        """Handle A/B slot detection result."""
        slot_count = info.get('slot-count', info.get('slot_count', ''))
        current_slot = info.get('current-slot', info.get('current_slot', ''))
        
        # Clean up values
        if isinstance(current_slot, str):
            current_slot = current_slot.strip().lower().replace('_', '')
        if isinstance(slot_count, str):
            slot_count = slot_count.strip()
        
        if slot_count == '2' or current_slot in ('a', 'b'):
            # A/B device
            self._bootmod_is_ab = True
            self._bootmod_current_slot = current_slot or 'a'
            
            # Use selected partition type for target
            ptype = self.bootmod_ptype_combo.currentData() or 'boot'
            target = f"{ptype}_{self._bootmod_current_slot}"
            idx = self.bootmod_partition.findText(target)
            if idx >= 0:
                self.bootmod_partition.setCurrentIndex(idx)
            else:
                self.bootmod_partition.setEditText(target)
            
            other = 'b' if self._bootmod_current_slot == 'a' else 'a'
            self.bootmod_slot_label.setText(
                f"✅ A/B device detected — Current slot: <b>{self._bootmod_current_slot.upper()}</b> | "
                f"Will flash: <b>{target}</b>\n"
                f"💡 <span style='color: #f84;'>Don't forget to flash {ptype}_{other} too, "
                f"or check \"Flash BOTH slots\"!</span>"
            )
            self.bootmod_slot_label.setStyleSheet("color: #4fc3f7; padding: 2px;")
            self._log(f"🔀 A/B device: current-slot={self._bootmod_current_slot}, slot-count={slot_count}")
            self._log(f"💡 Target set to {target}. Check 'Flash BOTH slots' to cover both sides.")
        else:
            # A-only device
            ptype = self.bootmod_ptype_combo.currentData() or 'boot'
            self._bootmod_is_ab = False
            self._bootmod_current_slot = ''
            self.bootmod_partition.setCurrentIndex(0)  # First item (base partition)
            self.bootmod_slot_label.setText(f"ℹ️ A-only device (no A/B slots). Target: <b>{ptype}</b>")
            self.bootmod_slot_label.setStyleSheet("color: #888; padding: 2px;")
            self._log(f"ℹ️ Device does not have A/B slots. Using '{ptype}' partition.")
    
    def _fetch_boot_for_mod(self):
        """Fetch boot partition from device for modification (slot-aware)."""
        device = self._get_device()
        if not device:
            QMessageBox.warning(self.parent_window, "Error", "No device connected in fastboot")
            return
        
        # Use the selected partition from the target selector
        partition = self.bootmod_partition.currentText().strip() or 'boot'
        
        # Save to temp location
        out_dir = tempfile.mkdtemp(prefix="ia_bootmod_")
        out_path = os.path.join(out_dir, f"{partition}.img")
        
        self._log(f"📥 Fetching {partition} partition from device...")
        self.worker = FastbootWorkerThread("fetch", device=device, partition=partition, output_path=out_path)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._on_boot_fetched(s, m, out_path))
        self.worker.start()
    
    def _on_boot_fetched(self, success, message, path):
        """Handle fetched boot image."""
        if success and os.path.isfile(path) and os.path.getsize(path) > 0:
            self.bootmod_input.setText(path)
            self._log(f"✅ Boot image fetched: {path}")
        else:
            self._log(f"❌ Failed to fetch boot: {message}")
            self._log("💡 Tip: 'fastboot fetch' isn't supported on all devices. "
                      "Try fetching via ADB in recovery instead.")
    
    def _run_boot_mod(self, mod_type: str):
        """Run a boot image modification."""
        input_path = self.bootmod_input.text()
        if not input_path or not os.path.isfile(input_path):
            QMessageBox.warning(self.parent_window, "Error", "Please select a valid boot image")
            return
        
        output_path = self.bootmod_output.text()
        if not output_path:
            base = os.path.splitext(input_path)[0]
            output_path = f"{base}_modded.img"
            self.bootmod_output.setText(output_path)
        
        # Confirm
        mod_names = {
            'fix_adb': 'Fix ADB Access (disable auth, enable debugging, set USB=ADB)',
            'full_rescue': 'FULL RESCUE (ADB + SELinux permissive + disable verity + inject key)',
            'enable_adb': 'Enable ADB without authorization',
            'usb_adb_default': 'Set USB config to MTP+ADB by default',
            'selinux_permissive': 'Set SELinux to permissive mode',
            'patch_verity': 'Remove dm-verity from fstab',
            'inject_key': 'Inject ADB public key into ramdisk',
        }
        
        flash_after = self.bootmod_auto_flash.isChecked()
        device = self._get_device() if flash_after else None
        flash_both = self.bootmod_flash_both.isChecked() if flash_after else False
        target_partition = self.bootmod_partition.currentText().strip() or 'boot'
        
        msg = (
            f"Modification: {mod_names.get(mod_type, mod_type)}\n\n"
            f"Input: {os.path.basename(input_path)}\n"
            f"Output: {os.path.basename(output_path)}\n"
        )
        partition_type = self.bootmod_ptype_combo.currentData() or 'boot'
        
        if flash_after:
            if flash_both:
                # Derive both slot names - only strip trailing slot suffix
                base_part = re.sub(r'_(a|b)$', '', target_partition)
                msg += (f"\n⚡ Will flash to BOTH slots: {base_part}_a AND {base_part}_b!"
                        f"\nDevice: {device}\n")
            else:
                msg += f"\n⚡ Will flash to {target_partition} after modification!\nDevice: {device}\n"
            
        msg += "\nContinue?"
        
        reply = QMessageBox.question(
            self.parent_window, "Confirm Boot Modification", msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # Get ADB key path
        adb_key_path = self.bootmod_adbkey.text().strip()
        if not adb_key_path or not os.path.isfile(adb_key_path):
            adb_key_path = None
        
        # Warn loudly if no ADB key for ADB-related mods
        if mod_type in ('fix_adb', 'full_rescue', 'inject_key') and adb_key_path is None:
            warn_reply = QMessageBox.warning(
                self.parent_window, "⚠️ No ADB Key — Auth Will Fail on Production Devices",
                "No ADB public key found!\n\n"
                "On production firmware (Pixel, Samsung, etc.), the ro.adb.secure=0\n"
                "property trick does NOT work — it's compiled out of the adbd binary.\n\n"
                "The ONLY way to authorize ADB without the on-screen dialog is to inject\n"
                "your PC's public key (adbkey.pub) into the ramdisk.\n\n"
                "Your key is usually at:\n"
                "  Windows: C:\\Users\\<you>\\.android\\adbkey.pub\n"
                "  Linux/Mac: ~/.android/adbkey.pub\n\n"
                "Generate one by running 'adb devices' on any connected Android device.\n\n"
                "Continue anyway? (Properties will still be set, but auth bypass\n"
                "will NOT work on production devices without the key)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if warn_reply != QMessageBox.StandardButton.Yes:
                return
        
        self._log(f"🛠️ Starting boot mod: {mod_names.get(mod_type, mod_type)}")
        
        self.worker = FastbootWorkerThread(
            "boot_mod",
            mod_type=mod_type,
            input_path=input_path,
            output_path=output_path,
            adb_key_path=adb_key_path,
        )
        self.worker.log.connect(self._log)
        self.worker.result_data.connect(
            lambda r: self._on_boot_mod_complete(
                r, flash_after, target_partition, flash_both,
                mod_type=mod_type, partition_type=partition_type
            )
        )
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _on_boot_mod_complete(self, result, flash_after, target_partition='boot', flash_both=False,
                               mod_type='', partition_type='boot'):
        """Handle boot mod completion — flash to target partition(s) with A/B awareness."""
        if not isinstance(result, dict):
            return
        
        output_path = result.get('output_path', '')
        
        if flash_after and output_path and os.path.isfile(output_path):
            device = self._get_device()
            if device:
                if flash_both:
                    # Flash both slots sequentially - only strip trailing slot suffix
                    base_part = re.sub(r'_(a|b)$', '', target_partition)
                    self._flash_boot_mod_slot(
                        device, output_path,
                        slot_a=f"{base_part}_a",
                        slot_b=f"{base_part}_b",
                    )
                else:
                    # Flash single partition
                    self._flash_boot_mod_slot(device, output_path, slot_a=target_partition)
            else:
                self._log("⚠️ No device connected — modified image saved but not flashed")
    
    def _flash_boot_mod_slot(self, device, image_path, slot_a, slot_b=None):
        """Flash modified boot image to one or two slots."""
        self._log(f"⚡ Flashing modified image to {slot_a}...")
        self.worker = FastbootWorkerThread("flash", device=device, partition=slot_a, image_path=image_path)
        self.worker.log.connect(self._log)
        
        if slot_b:
            # After slot_a finishes, chain flash to slot_b
            self.worker.finished_signal.connect(
                lambda s, m: self._on_slot_a_flashed(s, m, device, image_path, slot_a, slot_b)
            )
        else:
            # Single slot — done after this
            self.worker.finished_signal.connect(
                lambda s, m: self._on_single_slot_flashed(s, m, slot_a)
            )
        self.worker.start()
    
    def _on_slot_a_flashed(self, success, message, device, image_path, slot_a, slot_b):
        """Slot A flashed — now flash slot B."""
        if success or 'OKAY' in str(message):
            self._log(f"✅ {slot_a} flashed successfully")
            self._log(f"⚡ Now flashing {slot_b}...")
            
            self.worker = FastbootWorkerThread("flash", device=device, partition=slot_b, image_path=image_path)
            self.worker.log.connect(self._log)
            self.worker.finished_signal.connect(
                lambda s, m: self._on_both_slots_flashed(s, m, slot_a, slot_b)
            )
            self.worker.start()
        else:
            self._log(f"❌ Failed to flash {slot_a}: {message}")
            self._log(f"⚠️ {slot_b} was NOT flashed. Fix the issue and try again.")
    
    def _on_both_slots_flashed(self, success, message, slot_a, slot_b):
        """Both A/B slots flashed."""
        if success or 'OKAY' in str(message):
            self._log(f"✅ {slot_b} flashed successfully")
            self._log(f"🎉 Both {slot_a} and {slot_b} flashed! Reboot to apply.")
        else:
            self._log(f"❌ Failed to flash {slot_b}: {message}")
            self._log(f"⚠️ {slot_a} was flashed but {slot_b} FAILED. Flash {slot_b} manually!")
    
    def _auto_patch_boot_cmdline(self):
        """Auto-fetch boot.img, patch kernel cmdline for ADB, and flash both slots.
        
        On Android 13+ GKI, the kernel cmdline lives in boot.img (not init_boot).
        The bootloader sets androidboot.adb.secure=1 there, and since ro.boot.*
        properties are read-only once set, nothing in init_boot's ramdisk can
        override it. This method patches boot.img's cmdline directly.
        """
        device = self._get_device()
        if not device:
            self._log("⚠️ No device for boot.img cmdline patch — do it manually")
            return
        
        self._log("")
        self._log("🔄 ══════════════════════════════════════════════")
        self._log("🔄 AUTO-PATCHING boot.img KERNEL CMDLINE")
        self._log("🔄 (Required for ADB auth bypass on GKI devices)")
        self._log("🔄 ══════════════════════════════════════════════")
        
        # Fetch boot_a
        import tempfile
        boot_dir = tempfile.mkdtemp(prefix='ia_boot_cmdline_')
        boot_path = os.path.join(boot_dir, 'boot.img')
        boot_modded = os.path.join(boot_dir, 'boot_modded.img')
        
        self._log(f"📥 Fetching boot_a from device...")
        self.worker = FastbootWorkerThread(
            "fetch",
            device=device,
            partition='boot_a',
            output_path=boot_path,
        )
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(
            lambda s, m: self._on_boot_fetched_for_cmdline(s, m, device, boot_path, boot_modded)
        )
        self.worker.start()
    
    def _on_boot_fetched_for_cmdline(self, success, message, device, boot_path, boot_modded):
        """boot.img fetched — now patch cmdline and flash."""
        if not success and not os.path.isfile(boot_path):
            self._log(f"⚠️ Could not fetch boot.img: {message}")
            self._log("⚠️ You need to manually patch boot.img cmdline for ADB auth bypass.")
            self._log("⚠️ Switch partition type to 'boot', fetch, run Fix ADB, flash both slots.")
            return
        
        try:
            self._log("🔧 Patching boot.img kernel cmdline...")
            modifier = BootImageModifier(boot_path)
            info = modifier.parse()
            
            self._log(f"  Header v{info['header_version']}, cmdline: {modifier.cmdline[:80]}...")
            
            # Only patch cmdline — do NOT touch the ramdisk (it's a GKI stub)
            changes = modifier.modify_cmdline(
                additions=['androidboot.adb.secure=0'],
                removals=['androidboot.adb.secure=1']
            )
            for c in changes:
                self._log(f"  ✓ {c}")
            
            modifier.save(boot_modded)
            self._log(f"💾 Saved patched boot.img ({os.path.getsize(boot_modded) / (1024*1024):.1f} MB)")
            
            # Flash boot_a and boot_b
            self._log("⚡ Flashing patched boot.img to both slots...")
            self._flash_boot_mod_slot(
                device, boot_modded,
                slot_a='boot_a',
                slot_b='boot_b',
            )
            
        except Exception as e:
            self._log(f"❌ boot.img cmdline patch failed: {e}")
            self._log("⚠️ Manually: switch to 'boot' partition type → Fetch → Fix ADB → Flash both")
            import traceback
            traceback.print_exc()
    
    def _on_single_slot_flashed(self, success, message, partition):
        """Single partition flash completed — prompt for other slot if A/B."""
        if success or 'OKAY' in str(message):
            self._log(f"✅ {partition} flashed! Reboot to apply.")
            
            # If this was an A/B slot, remind about the other one
            if partition.endswith('_a'):
                other = partition.replace('_a', '_b')
                self._log(
                    f"<span style='color: #f84; font-weight: bold;'>"
                    f"⚠️ Remember: You only flashed {partition}. "
                    f"If you want the mod on BOTH slots, you still need to flash {other}!</span>"
                )
                # Auto-update the partition selector to the other slot
                idx = self.bootmod_partition.findText(other)
                if idx >= 0:
                    self.bootmod_partition.setCurrentIndex(idx)
                else:
                    self.bootmod_partition.setEditText(other)
                self.bootmod_slot_label.setText(
                    f"🔀 <b>{partition}</b> done → Target auto-switched to <b>{other}</b>. "
                    f"Flash again to cover both slots!"
                )
                self.bootmod_slot_label.setStyleSheet("color: #f84; padding: 2px; font-weight: bold;")
            elif partition.endswith('_b'):
                other = partition.replace('_b', '_a')
                self._log(
                    f"<span style='color: #f84; font-weight: bold;'>"
                    f"⚠️ Remember: You only flashed {partition}. "
                    f"If you want the mod on BOTH slots, you still need to flash {other}!</span>"
                )
                idx = self.bootmod_partition.findText(other)
                if idx >= 0:
                    self.bootmod_partition.setCurrentIndex(idx)
                else:
                    self.bootmod_partition.setEditText(other)
                self.bootmod_slot_label.setText(
                    f"🔀 <b>{partition}</b> done → Target auto-switched to <b>{other}</b>. "
                    f"Flash again to cover both slots!"
                )
                self.bootmod_slot_label.setStyleSheet("color: #f84; padding: 2px; font-weight: bold;")
        else:
            self._log(f"❌ Flash failed for {partition}: {message}")
    
    def _apply_custom_props(self):
        """Apply custom properties from the text editor."""
        text = self.bootmod_custom_props.toPlainText().strip()
        if not text:
            QMessageBox.warning(self.parent_window, "Error", "Enter properties in key=value format, one per line")
            return
        
        # Parse custom props
        custom_props = {}
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, _, value = line.partition('=')
                custom_props[key.strip()] = value.strip()
        
        if not custom_props:
            QMessageBox.warning(self.parent_window, "Error", "No valid key=value pairs found")
            return
        
        input_path = self.bootmod_input.text()
        output_path = self.bootmod_output.text()
        if not output_path:
            base = os.path.splitext(input_path)[0]
            output_path = f"{base}_modded.img"
            self.bootmod_output.setText(output_path)
        
        self._log(f"📝 Applying {len(custom_props)} custom props...")
        
        self.worker = FastbootWorkerThread(
            "boot_mod",
            mod_type='custom_props',
            input_path=input_path,
            output_path=output_path,
            custom_props=custom_props,
        )
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _view_current_props(self):
        """Show current properties from the loaded boot image."""
        if not hasattr(self, '_bootmod_modifier') or self._bootmod_modifier is None:
            return
        
        props = self._bootmod_modifier.get_current_props()
        if not props:
            self._log("No properties found in ramdisk")
            return
        
        self._log(f"📋 Current boot image properties ({len(props)} total):")
        for key in sorted(props.keys()):
            value = props[key]
            # Highlight security-relevant props
            if any(k in key for k in ['adb', 'debug', 'secure', 'selinux', 'usb']):
                self._log(f"  <span style='color: #ff0;'>{key}={value}</span>")
            else:
                self._log(f"  {key}={value}")
    
    def _view_ramdisk_files(self):
        """List all files in the ramdisk."""
        if not hasattr(self, '_bootmod_modifier') or self._bootmod_modifier is None:
            return
        
        files = self._bootmod_modifier.list_ramdisk_files()
        self._log(f"📂 Ramdisk contents ({len(files)} entries):")
        for f in sorted(files):
            entry = self._bootmod_modifier.cpio.find_entry(f)
            if entry and entry.is_dir:
                self._log(f"  📁 {f}/")
            elif entry and entry.is_symlink:
                target = entry.data.decode('utf-8', errors='replace')
                self._log(f"  🔗 {f} → {target}")
            else:
                size = len(entry.data) if entry else 0
                self._log(f"  📄 {f} ({size} bytes)")
    
    # ===== FETCH TAB =====
    def _create_fetch_tab(self):
        tab = QWidget()
        main_layout = QVBoxLayout(tab)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Use scroll area for content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        
        scroll_content = QWidget()
        layout = QVBoxLayout(scroll_content)
        layout.setSpacing(8)
        
        layout.addWidget(QLabel("Download partition images from device (requires unlocked bootloader)"))
        
        # Partition list from device
        list_group = QGroupBox("Device Partitions")
        list_layout = QVBoxLayout(list_group)
        
        self.fb_partition_list = QListWidget()
        self.fb_partition_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.fb_partition_list.setMinimumHeight(100)
        self.fb_partition_list.setMaximumHeight(150)
        self.fb_partition_list.itemDoubleClicked.connect(self._on_partition_double_click)
        list_layout.addWidget(self.fb_partition_list)
        
        list_btn_row = QHBoxLayout()
        list_refresh_btn = QPushButton("🔄 List Partitions")
        list_refresh_btn.clicked.connect(self._list_partitions)
        list_btn_row.addWidget(list_refresh_btn)
        
        fetch_selected_btn = QPushButton("📥 Fetch Selected")
        fetch_selected_btn.clicked.connect(self._fetch_selected_partitions)
        list_btn_row.addWidget(fetch_selected_btn)
        list_btn_row.addStretch()
        list_layout.addLayout(list_btn_row)
        
        layout.addWidget(list_group)
        
        # Manual fetch section
        self._fetch_group = QGroupBox("Manual Fetch")
        fetch_layout = QVBoxLayout(self._fetch_group)
        
        # Partition input row
        part_row = QHBoxLayout()
        part_row.addWidget(QLabel("Partition:"))
        self.fetch_partition = QLineEdit()
        self.fetch_partition.setPlaceholderText("e.g., boot, recovery, vbmeta")
        part_row.addWidget(self.fetch_partition)
        fetch_layout.addLayout(part_row)
        
        # Output row (will be hidden when setup directories active)
        self._fetch_output_row = QWidget()
        output_row_layout = QHBoxLayout(self._fetch_output_row)
        output_row_layout.setContentsMargins(0, 0, 0, 0)
        output_row_layout.addWidget(QLabel("Output Dir:"))
        self.fetch_output = QLineEdit(os.path.expanduser("~"))
        output_row_layout.addWidget(self.fetch_output)
        fetch_browse = QPushButton("Browse...")
        fetch_browse.clicked.connect(lambda: self._browse_dir(self.fetch_output))
        output_row_layout.addWidget(fetch_browse)
        fetch_layout.addWidget(self._fetch_output_row)
        
        # Setup directories indicator (hidden by default)
        self._fb_setup_indicator = QLabel()
        self._fb_setup_indicator.setStyleSheet("background: #2e7d32; color: white; padding: 8px; border-radius: 4px;")
        self._fb_setup_indicator.setVisible(False)
        fetch_layout.addWidget(self._fb_setup_indicator)
        
        # Progress bar
        progress_row = QHBoxLayout()
        progress_row.addWidget(QLabel("Progress:"))
        self.fetch_progress = QProgressBar()
        progress_row.addWidget(self.fetch_progress)
        fetch_layout.addLayout(progress_row)
        
        fetch_btn = QPushButton("📥 Fetch Partition")
        fetch_btn.clicked.connect(self._fetch_partition)
        fetch_layout.addWidget(fetch_btn)
        
        layout.addWidget(self._fetch_group)
        
        # Quick fetch
        quick_group = QGroupBox("Quick Fetch")
        quick_layout = QHBoxLayout(quick_group)
        for part in ["boot", "recovery", "vbmeta", "dtbo"]:
            btn = QPushButton(f"📥 {part}")
            btn.clicked.connect(lambda c, p=part: self._quick_fetch(p))
            quick_layout.addWidget(btn)
        layout.addWidget(quick_group)
        
        # Setup Directories - creates folders for common partitions
        setup_group = QGroupBox("Setup Directories")
        setup_layout = QVBoxLayout(setup_group)
        setup_layout.addWidget(QLabel("Create folders for each partition in a selected directory."))
        
        setup_btn_row = QHBoxLayout()
        self.setup_dirs_btn = QPushButton("📁 Setup Directories (Common)")
        self.setup_dirs_btn.setToolTip("Create folders for common Android partitions")
        self.setup_dirs_btn.clicked.connect(self._setup_partition_directories)
        setup_btn_row.addWidget(self.setup_dirs_btn)
        
        self.setup_dirs_device_btn = QPushButton("📁 Setup Directories (From Device)")
        self.setup_dirs_device_btn.setToolTip("Create folders based on partitions detected from device")
        self.setup_dirs_device_btn.clicked.connect(self._setup_device_partition_directories)
        self.setup_dirs_device_btn.setEnabled(False)
        setup_btn_row.addWidget(self.setup_dirs_device_btn)
        
        self._fb_clear_setup_btn = QPushButton("✕ Clear Setup")
        self._fb_clear_setup_btn.setToolTip("Return to manual output directory mode")
        self._fb_clear_setup_btn.clicked.connect(self._clear_fb_setup_directories)
        self._fb_clear_setup_btn.setVisible(False)
        setup_btn_row.addWidget(self._fb_clear_setup_btn)
        
        setup_layout.addLayout(setup_btn_row)
        layout.addWidget(setup_group)
        
        # Initialize setup directories base path
        self._fb_setup_base_dir = None
        
        layout.addStretch()
        
        scroll.setWidget(scroll_content)
        main_layout.addWidget(scroll)
        return tab
    
    def _list_partitions(self):
        """List partitions from device using getvar all."""
        device = self._get_device()
        if not device:
            QMessageBox.warning(self.parent_window, "Error", "No device connected in fastboot mode")
            return
        
        lg_safe = self.lg_safe_mode.isChecked()
        self._log(f"Listing partitions from device...{' (LG Safe Mode)' if lg_safe else ''}")
        self.worker = FastbootWorkerThread("list_partitions", device=device, lg_safe=lg_safe)
        self.worker.result_data.connect(self._on_partitions_found)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _on_partitions_found(self, partitions):
        """Handle partition list results."""
        self.fb_partition_list.clear()
        self._fb_loaded_partitions = partitions  # Store for Setup Directories
        
        for p in partitions:
            item = QListWidgetItem(f"{p['name']} ({p['size']})")
            item.setData(Qt.ItemDataRole.UserRole, p)
            self.fb_partition_list.addItem(item)
        
        # Enable device-based Setup Directories button
        if hasattr(self, 'setup_dirs_device_btn'):
            self.setup_dirs_device_btn.setEnabled(len(partitions) > 0)
    
    def _on_partition_double_click(self, item):
        """Double-click partition to fill in fetch field."""
        data = item.data(Qt.ItemDataRole.UserRole)
        if data:
            self.fetch_partition.setText(data['name'])
    
    def _fetch_selected_partitions(self):
        """Fetch all selected partitions."""
        device = self._get_device()
        if not device:
            return
        
        selected = self.fb_partition_list.selectedItems()
        if not selected:
            QMessageBox.warning(self.parent_window, "Error", "Select partitions first")
            return
        
        # Fetch first selected - set the partition name and let _fetch_partition handle directory logic
        data = selected[0].data(Qt.ItemDataRole.UserRole)
        self.fetch_partition.setText(data['name'])
        self._fetch_partition()
    
    def _setup_device_partition_directories(self):
        """Create directories for partitions detected from device."""
        if not hasattr(self, '_fb_loaded_partitions') or not self._fb_loaded_partitions:
            QMessageBox.warning(self.parent_window, "No Partitions", 
                "No partitions loaded. Please list partitions first.")
            return
        
        base_dir = QFileDialog.getExistingDirectory(
            self.parent_window,
            "Select Base Directory for Partition Folders",
            os.path.expanduser("~"),
            QFileDialog.Option.ShowDirsOnly
        )
        
        if not base_dir:
            return
        
        created = []
        errors = []
        for partition in self._fb_loaded_partitions:
            part_name = partition['name']
            part_dir = os.path.join(base_dir, part_name)
            try:
                os.makedirs(part_dir, exist_ok=True)
                created.append(part_name)
            except Exception as e:
                errors.append(f"{part_name}: {str(e)}")
        
        if created:
            self._log(f"✓ Created {len(created)} partition directories in {base_dir}")
            
            # Activate setup directories mode
            self._fb_setup_base_dir = base_dir
            self._fetch_output_row.setVisible(False)
            self._fb_setup_indicator.setText(f"📁 Setup Active: {base_dir}\n   Each partition will be saved to its own folder")
            self._fb_setup_indicator.setVisible(True)
            self._fb_clear_setup_btn.setVisible(True)
            self.setup_dirs_btn.setEnabled(False)
            self.setup_dirs_device_btn.setEnabled(False)
            
            msg = f"✓ Setup Directories Active!\\n\\n"
            msg += f"📁 Base: {base_dir}\\n"
            msg += f"   Created {len(created)} folders\\n\\n"
            msg += "Partitions will now be fetched to their own folders:\\n"
            msg += f"   • boot → {base_dir}/boot/boot.img\\n"
            msg += f"   • recovery → {base_dir}/recovery/recovery.img\\n"
            msg += "   etc..."
            
            if errors:
                msg += f"\\n\\n⚠️ {len(errors)} errors:\\n" + "\\n".join(errors[:5])
            
            QMessageBox.information(self.parent_window, "Setup Directories Active", msg)
        elif errors:
            QMessageBox.warning(self.parent_window, "Error", 
                f"Failed to create directories:\\n" + "\\n".join(errors[:10]))
    
    def _clear_fb_setup_directories(self):
        """Clear setup directories mode and return to manual output."""
        self._fb_setup_base_dir = None
        self._fetch_output_row.setVisible(True)
        self._fb_setup_indicator.setVisible(False)
        self._fb_clear_setup_btn.setVisible(False)
        self.setup_dirs_btn.setEnabled(True)
        if hasattr(self, '_fb_loaded_partitions') and self._fb_loaded_partitions:
            self.setup_dirs_device_btn.setEnabled(True)
        self._log("Setup Directories mode cleared - using manual output directory")
    
    def _quick_fetch(self, partition):
        self.fetch_partition.setText(partition)
        self._fetch_partition()
    
    def _setup_partition_directories(self):
        """Create a directory for each common partition in a user-selected folder."""
        # Common Android partitions that users typically work with
        common_partitions = [
            "boot", "boot_a", "boot_b",
            "init_boot", "init_boot_a", "init_boot_b",
            "recovery", "recovery_a", "recovery_b",
            "vendor_boot", "vendor_boot_a", "vendor_boot_b",
            "vbmeta", "vbmeta_a", "vbmeta_b",
            "vbmeta_system", "vbmeta_system_a", "vbmeta_system_b",
            "dtbo", "dtbo_a", "dtbo_b",
            "super", "system", "system_a", "system_b",
            "vendor", "vendor_a", "vendor_b",
            "product", "product_a", "product_b",
            "odm", "odm_a", "odm_b",
            "system_ext", "system_ext_a", "system_ext_b",
            "cache", "userdata", "metadata", "persist",
            "modem", "modem_a", "modem_b",
            "abl", "abl_a", "abl_b",
            "xbl", "xbl_a", "xbl_b",
            "tz", "tz_a", "tz_b",
            "hyp", "hyp_a", "hyp_b",
            "keymaster", "keymaster_a", "keymaster_b",
            "cmnlib", "cmnlib_a", "cmnlib_b",
            "devcfg", "devcfg_a", "devcfg_b",
            "dsp", "dsp_a", "dsp_b",
            "bluetooth", "bluetooth_a", "bluetooth_b",
            "logo", "splash", "misc", "frp"
        ]
        
        # Ask user to select base directory
        base_dir = QFileDialog.getExistingDirectory(
            self.parent_window,
            "Select Base Directory for Partition Folders",
            os.path.expanduser("~"),
            QFileDialog.Option.ShowDirsOnly
        )
        
        if not base_dir:
            return
        
        # Create directories
        created = []
        errors = []
        for part_name in common_partitions:
            part_dir = os.path.join(base_dir, part_name)
            try:
                os.makedirs(part_dir, exist_ok=True)
                created.append(part_name)
            except Exception as e:
                errors.append(f"{part_name}: {str(e)}")
        
        # Report results and activate setup mode
        if created:
            self._log(f"✓ Created {len(created)} partition directories in {base_dir}")
            
            # Activate setup directories mode
            self._fb_setup_base_dir = base_dir
            self._fetch_output_row.setVisible(False)
            self._fb_setup_indicator.setText(f"📁 Setup Active: {base_dir}\\n   Each partition will be saved to its own folder")
            self._fb_setup_indicator.setVisible(True)
            self._fb_clear_setup_btn.setVisible(True)
            self.setup_dirs_btn.setEnabled(False)
            self.setup_dirs_device_btn.setEnabled(False)
            
            msg = f"✓ Setup Directories Active!\\n\\n"
            msg += f"📁 Base: {base_dir}\\n"
            msg += f"   Created {len(created)} folders\\n\\n"
            msg += "Partitions will now be fetched to their own folders:\\n"
            msg += f"   • boot → {base_dir}/boot/boot.img\\n"
            msg += f"   • recovery → {base_dir}/recovery/recovery.img\\n"
            msg += "   etc..."
            
            if errors:
                msg += f"\\n\\n⚠️ {len(errors)} errors:\\n" + "\\n".join(errors[:5])
            
            QMessageBox.information(self.parent_window, "Setup Directories Active", msg)
        elif errors:
            QMessageBox.warning(self.parent_window, "Error", 
                f"Failed to create directories:\\n" + "\\n".join(errors[:10]))
    
    def _fetch_partition(self):
        device = self._get_device()
        partition = self.fetch_partition.text()
        
        if not device or not partition:
            return
        
        # Determine base output directory
        if hasattr(self, '_fb_setup_base_dir') and self._fb_setup_base_dir:
            base_output_dir = self._fb_setup_base_dir
        else:
            base_output_dir = self.fetch_output.text()
        
        # Always create partition-specific subfolder (e.g., output/boot/ for boot.img)
        output_dir = os.path.join(base_output_dir, partition)
        os.makedirs(output_dir, exist_ok=True)
        
        output_path = os.path.join(output_dir, f"{partition}.img")
        
        self.worker = FastbootWorkerThread("fetch", device=device, partition=partition, output_path=output_path)
        self.worker.log.connect(self._log)
        self.worker.progress.connect(lambda c, t, m: self.fetch_progress.setValue(c))
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== ERASE TAB =====
    def _create_erase_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        warning = QLabel("⚠️ DANGER: Erasing partitions can make your device unbootable!")
        warning.setStyleSheet("color: #ff4444; font-weight: bold;")
        layout.addWidget(warning)
        
        erase_group = QGroupBox("Erase Partition")
        erase_layout = QFormLayout(erase_group)
        
        self.erase_partition = QLineEdit()
        self.erase_partition.setPlaceholderText("e.g., userdata, cache")
        erase_layout.addRow("Partition:", self.erase_partition)
        
        erase_btn = QPushButton("🗑️ Erase Partition")
        erase_btn.setStyleSheet("background: #b71c1c; font-weight: bold;")
        erase_btn.clicked.connect(self._erase_partition)
        erase_layout.addRow("", erase_btn)
        
        layout.addWidget(erase_group)
        
        # Format data
        format_group = QGroupBox("Format Data (Factory Reset)")
        format_layout = QVBoxLayout(format_group)
        
        format_btn = QPushButton("🗑️ Format Userdata (Factory Reset)")
        format_btn.setStyleSheet("background: #b71c1c;")
        format_btn.clicked.connect(self._format_data)
        format_layout.addWidget(format_btn)
        
        format_layout.addWidget(QLabel("This will erase ALL user data, apps, and settings!"))
        layout.addWidget(format_group)
        
        layout.addStretch()
        return tab
    
    def _erase_partition(self):
        device = self._get_device()
        partition = self.erase_partition.text()
        
        if not device or not partition:
            return
        
        reply = QMessageBox.question(
            self.parent_window, "⚠️ Confirm Erase",
            f"ERASE partition '{partition}'?\n\nThis CANNOT be undone!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = FastbootWorkerThread("erase", device=device, partition=partition)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _format_data(self):
        device = self._get_device()
        if not device:
            return
        
        reply = QMessageBox.question(
            self.parent_window, "⚠️ Factory Reset",
            "This will ERASE ALL USER DATA!\n\nPhotos, apps, settings - EVERYTHING!\n\nAre you absolutely sure?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = FastbootWorkerThread("erase", device=device, partition="userdata")
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== PATCH TAB =====
    def _create_patch_tab(self):
        """Create vbmeta patching tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Info header
        info_label = QLabel(
            "🔧 <b>vbmeta Patcher</b> - Disable dm-verity and AVB verification<br>"
            "<span style='color: #FFA500;'>⚠️ Bootloader must be unlocked to use patched vbmeta</span>"
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Input file selection
        input_group = QGroupBox("Input vbmeta Image")
        input_layout = QHBoxLayout(input_group)
        
        self.patch_input_edit = QLineEdit()
        self.patch_input_edit.setPlaceholderText("Select vbmeta.img file...")
        self.patch_input_edit.textChanged.connect(self._on_patch_input_changed)
        input_layout.addWidget(self.patch_input_edit, 1)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(lambda: self._browse_file(self.patch_input_edit, "Image Files (*.img);;All Files (*)"))
        input_layout.addWidget(browse_btn)
        
        layout.addWidget(input_group)
        
        # Current vbmeta info display
        self.patch_info_group = QGroupBox("Current vbmeta Status")
        info_layout = QVBoxLayout(self.patch_info_group)
        
        self.patch_status_label = QLabel("No file selected")
        self.patch_status_label.setStyleSheet("color: #888;")
        info_layout.addWidget(self.patch_status_label)
        
        self.patch_flags_label = QLabel("")
        info_layout.addWidget(self.patch_flags_label)
        
        layout.addWidget(self.patch_info_group)
        
        # Patch options
        options_group = QGroupBox("Patch Options")
        options_layout = QVBoxLayout(options_group)
        
        self.disable_verity_check = QCheckBox("Disable dm-verity (--disable-verity)")
        self.disable_verity_check.setToolTip(
            "Disables dm-verity hashtree verification.\n"
            "Allows modifying system/vendor partitions without boot failure."
        )
        self.disable_verity_check.setChecked(True)
        options_layout.addWidget(self.disable_verity_check)
        
        self.disable_verification_check = QCheckBox("Disable AVB verification (--disable-verification)")
        self.disable_verification_check.setToolTip(
            "Disables Android Verified Boot signature checking.\n"
            "Required when using modified boot/system images."
        )
        self.disable_verification_check.setChecked(True)
        options_layout.addWidget(self.disable_verification_check)
        
        layout.addWidget(options_group)
        
        # Output options
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout(output_group)
        
        output_row = QHBoxLayout()
        self.patch_output_edit = QLineEdit()
        self.patch_output_edit.setPlaceholderText("Output path (default: vbmeta_patched.img)")
        output_row.addWidget(self.patch_output_edit, 1)
        
        output_browse_btn = QPushButton("📁 Browse")
        output_browse_btn.clicked.connect(self._browse_patch_output)
        output_row.addWidget(output_browse_btn)
        output_layout.addLayout(output_row)
        
        layout.addWidget(output_group)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        self.patch_btn = QPushButton("🔧 Patch vbmeta")
        self.patch_btn.setMinimumHeight(40)
        self.patch_btn.setStyleSheet("font-weight: bold; font-size: 13px;")
        self.patch_btn.clicked.connect(self._patch_vbmeta)
        self.patch_btn.setEnabled(False)
        btn_layout.addWidget(self.patch_btn)
        
        self.patch_and_flash_btn = QPushButton("⚡ Patch && Flash")
        self.patch_and_flash_btn.setMinimumHeight(40)
        self.patch_and_flash_btn.setToolTip("Patch the vbmeta and immediately flash it to the device")
        self.patch_and_flash_btn.clicked.connect(self._patch_and_flash_vbmeta)
        self.patch_and_flash_btn.setEnabled(False)
        btn_layout.addWidget(self.patch_and_flash_btn)
        
        layout.addLayout(btn_layout)
        
        layout.addStretch()
        return tab
    
    def _on_patch_input_changed(self, path):
        """Handle patch input file selection."""
        if not path or not os.path.isfile(path):
            self.patch_status_label.setText("No file selected")
            self.patch_status_label.setStyleSheet("color: #888;")
            self.patch_flags_label.setText("")
            self.patch_btn.setEnabled(False)
            self.patch_and_flash_btn.setEnabled(False)
            return
        
        # Analyze the vbmeta
        patcher = VbmetaPatcher(path)
        info = patcher.get_info()
        
        if not info.get('valid', False):
            self.patch_status_label.setText(f"❌ Invalid: {info.get('error', 'Unknown error')}")
            self.patch_status_label.setStyleSheet("color: #f44;")
            self.patch_flags_label.setText("")
            self.patch_btn.setEnabled(False)
            self.patch_and_flash_btn.setEnabled(False)
            return
        
        # Show current status
        size_kb = info['size'] / 1024
        self.patch_status_label.setText(f"✅ Valid vbmeta image ({size_kb:.1f} KB)")
        self.patch_status_label.setStyleSheet("color: #4f4;")
        
        # Show flag status
        flags_text = f"Current flags: 0x{info['flags']:02X}"
        flag_details = []
        if info['verity_disabled']:
            flag_details.append("🔓 Verity DISABLED")
            self.disable_verity_check.setChecked(True)
        else:
            flag_details.append("🔒 Verity enabled")
        
        if info['verification_disabled']:
            flag_details.append("🔓 Verification DISABLED")
            self.disable_verification_check.setChecked(True)
        else:
            flag_details.append("🔒 Verification enabled")
        
        self.patch_flags_label.setText(f"{flags_text}  •  {' | '.join(flag_details)}")
        
        self.patch_btn.setEnabled(True)
        self.patch_and_flash_btn.setEnabled(True)
        
        # Set default output path
        if not self.patch_output_edit.text():
            base = os.path.splitext(path)[0]
            self.patch_output_edit.setText(f"{base}_patched.img")
    
    def _browse_patch_output(self):
        """Browse for patch output file."""
        path, _ = QFileDialog.getSaveFileName(
            self.parent_window, 
            "Save Patched vbmeta", 
            self.patch_output_edit.text() or "vbmeta_patched.img",
            "Image Files (*.img);;All Files (*)"
        )
        if path:
            self.patch_output_edit.setText(path)
    
    def _patch_vbmeta(self):
        """Patch the vbmeta image."""
        input_path = self.patch_input_edit.text()
        if not input_path or not os.path.isfile(input_path):
            QMessageBox.warning(self.parent_window, "Error", "Please select a valid input file")
            return
        
        output_path = self.patch_output_edit.text()
        if not output_path:
            output_path = os.path.splitext(input_path)[0] + "_patched.img"
            self.patch_output_edit.setText(output_path)
        
        disable_verity = self.disable_verity_check.isChecked()
        disable_verification = self.disable_verification_check.isChecked()
        
        if not disable_verity and not disable_verification:
            QMessageBox.warning(self.parent_window, "Error", "Please select at least one patch option")
            return
        
        self._log(f"Patching vbmeta: {os.path.basename(input_path)}")
        
        patcher = VbmetaPatcher(input_path)
        success, message = patcher.patch(output_path, disable_verity, disable_verification)
        
        if success:
            self._log(f"✅ {message}")
            self._log(f"📁 Saved to: {output_path}")
            QMessageBox.information(
                self.parent_window, 
                "Patch Complete", 
                f"vbmeta patched successfully!\n\n{message}\n\nSaved to:\n{output_path}"
            )
            # Refresh the info display
            self._on_patch_input_changed(output_path)
        else:
            self._log(f"❌ {message}")
            QMessageBox.critical(self.parent_window, "Patch Failed", message)
    
    def _patch_and_flash_vbmeta(self):
        """Patch vbmeta and flash it to the device."""
        device = self._get_device()
        if not device:
            return
        
        input_path = self.patch_input_edit.text()
        if not input_path or not os.path.isfile(input_path):
            QMessageBox.warning(self.parent_window, "Error", "Please select a valid input file")
            return
        
        # Create temp patched file
        import tempfile
        temp_dir = tempfile.mkdtemp()
        output_path = os.path.join(temp_dir, "vbmeta_patched.img")
        
        disable_verity = self.disable_verity_check.isChecked()
        disable_verification = self.disable_verification_check.isChecked()
        
        if not disable_verity and not disable_verification:
            QMessageBox.warning(self.parent_window, "Error", "Please select at least one patch option")
            return
        
        # Confirm flash
        reply = QMessageBox.warning(
            self.parent_window,
            "Flash Patched vbmeta",
            f"This will:\n"
            f"1. Patch the vbmeta image\n"
            f"2. Flash it to the 'vbmeta' partition\n\n"
            f"Device: {device}\n\n"
            f"⚠️ Make sure your bootloader is unlocked!\n\n"
            f"Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self._log(f"Patching vbmeta: {os.path.basename(input_path)}")
        
        patcher = VbmetaPatcher(input_path)
        success, message = patcher.patch(output_path, disable_verity, disable_verification)
        
        if not success:
            self._log(f"❌ Patch failed: {message}")
            QMessageBox.critical(self.parent_window, "Patch Failed", message)
            shutil.rmtree(temp_dir, ignore_errors=True)
            return
        
        self._log(f"✅ {message}")
        self._log(f"⚡ Flashing patched vbmeta to device...")
        
        # Store temp dir for cleanup
        self._patch_temp_dir = temp_dir
        self._patch_temp_file = output_path
        
        # Flash the patched vbmeta
        self.worker = FastbootWorkerThread("flash", device=device, partition="vbmeta", file=output_path)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(self._on_patch_flash_complete)
        self.worker.start()
    
    def _on_patch_flash_complete(self, success, message):
        """Handle patch+flash completion."""
        self._log(message)
        
        # Cleanup temp files
        if hasattr(self, '_patch_temp_dir') and self._patch_temp_dir:
            shutil.rmtree(self._patch_temp_dir, ignore_errors=True)
            self._patch_temp_dir = None
        
        if success:
            QMessageBox.information(
                self.parent_window,
                "Flash Complete",
                "Patched vbmeta flashed successfully!\n\n"
                "You may need to reboot for changes to take effect."
            )

    # ===== OEM TAB =====
    def _create_oem_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        layout.addWidget(QLabel("Bootloader lock/unlock operations"))
        
        # Unlock
        unlock_group = QGroupBox("Unlock Bootloader")
        unlock_layout = QVBoxLayout(unlock_group)
        
        unlock_layout.addWidget(QLabel(
            "Requirements:\n"
            "• OEM unlocking enabled in Developer Options\n"
            "• Google account removed (for some devices)\n"
            "• ⚠️ This will FACTORY RESET your device!"
        ))
        
        oem_unlock_btn = QPushButton("🔓 OEM Unlock")
        oem_unlock_btn.setStyleSheet("background: #e65100;")
        oem_unlock_btn.clicked.connect(self._oem_unlock)
        unlock_layout.addWidget(oem_unlock_btn)
        
        flashing_unlock_btn = QPushButton("🔓 Flashing Unlock (Pixel/newer)")
        flashing_unlock_btn.setStyleSheet("background: #e65100;")
        flashing_unlock_btn.clicked.connect(self._flashing_unlock)
        unlock_layout.addWidget(flashing_unlock_btn)
        
        layout.addWidget(unlock_group)
        
        # Lock
        lock_group = QGroupBox("Lock Bootloader")
        lock_layout = QVBoxLayout(lock_group)
        
        lock_layout.addWidget(QLabel(
            "⚠️ Only lock if you're running STOCK firmware!\n"
            "Locking with custom ROM/recovery = BRICK"
        ))
        
        oem_lock_btn = QPushButton("🔒 OEM Lock")
        oem_lock_btn.clicked.connect(self._oem_lock)
        lock_layout.addWidget(oem_lock_btn)
        
        flashing_lock_btn = QPushButton("🔒 Flashing Lock (Pixel/newer)")
        flashing_lock_btn.clicked.connect(self._flashing_lock)
        lock_layout.addWidget(flashing_lock_btn)
        
        layout.addWidget(lock_group)
        layout.addStretch()
        
        return tab
    
    def _oem_unlock(self):
        device = self._get_device()
        if not device:
            return
        
        reply = QMessageBox.question(
            self.parent_window, "⚠️ OEM Unlock",
            "This will:\n• Factory reset your device\n• Void warranty (possibly)\n• Enable custom firmware\n\nContinue?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = FastbootWorkerThread("oem_unlock", device=device)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _flashing_unlock(self):
        device = self._get_device()
        if not device:
            return
        
        reply = QMessageBox.question(
            self.parent_window, "⚠️ Flashing Unlock",
            "This will:\n• Factory reset your device\n• Enable flashing custom images\n\nContinue?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = FastbootWorkerThread("flashing_unlock", device=device)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _oem_lock(self):
        device = self._get_device()
        if not device:
            return
        
        reply = QMessageBox.question(
            self.parent_window, "⚠️ OEM Lock",
            "Only do this if running STOCK firmware!\n\nLocking with custom ROM = BRICK\n\nAre you on stock?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = FastbootWorkerThread("oem_lock", device=device)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    def _flashing_lock(self):
        device = self._get_device()
        if not device:
            return
        
        reply = QMessageBox.question(
            self.parent_window, "⚠️ Flashing Lock",
            "Only do this if running STOCK firmware!\n\nContinue?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.worker = FastbootWorkerThread("flashing_lock", device=device)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== SLOT TAB =====
    def _create_slot_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        layout.addWidget(QLabel("A/B slot management for devices with seamless updates"))
        
        slot_group = QGroupBox("Set Active Slot")
        slot_layout = QVBoxLayout(slot_group)
        
        self.slot_a = QRadioButton("Slot A")
        self.slot_b = QRadioButton("Slot B")
        self.slot_a.setChecked(True)
        
        slot_layout.addWidget(self.slot_a)
        slot_layout.addWidget(self.slot_b)
        
        set_slot_btn = QPushButton("🔀 Set Active Slot")
        set_slot_btn.clicked.connect(self._set_slot)
        slot_layout.addWidget(set_slot_btn)
        
        layout.addWidget(slot_group)
        
        info = QLabel(
            "About A/B slots:\n"
            "• Modern devices have two copies of system partitions\n"
            "• boot_a/boot_b, system_a/system_b, etc.\n"
            "• Allows seamless OTA updates\n"
            "• Can switch between slots if one fails"
        )
        info.setStyleSheet("color: #888;")
        layout.addWidget(info)
        
        layout.addStretch()
        return tab
    
    def _set_slot(self):
        device = self._get_device()
        if not device:
            return
        
        slot = "a" if self.slot_a.isChecked() else "b"
        
        self.worker = FastbootWorkerThread("set_active", device=device, slot=slot)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()

    # ===== ADB RESCUE TAB =====
    def _create_adb_rescue_tab(self):
        """Create the ADB Rescue tab — product partition key injection for broken screens."""
        tab = QWidget()
        main_layout = QVBoxLayout(tab)

        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        scroll_widget = QWidget()
        layout = QVBoxLayout(scroll_widget)

        # Hero header
        hero = QLabel(
            "🔓 <b style='font-size: 14px;'>ADB Rescue</b> — "
            "<span style='color: #4fc3f7;'>Enable ADB with ZERO screen interaction</span><br>"
            "<span style='color: #888;'>Injects your ADB key into the product partition. "
            "Works on Pixel / GKI devices where /adb_keys → /product/etc/security/adb_keys. "
            "Survives reboots and factory resets.</span>"
        )
        hero.setWordWrap(True)
        hero.setStyleSheet("padding: 8px; background: #1a2a3a; border-radius: 6px; margin-bottom: 4px;")
        layout.addWidget(hero)

        # Requirements banner
        req_label = QLabel(
            "📋 <b>Requirements:</b><br>"
            "• Device in <b>Recovery mode</b> with root ADB shell (LineageOS recovery, TWRP, etc.)<br>"
            "• Bootloader must be unlocked (to flash custom recovery)<br>"
            "• Device uses dynamic partitions with product partition (Pixel 3+, most 2019+ devices)<br>"
            "• <b>NOT</b> in fastboot — this uses ADB in recovery, not fastboot commands"
        )
        req_label.setWordWrap(True)
        req_label.setStyleSheet(
            "padding: 8px; background: rgba(255,152,0,0.15); border: 1px solid #664400; "
            "border-radius: 4px; color: #ffcc80;"
        )
        layout.addWidget(req_label)

        # ── How it works ──
        how_group = QGroupBox("💡 How It Works")
        how_layout = QVBoxLayout(how_group)
        how_label = QLabel(
            "<span style='color: #aaa;'>"
            "On Pixel/GKI devices, <code>/adb_keys</code> is a <b>symlink</b> to "
            "<code>/product/etc/security/adb_keys</code>. This is Google's mechanism for "
            "pre-provisioned ADB keys (factory/enterprise). adbd reads this file at startup.<br><br>"
            "<b>The process:</b> Parse LP (super) metadata → Create loop device over product partition → "
            "Fix ext4 shared_blocks dedup → Resize filesystem → Mount RW → Write your ADB key → Reboot.<br><br>"
            "After reboot, your PC is automatically trusted — no touch required. "
            "This is the <b>first tool in the world</b> that can enable USB ADB "
            "without any screen interaction!"
            "</span>"
        )
        how_label.setWordWrap(True)
        how_layout.addWidget(how_label)
        layout.addWidget(how_group)

        # ── Device Serial ──
        device_group = QGroupBox("📱 Device (ADB in Recovery)")
        device_layout = QVBoxLayout(device_group)

        serial_row = QHBoxLayout()
        serial_row.addWidget(QLabel("Serial:"))
        self.rescue_serial = QLineEdit()
        self.rescue_serial.setPlaceholderText("Auto-detected when you click Scan...")
        serial_row.addWidget(self.rescue_serial, 1)

        scan_btn = QPushButton("🔍 Scan ADB Devices")
        scan_btn.clicked.connect(self._rescue_scan_devices)
        serial_row.addWidget(scan_btn)
        device_layout.addLayout(serial_row)

        self.rescue_device_status = QLabel("Click 'Scan' to find devices in recovery mode")
        self.rescue_device_status.setStyleSheet("color: #888; padding: 2px;")
        device_layout.addWidget(self.rescue_device_status)

        layout.addWidget(device_group)

        # ── ADB Key ──
        key_group = QGroupBox("🔑 ADB Public Key")
        key_layout = QVBoxLayout(key_group)

        key_row = QHBoxLayout()
        self.rescue_adbkey = QLineEdit()
        default_key = os.path.join(os.path.expanduser('~'), '.android', 'adbkey.pub')
        if os.path.isfile(default_key):
            self.rescue_adbkey.setText(default_key)
            self.rescue_adbkey.setStyleSheet("color: #4f4;")
        else:
            self.rescue_adbkey.setPlaceholderText("Path to adbkey.pub — run 'adb devices' once to generate")
            self.rescue_adbkey.setStyleSheet("color: #f44;")
        key_row.addWidget(self.rescue_adbkey, 1)

        key_browse = QPushButton("📁")
        key_browse.setMaximumWidth(40)
        key_browse.clicked.connect(lambda: self._browse_file(self.rescue_adbkey, "Public Keys (*.pub);;All Files (*)"))
        key_row.addWidget(key_browse)
        key_layout.addLayout(key_row)

        key_info = QLabel(
            "This is your PC's ADB RSA public key. Usually at:\n"
            "  Windows: C:\\Users\\<you>\\.android\\adbkey.pub\n"
            "  Linux/Mac: ~/.android/adbkey.pub"
        )
        key_info.setStyleSheet("color: #888; font-size: 11px; padding: 4px;")
        key_layout.addWidget(key_info)

        layout.addWidget(key_group)

        # ── Options ──
        opts_group = QGroupBox("⚙️ Options")
        opts_layout = QVBoxLayout(opts_group)

        self.rescue_reboot = QCheckBox("🔄 Reboot to Android after injection")
        self.rescue_reboot.setChecked(True)
        self.rescue_reboot.setToolTip("Automatically reboot to Android after the key is written")
        opts_layout.addWidget(self.rescue_reboot)

        layout.addWidget(opts_group)

        # ── THE BUTTON ──
        self.btn_rescue_inject = QPushButton("🔓 INJECT ADB KEY — Break Free!\n(Product Partition Key Injection)")
        self.btn_rescue_inject.setMinimumHeight(70)
        self.btn_rescue_inject.setStyleSheet(
            "background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
            "stop:0 #b71c1c, stop:1 #c62828); "
            "font-weight: bold; font-size: 14px; "
            "border-radius: 8px; padding: 12px; color: white;"
        )
        self.btn_rescue_inject.setToolTip(
            "Injects your ADB public key into /product/etc/security/adb_keys\n"
            "via the super partition's LP metadata. After reboot, USB ADB is\n"
            "automatically authorized — no screen interaction needed!\n\n"
            "Device must be in recovery with root ADB shell."
        )
        self.btn_rescue_inject.clicked.connect(self._rescue_inject_key)
        layout.addWidget(self.btn_rescue_inject)

        # ── Log output specific to rescue ──
        log_group = QGroupBox("📋 Injection Log")
        log_layout = QVBoxLayout(log_group)

        self.rescue_log = QTextEdit()
        self.rescue_log.setReadOnly(True)
        self.rescue_log.setMinimumHeight(200)
        self.rescue_log.setStyleSheet(
            "font-family: Consolas, monospace; font-size: 11px; "
            "background-color: #0d1117; color: #c9d1d9; border: 1px solid #30363d;"
        )
        log_layout.addWidget(self.rescue_log)

        clear_btn = QPushButton("🗑️ Clear Log")
        clear_btn.clicked.connect(lambda: self.rescue_log.clear())
        log_layout.addWidget(clear_btn)

        layout.addWidget(log_group)

        layout.addStretch()
        scroll.setWidget(scroll_widget)
        main_layout.addWidget(scroll)
        return tab

    def _rescue_scan_devices(self):
        """Scan for ADB devices in recovery mode."""
        self.rescue_device_status.setText("Scanning...")
        self.rescue_device_status.setStyleSheet("color: #ff8;")

        ok, output = run_adb(["devices", "-l"], timeout=10)
        if not ok:
            self.rescue_device_status.setText(f"ADB not found or error: {output[:100]}")
            self.rescue_device_status.setStyleSheet("color: #f44;")
            return

        # Parse device list
        devices = []
        for line in output.split('\n'):
            line = line.strip()
            if '\t' in line or '  ' in line:
                parts = line.split()
                if len(parts) >= 2 and parts[1] in ('device', 'recovery'):
                    serial = parts[0]
                    mode = parts[1]
                    model = ''
                    for p in parts[2:]:
                        if p.startswith('model:'):
                            model = p.split(':')[1]
                    devices.append((serial, mode, model))

        if not devices:
            self.rescue_device_status.setText(
                "No ADB devices found. Is the device in recovery with ADB enabled?"
            )
            self.rescue_device_status.setStyleSheet("color: #f44;")
            return

        # Use first recovery device, or first device
        selected = None
        for serial, mode, model in devices:
            if mode == 'recovery':
                selected = (serial, mode, model)
                break
        if not selected:
            selected = devices[0]

        serial, mode, model = selected
        self.rescue_serial.setText(serial)

        mode_color = "#4f4" if mode == 'recovery' else "#ff8"
        mode_icon = "🔧" if mode == 'recovery' else "📱"
        self.rescue_device_status.setText(
            f"{mode_icon} {serial} ({model or 'unknown'}) — mode: {mode}"
            + ("" if mode == 'recovery' else " ⚠️ Not in recovery! Boot to recovery first.")
        )
        self.rescue_device_status.setStyleSheet(f"color: {mode_color}; font-weight: bold;")

        self._log(f"ADB Rescue: Found device {serial} in {mode} mode")

    def _rescue_inject_key(self):
        """Launch the product partition key injection."""
        serial = self.rescue_serial.text().strip()
        if not serial:
            QMessageBox.warning(self.parent_window, "No Device",
                "No device serial specified. Click 'Scan' first.")
            return

        key_path = self.rescue_adbkey.text().strip()
        if not key_path or not os.path.isfile(key_path):
            QMessageBox.warning(self.parent_window, "No ADB Key",
                "Please select your ADB public key file (adbkey.pub).\n\n"
                "It's usually at:\n"
                "  Windows: C:\\Users\\<you>\\.android\\adbkey.pub\n"
                "  Linux/Mac: ~/.android/adbkey.pub\n\n"
                "Generate it by running 'adb devices' while connected to any Android device.")
            return

        # Read key content
        try:
            with open(key_path, 'r') as f:
                pubkey_content = f.read().strip()
            if len(pubkey_content) < 50:
                QMessageBox.warning(self.parent_window, "Invalid Key",
                    f"Key file seems too small ({len(pubkey_content)} chars). "
                    "Are you sure this is a valid adbkey.pub?")
                return
        except Exception as e:
            QMessageBox.critical(self.parent_window, "Read Error",
                f"Could not read key file:\n{e}")
            return

        # Confirm
        reboot_after = self.rescue_reboot.isChecked()
        reply = QMessageBox.question(
            self.parent_window,
            "🔓 ADB Rescue — Confirm Injection",
            f"This will inject your ADB public key into the product partition.\n\n"
            f"Device: {serial}\n"
            f"Key: {os.path.basename(key_path)} ({len(pubkey_content)} bytes)\n"
            f"Reboot after: {'Yes' if reboot_after else 'No'}\n\n"
            f"The process:\n"
            f"  1. Parse super partition LP metadata\n"
            f"  2. Map product partition via loop device\n"
            f"  3. Fix ext4 shared_blocks + resize\n"
            f"  4. Mount RW and write key\n"
            f"  5. {'Reboot to Android' if reboot_after else 'Cleanup'}\n\n"
            f"Your device must be in RECOVERY with root ADB.\n"
            f"Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        # Clear log and start
        self.rescue_log.clear()
        self.rescue_log.append(f"<span style='color: #58a6ff;'>Starting ADB Rescue for {serial}...</span>\n")
        self.btn_rescue_inject.setEnabled(False)
        self.btn_rescue_inject.setText("⏳ Injecting... Please wait")

        self._log(f"🔓 ADB Rescue: Starting injection for {serial}")

        self.worker = FastbootWorkerThread(
            "inject_product_key",
            device=serial,
            pubkey_content=pubkey_content,
            reboot_after=reboot_after,
        )
        self.worker.log.connect(self._rescue_log_msg)
        self.worker.finished_signal.connect(self._rescue_on_complete)
        self.worker.start()

    def _rescue_log_msg(self, msg: str):
        """Append a message to the rescue log."""
        # Color-code based on content
        if msg.startswith('✅') or msg.startswith('  ✓'):
            color = '#4f4'
        elif msg.startswith('❌') or 'FAILED' in msg:
            color = '#f44'
        elif msg.startswith('⚠️'):
            color = '#ff8'
        elif msg.startswith('🔓') or msg.startswith('═'):
            color = '#58a6ff'
        else:
            color = '#c9d1d9'

        escaped = msg.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        self.rescue_log.append(f"<span style='color: {color};'>{escaped}</span>")
        # Also echo to main log
        self._log(msg)

    def _rescue_on_complete(self, success: bool, message: str):
        """Handle injection completion."""
        self.btn_rescue_inject.setEnabled(True)
        self.btn_rescue_inject.setText("🔓 INJECT ADB KEY — Break Free!\n(Product Partition Key Injection)")

        if success:
            self.rescue_log.append("")
            self.rescue_log.append(
                "<span style='color: #4f4; font-size: 13px; font-weight: bold;'>"
                "🎉 Mission accomplished! Freedom achieved!</span>"
            )
            self.rescue_log.append(
                "<span style='color: #888;'>Wait ~60 seconds after reboot, then run "
                "'adb devices' — your device should show as authorized.</span>"
            )
        else:
            self.rescue_log.append("")
            self.rescue_log.append(
                f"<span style='color: #f44; font-weight: bold;'>"
                f"The chains held... {message}</span>"
            )

    # ===== REBOOT TAB =====
    def _create_reboot_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        buttons = [
            ("🔄 Reboot System", ""),
            ("⚡ Reboot Bootloader", "bootloader"),
            ("📦 Reboot Fastbootd", "fastbootd"),
            ("🔧 Reboot Recovery", "recovery"),
            ("🔥 Reboot EDL (Emergency)", "edl"),
        ]
        
        for text, mode in buttons:
            btn = QPushButton(text)
            btn.setMinimumHeight(40)
            btn.clicked.connect(lambda c, m=mode: self._reboot(m))
            layout.addWidget(btn)
        
        layout.addStretch()
        return tab
    
    def _reboot(self, mode):
        device = self._get_device()
        if not device:
            return
        
        self.worker = FastbootWorkerThread("reboot", device=device, mode=mode)
        self.worker.log.connect(self._log)
        self.worker.finished_signal.connect(lambda s, m: self._log(m))
        self.worker.start()
    
    # ===== SHELL TAB =====
    def _create_shell_tab(self):
        """Create fastboot shell tab for custom commands."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Info header
        info_label = QLabel(
            "💻 <b>Fastboot Shell</b> - Run custom fastboot commands<br>"
            "<span style='color: #888;'>Enter commands without 'fastboot' prefix. Device is auto-selected.</span>"
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Quick commands
        quick_group = QGroupBox("Quick Commands")
        quick_layout = QVBoxLayout(quick_group)
        
        # Row 1: Common safe commands
        row1 = QHBoxLayout()
        quick_cmds = [
            ("getvar product", "getvar product"),
            ("getvar serialno", "getvar serialno"),
            ("getvar unlocked", "getvar unlocked"),
            ("getvar slot-count", "getvar slot-count"),
        ]
        for label, cmd in quick_cmds:
            btn = QPushButton(label)
            btn.setMaximumWidth(150)
            btn.clicked.connect(lambda c, cmd=cmd: self._run_shell_command(cmd))
            row1.addWidget(btn)
        quick_layout.addLayout(row1)
        
        # Row 2: Flash with flags (the important one for vbmeta!)
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Flash vbmeta with flags:"))
        self.shell_vbmeta_path = QLineEdit()
        self.shell_vbmeta_path.setPlaceholderText("Select vbmeta.img...")
        row2.addWidget(self.shell_vbmeta_path, 1)
        
        browse_btn = QPushButton("📁")
        browse_btn.setMaximumWidth(40)
        browse_btn.clicked.connect(lambda: self._browse_file(self.shell_vbmeta_path, "Image Files (*.img);;All Files (*)"))
        row2.addWidget(browse_btn)
        
        flash_flags_btn = QPushButton("⚡ Flash --disable-verity --disable-verification")
        flash_flags_btn.setStyleSheet("background-color: #4a6; color: white; font-weight: bold;")
        flash_flags_btn.setToolTip("Flash vbmeta with bootloader flags - use ORIGINAL unpatched vbmeta!")
        flash_flags_btn.clicked.connect(self._flash_vbmeta_with_flags)
        row2.addWidget(flash_flags_btn)
        quick_layout.addLayout(row2)
        
        # Row 3: Create and flash blank vbmeta
        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Blank vbmeta (for stubborn MTK devices):"))
        
        create_blank_btn = QPushButton("📝 Create Blank vbmeta")
        create_blank_btn.setToolTip("Create a minimal valid vbmeta with flags already disabled")
        create_blank_btn.clicked.connect(self._create_blank_vbmeta)
        row3.addWidget(create_blank_btn)
        
        flash_blank_btn = QPushButton("⚡ Create && Flash Blank")
        flash_blank_btn.setStyleSheet("background-color: #a64; color: white;")
        flash_blank_btn.setToolTip("Create blank vbmeta and flash it immediately")
        flash_blank_btn.clicked.connect(self._create_and_flash_blank_vbmeta)
        row3.addWidget(flash_blank_btn)
        row3.addStretch()
        quick_layout.addLayout(row3)
        
        layout.addWidget(quick_group)
        
        # Custom command input
        cmd_group = QGroupBox("Custom Command")
        cmd_layout = QVBoxLayout(cmd_group)
        
        input_row = QHBoxLayout()
        input_row.addWidget(QLabel("fastboot"))
        
        self.shell_input = QLineEdit()
        self.shell_input.setPlaceholderText("Enter command arguments (e.g., 'getvar all' or 'flash boot boot.img')")
        self.shell_input.returnPressed.connect(self._execute_shell_command)
        input_row.addWidget(self.shell_input, 1)
        
        exec_btn = QPushButton("▶ Execute")
        exec_btn.clicked.connect(self._execute_shell_command)
        input_row.addWidget(exec_btn)
        cmd_layout.addLayout(input_row)
        
        # Command history
        history_label = QLabel("Command History (double-click to reuse):")
        history_label.setStyleSheet("color: #888; margin-top: 5px;")
        cmd_layout.addWidget(history_label)
        
        self.shell_history = QListWidget()
        self.shell_history.setMaximumHeight(80)
        self.shell_history.itemDoubleClicked.connect(self._reuse_history_command)
        cmd_layout.addWidget(self.shell_history)
        
        layout.addWidget(cmd_group)
        
        # Output
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout(output_group)
        
        self.shell_output = QTextEdit()
        self.shell_output.setReadOnly(True)
        self.shell_output.setStyleSheet("font-family: Consolas, monospace; font-size: 11px; background-color: #1e1e1e; color: #ddd;")
        self.shell_output.setMinimumHeight(150)
        output_layout.addWidget(self.shell_output)
        
        clear_btn = QPushButton("🗑️ Clear Output")
        clear_btn.clicked.connect(lambda: self.shell_output.clear())
        output_layout.addWidget(clear_btn)
        
        layout.addWidget(output_group)
        
        # Warning
        warning = QLabel(
            "⚠️ <b>Warning:</b> Some commands can brick your device. "
            "Commands are only executed when you press Enter or click Execute."
        )
        warning.setStyleSheet("color: #f84;")
        warning.setWordWrap(True)
        layout.addWidget(warning)
        
        # Initialize history
        self.shell_command_history = []
        
        return tab
    
    def _run_shell_command(self, cmd: str):
        """Run a predefined shell command."""
        self.shell_input.setText(cmd)
        self._execute_shell_command()
    
    def _execute_shell_command(self):
        """Execute the command in the shell input - ONLY when explicitly triggered."""
        cmd_text = self.shell_input.text().strip()
        if not cmd_text:
            return
        
        device = self._get_device()
        if not device:
            self.shell_output.append("<span style='color: #f44;'>❌ No device connected</span>")
            return
        
        # Add to history
        if cmd_text not in self.shell_command_history:
            self.shell_command_history.insert(0, cmd_text)
            self.shell_history.insertItem(0, cmd_text)
            # Keep only last 20 commands
            if len(self.shell_command_history) > 20:
                self.shell_command_history.pop()
                self.shell_history.takeItem(20)
        
        # Parse command arguments
        args = cmd_text.split()
        
        # Show what we're running
        self.shell_output.append(f"<span style='color: #4af;'>$ fastboot -s {device} {cmd_text}</span>")
        
        # Run the command
        self._log(f"Shell: fastboot {cmd_text}")
        success, output = run_fastboot(args, device, timeout=120)
        
        # Display output
        if output:
            # Escape HTML and preserve formatting
            escaped = output.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            color = "#4f4" if success else "#f84"
            self.shell_output.append(f"<pre style='color: {color}; margin: 0;'>{escaped}</pre>")
        
        if success:
            self.shell_output.append("<span style='color: #4f4;'>✓ Command completed</span>")
        else:
            self.shell_output.append("<span style='color: #f44;'>✗ Command failed</span>")
        
        self.shell_output.append("")  # Blank line
        
        # Clear input for next command
        self.shell_input.clear()
        self.shell_input.setFocus()
    
    def _reuse_history_command(self, item):
        """Reuse a command from history."""
        self.shell_input.setText(item.text())
        self.shell_input.setFocus()
    
    def _flash_vbmeta_with_flags(self):
        """Flash vbmeta with --disable-verity --disable-verification flags."""
        vbmeta_path = self.shell_vbmeta_path.text().strip()
        if not vbmeta_path or not os.path.isfile(vbmeta_path):
            QMessageBox.warning(self.parent_window, "Error", "Please select a valid vbmeta.img file")
            return
        
        device = self._get_device()
        if not device:
            QMessageBox.warning(self.parent_window, "Error", "No device connected")
            return
        
        # Confirm
        reply = QMessageBox.question(
            self.parent_window,
            "Flash vbmeta with Flags",
            f"Flash vbmeta with verification disabled?\n\n"
            f"File: {os.path.basename(vbmeta_path)}\n"
            f"Device: {device}\n\n"
            f"Command: fastboot --disable-verity --disable-verification flash vbmeta {vbmeta_path}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.shell_output.append(f"<span style='color: #4af;'>$ fastboot --disable-verity --disable-verification flash vbmeta {vbmeta_path}</span>")
        self._log(f"Flashing vbmeta with flags: {vbmeta_path}")
        
        # Run with the flags BEFORE the flash command
        success, output = run_fastboot(
            ["--disable-verity", "--disable-verification", "flash", "vbmeta", vbmeta_path],
            device,
            timeout=120
        )
        
        escaped = output.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        color = "#4f4" if success else "#f84"
        self.shell_output.append(f"<pre style='color: {color};'>{escaped}</pre>")
        
        if success:
            self._log("✓ vbmeta flashed with flags")
            self.shell_output.append("<span style='color: #4f4;'>✓ vbmeta flashed successfully with verification disabled</span>")
        else:
            self._log("✗ Failed to flash vbmeta")
            self.shell_output.append("<span style='color: #f44;'>✗ Failed to flash vbmeta</span>")
    
    def _create_blank_vbmeta(self):
        """Create a blank/minimal vbmeta image with flags disabled."""
        # Ask where to save
        path, _ = QFileDialog.getSaveFileName(
            self.parent_window,
            "Save Blank vbmeta",
            "vbmeta_blank.img",
            "Image Files (*.img)"
        )
        
        if not path:
            return
        
        try:
            self._write_blank_vbmeta(path)
            self._log(f"✓ Created blank vbmeta: {path}")
            self.shell_output.append(f"<span style='color: #4f4;'>✓ Created blank vbmeta: {path}</span>")
            QMessageBox.information(self.parent_window, "Success", f"Blank vbmeta created:\n{path}")
        except Exception as e:
            self._log(f"✗ Failed to create blank vbmeta: {e}")
            QMessageBox.critical(self.parent_window, "Error", f"Failed to create blank vbmeta:\n{e}")
    
    def _create_and_flash_blank_vbmeta(self):
        """Create blank vbmeta and flash it immediately."""
        device = self._get_device()
        if not device:
            QMessageBox.warning(self.parent_window, "Error", "No device connected")
            return
        
        # Confirm
        reply = QMessageBox.question(
            self.parent_window,
            "Create and Flash Blank vbmeta",
            "This will create a minimal vbmeta image with verification disabled\n"
            "and flash it to your device.\n\n"
            "This is useful for MTK devices that don't accept patched vbmeta.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        try:
            # Create temp file
            import tempfile
            temp_path = os.path.join(tempfile.gettempdir(), "vbmeta_blank.img")
            self._write_blank_vbmeta(temp_path)
            
            self._log(f"Created blank vbmeta, flashing...")
            self.shell_output.append("<span style='color: #4af;'>$ fastboot flash vbmeta vbmeta_blank.img</span>")
            
            # Flash it
            success, output = run_fastboot(["flash", "vbmeta", temp_path], device, timeout=120)
            
            escaped = output.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            color = "#4f4" if success else "#f84"
            self.shell_output.append(f"<pre style='color: {color};'>{escaped}</pre>")
            
            if success:
                self._log("✓ Blank vbmeta flashed successfully")
                self.shell_output.append("<span style='color: #4f4;'>✓ Blank vbmeta flashed successfully</span>")
            else:
                self._log("✗ Failed to flash blank vbmeta")
                self.shell_output.append("<span style='color: #f44;'>✗ Failed to flash blank vbmeta</span>")
            
            # Clean up
            try:
                os.remove(temp_path)
            except:
                pass
                
        except Exception as e:
            self._log(f"✗ Error: {e}")
            QMessageBox.critical(self.parent_window, "Error", str(e))
    
    def _write_blank_vbmeta(self, path: str):
        """Write a minimal valid vbmeta image with flags disabled."""
        # Create a minimal AVB vbmeta header (256 bytes)
        # This is the smallest valid vbmeta that will pass basic checks
        header = bytearray(256)
        
        # Magic: "AVB0"
        header[0:4] = b'AVB0'
        
        # Version: 1.0 (major=1, minor=0)
        header[4:8] = struct.pack('>I', 1)   # major
        header[8:12] = struct.pack('>I', 0)  # minor
        
        # Auth block size: 0 (no signature)
        header[12:20] = struct.pack('>Q', 0)
        
        # Aux block size: 0 (no descriptors)
        header[20:28] = struct.pack('>Q', 0)
        
        # Algorithm: 0 (none/unsigned)
        header[28:32] = struct.pack('>I', 0)
        
        # Flags at offset 120: 0x03 (both verity and verification disabled)
        header[120:124] = struct.pack('>I', 0x03)
        
        # Write to file (some devices need padding to 4096 or larger)
        with open(path, 'wb') as f:
            f.write(header)
            # Pad to 4096 bytes (common partition alignment)
            f.write(b'\x00' * (4096 - 256))
    
    # ===== HELPERS =====
    def _browse_file(self, line_edit, filter="All Files (*)"):
        path, _ = QFileDialog.getOpenFileName(self.parent_window, "Select File", "", filter)
        if path:
            line_edit.setText(path)
    
    def _browse_dir(self, line_edit):
        path = QFileDialog.getExistingDirectory(self.parent_window, "Select Directory")
        if path:
            line_edit.setText(path)


Plugin = FastbootToolkitPlugin
