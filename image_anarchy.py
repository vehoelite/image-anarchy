#!/usr/bin/env python3
"""
Image Anarchy - Android Image Swiss Army Knife
Version: 2.0

A modern PyQt6 application for extracting, creating, and manipulating
Android OTA payloads and image formats.

GitHub: https://github.com/vehoelite/image-anarchy

Features:
- EXTRACT: Dump partitions from payload.bin files
- CREATE: Repack partition images into a new payload.bin  
- IMAGE EXTRACT: Analyze and extract Android image formats:
  * Sparse images → Raw images
  * Boot/recovery/vendor_boot images → kernel, ramdisk, DTB
  * Super (dynamic partition) images → individual partition images
  * vbmeta patching (disable verity/verification) with optional re-signing
  * ext4/FAT filesystem extraction
  * ELF/bootloader analysis
- IMAGE REPACK: Create Android images from components:
  * Boot/recovery/vendor_boot images (v0-v4)
  * Sparse images from raw
  * vbmeta images (disabled AVB)
  * Ramdisk from directory
- PLUGINS: Extensible plugin system with ADB/Fastboot toolkits
  * ADB Toolkit - Device info, partitions, files, apps, shell, reboot
  * Fastboot Toolkit - Flash, boot, fetch, erase, OEM unlock, slots
  * Create your own plugins with monetization support!
- Support for local files and remote URLs (http, https, s3, gs)
- Automatic zip file handling
- Differential OTA support (extract only)
- Multiple compression formats: ZSTD, XZ, BZ2, Brotli
- Modern dark-themed GUI with drag & drop
- Non-blocking threaded operations
- Custom AVB key signing support

Dependencies:
    pip install PyQt6 bsdiff4 brotli zstandard fsspec protobuf
    pip install cryptography  # Optional: for AVB signing

Usage:
    python image_anarchy.py                           # Launch GUI
    
    # Extract mode (payload)
    python image_anarchy.py --extract payload.bin     # Extract all partitions
    python image_anarchy.py --extract ota.zip -i system,vendor
    
    # Create mode  
    python image_anarchy.py --create ./images -o new_payload.bin
    python image_anarchy.py --create ./images --compression xz --level 6
    
    # Image extraction mode
    python image_anarchy.py --image super.img         # Extract super partitions
    python image_anarchy.py --image boot.img          # Extract boot components
    python image_anarchy.py --image sparse.img        # Convert sparse to raw
    python image_anarchy.py --image system.img --analyze  # Analyze only
"""

import argparse
import bz2
import gzip
import hashlib
import io
import json
import logging
import os
import shutil
import struct
import subprocess
import sys
import urllib.parse
import uuid
import webbrowser
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Dict, List, Optional, Tuple

# Fix for PyInstaller windowed mode: sys.stdout/stderr are None, but some
# libraries (like mtkclient) call sys.stdout.detach() which crashes.
# Create a proper mock stream that supports detach() for binary mode conversion.
if sys.stdout is None or sys.stderr is None:
    class _NullStream:
        """Null stream that supports both text and binary operations including detach()."""
        def write(self, *args, **kwargs): return 0
        def read(self, *args, **kwargs): return ''
        def flush(self, *args, **kwargs): pass
        def close(self, *args, **kwargs): pass
        def fileno(self, *args, **kwargs): raise OSError("Null stream has no file descriptor")
        def isatty(self): return False
        def readable(self): return False
        def writable(self): return True
        def seekable(self): return False
        def detach(self): return _NullBinaryStream()
        def __enter__(self): return self
        def __exit__(self, *args): pass
        encoding = 'utf-8'
        errors = 'strict'
        newlines = None
        buffer = None
        closed = False
        
    class _NullBinaryStream:
        """Null binary stream returned by detach()."""
        def write(self, *args, **kwargs): return 0
        def read(self, *args, **kwargs): return b''
        def flush(self, *args, **kwargs): pass
        def close(self, *args, **kwargs): pass
        def fileno(self, *args, **kwargs): raise OSError("Null stream has no file descriptor")
        def isatty(self): return False
        def readable(self): return False
        def writable(self): return True
        def seekable(self): return False
        def __enter__(self): return self
        def __exit__(self, *args): pass
        mode = 'wb'
        closed = False
    
    if sys.stdout is None:
        sys.stdout = _NullStream()
    if sys.stderr is None:
        sys.stderr = _NullStream()

# Plugin dependency support: When running as a frozen exe, plugins install their
# pip dependencies to a local site-packages directory. Add it to sys.path so
# the bundled Python can find packages installed after the exe was built.
def _setup_plugin_site_packages():
    """Add local plugin site-packages to sys.path for frozen exe support."""
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller exe
        base_dir = os.path.dirname(sys.executable)
    else:
        # Running from source
        base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Local site-packages for plugin dependencies
    local_site_packages = os.path.join(base_dir, 'plugin_packages')
    
    # Create if doesn't exist
    if not os.path.exists(local_site_packages):
        try:
            os.makedirs(local_site_packages, exist_ok=True)
        except Exception:
            pass  # May fail if no write permission, that's OK
    
    # Add to sys.path if not already there (insert at front for priority)
    if local_site_packages not in sys.path:
        sys.path.insert(0, local_site_packages)
    
    return local_site_packages

# Initialize plugin site-packages path
_PLUGIN_PACKAGES_DIR = _setup_plugin_site_packages()

# Third-party imports
import brotli
import bsdiff4
import fsspec
import zstandard
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

# Cryptography imports for AVB signing
try:
    from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import rsa, padding  # type: ignore
    from cryptography.hazmat.backends import default_backend  # type: ignore
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def _extract_bundled_resources():
    """Extract bundled resources from PyInstaller _MEIPASS to app directory.
    
    When running as a frozen exe, PyInstaller extracts files to a temp directory.
    This function copies necessary resources (drivers, platform-tools, etc.) to
    the app's directory so they persist and can be used by plugins.
    """
    if not getattr(sys, 'frozen', False):
        return  # Not running as frozen exe
    
    # PyInstaller temp directory with bundled files
    meipass = getattr(sys, '_MEIPASS', None)
    if not meipass:
        return
    
    # App directory (where exe is located)
    app_dir = os.path.dirname(sys.executable)
    
    # Resources to extract if they don't exist
    resources = ['drivers', 'platform-tools', 'PortableGit', 'plugins']
    
    for resource in resources:
        src = os.path.join(meipass, resource)
        dst = os.path.join(app_dir, resource)
        
        if os.path.exists(src) and not os.path.exists(dst):
            try:
                if os.path.isdir(src):
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)
            except Exception:
                pass  # Silently continue if extraction fails


# Extract bundled resources on import (runs once on first launch)
_extract_bundled_resources()


def _get_python_executable() -> Optional[str]:
    """Get the Python interpreter path, handling frozen exe case.
    
    When running as a PyInstaller frozen exe, sys.executable points to the exe,
    not Python. This function finds the actual Python interpreter.
    
    Returns:
        Path to Python interpreter, or None if not found when frozen.
    """
    if getattr(sys, 'frozen', False):
        # Running as frozen exe - find Python in PATH
        return shutil.which('python') or shutil.which('python3') or shutil.which('py')
    return sys.executable


try:
    import lzma
except ImportError:
    from backports import lzma  # type: ignore

# =============================================================================
# EMBEDDED PROTOBUF DEFINITIONS
# =============================================================================
# This replaces the need for update_metadata_pb2.py
# Generated from update_metadata.proto (ChromeOS/Android OTA format)

_sym_db = _symbol_database.Default()

_PROTOBUF_DESCRIPTOR = (
    b'\n\x15update_metadata.proto\x12\x16chromeos_update_engine\"1\n\x06Extent'
    b'\x12\x13\n\x0bstart_block\x18\x01 \x01(\x04\x12\x12\n\nnum_blocks\x18\x02'
    b' \x01(\x04\"\x9f\x01\n\nSignatures\x12@\n\nsignatures\x18\x01 \x03(\x0b2'
    b',.chromeos_update_engine.Signatures.Signature\x1aO\n\tSignature\x12\x13\n'
    b'\x07version\x18\x01 \x01(\rB\x02\x18\x01\x12\x0c\n\x04data\x18\x02 \x01(\x0c'
    b'\x12\x1f\n\x17unpadded_signature_size\x18\x03 \x01(\x07\"+\n\rPartitionInfo'
    b'\x12\x0c\n\x04size\x18\x01 \x01(\x04\x12\x0c\n\x04hash\x18\x02 \x01(\x0c\"'
    b'\xb0\x04\n\x10InstallOperation\x12;\n\x04type\x18\x01 \x02(\x0e2-.chromeos'
    b'_update_engine.InstallOperation.Type\x12\x13\n\x0bdata_offset\x18\x02 \x01'
    b'(\x04\x12\x13\n\x0bdata_length\x18\x03 \x01(\x04\x123\n\x0bsrc_extents\x18'
    b'\x04 \x03(\x0b2\x1e.chromeos_update_engine.Extent\x12\x12\n\nsrc_length\x18'
    b'\x05 \x01(\x04\x123\n\x0bdst_extents\x18\x06 \x03(\x0b2\x1e.chromeos_update'
    b'_engine.Extent\x12\x12\n\ndst_length\x18\x07 \x01(\x04\x12\x18\n\x10data_sha'
    b'256_hash\x18\x08 \x01(\x0c\x12\x17\n\x0fsrc_sha256_hash\x18\t \x01(\x0c\"\xef'
    b'\x01\n\x04Type\x12\x0b\n\x07REPLACE\x10\x00\x12\x0e\n\nREPLACE_BZ\x10\x01'
    b'\x12\x0c\n\x04MOVE\x10\x02\x1a\x02\x08\x01\x12\x0e\n\x06BSDIFF\x10\x03\x1a'
    b'\x02\x08\x01\x12\x0f\n\x0bSOURCE_COPY\x10\x04\x12\x11\n\rSOURCE_BSDIFF\x10'
    b'\x05\x12\x0e\n\nREPLACE_XZ\x10\x08\x12\x08\n\x04ZERO\x10\x06\x12\x0b\n\x07'
    b'DISCARD\x10\x07\x12\x11\n\rBROTLI_BSDIFF\x10\n\x12\x0c\n\x08PUFFDIFF\x10\t'
    b'\x12\x0c\n\x08ZUCCHINI\x10\x0b\x12\x12\n\x0eLZ4DIFF_BSDIFF\x10\x0c\x12\x14'
    b'\n\x10LZ4DIFF_PUFFDIFF\x10\r\x12\x08\n\x04ZSTD\x10\x0e\"\x81\x02\n\x11Cow'
    b'MergeOperation\x12<\n\x04type\x18\x01 \x01(\x0e2..chromeos_update_engine.'
    b'CowMergeOperation.Type\x122\n\nsrc_extent\x18\x02 \x01(\x0b2\x1e.chromeos'
    b'_update_engine.Extent\x122\n\ndst_extent\x18\x03 \x01(\x0b2\x1e.chromeos_'
    b'update_engine.Extent\x12\x12\n\nsrc_offset\x18\x04 \x01(\r\"2\n\x04Type\x12'
    b'\x0c\n\x08COW_COPY\x10\x00\x12\x0b\n\x07COW_XOR\x10\x01\x12\x0f\n\x0bCOW_'
    b'REPLACE\x10\x02\"\xe7\x06\n\x0fPartitionUpdate\x12\x16\n\x0epartition_name'
    b'\x18\x01 \x02(\t\x12\x17\n\x0frun_postinstall\x18\x02 \x01(\x08\x12\x18\n'
    b'\x10postinstall_path\x18\x03 \x01(\t\x12\x17\n\x0ffilesystem_type\x18\x04'
    b' \x01(\t\x12M\n\x17new_partition_signature\x18\x05 \x03(\x0b2,.chromeos_'
    b'update_engine.Signatures.Signature\x12A\n\x12old_partition_info\x18\x06 '
    b'\x01(\x0b2%.chromeos_update_engine.PartitionInfo\x12A\n\x12new_partition_'
    b'info\x18\x07 \x01(\x0b2%.chromeos_update_engine.PartitionInfo\x12<\n\n'
    b'operations\x18\x08 \x03(\x0b2(.chromeos_update_engine.InstallOperation'
    b'\x12\x1c\n\x14postinstall_optional\x18\t \x01(\x08\x12=\n\x15hash_tree_data'
    b'_extent\x18\n \x01(\x0b2\x1e.chromeos_update_engine.Extent\x128\n\x10hash'
    b'_tree_extent\x18\x0b \x01(\x0b2\x1e.chromeos_update_engine.Extent\x12\x1b'
    b'\n\x13hash_tree_algorithm\x18\x0c \x01(\t\x12\x16\n\x0ehash_tree_salt\x18'
    b'\r \x01(\x0c\x127\n\x0ffec_data_extent\x18\x0e \x01(\x0b2\x1e.chromeos_'
    b'update_engine.Extent\x122\n\nfec_extent\x18\x0f \x01(\x0b2\x1e.chromeos_'
    b'update_engine.Extent\x12\x14\n\tfec_roots\x18\x10 \x01(\r:\x012\x12\x0f\n'
    b'\x07version\x18\x11 \x01(\t\x12C\n\x10merge_operations\x18\x12 \x03(\x0b2)'
    b'.chromeos_update_engine.CowMergeOperation\x12\x19\n\x11estimate_cow_size'
    b'\x18\x13 \x01(\x04\x12\x1d\n\x15estimate_op_count_max\x18\x14 \x01(\x04\"L'
    b'\n\x15DynamicPartitionGroup\x12\x0c\n\x04name\x18\x01 \x02(\t\x12\x0c\n\x04'
    b'size\x18\x02 \x01(\x04\x12\x17\n\x0fpartition_names\x18\x03 \x03(\t\"8\n\x0e'
    b'VABCFeatureSet\x12\x10\n\x08threaded\x18\x01 \x01(\x08\x12\x14\n\x0cbatch_'
    b'writes\x18\x02 \x01(\x08\"\x9c\x02\n\x18DynamicPartitionMetadata\x12=\n\x06'
    b'groups\x18\x01 \x03(\x0b2-.chromeos_update_engine.DynamicPartitionGroup'
    b'\x12\x18\n\x10snapshot_enabled\x18\x02 \x01(\x08\x12\x14\n\x0cvabc_enabled'
    b'\x18\x03 \x01(\x08\x12\x1e\n\x16vabc_compression_param\x18\x04 \x01(\t\x12'
    b'\x13\n\x0bcow_version\x18\x05 \x01(\r\x12@\n\x10vabc_feature_set\x18\x06 '
    b'\x01(\x0b2&.chromeos_update_engine.VABCFeatureSet\x12\x1a\n\x12compression'
    b'_factor\x18\x07 \x01(\x04\"c\n\x08ApexInfo\x12\x14\n\x0cpackage_name\x18'
    b'\x01 \x01(\t\x12\x0f\n\x07version\x18\x02 \x01(\x03\x12\x15\n\ris_compressed'
    b'\x18\x03 \x01(\x08\x12\x19\n\x11decompressed_size\x18\x04 \x01(\x03\"C\n\x0c'
    b'ApexMetadata\x123\n\tapex_info\x18\x01 \x03(\x0b2 .chromeos_update_engine.'
    b'ApexInfo\"\xc3\x03\n\x14DeltaArchiveManifest\x12\x18\n\nblock_size\x18\x03'
    b' \x01(\r:\x044096\x12\x19\n\x11signatures_offset\x18\x04 \x01(\x04\x12\x17'
    b'\n\x0fsignatures_size\x18\x05 \x01(\x04\x12\x18\n\rminor_version\x18\x0c '
    b'\x01(\r:\x010\x12;\n\npartitions\x18\r \x03(\x0b2\'.chromeos_update_engine.'
    b'PartitionUpdate\x12\x15\n\rmax_timestamp\x18\x0e \x01(\x03\x12T\n\x1adynamic'
    b'_partition_metadata\x18\x0f \x01(\x0b20.chromeos_update_engine.Dynamic'
    b'PartitionMetadata\x12\x16\n\x0epartial_update\x18\x10 \x01(\x08\x123\n\t'
    b'apex_info\x18\x11 \x03(\x0b2 .chromeos_update_engine.ApexInfo\x12\x1c\n\x14'
    b'security_patch_level\x18\x12 \x01(\tJ\x04\x08\x01\x10\x02J\x04\x08\x02\x10'
    b'\x03J\x04\x08\x06\x10\x07J\x04\x08\x07\x10\x08J\x04\x08\x08\x10\tJ\x04\x08'
    b'\t\x10\nJ\x04\x08\n\x10\x0bJ\x04\x08\x0b\x10\x0c'
)

DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(_PROTOBUF_DESCRIPTOR)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'update_metadata_pb2', _globals)

# Reference the built message classes (created by BuildTopDescriptorsAndMessages)
DeltaArchiveManifest = _globals['DeltaArchiveManifest']
InstallOperation = _globals['InstallOperation']
Extent = _globals['Extent']
PartitionUpdate = _globals['PartitionUpdate']
Signatures = _globals['Signatures']
PartitionInfo = _globals['PartitionInfo']


# =============================================================================
# CONSTANTS AND LOGGING
# =============================================================================

PAYLOAD_MAGIC = b'CrAU'
BSDF2_MAGIC = b'BSDF2'
SUPPORTED_FORMAT_VERSION = 2

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


# =============================================================================
# EXCEPTIONS
# =============================================================================

class PayloadError(Exception):
    """Base exception for payload processing errors."""
    pass


class UnsupportedOperationError(PayloadError):
    """Raised when an unsupported operation type is encountered."""
    pass


class DifferentialOTAError(PayloadError):
    """Raised when differential OTA requirements are not met."""
    pass


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def unpack_u32(data: bytes) -> int:
    """Unpack a big-endian 32-bit unsigned integer."""
    return struct.unpack('>I', data)[0]


def unpack_u64(data: bytes) -> int:
    """Unpack a big-endian 64-bit unsigned integer."""
    return struct.unpack('>Q', data)[0]


def bsdf2_decompress(algorithm: int, data: bytes) -> bytes:
    """Decompress data using the specified BSDF2 algorithm."""
    decompressors = {
        0: lambda d: d,
        1: bz2.decompress,
        2: brotli.decompress,
    }
    if algorithm not in decompressors:
        raise PayloadError(f"Unknown BSDF2 compression algorithm: {algorithm}")
    return decompressors[algorithm](data)


def bsdf2_read_patch(stream: BinaryIO) -> tuple:
    """Read a bsdiff/BSDF2-format patch from a stream."""
    magic = stream.read(8)
    
    if magic == bsdiff4.format.MAGIC:
        alg_control = alg_diff = alg_extra = 1
    elif magic[:5] == BSDF2_MAGIC:
        alg_control, alg_diff, alg_extra = magic[5], magic[6], magic[7]
    else:
        raise PayloadError("Invalid bsdiff/BSDF2 header")

    len_control = bsdiff4.core.decode_int64(stream.read(8))
    len_diff = bsdiff4.core.decode_int64(stream.read(8))
    len_dst = bsdiff4.core.decode_int64(stream.read(8))

    bcontrol = bsdf2_decompress(alg_control, stream.read(len_control))
    tcontrol = [
        (
            bsdiff4.core.decode_int64(bcontrol[i:i + 8]),
            bsdiff4.core.decode_int64(bcontrol[i + 8:i + 16]),
            bsdiff4.core.decode_int64(bcontrol[i + 16:i + 24])
        )
        for i in range(0, len(bcontrol), 24)
    ]

    bdiff = bsdf2_decompress(alg_diff, stream.read(len_diff))
    bextra = bsdf2_decompress(alg_extra, stream.read())
    
    return len_dst, tcontrol, bdiff, bextra


# =============================================================================
# PAYLOAD FILE HANDLING
# =============================================================================

class PayloadFile:
    """Context manager for opening payload files (local, remote, or inside zip)."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self._file: Optional[BinaryIO] = None
        self._zip_file: Optional[zipfile.ZipFile] = None
        self._remote_file: Optional[BinaryIO] = None
    
    def __enter__(self) -> BinaryIO:
        is_url = self.file_path.startswith(('http://', 'https://', 's3://', 'gs://'))
        self._file = self._open_remote() if is_url else self._open_local()
        return self._file
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._file:
            self._file.close()
        if self._zip_file:
            self._zip_file.close()
        if self._remote_file:
            self._remote_file.close()
    
    def _open_remote(self) -> BinaryIO:
        protocol = urllib.parse.urlparse(self.file_path).scheme
        fs = fsspec.filesystem(protocol)
        self._remote_file = fs.open(self.file_path)
        
        if zipfile.is_zipfile(self._remote_file):
            self._remote_file.seek(0)
            self._zip_file = zipfile.ZipFile(self._remote_file)
            return self._extract_payload_from_zip(self._zip_file)
        
        self._remote_file.seek(0)
        return self._remote_file
    
    def _open_local(self) -> BinaryIO:
        if zipfile.is_zipfile(self.file_path):
            self._zip_file = zipfile.ZipFile(self.file_path)
            return self._extract_payload_from_zip(self._zip_file)
        return open(self.file_path, 'rb')
    
    @staticmethod
    def _extract_payload_from_zip(zf: zipfile.ZipFile) -> BinaryIO:
        if "payload.bin" not in zf.namelist():
            raise PayloadError("payload.bin not found in zip file")
        return zf.open("payload.bin")


# =============================================================================
# OPERATION HANDLER
# =============================================================================

class OperationHandler:
    """Handles different operation types for partition extraction."""
    
    def __init__(self, payload_file: BinaryIO, data_offset: int, block_size: int):
        self.payload_file = payload_file
        self.data_offset = data_offset
        self.block_size = block_size
    
    def process(self, op, out_file: BinaryIO, old_file: Optional[BinaryIO] = None) -> bytes:
        """Process an operation and write the result to the output file."""
        data = self._read_operation_data(op)
        
        handlers = {
            op.REPLACE_XZ: self._handle_replace_xz,
            op.ZSTD: self._handle_zstd,
            op.REPLACE_BZ: self._handle_replace_bz,
            op.REPLACE: self._handle_replace,
            op.SOURCE_COPY: self._handle_source_copy,
            op.SOURCE_BSDIFF: self._handle_bsdiff,
            op.BROTLI_BSDIFF: self._handle_bsdiff,
            op.ZERO: self._handle_zero,
        }
        
        handler = handlers.get(op.type)
        if handler is None:
            raise UnsupportedOperationError(f"Unsupported operation type: {op.type}")
        
        handler(op, data, out_file, old_file)
        return data
    
    def _read_operation_data(self, op) -> bytes:
        self.payload_file.seek(self.data_offset + op.data_offset)
        data = self.payload_file.read(op.data_length)
        
        if op.data_sha256_hash:
            if hashlib.sha256(data).digest() != op.data_sha256_hash:
                raise PayloadError("Operation data hash mismatch")
        return data
    
    def _handle_replace_xz(self, op, data: bytes, out_file: BinaryIO, _old_file) -> None:
        decompressed = lzma.LZMADecompressor().decompress(data)
        self._write_to_extent(out_file, op.dst_extents[0], decompressed)
    
    def _handle_zstd(self, op, data: bytes, out_file: BinaryIO, _old_file) -> None:
        decompressed = zstandard.ZstdDecompressor().decompressobj().decompress(data)
        self._write_to_extent(out_file, op.dst_extents[0], decompressed)
    
    def _handle_replace_bz(self, op, data: bytes, out_file: BinaryIO, _old_file) -> None:
        decompressed = bz2.BZ2Decompressor().decompress(data)
        self._write_to_extent(out_file, op.dst_extents[0], decompressed)
    
    def _handle_replace(self, op, data: bytes, out_file: BinaryIO, _old_file) -> None:
        self._write_to_extent(out_file, op.dst_extents[0], data)
    
    def _handle_source_copy(self, op, _data: bytes, out_file: BinaryIO, old_file: Optional[BinaryIO]) -> None:
        if not old_file:
            raise DifferentialOTAError("SOURCE_COPY requires original image for differential OTA")
        
        out_file.seek(op.dst_extents[0].start_block * self.block_size)
        for ext in op.src_extents:
            old_file.seek(ext.start_block * self.block_size)
            out_file.write(old_file.read(ext.num_blocks * self.block_size))
    
    def _handle_bsdiff(self, op, data: bytes, out_file: BinaryIO, old_file: Optional[BinaryIO]) -> None:
        if not old_file:
            raise DifferentialOTAError("BSDIFF requires original image for differential OTA")
        
        src_buffer = io.BytesIO()
        for ext in op.src_extents:
            old_file.seek(ext.start_block * self.block_size)
            src_buffer.write(old_file.read(ext.num_blocks * self.block_size))
        
        src_buffer.seek(0)
        patched = bsdiff4.core.patch(src_buffer.read(), *bsdf2_read_patch(io.BytesIO(data)))
        
        patched_buffer = io.BytesIO(patched)
        block_offset = 0
        for ext in op.dst_extents:
            patched_buffer.seek(block_offset * self.block_size)
            block_offset += ext.num_blocks
            out_file.seek(ext.start_block * self.block_size)
            out_file.write(patched_buffer.read(ext.num_blocks * self.block_size))
    
    def _handle_zero(self, op, _data: bytes, out_file: BinaryIO, _old_file) -> None:
        for ext in op.dst_extents:
            out_file.seek(ext.start_block * self.block_size)
            out_file.write(b'\x00' * ext.num_blocks * self.block_size)
    
    def _write_to_extent(self, out_file: BinaryIO, extent, data: bytes) -> None:
        out_file.seek(extent.start_block * self.block_size)
        out_file.write(data)


# =============================================================================
# PAYLOAD CREATOR (REPACKER)
# =============================================================================

class CompressionType:
    """Supported compression types for payload creation."""
    NONE = 'none'
    ZSTD = 'zstd'
    XZ = 'xz'
    BZ2 = 'bz2'
    
    @classmethod
    def all(cls) -> list[str]:
        return [cls.NONE, cls.ZSTD, cls.XZ, cls.BZ2]


def pack_u32(value: int) -> bytes:
    """Pack a big-endian 32-bit unsigned integer."""
    return struct.pack('>I', value)


def pack_u64(value: int) -> bytes:
    """Pack a big-endian 64-bit unsigned integer."""
    return struct.pack('>Q', value)


def compress_data(data: bytes, compression: str, level: int = 9) -> tuple[bytes, int]:
    """
    Compress data using the specified algorithm.
    Returns (compressed_data, operation_type).
    """
    if compression == CompressionType.NONE:
        return data, 0  # REPLACE
    elif compression == CompressionType.ZSTD:
        cctx = zstandard.ZstdCompressor(level=level)
        return cctx.compress(data), 14  # ZSTD
    elif compression == CompressionType.XZ:
        return lzma.compress(data, preset=level), 8  # REPLACE_XZ
    elif compression == CompressionType.BZ2:
        return bz2.compress(data, compresslevel=level), 1  # REPLACE_BZ
    else:
        raise PayloadError(f"Unknown compression type: {compression}")


class PayloadCreator:
    """Creates OTA payload files from partition images."""
    
    DEFAULT_BLOCK_SIZE = 4096
    BLOCKS_PER_OPERATION = 2048  # ~8MB per operation for better parallelism
    
    def __init__(
        self,
        output_path: str,
        block_size: int = DEFAULT_BLOCK_SIZE,
        compression: str = CompressionType.ZSTD,
        compression_level: int = 9,
        progress_callback: Optional[Callable] = None
    ):
        self.output_path = Path(output_path)
        self.block_size = block_size
        self.compression = compression
        self.compression_level = compression_level
        self.progress_callback = progress_callback
    
    def create(self, image_paths: list[str]) -> None:
        """
        Create a payload.bin from partition images.
        
        Args:
            image_paths: List of paths to partition image files.
                        Partition names are derived from filenames (e.g., system.img -> system)
        """
        logger.info(f"Creating payload with {len(image_paths)} partition(s)...")
        logger.info(f"Compression: {self.compression}, Block size: {self.block_size}")
        
        # Collect all operation data first
        partitions_data = []
        all_data_blobs = []
        current_data_offset = 0
        
        total_size = sum(os.path.getsize(p) for p in image_paths)
        processed_size = 0
        
        for image_path in image_paths:
            path = Path(image_path)
            partition_name = path.stem  # system.img -> system
            
            logger.info(f"Processing {partition_name}...")
            
            partition_ops, data_blobs, partition_size = self._process_partition(
                path, partition_name, current_data_offset
            )
            
            # Update data offset for next partition
            for blob in data_blobs:
                current_data_offset += len(blob)
                all_data_blobs.append(blob)
            
            partitions_data.append((partition_name, partition_ops, partition_size))
            
            processed_size += os.path.getsize(image_path)
            if self.progress_callback:
                self.progress_callback(processed_size, total_size, f"Processed {partition_name}")
        
        # Build manifest
        manifest = self._build_manifest(partitions_data)
        manifest_bytes = manifest.SerializeToString()
        
        # Write payload file
        logger.info(f"Writing payload to {self.output_path}...")
        self._write_payload(manifest_bytes, all_data_blobs)
        
        logger.info(f"Payload created successfully: {self.output_path}")
        logger.info(f"Total size: {self.output_path.stat().st_size / (1024*1024):.2f} MB")
    
    def _process_partition(
        self, 
        image_path: Path, 
        partition_name: str,
        base_data_offset: int
    ) -> tuple[list, list[bytes], int]:
        """Process a single partition image and return operations and data blobs."""
        operations = []
        data_blobs = []
        current_offset = base_data_offset
        
        file_size = image_path.stat().st_size
        total_blocks = (file_size + self.block_size - 1) // self.block_size
        
        with open(image_path, 'rb') as f:
            block_num = 0
            
            while block_num < total_blocks:
                # Determine how many blocks to process in this operation
                remaining_blocks = total_blocks - block_num
                op_blocks = min(self.BLOCKS_PER_OPERATION, remaining_blocks)
                
                # Read the data
                chunk_size = op_blocks * self.block_size
                data = f.read(chunk_size)
                
                # Pad last chunk if needed
                if len(data) < chunk_size:
                    data = data + b'\x00' * (chunk_size - len(data))
                
                # Check if block is all zeros (can use ZERO operation)
                if data == b'\x00' * len(data):
                    op = InstallOperation()
                    op.type = 6  # ZERO
                    
                    dst_extent = op.dst_extents.add()
                    dst_extent.start_block = block_num
                    dst_extent.num_blocks = op_blocks
                    
                    operations.append(op)
                else:
                    # Compress the data
                    compressed, op_type = compress_data(
                        data, self.compression, self.compression_level
                    )
                    
                    # Create operation
                    op = InstallOperation()
                    op.type = op_type
                    op.data_offset = current_offset
                    op.data_length = len(compressed)
                    op.data_sha256_hash = hashlib.sha256(compressed).digest()
                    
                    dst_extent = op.dst_extents.add()
                    dst_extent.start_block = block_num
                    dst_extent.num_blocks = op_blocks
                    
                    operations.append(op)
                    data_blobs.append(compressed)
                    current_offset += len(compressed)
                
                block_num += op_blocks
        
        return operations, data_blobs, file_size
    
    def _build_manifest(self, partitions_data: list) -> DeltaArchiveManifest:
        """Build the DeltaArchiveManifest protobuf message."""
        manifest = DeltaArchiveManifest()
        manifest.block_size = self.block_size
        manifest.minor_version = 0
        
        for partition_name, operations, partition_size in partitions_data:
            partition = manifest.partitions.add()
            partition.partition_name = partition_name
            
            # Add partition info
            partition.new_partition_info.size = partition_size
            
            # Add operations
            for op in operations:
                new_op = partition.operations.add()
                new_op.CopyFrom(op)
        
        return manifest
    
    def _write_payload(self, manifest_bytes: bytes, data_blobs: list[bytes]) -> None:
        """Write the complete payload file."""
        with open(self.output_path, 'wb') as f:
            # Write header
            f.write(PAYLOAD_MAGIC)  # Magic: "CrAU"
            f.write(pack_u64(SUPPORTED_FORMAT_VERSION))  # Version: 2
            f.write(pack_u64(len(manifest_bytes)))  # Manifest size
            f.write(pack_u32(0))  # Metadata signature size (none)
            
            # Write manifest
            f.write(manifest_bytes)
            
            # Write all data blobs
            for blob in data_blobs:
                f.write(blob)


def run_create(args) -> None:
    """Run payload creation from command line."""
    image_paths = []
    input_dir = Path(args.input_dir)
    
    if args.images:
        # Specific images requested
        for name in args.images.split(','):
            name = name.strip()
            img_path = input_dir / f"{name}.img"
            if img_path.exists():
                image_paths.append(str(img_path))
            else:
                logger.warning(f"Image not found: {img_path}")
    else:
        # All .img files in directory
        image_paths = sorted([str(p) for p in input_dir.glob("*.img")])
    
    if not image_paths:
        raise PayloadError(f"No partition images found in {input_dir}")
    
    logger.info(f"Found {len(image_paths)} partition image(s)")
    
    def progress(current, total, msg):
        pct = int(current / total * 100)
        logger.info(f"  [{pct:3d}%] {msg}")
    
    creator = PayloadCreator(
        output_path=args.output,
        compression=args.compression,
        compression_level=args.level,
        progress_callback=progress
    )
    creator.create(image_paths)


# =============================================================================
# ANDROID IMAGE EXTRACTION
# =============================================================================

# Magic numbers for Android image formats
SPARSE_HEADER_MAGIC = 0xED26FF3A
BOOT_MAGIC = b'ANDROID!'
BOOT_MAGIC_V3 = b'ANDROID!'
VENDOR_BOOT_MAGIC = b'VNDRBOOT'
LP_METADATA_MAGIC = 0x414C5030  # "0PLA" - Android Logical Partition
EROFS_MAGIC = 0xE0F5E1E2
EXT4_MAGIC = 0xEF53
FAT_BOOT_SIG = 0xAA55  # FAT boot signature at offset 0x1FE
ELF_MAGIC = b'\x7fELF'  # ELF executable format
MBN_MAGIC = 0x00000005  # Qualcomm MBN type 5 (common)
AVB_MAGIC = b'AVB0'  # Android Verified Boot magic

# Bootloader format magic numbers
LK_MAGIC = b'BOOTLDR!'  # Little Kernel bootloader (MediaTek)
QCOM_MBN_MAGIC_1 = 0x00000005  # Qualcomm MBN format (type 5)
QCOM_MBN_MAGIC_2 = 0x00000007  # Qualcomm MBN format (type 7)
QCOM_ELF_MAGIC = b'\x7fELF'  # Qualcomm signed ELF (XBL, ABL, etc.)
MTK_LOGO_MAGIC = b'LOGO'  # MediaTek logo partition
GZIP_MAGIC = b'\x1f\x8b'  # Gzip compressed
DTBO_MAGIC = 0xD7B7AB1E  # DTBO table magic (Android Device Tree Blob Overlay)


@dataclass
class SparseHeader:
    """Android sparse image header."""
    magic: int
    major_version: int
    minor_version: int
    file_header_size: int
    chunk_header_size: int
    block_size: int
    total_blocks: int
    total_chunks: int
    checksum: int


@dataclass  
class BootImageInfo:
    """Parsed boot image information."""
    header_version: int
    kernel_size: int
    kernel_offset: int
    ramdisk_size: int
    ramdisk_offset: int
    second_size: int
    second_offset: int
    dtb_size: int
    dtb_offset: int
    page_size: int
    os_version: str
    cmdline: str
    extra_cmdline: str


@dataclass
class LpMetadataPartition:
    """Logical partition metadata."""
    name: str
    group_name: str
    first_sector: int
    size: int
    attributes: int


def detect_image_type(file_path: str) -> str:
    """Detect the type of Android image file."""
    with open(file_path, 'rb') as f:
        header = f.read(64)
    
    if len(header) < 4:
        return 'unknown'
    
    # Check for sparse image
    magic = struct.unpack('<I', header[:4])[0]
    if magic == SPARSE_HEADER_MAGIC:
        return 'sparse'
    
    # Check for boot image
    if header[:8] == BOOT_MAGIC:
        return 'boot'
    
    # Check for vendor boot image
    if header[:8] == VENDOR_BOOT_MAGIC:
        return 'vendor_boot'
    
    # Check for super partition (LP metadata at offset 4096)
    with open(file_path, 'rb') as f:
        f.seek(4096)  # LP_METADATA_GEOMETRY_OFFSET
        lp_header = f.read(4)
        if len(lp_header) >= 4:
            lp_magic = struct.unpack('<I', lp_header)[0]
            if lp_magic == LP_METADATA_MAGIC:
                return 'super'
    
    # Check for ext4 (superblock at offset 0x400)
    with open(file_path, 'rb') as f:
        f.seek(0x438)  # ext4 magic offset
        ext4_header = f.read(2)
        if len(ext4_header) >= 2:
            ext4_magic = struct.unpack('<H', ext4_header)[0]
            if ext4_magic == EXT4_MAGIC:
                return 'ext4'
    
    # Check for EROFS
    with open(file_path, 'rb') as f:
        f.seek(0x400)  # EROFS superblock offset
        erofs_header = f.read(4)
        if len(erofs_header) >= 4:
            erofs_magic = struct.unpack('<I', erofs_header)[0]
            if erofs_magic == EROFS_MAGIC:
                return 'erofs'
    
    # Check for FAT filesystem (common for modem, firmware partitions)
    with open(file_path, 'rb') as f:
        # Check boot signature at offset 0x1FE
        f.seek(0x1FE)
        boot_sig = f.read(2)
        if len(boot_sig) >= 2 and struct.unpack('<H', boot_sig)[0] == FAT_BOOT_SIG:
            # Check for FAT string
            f.seek(0x36)
            fat_type = f.read(8)
            if fat_type[:3] == b'FAT':
                return 'fat'
            # Check for FAT32
            f.seek(0x52)
            fat32_type = f.read(8)
            if fat32_type[:5] == b'FAT32':
                return 'fat'
    
    # Check for ELF - further classify as bootloader if it's a signed Qualcomm image
    if header[:4] == ELF_MAGIC:
        # Check for Qualcomm signed ELF characteristics
        # Qualcomm bootloader ELFs often have specific machine types and program headers
        with open(file_path, 'rb') as f:
            f.seek(0)
            elf_header = f.read(64)
            if len(elf_header) >= 52:
                # Check ELF machine type (0x12 offset for 32-bit, same for 64-bit conceptually)
                ei_class = elf_header[4]  # 1=32-bit, 2=64-bit
                if ei_class == 1:  # 32-bit
                    e_machine = struct.unpack('<H', elf_header[18:20])[0]
                else:  # 64-bit
                    e_machine = struct.unpack('<H', elf_header[18:20])[0]
                
                # ARM=40, AArch64=183, Hexagon=164
                # Check file name hints for bootloader
                filename = Path(file_path).stem.lower()
                
                # ABL is special - return specific type for deeper analysis
                if 'abl' in filename:
                    return 'abl'
                
                bootloader_names = ['xbl', 'hyp', 'tz', 'tzsq', 'devcfg', 'aop', 
                                    'keymaster', 'cmnlib', 'qupfw', 'storsec', 'uefi',
                                    'lk', 'preloader', 'sbl1', 'rpm', 'pmic']
                if any(bl in filename for bl in bootloader_names):
                    return 'bootloader'
        return 'elf'
    
    # Check for AVB vbmeta (Android Verified Boot)
    if header[:4] == AVB_MAGIC:
        return 'vbmeta'
    
    # Check for DTBO (Device Tree Blob Overlay) image
    if len(header) >= 4:
        dtbo_magic = struct.unpack('>I', header[:4])[0]  # Big endian!
        if dtbo_magic == DTBO_MAGIC:
            return 'dtbo'
    
    # Check for Little Kernel bootloader (MediaTek)
    if header[:8] == LK_MAGIC:
        return 'bootloader'
    
    # Check for Qualcomm MBN format
    if len(header) >= 40:
        # MBN has a specific header structure
        mbn_type = struct.unpack('<I', header[0:4])[0]
        if mbn_type in (QCOM_MBN_MAGIC_1, QCOM_MBN_MAGIC_2):
            # Further verify by checking header fields
            flash_parti_ver = struct.unpack('<I', header[4:8])[0]
            if flash_parti_ver in (3, 4, 5, 6, 7):  # Known versions
                return 'bootloader'
    
    # Check filename for ABL even if not ELF (Pixel/Tensor, Samsung Exynos)
    # These devices use signed binary blobs instead of ELF
    filename = Path(file_path).stem.lower()
    if 'abl' in filename or filename in ['bl1', 'bl2', 'bl31']:
        return 'abl'
    
    return 'raw'


class SparseImageConverter:
    """Convert Android sparse images to raw images."""
    
    CHUNK_TYPE_RAW = 0xCAC1
    CHUNK_TYPE_FILL = 0xCAC2
    CHUNK_TYPE_DONT_CARE = 0xCAC3
    CHUNK_TYPE_CRC32 = 0xCAC4
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        self.progress_callback = progress_callback
    
    def convert(self, input_path: str, output_path: str) -> None:
        """Convert sparse image to raw image."""
        with open(input_path, 'rb') as f_in:
            # Read sparse header
            header = self._read_header(f_in)
            
            logger.info(f"Sparse image: {header.total_blocks} blocks of {header.block_size} bytes")
            logger.info(f"Output size: {header.total_blocks * header.block_size / (1024*1024):.2f} MB")
            
            with open(output_path, 'wb') as f_out:
                for chunk_idx in range(header.total_chunks):
                    self._process_chunk(f_in, f_out, header)
                    
                    if self.progress_callback:
                        self.progress_callback(
                            chunk_idx + 1, 
                            header.total_chunks,
                            f"Converting chunk {chunk_idx + 1}/{header.total_chunks}"
                        )
    
    def _read_header(self, f: BinaryIO) -> SparseHeader:
        """Read and parse sparse image header."""
        data = f.read(28)
        if len(data) < 28:
            raise PayloadError("Invalid sparse image header")
        
        magic, major, minor, file_hdr_sz, chunk_hdr_sz, block_sz, total_blks, total_chunks, checksum = \
            struct.unpack('<IHHHHIIII', data)
        
        if magic != SPARSE_HEADER_MAGIC:
            raise PayloadError(f"Invalid sparse magic: {hex(magic)}")
        
        # Skip any extra header bytes
        if file_hdr_sz > 28:
            f.read(file_hdr_sz - 28)
        
        return SparseHeader(
            magic=magic,
            major_version=major,
            minor_version=minor,
            file_header_size=file_hdr_sz,
            chunk_header_size=chunk_hdr_sz,
            block_size=block_sz,
            total_blocks=total_blks,
            total_chunks=total_chunks,
            checksum=checksum
        )
    
    def _process_chunk(self, f_in: BinaryIO, f_out: BinaryIO, header: SparseHeader) -> None:
        """Process a single chunk from sparse image."""
        chunk_header = f_in.read(12)
        if len(chunk_header) < 12:
            raise PayloadError("Unexpected end of sparse image")
        
        chunk_type, reserved, chunk_sz, total_sz = struct.unpack('<HHII', chunk_header)
        
        # Skip any extra chunk header bytes
        if header.chunk_header_size > 12:
            f_in.read(header.chunk_header_size - 12)
        
        data_size = total_sz - header.chunk_header_size
        
        if chunk_type == self.CHUNK_TYPE_RAW:
            # Raw data - copy directly
            data = f_in.read(data_size)
            f_out.write(data)
        
        elif chunk_type == self.CHUNK_TYPE_FILL:
            # Fill with repeated 4-byte value
            fill_data = f_in.read(4)
            fill_count = chunk_sz * header.block_size // 4
            f_out.write(fill_data * fill_count)
        
        elif chunk_type == self.CHUNK_TYPE_DONT_CARE:
            # Skip (write zeros)
            f_out.write(b'\x00' * (chunk_sz * header.block_size))
        
        elif chunk_type == self.CHUNK_TYPE_CRC32:
            # CRC32 checksum - skip
            f_in.read(4)
        
        else:
            raise PayloadError(f"Unknown chunk type: {hex(chunk_type)}")


class BootImageExtractor:
    """Extract components from Android boot/recovery images.
    
    Supports:
    - boot.img (v0-v4)
    - recovery.img (same format as boot.img)
    - vendor_boot.img (v3-v4)
    
    Extracts: kernel, ramdisk, DTB, second bootloader, recovery_dtbo
    """
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        self.progress_callback = progress_callback
    
    def extract(self, input_path: str, output_dir: str) -> dict:
        """Extract kernel, ramdisk, and other components from boot image."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        with open(input_path, 'rb') as f:
            info = self._parse_header(f)
            extracted = {}
            
            # Extract kernel
            if info.kernel_size > 0:
                f.seek(info.kernel_offset)
                kernel_data = f.read(info.kernel_size)
                kernel_path = Path(output_dir) / 'kernel'
                kernel_path.write_bytes(kernel_data)
                extracted['kernel'] = str(kernel_path)
                logger.info(f"  Extracted kernel: {info.kernel_size} bytes")
                
                # Check if kernel is gzip compressed
                if kernel_data[:2] == b'\x1f\x8b':
                    extracted['kernel_compressed'] = 'gzip'
                elif kernel_data[:4] == b'\x28\xb5\x2f\xfd':
                    extracted['kernel_compressed'] = 'zstd'
                elif kernel_data[:2] == b'\x5d\x00':
                    extracted['kernel_compressed'] = 'lzma'
            
            # Extract ramdisk
            if info.ramdisk_size > 0:
                f.seek(info.ramdisk_offset)
                ramdisk_data = f.read(info.ramdisk_size)
                
                # Determine ramdisk format
                if ramdisk_data[:2] == b'\x1f\x8b':
                    ramdisk_ext = 'ramdisk.cpio.gz'
                elif ramdisk_data[:4] == b'\x28\xb5\x2f\xfd':
                    ramdisk_ext = 'ramdisk.cpio.zst'
                elif ramdisk_data[:6] == b'070701' or ramdisk_data[:6] == b'070702':
                    ramdisk_ext = 'ramdisk.cpio'
                elif ramdisk_data[:4] == b'\x5d\x00\x00\x00':
                    ramdisk_ext = 'ramdisk.cpio.lz4'
                else:
                    ramdisk_ext = 'ramdisk'
                
                ramdisk_path = Path(output_dir) / ramdisk_ext
                ramdisk_path.write_bytes(ramdisk_data)
                extracted['ramdisk'] = str(ramdisk_path)
                logger.info(f"  Extracted ramdisk: {info.ramdisk_size} bytes")
            
            # Extract second stage bootloader (if present)
            if info.second_size > 0:
                f.seek(info.second_offset)
                second_data = f.read(info.second_size)
                second_path = Path(output_dir) / 'second'
                second_path.write_bytes(second_data)
                extracted['second'] = str(second_path)
                logger.info(f"  Extracted second: {info.second_size} bytes")
            
            # Extract DTB (if present)
            if info.dtb_size > 0:
                f.seek(info.dtb_offset)
                dtb_data = f.read(info.dtb_size)
                dtb_path = Path(output_dir) / 'dtb'
                dtb_path.write_bytes(dtb_data)
                extracted['dtb'] = str(dtb_path)
                logger.info(f"  Extracted DTB: {info.dtb_size} bytes")
            
            # Save boot image info
            info_path = Path(output_dir) / 'boot_info.txt'
            with open(info_path, 'w') as f_info:
                f_info.write(f"Header Version: {info.header_version}\n")
                f_info.write(f"Page Size: {info.page_size}\n")
                f_info.write(f"OS Version: {info.os_version}\n")
                f_info.write(f"Kernel Size: {info.kernel_size}\n")
                f_info.write(f"Ramdisk Size: {info.ramdisk_size}\n")
                f_info.write(f"Second Size: {info.second_size}\n")
                f_info.write(f"DTB Size: {info.dtb_size}\n")
                f_info.write(f"Cmdline: {info.cmdline}\n")
                if info.extra_cmdline:
                    f_info.write(f"Extra Cmdline: {info.extra_cmdline}\n")
            extracted['info'] = str(info_path)
            
            return extracted
    
    def _parse_header(self, f: BinaryIO) -> BootImageInfo:
        """Parse boot image header (supports v0-v4 and vendor_boot v3/v4)."""
        magic = f.read(8)
        
        if magic == VENDOR_BOOT_MAGIC:
            # Parse vendor_boot image
            return self._parse_vendor_boot_header(f)
        
        if magic != BOOT_MAGIC:
            raise PayloadError(f"Invalid boot image magic: {magic!r}")
        
        # First, we need to determine the header version
        # In v0/v1/v2: header_version is at offset 40
        # In v3/v4: header_version is at offset 40 as well, but structure differs
        
        # Read first part common to detect version
        # Save position after magic
        f.seek(8)
        
        # Read kernel_size (4 bytes) - same position in all versions
        kernel_size = struct.unpack('<I', f.read(4))[0]
        
        # In v3/v4, the next field is ramdisk_size directly
        # In v0/v1/v2, next is kernel_addr
        # We can detect by reading ahead to get header_version
        
        # Save current position
        f.seek(8)
        
        # Try to read as v0/v1/v2 first to get header_version location
        # v0/v1/v2 header structure:
        # 0-7: magic, 8-11: kernel_size, 12-15: kernel_addr, 16-19: ramdisk_size, 20-23: ramdisk_addr
        # 24-27: second_size, 28-31: second_addr, 32-35: tags_addr, 36-39: page_size
        # 40-43: header_version (or dt_size for v0), 44-47: os_version
        
        # v3/v4 header structure:
        # 0-7: magic, 8-11: kernel_size, 12-15: ramdisk_size
        # 16-19: os_version, 20-23: header_size, 24-39: reserved[4]
        # 40-43: header_version, 44-47: cmdline_size (v4) or start of cmdline (v3)
        
        # Read enough to check header_version at offset 40
        f.seek(40)
        header_version = struct.unpack('<I', f.read(4))[0]
        
        # Validate - header_version should be 0-4 typically
        if header_version > 10:
            # Might be reading garbage, assume v0
            header_version = 0
        
        f.seek(8)  # Reset to after magic
        
        if header_version >= 3:
            # Parse v3/v4 header
            return self._parse_header_v3_v4(f, header_version)
        else:
            # Parse v0/v1/v2 header
            return self._parse_header_v0_v2(f, header_version)
    
    def _parse_header_v0_v2(self, f: BinaryIO, header_version: int) -> BootImageInfo:
        """Parse boot image header v0/v1/v2."""
        # f is positioned at offset 8 (after magic)
        kernel_size, kernel_addr, ramdisk_size, ramdisk_addr = struct.unpack('<IIII', f.read(16))
        second_size, second_addr, tags_addr, page_size = struct.unpack('<IIII', f.read(16))
        
        # Skip header_version (already known) and read os_version
        f.read(4)  # header_version
        os_version_raw = struct.unpack('<I', f.read(4))[0]
        
        # Parse OS version
        os_version = self._parse_os_version(os_version_raw)
        
        # Product name (16 bytes)
        f.read(16)
        
        # Command line (512 bytes)
        cmdline = f.read(512).rstrip(b'\x00').decode('utf-8', errors='ignore')
        
        # SHA1 hash (32 bytes)
        f.read(32)
        
        # Extra command line (1024 bytes)
        extra_cmdline = f.read(1024).rstrip(b'\x00').decode('utf-8', errors='ignore')
        
        # Validate page_size
        if page_size == 0 or page_size > 65536:
            page_size = 4096
        
        # Calculate offsets
        def align_page(size, page):
            if page == 0:
                return size
            return ((size + page - 1) // page) * page
        
        kernel_offset = page_size  # After header
        ramdisk_offset = kernel_offset + align_page(kernel_size, page_size)
        second_offset = ramdisk_offset + align_page(ramdisk_size, page_size)
        
        # DTB for header version 2
        dtb_size = 0
        dtb_offset = 0
        if header_version == 2:
            f.seek(1632)  # DTB size offset in v2 header
            dtb_data = f.read(8)
            if len(dtb_data) >= 8:
                dtb_size = struct.unpack('<I', dtb_data[:4])[0]
                dtb_offset = second_offset + align_page(second_size, page_size)
        
        return BootImageInfo(
            header_version=header_version,
            kernel_size=kernel_size,
            kernel_offset=kernel_offset,
            ramdisk_size=ramdisk_size,
            ramdisk_offset=ramdisk_offset,
            second_size=second_size,
            second_offset=second_offset,
            dtb_size=dtb_size,
            dtb_offset=dtb_offset,
            page_size=page_size,
            os_version=os_version,
            cmdline=cmdline,
            extra_cmdline=extra_cmdline
        )
    
    def _parse_header_v3_v4(self, f: BinaryIO, header_version: int) -> BootImageInfo:
        """Parse boot image header v3/v4."""
        # v3/v4 header structure (starting at offset 8, after magic):
        # 8-11: kernel_size
        # 12-15: ramdisk_size
        # 16-19: os_version
        # 20-23: header_size
        # 24-39: reserved[4] (16 bytes)
        # 40-43: header_version
        # 44-1579: cmdline (1536 bytes)
        
        kernel_size = struct.unpack('<I', f.read(4))[0]
        ramdisk_size = struct.unpack('<I', f.read(4))[0]
        os_version_raw = struct.unpack('<I', f.read(4))[0]
        header_size = struct.unpack('<I', f.read(4))[0]
        
        # Skip reserved (16 bytes) and header_version (4 bytes, already known)
        f.read(20)
        
        # Command line (1536 bytes for v3/v4)
        cmdline = f.read(1536).rstrip(b'\x00').decode('utf-8', errors='ignore')
        
        os_version = self._parse_os_version(os_version_raw)
        
        # v3/v4 always uses 4096 page size
        page_size = 4096
        
        # Calculate offsets - v3/v4 has simpler layout
        # Header is one page (4096 bytes)
        # Kernel follows immediately after header page
        # Ramdisk follows kernel (page aligned)
        
        def align_page(size, page=4096):
            return ((size + page - 1) // page) * page
        
        kernel_offset = page_size  # After 4096-byte header
        ramdisk_offset = kernel_offset + align_page(kernel_size)
        
        # v3/v4 don't have second stage or DTB in boot image
        # (DTB is in vendor_boot for v3+)
        
        return BootImageInfo(
            header_version=header_version,
            kernel_size=kernel_size,
            kernel_offset=kernel_offset,
            ramdisk_size=ramdisk_size,
            ramdisk_offset=ramdisk_offset,
            second_size=0,
            second_offset=0,
            dtb_size=0,
            dtb_offset=0,
            page_size=page_size,
            os_version=os_version,
            cmdline=cmdline,
            extra_cmdline=""
        )
    
    def _parse_os_version(self, os_version_raw: int) -> str:
        """Parse OS version from raw value."""
        if os_version_raw == 0:
            return "unknown"
        
        # OS version format:
        # bits 0-10: patch level year-month (YYYY*12 + MM - 2000*12)
        # bits 11-17: version C (patch)
        # bits 18-24: version B (minor)
        # bits 25-31: version A (major)
        
        patch_level = os_version_raw & 0x7ff
        version_c = (os_version_raw >> 11) & 0x7f
        version_b = (os_version_raw >> 18) & 0x7f
        version_a = (os_version_raw >> 25) & 0x7f
        
        if patch_level > 0:
            patch_year = 2000 + (patch_level // 12)
            patch_month = (patch_level % 12) or 12
            return f"{version_a}.{version_b}.{version_c} ({patch_year}-{patch_month:02d})"
        else:
            return f"{version_a}.{version_b}.{version_c}"
    
    def _parse_vendor_boot_header(self, f: BinaryIO) -> BootImageInfo:
        """Parse vendor_boot image header (v3/v4).
        
        Vendor boot image structure (after 8-byte magic):
        v3:
            8-11: header_version
            12-15: page_size
            16-19: kernel_addr
            20-23: ramdisk_addr  
            24-27: vendor_ramdisk_size
            28-2075: cmdline (2048 bytes)
            2076-2079: tags_addr
            2080-2095: name (16 bytes)
            2096-2099: header_size
            2100-2103: dtb_size
            2104-2111: dtb_addr
        v4 adds:
            vendor_ramdisk_table_size
            vendor_ramdisk_table_entry_num
            vendor_ramdisk_table_entry_size
            bootconfig_size
        """
        # f is positioned at offset 8 (after magic)
        header_version = struct.unpack('<I', f.read(4))[0]
        page_size = struct.unpack('<I', f.read(4))[0]
        kernel_addr = struct.unpack('<I', f.read(4))[0]
        ramdisk_addr = struct.unpack('<I', f.read(4))[0]
        vendor_ramdisk_size = struct.unpack('<I', f.read(4))[0]
        
        # Command line (2048 bytes)
        cmdline = f.read(2048).rstrip(b'\x00').decode('utf-8', errors='ignore')
        
        tags_addr = struct.unpack('<I', f.read(4))[0]
        
        # Product name (16 bytes)
        product_name = f.read(16).rstrip(b'\x00').decode('utf-8', errors='ignore')
        
        header_size = struct.unpack('<I', f.read(4))[0]
        dtb_size = struct.unpack('<I', f.read(4))[0]
        dtb_addr = struct.unpack('<Q', f.read(8))[0]
        
        # Validate page_size
        if page_size == 0 or page_size > 65536:
            page_size = 4096
        
        # Calculate offsets
        def align_page(size, page):
            if page == 0:
                return size
            return ((size + page - 1) // page) * page
        
        # Vendor boot layout:
        # [header pages] [vendor ramdisk pages] [dtb pages]
        header_pages = align_page(header_size, page_size)
        ramdisk_offset = header_pages
        dtb_offset = ramdisk_offset + align_page(vendor_ramdisk_size, page_size)
        
        # vendor_boot doesn't have a kernel - it's in boot.img
        # The "ramdisk" in vendor_boot is the vendor ramdisk
        return BootImageInfo(
            header_version=header_version,
            kernel_size=0,  # No kernel in vendor_boot
            kernel_offset=0,
            ramdisk_size=vendor_ramdisk_size,
            ramdisk_offset=ramdisk_offset,
            second_size=0,
            second_offset=0,
            dtb_size=dtb_size,
            dtb_offset=dtb_offset,
            page_size=page_size,
            os_version=f"vendor_boot v{header_version}",
            cmdline=cmdline,
            extra_cmdline=f"product: {product_name}" if product_name else ""
        )


class FatImageExtractor:
    """Extract files from FAT filesystem images (modem, firmware, etc.)."""
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        self.progress_callback = progress_callback
    
    def list_files(self, input_path: str) -> list[dict]:
        """List all files in a FAT image."""
        files = []
        
        with open(input_path, 'rb') as f:
            boot_sector = self._read_boot_sector(f)
            
            if boot_sector['fat_type'] == 'FAT32':
                self._list_fat32(f, boot_sector, '', files)
            else:
                self._list_fat16(f, boot_sector, '', files)
        
        return files
    
    def extract(self, input_path: str, output_dir: str, 
                file_list: Optional[list[str]] = None) -> dict:
        """Extract files from FAT image."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        extracted = {}
        
        with open(input_path, 'rb') as f:
            boot_sector = self._read_boot_sector(f)
            
            if boot_sector['fat_type'] == 'FAT32':
                self._extract_fat32(f, boot_sector, '', output_dir, file_list, extracted)
            else:
                self._extract_fat16(f, boot_sector, '', output_dir, file_list, extracted)
        
        return extracted
    
    def _read_boot_sector(self, f: BinaryIO) -> dict:
        """Read and parse FAT boot sector."""
        f.seek(0)
        data = f.read(512)
        
        bytes_per_sector = struct.unpack('<H', data[0x0B:0x0D])[0]
        sectors_per_cluster = data[0x0D]
        reserved_sectors = struct.unpack('<H', data[0x0E:0x10])[0]
        num_fats = data[0x10]
        root_entry_count = struct.unpack('<H', data[0x11:0x13])[0]
        total_sectors_16 = struct.unpack('<H', data[0x13:0x15])[0]
        fat_size_16 = struct.unpack('<H', data[0x16:0x18])[0]
        total_sectors_32 = struct.unpack('<I', data[0x20:0x24])[0]
        
        # Determine FAT type
        if fat_size_16 != 0:
            fat_size = fat_size_16
            root_cluster = 0
        else:
            fat_size = struct.unpack('<I', data[0x24:0x28])[0]
            root_cluster = struct.unpack('<I', data[0x2C:0x30])[0]
        
        total_sectors = total_sectors_16 if total_sectors_16 != 0 else total_sectors_32
        
        root_dir_sectors = ((root_entry_count * 32) + (bytes_per_sector - 1)) // bytes_per_sector
        first_data_sector = reserved_sectors + (num_fats * fat_size) + root_dir_sectors
        data_sectors = total_sectors - first_data_sector
        cluster_count = data_sectors // sectors_per_cluster if sectors_per_cluster > 0 else 0
        
        # Determine FAT type based on cluster count
        if cluster_count < 4085:
            fat_type = 'FAT12'
        elif cluster_count < 65525:
            fat_type = 'FAT16'
        else:
            fat_type = 'FAT32'
        
        return {
            'fat_type': fat_type,
            'bytes_per_sector': bytes_per_sector,
            'sectors_per_cluster': sectors_per_cluster,
            'reserved_sectors': reserved_sectors,
            'num_fats': num_fats,
            'root_entry_count': root_entry_count,
            'fat_size': fat_size,
            'root_cluster': root_cluster,
            'first_data_sector': first_data_sector,
            'root_dir_sector': reserved_sectors + (num_fats * fat_size),
            'cluster_size': bytes_per_sector * sectors_per_cluster,
        }
    
    def _cluster_to_offset(self, cluster: int, boot: dict) -> int:
        """Convert cluster number to byte offset."""
        return ((cluster - 2) * boot['sectors_per_cluster'] + boot['first_data_sector']) * boot['bytes_per_sector']
    
    def _read_cluster_chain(self, f: BinaryIO, boot: dict, start_cluster: int) -> bytes:
        """Read all data from a cluster chain."""
        data = bytearray()
        cluster = start_cluster
        visited = set()
        
        while cluster >= 2 and cluster not in visited:
            visited.add(cluster)
            
            # Read cluster data
            offset = self._cluster_to_offset(cluster, boot)
            f.seek(offset)
            data.extend(f.read(boot['cluster_size']))
            
            # Get next cluster from FAT
            cluster = self._get_next_cluster(f, boot, cluster)
            
            # Check for end of chain
            if boot['fat_type'] == 'FAT32':
                if cluster >= 0x0FFFFFF8:
                    break
            else:
                if cluster >= 0xFFF8:
                    break
        
        return bytes(data)
    
    def _get_next_cluster(self, f: BinaryIO, boot: dict, cluster: int) -> int:
        """Get next cluster number from FAT."""
        fat_offset = boot['reserved_sectors'] * boot['bytes_per_sector']
        
        if boot['fat_type'] == 'FAT32':
            f.seek(fat_offset + cluster * 4)
            return struct.unpack('<I', f.read(4))[0] & 0x0FFFFFFF
        elif boot['fat_type'] == 'FAT16':
            f.seek(fat_offset + cluster * 2)
            return struct.unpack('<H', f.read(2))[0]
        else:  # FAT12
            f.seek(fat_offset + (cluster * 3) // 2)
            data = f.read(2)
            val = struct.unpack('<H', data)[0]
            if cluster % 2 == 0:
                return val & 0xFFF
            else:
                return val >> 4
    
    def _parse_dir_entry(self, data: bytes) -> Optional[dict]:
        """Parse a 32-byte directory entry."""
        if len(data) < 32:
            return None
        
        first_byte = data[0]
        if first_byte == 0x00:  # End of directory
            return None
        if first_byte == 0xE5:  # Deleted entry
            return {'deleted': True}
        
        attr = data[0x0B]
        
        # Skip long filename entries
        if attr == 0x0F:
            return {'lfn': True}
        
        # Parse 8.3 filename
        name = data[0:8].rstrip(b' ').decode('ascii', errors='ignore')
        ext = data[8:11].rstrip(b' ').decode('ascii', errors='ignore')
        
        if ext:
            filename = f"{name}.{ext}"
        else:
            filename = name
        
        # Get cluster and size
        cluster_high = struct.unpack('<H', data[0x14:0x16])[0]
        cluster_low = struct.unpack('<H', data[0x1A:0x1C])[0]
        cluster = (cluster_high << 16) | cluster_low
        size = struct.unpack('<I', data[0x1C:0x20])[0]
        
        is_dir = bool(attr & 0x10)
        
        return {
            'name': filename,
            'cluster': cluster,
            'size': size,
            'is_dir': is_dir,
            'attr': attr,
        }
    
    def _list_fat16(self, f: BinaryIO, boot: dict, path: str, files: list):
        """List files in FAT12/FAT16 root directory."""
        root_offset = boot['root_dir_sector'] * boot['bytes_per_sector']
        f.seek(root_offset)
        
        for _ in range(boot['root_entry_count']):
            entry = self._parse_dir_entry(f.read(32))
            if entry is None:
                break
            if entry.get('deleted') or entry.get('lfn'):
                continue
            
            full_path = f"{path}/{entry['name']}" if path else entry['name']
            
            if entry['is_dir'] and entry['name'] not in ('.', '..'):
                self._list_dir_cluster(f, boot, entry['cluster'], full_path, files)
            elif not entry['is_dir']:
                files.append({'name': full_path, 'size': entry['size'], 'type': 'file'})
    
    def _list_fat32(self, f: BinaryIO, boot: dict, path: str, files: list):
        """List files in FAT32 starting from root cluster."""
        self._list_dir_cluster(f, boot, boot['root_cluster'], path, files)
    
    def _list_dir_cluster(self, f: BinaryIO, boot: dict, cluster: int, path: str, files: list):
        """List files in a directory cluster chain."""
        if cluster < 2:
            return
        
        dir_data = self._read_cluster_chain(f, boot, cluster)
        
        for i in range(0, len(dir_data), 32):
            entry = self._parse_dir_entry(dir_data[i:i+32])
            if entry is None:
                break
            if entry.get('deleted') or entry.get('lfn'):
                continue
            
            full_path = f"{path}/{entry['name']}" if path else entry['name']
            
            if entry['is_dir'] and entry['name'] not in ('.', '..'):
                self._list_dir_cluster(f, boot, entry['cluster'], full_path, files)
            elif not entry['is_dir']:
                files.append({'name': full_path, 'size': entry['size'], 'type': 'file'})
    
    def _extract_fat16(self, f: BinaryIO, boot: dict, path: str, output_dir: str,
                       file_list: Optional[list[str]], extracted: dict):
        """Extract files from FAT12/FAT16."""
        root_offset = boot['root_dir_sector'] * boot['bytes_per_sector']
        f.seek(root_offset)
        
        for _ in range(boot['root_entry_count']):
            entry = self._parse_dir_entry(f.read(32))
            if entry is None:
                break
            if entry.get('deleted') or entry.get('lfn'):
                continue
            
            full_path = f"{path}/{entry['name']}" if path else entry['name']
            
            if entry['is_dir'] and entry['name'] not in ('.', '..'):
                dir_path = Path(output_dir) / full_path
                dir_path.mkdir(parents=True, exist_ok=True)
                self._extract_dir_cluster(f, boot, entry['cluster'], full_path, output_dir, file_list, extracted)
            elif not entry['is_dir']:
                if file_list is None or full_path in file_list:
                    self._extract_file(f, boot, entry, full_path, output_dir, extracted)
    
    def _extract_fat32(self, f: BinaryIO, boot: dict, path: str, output_dir: str,
                       file_list: Optional[list[str]], extracted: dict):
        """Extract files from FAT32."""
        self._extract_dir_cluster(f, boot, boot['root_cluster'], path, output_dir, file_list, extracted)
    
    def _extract_dir_cluster(self, f: BinaryIO, boot: dict, cluster: int, path: str,
                             output_dir: str, file_list: Optional[list[str]], extracted: dict):
        """Extract files from a directory cluster chain."""
        if cluster < 2:
            return
        
        dir_data = self._read_cluster_chain(f, boot, cluster)
        
        for i in range(0, len(dir_data), 32):
            entry = self._parse_dir_entry(dir_data[i:i+32])
            if entry is None:
                break
            if entry.get('deleted') or entry.get('lfn'):
                continue
            
            full_path = f"{path}/{entry['name']}" if path else entry['name']
            
            if entry['is_dir'] and entry['name'] not in ('.', '..'):
                dir_path = Path(output_dir) / full_path
                dir_path.mkdir(parents=True, exist_ok=True)
                self._extract_dir_cluster(f, boot, entry['cluster'], full_path, output_dir, file_list, extracted)
            elif not entry['is_dir']:
                if file_list is None or full_path in file_list:
                    self._extract_file(f, boot, entry, full_path, output_dir, extracted)
    
    def _extract_file(self, f: BinaryIO, boot: dict, entry: dict, full_path: str,
                      output_dir: str, extracted: dict):
        """Extract a single file."""
        output_path = Path(output_dir) / full_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if entry['cluster'] >= 2 and entry['size'] > 0:
            data = self._read_cluster_chain(f, boot, entry['cluster'])
            output_path.write_bytes(data[:entry['size']])
        else:
            output_path.write_bytes(b'')
        
        extracted[full_path] = str(output_path)
        logger.info(f"  Extracted: {full_path} ({entry['size']} bytes)")


class ElfImageExtractor:
    """Extract segments from ELF (Executable and Linkable Format) files.
    
    Common for Qualcomm modem firmware (modem.bin), bootloaders, and executables.
    Extracts program segments and provides detailed header information.
    """
    
    # ELF classes
    ELFCLASS32 = 1
    ELFCLASS64 = 2
    
    # ELF data encoding
    ELFDATA2LSB = 1  # Little endian
    ELFDATA2MSB = 2  # Big endian
    
    # ELF types
    ET_NONE = 0
    ET_REL = 1    # Relocatable
    ET_EXEC = 2   # Executable
    ET_DYN = 3    # Shared object
    ET_CORE = 4   # Core dump
    
    # Segment types
    PT_NULL = 0
    PT_LOAD = 1       # Loadable segment
    PT_DYNAMIC = 2    # Dynamic linking info
    PT_INTERP = 3     # Interpreter path
    PT_NOTE = 4       # Auxiliary information
    PT_SHLIB = 5      # Reserved
    PT_PHDR = 6       # Program header table
    PT_TLS = 7        # Thread-local storage
    
    # Qualcomm-specific segment types
    PT_QUALCOMM_HASH = 0x6FFFFFFD
    
    SEGMENT_NAMES = {
        0: "NULL",
        1: "LOAD",
        2: "DYNAMIC",
        3: "INTERP",
        4: "NOTE",
        5: "SHLIB",
        6: "PHDR",
        7: "TLS",
        0x6474e550: "GNU_EH_FRAME",
        0x6474e551: "GNU_STACK",
        0x6474e552: "GNU_RELRO",
        0x6FFFFFFD: "QC_HASH",
    }
    
    ELF_TYPES = {
        0: "NONE",
        1: "REL (Relocatable)",
        2: "EXEC (Executable)",
        3: "DYN (Shared object)",
        4: "CORE (Core dump)",
    }
    
    def __init__(self, input_path: str, output_dir: str, 
                 progress_callback: Optional[Callable[[int], None]] = None):
        self.input_path = Path(input_path)
        self.output_dir = Path(output_dir)
        self.progress_callback = progress_callback
        self.is_64bit = False
        self.is_little_endian = True
        self.header = {}
        self.segments = []
        
    def extract(self) -> bool:
        """Extract ELF segments to output directory."""
        try:
            with open(self.input_path, 'rb') as f:
                # Parse ELF header
                if not self._parse_elf_header(f):
                    return False
                
                # Parse program headers (segments)
                self._parse_program_headers(f)
                
                # Create output directory
                self.output_dir.mkdir(parents=True, exist_ok=True)
                
                # Write ELF info file
                self._write_info_file()
                
                # Extract loadable segments
                self._extract_segments(f)
                
            return True
        except Exception as e:
            logger.error(f"Failed to extract ELF file: {e}")
            return False
    
    def _parse_elf_header(self, f: BinaryIO) -> bool:
        """Parse the ELF header."""
        f.seek(0)
        e_ident = f.read(16)
        
        # Verify magic
        if e_ident[:4] != ELF_MAGIC:
            logger.error("Invalid ELF magic")
            return False
        
        # ELF class (32-bit or 64-bit)
        ei_class = e_ident[4]
        self.is_64bit = (ei_class == self.ELFCLASS64)
        
        # Data encoding (endianness)
        ei_data = e_ident[5]
        self.is_little_endian = (ei_data == self.ELFDATA2LSB)
        endian = '<' if self.is_little_endian else '>'
        
        # ELF version
        ei_version = e_ident[6]
        
        self.header['class'] = '64-bit' if self.is_64bit else '32-bit'
        self.header['endian'] = 'Little endian' if self.is_little_endian else 'Big endian'
        self.header['version'] = ei_version
        
        # Read rest of header based on class
        if self.is_64bit:
            header_fmt = f'{endian}HHIQQQIHHHHHH'
            header_size = 64
        else:
            header_fmt = f'{endian}HHIIIIIHHHHHH'
            header_size = 52
        
        f.seek(16)
        header_data = f.read(header_size - 16)
        fields = struct.unpack(header_fmt, header_data)
        
        self.header['type'] = fields[0]
        self.header['type_name'] = self.ELF_TYPES.get(fields[0], f"Unknown ({fields[0]})")
        self.header['machine'] = fields[1]
        self.header['version2'] = fields[2]
        self.header['entry'] = fields[3]
        self.header['phoff'] = fields[4]  # Program header offset
        self.header['shoff'] = fields[5]  # Section header offset
        self.header['flags'] = fields[6]
        self.header['ehsize'] = fields[7]
        self.header['phentsize'] = fields[8]  # Program header entry size
        self.header['phnum'] = fields[9]      # Number of program headers
        self.header['shentsize'] = fields[10]
        self.header['shnum'] = fields[11]
        self.header['shstrndx'] = fields[12]
        
        # Common machine types
        machine_names = {
            0: "None",
            3: "Intel 386",
            8: "MIPS",
            40: "ARM",
            62: "x86-64",
            164: "Qualcomm Hexagon",
            183: "AArch64",
        }
        self.header['machine_name'] = machine_names.get(fields[1], f"Unknown ({fields[1]})")
        
        logger.info(f"ELF Header: {self.header['class']}, {self.header['endian']}, "
                   f"{self.header['type_name']}, {self.header['machine_name']}")
        
        return True
    
    def _parse_program_headers(self, f: BinaryIO):
        """Parse program headers (segments)."""
        endian = '<' if self.is_little_endian else '>'
        
        if self.is_64bit:
            ph_fmt = f'{endian}IIQQQQQQ'
            ph_size = 56
        else:
            ph_fmt = f'{endian}IIIIIIII'
            ph_size = 32
        
        f.seek(self.header['phoff'])
        
        for i in range(self.header['phnum']):
            ph_data = f.read(ph_size)
            if len(ph_data) < ph_size:
                break
            
            fields = struct.unpack(ph_fmt, ph_data)
            
            if self.is_64bit:
                segment = {
                    'type': fields[0],
                    'flags': fields[1],
                    'offset': fields[2],
                    'vaddr': fields[3],
                    'paddr': fields[4],
                    'filesz': fields[5],
                    'memsz': fields[6],
                    'align': fields[7],
                }
            else:
                segment = {
                    'type': fields[0],
                    'offset': fields[1],
                    'vaddr': fields[2],
                    'paddr': fields[3],
                    'filesz': fields[4],
                    'memsz': fields[5],
                    'flags': fields[6],
                    'align': fields[7],
                }
            
            segment['type_name'] = self.SEGMENT_NAMES.get(segment['type'], f"0x{segment['type']:08X}")
            segment['index'] = i
            self.segments.append(segment)
        
        logger.info(f"Found {len(self.segments)} program segments")
    
    def _write_info_file(self):
        """Write ELF information to a text file."""
        info_path = self.output_dir / "elf_info.txt"
        with open(info_path, 'w') as f:
            f.write("ELF File Information\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("Header:\n")
            f.write(f"  Class:        {self.header['class']}\n")
            f.write(f"  Endian:       {self.header['endian']}\n")
            f.write(f"  Type:         {self.header['type_name']}\n")
            f.write(f"  Machine:      {self.header['machine_name']}\n")
            f.write(f"  Entry point:  0x{self.header['entry']:X}\n")
            f.write(f"  Flags:        0x{self.header['flags']:X}\n")
            f.write("\n")
            
            f.write("Program Segments:\n")
            f.write("-" * 60 + "\n")
            
            for seg in self.segments:
                f.write(f"\nSegment {seg['index']}: {seg['type_name']}\n")
                f.write(f"  Offset:       0x{seg['offset']:X}\n")
                f.write(f"  Virtual addr: 0x{seg['vaddr']:X}\n")
                f.write(f"  Physical addr:0x{seg['paddr']:X}\n")
                f.write(f"  File size:    {seg['filesz']} bytes\n")
                f.write(f"  Memory size:  {seg['memsz']} bytes\n")
                
                # Decode flags
                flags = []
                if seg['flags'] & 0x1:
                    flags.append('X (Execute)')
                if seg['flags'] & 0x2:
                    flags.append('W (Write)')
                if seg['flags'] & 0x4:
                    flags.append('R (Read)')
                f.write(f"  Flags:        {', '.join(flags) if flags else 'None'}\n")
        
        logger.info(f"Wrote ELF info to: {info_path}")
    
    def _extract_segments(self, f: BinaryIO):
        """Extract loadable segments to files."""
        total_segments = len([s for s in self.segments if s['filesz'] > 0])
        extracted = 0
        
        for seg in self.segments:
            if seg['filesz'] == 0:
                continue
            
            # Create descriptive filename
            type_name = seg['type_name'].replace(' ', '_').replace('/', '_')
            filename = f"segment_{seg['index']:02d}_{type_name}_0x{seg['paddr']:08X}.bin"
            
            output_path = self.output_dir / filename
            
            # Read and write segment data
            f.seek(seg['offset'])
            data = f.read(seg['filesz'])
            
            with open(output_path, 'wb') as out:
                out.write(data)
            
            extracted += 1
            logger.info(f"  Extracted: {filename} ({seg['filesz']} bytes)")
            
            if self.progress_callback:
                progress = int(extracted * 100 / total_segments) if total_segments > 0 else 100
                self.progress_callback(progress)
        
        logger.info(f"Extracted {extracted} segments from ELF file")


class AblAnalyzer:
    """Analyze and patch Android Bootloader (ABL) images.
    
    ABL (abl.img) is critical for device boot, especially on:
    - LG devices (LAF mode, unlock verification, device checks)
    - Qualcomm devices (fastboot, AVB verification, anti-rollback)
    
    This class provides:
    - Deep analysis of ABL structure and embedded strings
    - Detection of unlock status checks
    - Detection of anti-rollback fuses
    - LG-specific LAF mode detection
    - Optional patching capabilities (DANGEROUS - can brick device!)
    
    EDUCATIONAL NOTES:
    ==================
    ABL is an ELF binary that runs on the Application Processor (AP).
    It's responsible for:
    1. Initializing hardware after XBL (eXtensible Bootloader)
    2. Implementing fastboot protocol
    3. Verifying boot/recovery images (AVB)
    4. Checking bootloader unlock status
    5. Loading and booting the kernel
    
    On LG devices, ABL also handles:
    - LAF (Download) mode entry
    - Device unlock token verification
    - IMEI/device binding checks
    
    Common ABL strings to look for:
    - "device is UNLOCKED" / "device is LOCKED"
    - "Orange State" / "Red State" / "Green State"
    - "Press VOLUME UP to continue"
    - "Start fastboot mode"
    - "SECURE BOOT"
    - "anti-rollback"
    
    WARNING: Patching ABL incorrectly WILL brick your device!
    Always have a backup and understand what you're doing.
    """
    
    # Known ABL string patterns for various checks
    UNLOCK_PATTERNS = [
        b'device is UNLOCKED',
        b'device is LOCKED',
        b'DEVICE_UNLOCKED',
        b'DEVICE_LOCKED',
        b'unlock_status',
        b'is_unlocked',
        b'get_unlock_state',
        b'verify_unlock',
        b'oem_unlock',
        b'UNLOCK=',
        b'LOCK=',
        b'unlock_ability',
        b'unlockable',
        b'unlock_allowed',
    ]
    
    SECURE_BOOT_PATTERNS = [
        b'SECURE BOOT',
        b'secure boot',
        b'secureboot',
        b'is_secure_boot',
        b'secure_boot_enabled',
        b'verify_secure_boot',
        b'verified boot',
        b'VERIFIED BOOT',
    ]
    
    AVB_PATTERNS = [
        b'avb_',
        b'AVB_',
        b'vbmeta',
        b'dm-verity',
        b'verify_vbmeta',
        b'avb_verify',
        b'verify_boot',
        b'android_verify_boot',
        b'AVB0',
        b'AvbFooter',
        b'AvbVBMeta',
    ]
    
    ANTI_ROLLBACK_PATTERNS = [
        b'anti-rollback',
        b'anti_rollback',
        b'rollback_index',
        b'ROLLBACK',
        b'fuse_read',
        b'fuse_write',
        b'qfprom',
        b'QFPROM',
        b'otp_read',
        b'efuse',
        b'EFUSE',
    ]
    
    # Google Pixel / Tensor specific patterns
    PIXEL_PATTERNS = [
        b'Pixel',
        b'pixel',
        b'GOOGLE',
        b'google',
        b'Tensor',
        b'tensor',
        b'gs101',  # Tensor G1
        b'gs201',  # Tensor G2
        b'gs301',  # Tensor G3
        b'zuma',   # Tensor G3 codename
        b'slider', # Pixel 6 codename
        b'cloudripper',  # Pixel 6 Pro codename
        b'oriole',  # Pixel 6 codename
        b'raven',   # Pixel 6 Pro codename
        b'bluejay', # Pixel 6a codename
        b'panther', # Pixel 7 codename
        b'cheetah', # Pixel 7 Pro codename
        b'lynx',    # Pixel 7a codename
        b'tangorpro', # Pixel Tablet codename
        b'felix',   # Pixel Fold codename
        b'shiba',   # Pixel 8 codename
        b'husky',   # Pixel 8 Pro codename
        b'akita',   # Pixel 8a codename
        b'tokay',   # Pixel 9 codename
        b'caiman',  # Pixel 9 Pro codename
        b'komodo',  # Pixel 9 Pro XL codename
        b'comet',   # Pixel 9 Pro Fold codename
        b'trusty',
        b'BL31',
        b'BL2',
    ]
    
    LG_PATTERNS = [
        b'LAF',
        b'laf_mode',
        b'download_mode',
        b'LG_UNLOCK',
        b'lg_unlock',
        b'device_unlock_token',
        b'LGUP',
        b'kdz',
        b'KDZ',
    ]
    
    FASTBOOT_PATTERNS = [
        b'fastboot',
        b'FASTBOOT',
        b'getvar:',
        b'oem ',
        b'flash:',
        b'boot:',
        b'reboot',
        b'continue',
        b'flashing unlock',
        b'flashing lock',
    ]
    
    WARNING_PATTERNS = [
        b'Orange State',
        b'Red State',
        b'Yellow State',
        b'green state',
        b'warranty void',
        b'WARRANTY VOID',
        b'tampered',
        b'TAMPERED',
        b'PRESS VOLUME',
        b'Press Volume',
    ]
    
    def __init__(self, input_path: str, output_dir: str = None,
                 progress_callback: Optional[Callable[[int], None]] = None):
        self.input_path = Path(input_path)
        self.output_dir = Path(output_dir) if output_dir else self.input_path.parent / 'abl_analysis'
        self.progress_callback = progress_callback
        self.data = None
        self.analysis = {}
        
    def analyze(self) -> dict:
        """Perform comprehensive ABL analysis."""
        logger.info(f"Analyzing ABL: {self.input_path.name}")
        
        with open(self.input_path, 'rb') as f:
            self.data = f.read()
        
        # Detect format
        is_elf = self.data[:4] == ELF_MAGIC
        is_signed_blob = False
        format_type = 'Unknown'
        
        if is_elf:
            format_type = 'ELF (Qualcomm)'
            is_64bit = len(self.data) > 4 and self.data[4] == 2
        else:
            # Check for common Pixel/Tensor/Exynos signatures
            # These are typically ARM Trusted Firmware (ATF) or signed blobs
            is_64bit = False  # Can't easily determine from blob
            
            # Check for certificate/signature headers (common in signed bootloaders)
            if self.data[:2] == b'\x30\x82':  # ASN.1 DER sequence (certificate)
                format_type = 'Signed Binary (Certificate Header)'
                is_signed_blob = True
            elif b'CERT' in self.data[:256] or b'RSA' in self.data[:256]:
                format_type = 'Signed Binary'
                is_signed_blob = True
            elif self.data[:4] == b'\x00\x00\xa0\xe1':  # ARM NOP instruction
                format_type = 'ARM Binary (Raw)'
            elif self.data[:4] == b'\xd5\x03\x20\x1f':  # AArch64 NOP
                format_type = 'AArch64 Binary (Raw)'
                is_64bit = True
            else:
                format_type = 'Binary Blob (Pixel/Tensor/Exynos format)'
        
        self.analysis = {
            'file': str(self.input_path),
            'size': len(self.data),
            'is_elf': is_elf,
            'is_64bit': is_64bit,
            'format': format_type,
            'is_signed_blob': is_signed_blob,
            'unlock_checks': [],
            'secure_boot': [],
            'avb_references': [],
            'anti_rollback': [],
            'lg_specific': [],
            'pixel_specific': [],
            'fastboot_commands': [],
            'warning_messages': [],
            'interesting_strings': [],
            'potential_patches': [],
        }
        
        if self.progress_callback:
            self.progress_callback(10)
        
        # Search for patterns
        self._find_patterns('unlock_checks', self.UNLOCK_PATTERNS)
        if self.progress_callback:
            self.progress_callback(20)
            
        self._find_patterns('secure_boot', self.SECURE_BOOT_PATTERNS)
        self._find_patterns('avb_references', self.AVB_PATTERNS)
        if self.progress_callback:
            self.progress_callback(35)
            
        self._find_patterns('anti_rollback', self.ANTI_ROLLBACK_PATTERNS)
        self._find_patterns('lg_specific', self.LG_PATTERNS)
        self._find_patterns('pixel_specific', self.PIXEL_PATTERNS)
        if self.progress_callback:
            self.progress_callback(50)
            
        self._find_patterns('fastboot_commands', self.FASTBOOT_PATTERNS)
        self._find_patterns('warning_messages', self.WARNING_PATTERNS)
        if self.progress_callback:
            self.progress_callback(65)
        
        # Find all printable strings (useful for further analysis)
        self._extract_interesting_strings()
        if self.progress_callback:
            self.progress_callback(80)
        
        # Identify potential patch points
        self._identify_patch_points()
        if self.progress_callback:
            self.progress_callback(100)
        
        return self.analysis
    
    def _find_patterns(self, category: str, patterns: list):
        """Search for byte patterns in the data."""
        for pattern in patterns:
            offset = 0
            while True:
                pos = self.data.find(pattern, offset)
                if pos == -1:
                    break
                
                # Get surrounding context
                context_start = max(0, pos - 20)
                context_end = min(len(self.data), pos + len(pattern) + 20)
                context = self.data[context_start:context_end]
                
                # Clean up context for display
                try:
                    context_str = context.decode('utf-8', errors='replace')
                    context_str = ''.join(c if c.isprintable() or c in '\n\r\t' else '.' for c in context_str)
                except:
                    context_str = repr(context)
                
                self.analysis[category].append({
                    'pattern': pattern.decode('utf-8', errors='replace'),
                    'offset': pos,
                    'hex_offset': f'0x{pos:08X}',
                    'context': context_str.strip(),
                })
                
                offset = pos + 1
    
    def _extract_interesting_strings(self):
        """Extract printable strings from ABL (like 'strings' command)."""
        min_length = 6
        strings = []
        current = b''
        start_offset = 0
        
        for i, byte in enumerate(self.data):
            if 32 <= byte <= 126:  # Printable ASCII
                if not current:
                    start_offset = i
                current += bytes([byte])
            else:
                if len(current) >= min_length:
                    try:
                        s = current.decode('ascii')
                        # Filter for interesting strings
                        if any(keyword in s.lower() for keyword in 
                               ['boot', 'unlock', 'lock', 'verify', 'secure', 'fuse', 
                                'avb', 'rollback', 'fastboot', 'oem', 'flash', 'error',
                                'failed', 'success', 'invalid', 'tamper', 'lg', 'laf']):
                            strings.append({
                                'string': s,
                                'offset': start_offset,
                                'hex_offset': f'0x{start_offset:08X}',
                            })
                    except:
                        pass
                current = b''
        
        # Deduplicate and limit
        seen = set()
        unique_strings = []
        for s in strings:
            if s['string'] not in seen:
                seen.add(s['string'])
                unique_strings.append(s)
        
        self.analysis['interesting_strings'] = unique_strings[:200]  # Limit to 200
    
    def _identify_patch_points(self):
        """Identify potential patch points (for educational purposes)."""
        patches = []
        
        # Common unlock bypass patterns
        # These are for EDUCATIONAL/RESEARCH purposes only
        
        # Pattern: Function returning lock status (return 0 vs return 1)
        # Often: mov w0, #1 (locked) can be changed to mov w0, #0 (unlocked)
        # ARM64: 20 00 80 52 (mov w0, #1) -> 00 00 80 52 (mov w0, #0)
        
        if self.analysis['is_64bit']:
            # ARM64 patterns
            mov_w0_1 = b'\x20\x00\x80\x52'  # mov w0, #1
            mov_w0_0 = b'\x00\x00\x80\x52'  # mov w0, #0
            
            for match in self.analysis['unlock_checks']:
                offset = match['offset']
                # Search nearby for the return instruction
                search_start = max(0, offset - 100)
                search_end = min(len(self.data), offset + 100)
                nearby = self.data[search_start:search_end]
                
                pos = nearby.find(mov_w0_1)
                if pos != -1:
                    patches.append({
                        'type': 'unlock_bypass_candidate',
                        'description': f"Potential unlock check near '{match['pattern']}'",
                        'offset': search_start + pos,
                        'hex_offset': f'0x{search_start + pos:08X}',
                        'original': mov_w0_1.hex(),
                        'patched': mov_w0_0.hex(),
                        'warning': 'DANGEROUS: Incorrect patching will brick device!',
                    })
        
        # Look for conditional branches after security checks
        for match in self.analysis['secure_boot']:
            patches.append({
                'type': 'secure_boot_check',
                'description': f"Secure boot check at '{match['pattern']}'",
                'offset': match['offset'],
                'hex_offset': match['hex_offset'],
                'warning': 'Research only - modifying secure boot checks is extremely risky',
            })
        
        self.analysis['potential_patches'] = patches
    
    def write_report(self) -> str:
        """Write detailed analysis report to file."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        report_path = self.output_dir / 'abl_analysis_report.txt'
        
        with open(report_path, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("ABL (Android Bootloader) Analysis Report\n")
            f.write("Generated by Image Anarchy\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"File: {self.analysis['file']}\n")
            f.write(f"Size: {self.analysis['size']} bytes ({self.analysis['size'] / 1024:.2f} KB)\n")
            f.write(f"Format: {self.analysis.get('format', 'Unknown')}\n")
            if self.analysis.get('is_elf'):
                f.write(f"ELF Class: {'64-bit' if self.analysis['is_64bit'] else '32-bit'}\n")
            f.write("\n")
            
            # Device detection
            if self.is_pixel_device():
                f.write("📱 GOOGLE PIXEL / TENSOR DEVICE DETECTED\n")
                f.write("-" * 70 + "\n")
                f.write("This ABL is from a Google Pixel device with Tensor chip.\n")
                f.write("Pixel ABL uses signed binary format (not ELF like Qualcomm).\n")
                f.write("Pattern matches: " + ", ".join(set(
                    m['pattern'] for m in self.analysis['pixel_specific'][:10]
                )) + "\n")
                f.write("\n")
            
            if self.is_lg_device():
                f.write("⚡ LG DEVICE DETECTED\n")
                f.write("-" * 70 + "\n")
                f.write("This ABL is from an LG device with LAF mode support.\n\n")
            
            # Unlock checks
            f.write("-" * 70 + "\n")
            f.write("UNLOCK STATUS CHECKS\n")
            f.write("-" * 70 + "\n")
            if self.analysis['unlock_checks']:
                for item in self.analysis['unlock_checks']:
                    f.write(f"\n  Pattern: {item['pattern']}\n")
                    f.write(f"  Offset:  {item['hex_offset']}\n")
                    f.write(f"  Context: {item['context']}\n")
            else:
                f.write("  None found\n")
            f.write("\n")
            
            # Secure boot
            f.write("-" * 70 + "\n")
            f.write("SECURE BOOT REFERENCES\n")
            f.write("-" * 70 + "\n")
            if self.analysis['secure_boot']:
                for item in self.analysis['secure_boot']:
                    f.write(f"\n  Pattern: {item['pattern']}\n")
                    f.write(f"  Offset:  {item['hex_offset']}\n")
            else:
                f.write("  None found\n")
            f.write("\n")
            
            # AVB references
            f.write("-" * 70 + "\n")
            f.write("AVB (Android Verified Boot) REFERENCES\n")
            f.write("-" * 70 + "\n")
            if self.analysis['avb_references']:
                for item in self.analysis['avb_references'][:20]:  # Limit output
                    f.write(f"\n  Pattern: {item['pattern']}\n")
                    f.write(f"  Offset:  {item['hex_offset']}\n")
                f.write(f"\n  Total: {len(self.analysis['avb_references'])} references\n")
            else:
                f.write("  None found\n")
            f.write("\n")
            
            # Anti-rollback
            f.write("-" * 70 + "\n")
            f.write("ANTI-ROLLBACK REFERENCES\n")
            f.write("-" * 70 + "\n")
            if self.analysis['anti_rollback']:
                for item in self.analysis['anti_rollback']:
                    f.write(f"\n  Pattern: {item['pattern']}\n")
                    f.write(f"  Offset:  {item['hex_offset']}\n")
            else:
                f.write("  None found\n")
            f.write("\n")
            
            # LG specific
            f.write("-" * 70 + "\n")
            f.write("LG DEVICE SPECIFIC\n")
            f.write("-" * 70 + "\n")
            if self.analysis['lg_specific']:
                for item in self.analysis['lg_specific']:
                    f.write(f"\n  Pattern: {item['pattern']}\n")
                    f.write(f"  Offset:  {item['hex_offset']}\n")
                    f.write(f"  Context: {item['context']}\n")
            else:
                f.write("  None found (not an LG device or no LG-specific code)\n")
            f.write("\n")
            
            # Fastboot commands
            f.write("-" * 70 + "\n")
            f.write("FASTBOOT COMMANDS\n")
            f.write("-" * 70 + "\n")
            if self.analysis['fastboot_commands']:
                for item in self.analysis['fastboot_commands'][:30]:
                    f.write(f"  {item['hex_offset']}: {item['pattern']}\n")
            else:
                f.write("  None found\n")
            f.write("\n")
            
            # Warning messages
            f.write("-" * 70 + "\n")
            f.write("WARNING/STATE MESSAGES\n")
            f.write("-" * 70 + "\n")
            if self.analysis['warning_messages']:
                for item in self.analysis['warning_messages']:
                    f.write(f"\n  Pattern: {item['pattern']}\n")
                    f.write(f"  Offset:  {item['hex_offset']}\n")
                    f.write(f"  Context: {item['context']}\n")
            else:
                f.write("  None found\n")
            f.write("\n")
            
            # Potential patches (educational)
            if self.analysis['potential_patches']:
                f.write("-" * 70 + "\n")
                f.write("POTENTIAL PATCH POINTS (EDUCATIONAL/RESEARCH ONLY)\n")
                f.write("-" * 70 + "\n")
                f.write("\n⚠️  WARNING: DO NOT ATTEMPT PATCHING UNLESS YOU FULLY UNDERSTAND\n")
                f.write("    THE RISKS. INCORRECT PATCHES WILL PERMANENTLY BRICK YOUR DEVICE!\n\n")
                
                for patch in self.analysis['potential_patches']:
                    f.write(f"\n  Type: {patch['type']}\n")
                    f.write(f"  Description: {patch['description']}\n")
                    f.write(f"  Offset: {patch['hex_offset']}\n")
                    if 'original' in patch:
                        f.write(f"  Original bytes: {patch['original']}\n")
                        f.write(f"  Patched bytes:  {patch['patched']}\n")
                    f.write(f"  ⚠️  {patch['warning']}\n")
            
            # Interesting strings
            f.write("\n" + "-" * 70 + "\n")
            f.write("INTERESTING STRINGS (first 100)\n")
            f.write("-" * 70 + "\n")
            for item in self.analysis['interesting_strings'][:100]:
                f.write(f"  {item['hex_offset']}: {item['string']}\n")
        
        logger.info(f"Wrote ABL analysis report to: {report_path}")
        return str(report_path)
    
    def is_lg_device(self) -> bool:
        """Check if this ABL is from an LG device."""
        return len(self.analysis.get('lg_specific', [])) > 0
    
    def is_pixel_device(self) -> bool:
        """Check if this ABL is from a Google Pixel device."""
        return len(self.analysis.get('pixel_specific', [])) > 0
    
    def get_summary(self) -> str:
        """Get a brief summary of the analysis."""
        summary = []
        summary.append(f"ABL Analysis: {self.input_path.name}")
        summary.append(f"  Format: {self.analysis.get('format', 'Unknown')}")
        summary.append(f"  Size: {self.analysis['size'] / 1024:.2f} KB")
        summary.append(f"  Unlock checks found: {len(self.analysis['unlock_checks'])}")
        summary.append(f"  Secure boot refs: {len(self.analysis['secure_boot'])}")
        summary.append(f"  AVB references: {len(self.analysis['avb_references'])}")
        summary.append(f"  Anti-rollback refs: {len(self.analysis['anti_rollback'])}")
        summary.append(f"  Fastboot commands: {len(self.analysis['fastboot_commands'])}")
        
        if self.is_lg_device():
            summary.append(f"  LG-specific: {len(self.analysis['lg_specific'])}")
            summary.append("\n  ⚡ LG device detected - LAF mode references found")
        
        if self.is_pixel_device():
            summary.append(f"  Pixel-specific: {len(self.analysis['pixel_specific'])}")
            summary.append("\n  📱 Google Pixel/Tensor device detected")
        
        if not self.analysis.get('is_elf'):
            summary.append("\n  ℹ️  Non-ELF format (Pixel/Tensor/Exynos signed binary)")
        
        return '\n'.join(summary)


class DtboExtractor:
    """Extract and parse Android DTBO (Device Tree Blob Overlay) images.
    
    DTBO images contain device tree overlays that are applied on top of the
    base device tree (DTB). They allow OEMs to customize hardware descriptions
    without modifying the main DTB.
    
    DTBO Image Format:
    - Header (32 bytes):
      - magic (4 bytes): 0xD7B7AB1E (big endian)
      - total_size (4 bytes): Total file size
      - header_size (4 bytes): Size of header
      - dt_entry_size (4 bytes): Size of each entry
      - dt_entry_count (4 bytes): Number of DT entries
      - dt_entries_offset (4 bytes): Offset to entries
      - page_size (4 bytes): Page size (typically 4096)
      - version (4 bytes): DTBO version
    - DT Entries (32 bytes each):
      - dt_size (4 bytes): Size of this overlay
      - dt_offset (4 bytes): Offset to overlay data
      - id (4 bytes): Identifier
      - rev (4 bytes): Revision
      - custom[4] (16 bytes): Custom data
    - DT Overlay Data: FDT (Flattened Device Tree) blobs
    """
    
    DTBO_MAGIC = 0xD7B7AB1E
    HEADER_SIZE = 32
    ENTRY_SIZE = 32
    FDT_MAGIC = 0xD00DFEED  # Device Tree magic
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        self.progress_callback = progress_callback
        self.header = {}
        self.entries = []
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Analyze DTBO image and return metadata."""
        result = {
            'format': 'dtbo',
            'valid': False,
            'version': 0,
            'entry_count': 0,
            'page_size': 0,
            'total_size': 0,
            'entries': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                # Read header (32 bytes, all big endian)
                header_data = f.read(32)
                if len(header_data) < 32:
                    return result
                
                magic = struct.unpack('>I', header_data[0:4])[0]
                if magic != self.DTBO_MAGIC:
                    return result
                
                total_size = struct.unpack('>I', header_data[4:8])[0]
                header_size = struct.unpack('>I', header_data[8:12])[0]
                dt_entry_size = struct.unpack('>I', header_data[12:16])[0]
                dt_entry_count = struct.unpack('>I', header_data[16:20])[0]
                dt_entries_offset = struct.unpack('>I', header_data[20:24])[0]
                page_size = struct.unpack('>I', header_data[24:28])[0]
                version = struct.unpack('>I', header_data[28:32])[0]
                
                self.header = {
                    'magic': magic,
                    'total_size': total_size,
                    'header_size': header_size,
                    'dt_entry_size': dt_entry_size,
                    'dt_entry_count': dt_entry_count,
                    'dt_entries_offset': dt_entries_offset,
                    'page_size': page_size,
                    'version': version
                }
                
                result['valid'] = True
                result['version'] = version
                result['entry_count'] = dt_entry_count
                result['page_size'] = page_size
                result['total_size'] = total_size
                result['header_size'] = header_size
                
                # Read entries
                f.seek(dt_entries_offset)
                entries = []
                for i in range(dt_entry_count):
                    entry_data = f.read(dt_entry_size)
                    if len(entry_data) < 32:
                        break
                    
                    dt_size = struct.unpack('>I', entry_data[0:4])[0]
                    dt_offset = struct.unpack('>I', entry_data[4:8])[0]
                    dt_id = struct.unpack('>I', entry_data[8:12])[0]
                    dt_rev = struct.unpack('>I', entry_data[12:16])[0]
                    custom = entry_data[16:32]
                    
                    # Try to identify overlay type from the FDT
                    overlay_info = self._get_overlay_info(f, dt_offset, dt_size)
                    
                    entry = {
                        'index': i,
                        'size': dt_size,
                        'offset': dt_offset,
                        'id': dt_id,
                        'rev': dt_rev,
                        'custom': custom.hex(),
                        'info': overlay_info
                    }
                    entries.append(entry)
                
                self.entries = entries
                result['entries'] = entries
                
        except Exception as e:
            logger.error(f"Error analyzing DTBO: {e}")
        
        return result
    
    def _get_overlay_info(self, f, offset: int, size: int) -> str:
        """Try to extract overlay identification from FDT."""
        try:
            current_pos = f.tell()
            f.seek(offset)
            fdt_data = f.read(min(size, 256))  # Read first 256 bytes
            f.seek(current_pos)
            
            # Check FDT magic
            if len(fdt_data) >= 4:
                fdt_magic = struct.unpack('>I', fdt_data[0:4])[0]
                if fdt_magic == self.FDT_MAGIC:
                    # Try to find compatible string
                    try:
                        # Search for 'compatible' property (rough search)
                        compat_idx = fdt_data.find(b'compatible')
                        if compat_idx > 0 and compat_idx < len(fdt_data) - 20:
                            # Extract string after 'compatible'
                            str_start = compat_idx + 11
                            str_end = fdt_data.find(b'\x00', str_start)
                            if str_end > str_start:
                                return fdt_data[str_start:str_end].decode('utf-8', errors='ignore')
                    except:
                        pass
                    return "Valid FDT overlay"
            return "Unknown"
        except:
            return "Unknown"
    
    def extract(self, file_path: str, output_dir: str) -> List[str]:
        """Extract all DT overlays from DTBO image."""
        if not self.header:
            self.analyze(file_path)
        
        if not self.entries:
            logger.warning("No DTBO entries found")
            return []
        
        os.makedirs(output_dir, exist_ok=True)
        extracted = []
        
        try:
            with open(file_path, 'rb') as f:
                for i, entry in enumerate(self.entries):
                    if self.progress_callback:
                        self.progress_callback(i, len(self.entries), f"Extracting overlay {i+1}...")
                    
                    f.seek(entry['offset'])
                    dt_data = f.read(entry['size'])
                    
                    # Name based on ID if available, otherwise index
                    if entry['id'] != 0:
                        out_name = f"dtbo_{entry['id']:08x}.dtbo"
                    else:
                        out_name = f"dtbo_{i:02d}.dtbo"
                    
                    out_path = os.path.join(output_dir, out_name)
                    with open(out_path, 'wb') as f_out:
                        f_out.write(dt_data)
                    
                    extracted.append(out_path)
                    logger.info(f"Extracted: {out_name} ({entry['size']} bytes)")
            
            # Write info file
            info_path = os.path.join(output_dir, 'dtbo_info.txt')
            self._write_info(info_path)
            extracted.append(info_path)
            
            if self.progress_callback:
                self.progress_callback(len(self.entries), len(self.entries), "Complete")
            
        except Exception as e:
            logger.error(f"Error extracting DTBO: {e}")
        
        return extracted
    
    def _write_info(self, info_path: str):
        """Write DTBO information to text file."""
        with open(info_path, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("DTBO (Device Tree Blob Overlay) Image Info\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("Header Information:\n")
            f.write("-" * 40 + "\n")
            f.write(f"  Magic: 0x{self.header.get('magic', 0):08X}\n")
            f.write(f"  Version: {self.header.get('version', 0)}\n")
            f.write(f"  Total Size: {self.header.get('total_size', 0)} bytes\n")
            f.write(f"  Header Size: {self.header.get('header_size', 0)} bytes\n")
            f.write(f"  Page Size: {self.header.get('page_size', 0)}\n")
            f.write(f"  Entry Count: {self.header.get('dt_entry_count', 0)}\n")
            f.write(f"  Entry Size: {self.header.get('dt_entry_size', 0)} bytes\n")
            f.write(f"  Entries Offset: 0x{self.header.get('dt_entries_offset', 0):X}\n")
            f.write("\n")
            
            f.write("DT Overlay Entries:\n")
            f.write("-" * 40 + "\n")
            for entry in self.entries:
                f.write(f"\n  Entry {entry['index']}:\n")
                f.write(f"    Offset: 0x{entry['offset']:X}\n")
                f.write(f"    Size: {entry['size']} bytes\n")
                f.write(f"    ID: 0x{entry['id']:08X}\n")
                f.write(f"    Rev: 0x{entry['rev']:08X}\n")
                f.write(f"    Info: {entry['info']}\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write("Extracted by Image Anarchy - https://github.com/vehoelite/image-anarchy\n")
    
    def get_summary(self) -> str:
        """Get human-readable summary of DTBO."""
        if not self.header:
            return "DTBO not analyzed"
        
        lines = [
            f"📦 DTBO Image (Device Tree Blob Overlay)",
            f"  Version: {self.header.get('version', 0)}",
            f"  Overlays: {self.header.get('dt_entry_count', 0)}",
            f"  Page Size: {self.header.get('page_size', 0)}",
            f"  Total Size: {self.header.get('total_size', 0) / 1024:.1f} KB"
        ]
        
        if self.entries:
            lines.append(f"\n  Overlay Details:")
            for entry in self.entries[:5]:  # Show first 5
                lines.append(f"    [{entry['index']:02d}] ID=0x{entry['id']:08X} Size={entry['size']} {entry['info'][:30]}")
            if len(self.entries) > 5:
                lines.append(f"    ... and {len(self.entries) - 5} more overlays")
        
        return '\n'.join(lines)


class VbmetaExtractor:
    """Extract and parse Android Verified Boot (AVB) vbmeta images.
    
    vbmeta images contain cryptographic metadata for verifying Android partitions.
    This extractor parses the AVB header, descriptors, and signatures.
    """
    
    # AVB descriptor types
    AVB_DESCRIPTOR_TAG_PROPERTY = 0
    AVB_DESCRIPTOR_TAG_HASHTREE = 1
    AVB_DESCRIPTOR_TAG_HASH = 2
    AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE = 3
    AVB_DESCRIPTOR_TAG_CHAIN_PARTITION = 4
    
    DESCRIPTOR_NAMES = {
        0: "Property",
        1: "Hashtree",
        2: "Hash",
        3: "Kernel Cmdline",
        4: "Chain Partition",
    }
    
    # AVB algorithm types
    AVB_ALGORITHMS = {
        0: "NONE",
        1: "SHA256_RSA2048",
        2: "SHA256_RSA4096",
        3: "SHA256_RSA8192",
        4: "SHA512_RSA2048",
        5: "SHA512_RSA4096",
        6: "SHA512_RSA8192",
    }
    
    def __init__(self, input_path: str, output_dir: str,
                 progress_callback: Optional[Callable[[int], None]] = None):
        self.input_path = Path(input_path)
        self.output_dir = Path(output_dir)
        self.progress_callback = progress_callback
        self.header = {}
        self.descriptors = []
        
    def extract(self) -> bool:
        """Parse vbmeta image and extract information."""
        try:
            with open(self.input_path, 'rb') as f:
                if not self._parse_header(f):
                    return False
                
                self._parse_descriptors(f)
                
                # Create output directory
                self.output_dir.mkdir(parents=True, exist_ok=True)
                
                # Write info file
                self._write_info_file()
                
                # Extract raw sections if requested
                self._extract_sections(f)
                
            return True
        except Exception as e:
            logger.error(f"Failed to parse vbmeta: {e}")
            return False
    
    def _parse_header(self, f: BinaryIO) -> bool:
        """Parse the AVB vbmeta header."""
        f.seek(0)
        magic = f.read(4)
        
        if magic != AVB_MAGIC:
            logger.error(f"Invalid AVB magic: {magic}")
            return False
        
        # AVB header format (256 bytes total):
        # 0-3: magic "AVB0"
        # 4-7: required_libavb_version_major
        # 8-11: required_libavb_version_minor
        # 12-19: authentication_data_block_size
        # 20-27: auxiliary_data_block_size
        # 28-31: algorithm_type
        # 32-39: hash_offset
        # 40-47: hash_size
        # 48-55: signature_offset
        # 56-63: signature_size
        # 64-71: public_key_offset
        # 72-79: public_key_size
        # 80-87: public_key_metadata_offset
        # 88-95: public_key_metadata_size
        # 96-103: descriptors_offset
        # 104-111: descriptors_size
        # 112-115: rollback_index
        # 116-119: flags
        # 120-123: rollback_index_location
        # 124-171: release_string (48 bytes, null-terminated)
        # 172-255: reserved
        
        header_data = f.read(252)  # Rest of 256-byte header
        
        self.header['version_major'] = struct.unpack('>I', header_data[0:4])[0]
        self.header['version_minor'] = struct.unpack('>I', header_data[4:8])[0]
        self.header['auth_block_size'] = struct.unpack('>Q', header_data[8:16])[0]
        self.header['aux_block_size'] = struct.unpack('>Q', header_data[16:24])[0]
        self.header['algorithm'] = struct.unpack('>I', header_data[24:28])[0]
        self.header['algorithm_name'] = self.AVB_ALGORITHMS.get(
            self.header['algorithm'], f"Unknown ({self.header['algorithm']})"
        )
        self.header['hash_offset'] = struct.unpack('>Q', header_data[28:36])[0]
        self.header['hash_size'] = struct.unpack('>Q', header_data[36:44])[0]
        self.header['signature_offset'] = struct.unpack('>Q', header_data[44:52])[0]
        self.header['signature_size'] = struct.unpack('>Q', header_data[52:60])[0]
        self.header['public_key_offset'] = struct.unpack('>Q', header_data[60:68])[0]
        self.header['public_key_size'] = struct.unpack('>Q', header_data[68:76])[0]
        self.header['descriptors_offset'] = struct.unpack('>Q', header_data[92:100])[0]
        self.header['descriptors_size'] = struct.unpack('>Q', header_data[100:108])[0]
        self.header['rollback_index'] = struct.unpack('>Q', header_data[108:116])[0]
        self.header['flags'] = struct.unpack('>I', header_data[116:120])[0]
        
        # Release string (null-terminated)
        release_bytes = header_data[120:168]
        null_pos = release_bytes.find(b'\x00')
        if null_pos != -1:
            release_bytes = release_bytes[:null_pos]
        self.header['release_string'] = release_bytes.decode('utf-8', errors='replace')
        
        # Decode flags
        flags = []
        if self.header['flags'] & 0x1:
            flags.append("DISABLE_VERITY")
        if self.header['flags'] & 0x2:
            flags.append("DISABLE_VERIFICATION")
        self.header['flags_decoded'] = flags if flags else ["NONE"]
        
        logger.info(f"AVB Header: version {self.header['version_major']}.{self.header['version_minor']}, "
                   f"algorithm: {self.header['algorithm_name']}")
        
        return True
    
    def _parse_descriptors(self, f: BinaryIO):
        """Parse AVB descriptors from auxiliary data block."""
        # Descriptors start after header (256 bytes) + auth block
        desc_start = 256 + self.header['auth_block_size'] + self.header['descriptors_offset']
        desc_end = desc_start + self.header['descriptors_size']
        
        f.seek(desc_start)
        pos = desc_start
        
        while pos < desc_end:
            # Each descriptor has a tag (8 bytes) and length (8 bytes)
            tag_data = f.read(8)
            if len(tag_data) < 8:
                break
            
            tag = struct.unpack('>Q', tag_data)[0]
            num_bytes = struct.unpack('>Q', f.read(8))[0]
            
            descriptor = {
                'tag': tag,
                'tag_name': self.DESCRIPTOR_NAMES.get(tag, f"Unknown ({tag})"),
                'size': num_bytes,
            }
            
            # Read descriptor data
            data = f.read(num_bytes)
            
            if tag == self.AVB_DESCRIPTOR_TAG_HASH:
                self._parse_hash_descriptor(descriptor, data)
            elif tag == self.AVB_DESCRIPTOR_TAG_HASHTREE:
                self._parse_hashtree_descriptor(descriptor, data)
            elif tag == self.AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE:
                self._parse_cmdline_descriptor(descriptor, data)
            elif tag == self.AVB_DESCRIPTOR_TAG_CHAIN_PARTITION:
                self._parse_chain_descriptor(descriptor, data)
            elif tag == self.AVB_DESCRIPTOR_TAG_PROPERTY:
                self._parse_property_descriptor(descriptor, data)
            
            self.descriptors.append(descriptor)
            pos = f.tell()
        
        logger.info(f"Found {len(self.descriptors)} AVB descriptor(s)")
    
    def _parse_hash_descriptor(self, desc: dict, data: bytes):
        """Parse hash descriptor - used for small partitions."""
        if len(data) < 72:
            return
        
        desc['image_size'] = struct.unpack('>Q', data[0:8])[0]
        desc['hash_algorithm'] = data[8:40].rstrip(b'\x00').decode('utf-8', errors='replace')
        partition_name_len = struct.unpack('>I', data[40:44])[0]
        salt_len = struct.unpack('>I', data[44:48])[0]
        digest_len = struct.unpack('>I', data[48:52])[0]
        # 52-55: flags
        # 56-63: reserved
        
        offset = 64
        desc['partition_name'] = data[offset:offset+partition_name_len].decode('utf-8', errors='replace')
        offset += partition_name_len
        desc['salt'] = data[offset:offset+salt_len].hex() if salt_len > 0 else ""
        offset += salt_len
        desc['digest'] = data[offset:offset+digest_len].hex() if digest_len > 0 else ""
    
    def _parse_hashtree_descriptor(self, desc: dict, data: bytes):
        """Parse hashtree descriptor - used for large partitions with dm-verity."""
        if len(data) < 120:
            return
        
        desc['dm_verity_version'] = struct.unpack('>I', data[0:4])[0]
        desc['image_size'] = struct.unpack('>Q', data[4:12])[0]
        desc['tree_offset'] = struct.unpack('>Q', data[12:20])[0]
        desc['tree_size'] = struct.unpack('>Q', data[20:28])[0]
        desc['data_block_size'] = struct.unpack('>I', data[28:32])[0]
        desc['hash_block_size'] = struct.unpack('>I', data[32:36])[0]
        desc['fec_num_roots'] = struct.unpack('>I', data[36:40])[0]
        desc['fec_offset'] = struct.unpack('>Q', data[40:48])[0]
        desc['fec_size'] = struct.unpack('>Q', data[48:56])[0]
        desc['hash_algorithm'] = data[56:88].rstrip(b'\x00').decode('utf-8', errors='replace')
        partition_name_len = struct.unpack('>I', data[88:92])[0]
        salt_len = struct.unpack('>I', data[92:96])[0]
        root_digest_len = struct.unpack('>I', data[96:100])[0]
        # 100-103: flags
        # 104-119: reserved
        
        offset = 120
        desc['partition_name'] = data[offset:offset+partition_name_len].decode('utf-8', errors='replace')
        offset += partition_name_len
        desc['salt'] = data[offset:offset+salt_len].hex() if salt_len > 0 else ""
        offset += salt_len
        desc['root_digest'] = data[offset:offset+root_digest_len].hex() if root_digest_len > 0 else ""
    
    def _parse_cmdline_descriptor(self, desc: dict, data: bytes):
        """Parse kernel command line descriptor."""
        if len(data) < 8:
            return
        
        # 0-3: flags
        cmdline_len = struct.unpack('>I', data[4:8])[0]
        desc['cmdline'] = data[8:8+cmdline_len].decode('utf-8', errors='replace')
    
    def _parse_chain_descriptor(self, desc: dict, data: bytes):
        """Parse chain partition descriptor - references vbmeta in another partition."""
        if len(data) < 28:
            return
        
        desc['rollback_index_location'] = struct.unpack('>I', data[0:4])[0]
        partition_name_len = struct.unpack('>I', data[4:8])[0]
        public_key_len = struct.unpack('>I', data[8:12])[0]
        # 12-27: reserved
        
        offset = 28
        desc['partition_name'] = data[offset:offset+partition_name_len].decode('utf-8', errors='replace')
        offset += partition_name_len
        if public_key_len > 0:
            desc['public_key_size'] = public_key_len
    
    def _parse_property_descriptor(self, desc: dict, data: bytes):
        """Parse property descriptor."""
        if len(data) < 8:
            return
        
        key_len = struct.unpack('>Q', data[0:8])[0]
        value_len = struct.unpack('>Q', data[8:16])[0]
        
        offset = 16
        desc['key'] = data[offset:offset+key_len].decode('utf-8', errors='replace')
        offset += key_len
        desc['value'] = data[offset:offset+value_len].decode('utf-8', errors='replace')
    
    def _write_info_file(self):
        """Write parsed vbmeta information to a text file."""
        info_path = self.output_dir / "vbmeta_info.txt"
        
        with open(info_path, 'w') as f:
            f.write("Android Verified Boot (AVB) vbmeta Information\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("Header:\n")
            f.write(f"  AVB Version:      {self.header['version_major']}.{self.header['version_minor']}\n")
            f.write(f"  Algorithm:        {self.header['algorithm_name']}\n")
            f.write(f"  Rollback Index:   {self.header['rollback_index']}\n")
            f.write(f"  Flags:            {', '.join(self.header['flags_decoded'])}\n")
            f.write(f"  Release String:   {self.header['release_string']}\n")
            f.write(f"  Auth Block Size:  {self.header['auth_block_size']} bytes\n")
            f.write(f"  Aux Block Size:   {self.header['aux_block_size']} bytes\n")
            f.write(f"  Signature Size:   {self.header['signature_size']} bytes\n")
            f.write(f"  Public Key Size:  {self.header['public_key_size']} bytes\n")
            f.write("\n")
            
            f.write(f"Descriptors ({len(self.descriptors)}):\n")
            f.write("-" * 60 + "\n")
            
            for i, desc in enumerate(self.descriptors):
                f.write(f"\n[{i}] {desc['tag_name']}\n")
                
                if 'partition_name' in desc:
                    f.write(f"    Partition:      {desc['partition_name']}\n")
                if 'image_size' in desc:
                    f.write(f"    Image Size:     {desc['image_size']} bytes ({desc['image_size']/(1024*1024):.2f} MB)\n")
                if 'hash_algorithm' in desc:
                    f.write(f"    Hash Algorithm: {desc['hash_algorithm']}\n")
                if 'digest' in desc:
                    f.write(f"    Digest:         {desc['digest'][:64]}{'...' if len(desc.get('digest','')) > 64 else ''}\n")
                if 'root_digest' in desc:
                    f.write(f"    Root Digest:    {desc['root_digest'][:64]}{'...' if len(desc.get('root_digest','')) > 64 else ''}\n")
                if 'tree_size' in desc:
                    f.write(f"    Tree Size:      {desc['tree_size']} bytes\n")
                if 'cmdline' in desc:
                    cmdline = desc['cmdline']
                    if len(cmdline) > 100:
                        cmdline = cmdline[:100] + "..."
                    f.write(f"    Cmdline:        {cmdline}\n")
                if 'key' in desc:
                    f.write(f"    Key:            {desc['key']}\n")
                    f.write(f"    Value:          {desc['value']}\n")
                if 'rollback_index_location' in desc:
                    f.write(f"    Rollback Idx:   {desc['rollback_index_location']}\n")
        
        logger.info(f"Wrote vbmeta info to: {info_path}")
    
    def _extract_sections(self, f: BinaryIO):
        """Extract raw sections (signature, public key) from vbmeta."""
        # Extract signature if present
        if self.header['signature_size'] > 0:
            sig_path = self.output_dir / "signature.bin"
            f.seek(256 + self.header['signature_offset'])
            sig_data = f.read(self.header['signature_size'])
            with open(sig_path, 'wb') as out:
                out.write(sig_data)
            logger.info(f"  Extracted: signature.bin ({self.header['signature_size']} bytes)")
        
        # Extract public key if present
        if self.header['public_key_size'] > 0:
            key_path = self.output_dir / "public_key.bin"
            f.seek(256 + self.header['auth_block_size'] + self.header['public_key_offset'])
            key_data = f.read(self.header['public_key_size'])
            with open(key_path, 'wb') as out:
                out.write(key_data)
            logger.info(f"  Extracted: public_key.bin ({self.header['public_key_size']} bytes)")
        
        if self.progress_callback:
            self.progress_callback(100)
    
    def get_partition_info(self) -> list[dict]:
        """Get list of partitions referenced in vbmeta."""
        partitions = []
        for desc in self.descriptors:
            if 'partition_name' in desc:
                partitions.append({
                    'name': desc['partition_name'],
                    'type': desc['tag_name'],
                    'size': desc.get('image_size', 0),
                })
        return partitions


class BootloaderImageAnalyzer:
    """Analyze and extract information from bootloader images.
    
    Supports:
    - Qualcomm: XBL, ABL, TZ, HYP, AOP, DEVCFG, etc. (ELF and MBN formats)
    - MediaTek: LK (Little Kernel), preloader
    - Generic: ELF-based bootloaders
    
    This class parses bootloader images to extract metadata like:
    - Format type and version
    - Signing information
    - Build timestamp
    - Code/data segments
    """
    
    # Qualcomm MBN header structure (v5/v6)
    MBN_HDR_VERSION_3 = 3
    MBN_HDR_VERSION_5 = 5
    MBN_HDR_VERSION_6 = 6
    MBN_HDR_VERSION_7 = 7
    
    # Known Qualcomm image IDs
    QCOM_IMAGE_IDS = {
        0x00: "NONE",
        0x01: "OEM_SBL",
        0x02: "AMSS",
        0x03: "QCSBL",
        0x04: "HASH",
        0x05: "APPSBL",  # ABL
        0x06: "APPS",
        0x07: "HOSTDL",
        0x08: "DSP1",
        0x09: "FSBL",
        0x0A: "DBL",
        0x0B: "OSBL",
        0x0C: "DSP2",
        0x0D: "EHOSTDL",
        0x0E: "NANDPRG",
        0x0F: "NORPRG",
        0x10: "RAMFS1",
        0x11: "RAMFS2",
        0x12: "ADSP_Q5",
        0x13: "APPS_KERNEL",
        0x14: "BACKUP_RAMFS",
        0x15: "SBL1",
        0x16: "SBL2",
        0x17: "RPM",
        0x18: "SBL3",
        0x19: "TZ",      # TrustZone
        0x1A: "PSI",
        0x1B: "MBA",     # Modem Boot Authenticator
        0x1C: "MODEM_SW",
        0x1D: "SDI",
        0x1E: "QDSP6_SW",
        0x1F: "XBL_SEC",
        0x20: "SMSS_PIL",
        0x21: "ABL",      # Android Bootloader
        0x22: "DEVCFG",
        0x23: "AOP",      # Always-On Processor
        0x24: "APDP",
        0x25: "MULTIIMGOEM",
        0x26: "QTI",
        0x27: "HYP",      # Hypervisor
        0x28: "SEC",
        0x29: "UEFI",
        0x2A: "XBL_CFG",
        0x2B: "STORSEC",
        0x2C: "SHRM",
        0x2D: "UEFI_SEC",
        0x2E: "CPUCP",
        0x2F: "QUPFW",
    }
    
    def __init__(self, input_path: str, output_dir: str,
                 progress_callback: Optional[Callable[[int], None]] = None):
        self.input_path = Path(input_path)
        self.output_dir = Path(output_dir)
        self.progress_callback = progress_callback
        self.info = {}
        self.segments = []
        
    def analyze(self) -> dict:
        """Analyze the bootloader image and return detailed information."""
        try:
            with open(self.input_path, 'rb') as f:
                header = f.read(64)
                
                # Detect format
                if header[:4] == ELF_MAGIC:
                    self._analyze_elf_bootloader(f, header)
                elif header[:8] == LK_MAGIC:
                    self._analyze_lk_bootloader(f, header)
                else:
                    # Try MBN format
                    self._analyze_mbn_bootloader(f, header)
                    
            return self.info
        except Exception as e:
            logger.error(f"Failed to analyze bootloader: {e}")
            return {'error': str(e)}
    
    def _analyze_elf_bootloader(self, f: BinaryIO, header: bytes):
        """Analyze ELF-format bootloader (Qualcomm XBL, ABL, etc.)."""
        self.info['format'] = 'ELF'
        
        # Parse ELF header
        ei_class = header[4]
        ei_data = header[5]
        self.info['elf_class'] = '64-bit' if ei_class == 2 else '32-bit'
        self.info['endian'] = 'Little' if ei_data == 1 else 'Big'
        endian = '<' if ei_data == 1 else '>'
        
        if ei_class == 2:  # 64-bit
            e_type, e_machine = struct.unpack(f'{endian}HH', header[16:20])
            e_entry = struct.unpack(f'{endian}Q', header[24:32])[0]
            e_phoff = struct.unpack(f'{endian}Q', header[32:40])[0]
            e_phentsize, e_phnum = struct.unpack(f'{endian}HH', header[54:58])
        else:  # 32-bit
            e_type, e_machine = struct.unpack(f'{endian}HH', header[16:20])
            e_entry = struct.unpack(f'{endian}I', header[24:28])[0]
            e_phoff = struct.unpack(f'{endian}I', header[28:32])[0]
            e_phentsize, e_phnum = struct.unpack(f'{endian}HH', header[42:46])
        
        machine_names = {
            0: "None", 3: "Intel 386", 8: "MIPS", 40: "ARM",
            62: "x86-64", 164: "Qualcomm Hexagon", 183: "AArch64",
        }
        
        self.info['machine'] = machine_names.get(e_machine, f"Unknown (0x{e_machine:X})")
        self.info['entry_point'] = f"0x{e_entry:X}"
        self.info['segments'] = e_phnum
        
        # Try to identify image type from filename
        filename = self.input_path.stem.lower()
        if 'xbl' in filename:
            self.info['type'] = 'XBL (eXtensible Boot Loader)'
            self.info['description'] = 'Primary bootloader, UEFI-based, handles secure boot'
        elif 'abl' in filename:
            self.info['type'] = 'ABL (Android Boot Loader)'
            self.info['description'] = 'Secondary bootloader, handles fastboot mode'
        elif 'tz' in filename or 'tzsq' in filename:
            self.info['type'] = 'TZ (TrustZone)'
            self.info['description'] = 'Secure world OS for TrustZone TEE'
        elif 'hyp' in filename:
            self.info['type'] = 'HYP (Hypervisor)'
            self.info['description'] = 'Hypervisor for hardware virtualization'
        elif 'aop' in filename:
            self.info['type'] = 'AOP (Always-On Processor)'
            self.info['description'] = 'Low-power processor firmware'
        elif 'devcfg' in filename:
            self.info['type'] = 'DEVCFG (Device Config)'
            self.info['description'] = 'Device configuration data'
        elif 'keymaster' in filename or 'km' in filename:
            self.info['type'] = 'Keymaster'
            self.info['description'] = 'Hardware-backed key storage trustlet'
        elif 'cmnlib' in filename:
            self.info['type'] = 'CMNLIB (Common Library)'
            self.info['description'] = 'Shared TrustZone library'
        elif 'storsec' in filename:
            self.info['type'] = 'STORSEC (Storage Security)'
            self.info['description'] = 'Secure storage firmware'
        elif 'qupfw' in filename:
            self.info['type'] = 'QUPFW (QUP Firmware)'
            self.info['description'] = 'Qualcomm Universal Peripheral firmware'
        elif 'uefi' in filename:
            self.info['type'] = 'UEFI'
            self.info['description'] = 'UEFI firmware component'
        else:
            self.info['type'] = 'Qualcomm Signed ELF'
            self.info['description'] = 'Qualcomm bootloader/firmware component'
        
        # Parse program headers to find hash segment (Qualcomm signing info)
        self._parse_elf_segments(f, e_phoff, e_phentsize, e_phnum, ei_class, endian)
        
        # Look for build info strings
        self._find_build_info(f)
    
    def _parse_elf_segments(self, f: BinaryIO, phoff: int, phentsize: int, 
                           phnum: int, ei_class: int, endian: str):
        """Parse ELF program headers."""
        f.seek(phoff)
        
        for i in range(phnum):
            ph_data = f.read(phentsize)
            
            if ei_class == 2:  # 64-bit
                p_type, p_flags = struct.unpack(f'{endian}II', ph_data[0:8])
                p_offset = struct.unpack(f'{endian}Q', ph_data[8:16])[0]
                p_vaddr = struct.unpack(f'{endian}Q', ph_data[16:24])[0]
                p_filesz = struct.unpack(f'{endian}Q', ph_data[32:40])[0]
            else:  # 32-bit
                p_type = struct.unpack(f'{endian}I', ph_data[0:4])[0]
                p_offset = struct.unpack(f'{endian}I', ph_data[4:8])[0]
                p_vaddr = struct.unpack(f'{endian}I', ph_data[8:12])[0]
                p_filesz = struct.unpack(f'{endian}I', ph_data[16:20])[0]
                p_flags = struct.unpack(f'{endian}I', ph_data[24:28])[0]
            
            segment_types = {
                0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP",
                4: "NOTE", 5: "SHLIB", 6: "PHDR", 7: "TLS",
                0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK",
                0x6474e552: "GNU_RELRO", 0x6FFFFFFD: "QC_HASH",
                0x6FFFFFFA: "QC_PHDR_HASH",
            }
            
            self.segments.append({
                'index': i,
                'type': segment_types.get(p_type, f"0x{p_type:X}"),
                'offset': p_offset,
                'vaddr': p_vaddr,
                'size': p_filesz,
                'flags': p_flags,
            })
            
            # Check for Qualcomm hash segment
            if p_type == 0x6FFFFFFD:  # QC_HASH
                self.info['qcom_signed'] = True
                self._parse_qcom_hash_segment(f, p_offset, p_filesz)
    
    def _parse_qcom_hash_segment(self, f: BinaryIO, offset: int, size: int):
        """Parse Qualcomm hash segment for signing info."""
        if size < 40:
            return
        
        f.seek(offset)
        hash_data = f.read(min(size, 256))
        
        # The hash segment contains certificate chain info
        # First few bytes often contain version/type info
        self.info['hash_segment_size'] = size
    
    def _find_build_info(self, f: BinaryIO):
        """Search for build information strings in the image."""
        f.seek(0)
        data = f.read()
        
        # Common build info patterns
        patterns = [
            (b'QC_IMAGE_VERSION_STRING=', 'qc_version'),
            (b'IMAGE_VARIANT_STRING=', 'variant'),
            (b'OEM_IMAGE_VERSION_STRING=', 'oem_version'),
            (b'BUILD_', 'build_info'),
            (b'@(#)', 'sccs_version'),
        ]
        
        for pattern, key in patterns:
            idx = data.find(pattern)
            if idx != -1:
                # Extract string until null or newline
                end = idx + len(pattern)
                string_data = b''
                while end < len(data) and data[end:end+1] not in (b'\x00', b'\n', b'\r'):
                    string_data += data[end:end+1]
                    end += 1
                if string_data:
                    try:
                        self.info[key] = string_data.decode('utf-8', errors='replace')[:100]
                    except:
                        pass
        
        # Look for timestamp patterns (common in Qualcomm images)
        import re
        date_pattern = rb'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}'
        time_pattern = rb'\d{2}:\d{2}:\d{2}'
        
        date_match = re.search(date_pattern, data)
        time_match = re.search(time_pattern, data)
        
        if date_match:
            try:
                self.info['build_date'] = date_match.group().decode('utf-8')
            except:
                pass
        if time_match:
            try:
                self.info['build_time'] = time_match.group().decode('utf-8')
            except:
                pass
    
    def _analyze_lk_bootloader(self, f: BinaryIO, header: bytes):
        """Analyze Little Kernel (MediaTek) bootloader."""
        self.info['format'] = 'Little Kernel (LK)'
        self.info['type'] = 'MediaTek Bootloader'
        self.info['description'] = 'Little Kernel based bootloader (MediaTek)'
        
        # LK header structure after magic
        if len(header) >= 40:
            # Parse LK header fields
            f.seek(8)
            lk_header = f.read(32)
            
            if len(lk_header) >= 24:
                size = struct.unpack('<I', lk_header[0:4])[0]
                self.info['image_size'] = size
    
    def _analyze_mbn_bootloader(self, f: BinaryIO, header: bytes):
        """Analyze Qualcomm MBN format bootloader."""
        mbn_type = struct.unpack('<I', header[0:4])[0]
        
        if mbn_type not in (self.MBN_HDR_VERSION_3, self.MBN_HDR_VERSION_5, 
                           self.MBN_HDR_VERSION_6, self.MBN_HDR_VERSION_7):
            self.info['format'] = 'Unknown'
            return
        
        self.info['format'] = f'Qualcomm MBN v{mbn_type}'
        self.info['mbn_version'] = mbn_type
        
        # MBN header structure (v5+)
        # 0x00: Image type (4 bytes)
        # 0x04: Flash partition version (4 bytes)
        # 0x08: Source image address (4 bytes)
        # 0x0C: Source image size (4 bytes)
        # 0x10: Code size (4 bytes)
        # 0x14: Signature address (4 bytes)
        # 0x18: Signature size (4 bytes)
        # 0x1C: Certificate chain address (4 bytes)
        # 0x20: Certificate chain size (4 bytes)
        
        f.seek(0)
        mbn_header = f.read(80)
        
        if len(mbn_header) >= 36:
            flash_parti_ver = struct.unpack('<I', mbn_header[4:8])[0]
            image_src = struct.unpack('<I', mbn_header[8:12])[0]
            image_size = struct.unpack('<I', mbn_header[12:16])[0]
            code_size = struct.unpack('<I', mbn_header[16:20])[0]
            sig_addr = struct.unpack('<I', mbn_header[20:24])[0]
            sig_size = struct.unpack('<I', mbn_header[24:28])[0]
            cert_addr = struct.unpack('<I', mbn_header[28:32])[0]
            cert_size = struct.unpack('<I', mbn_header[32:36])[0]
            
            self.info['flash_partition_version'] = flash_parti_ver
            self.info['image_size'] = image_size
            self.info['code_size'] = code_size
            self.info['signature_size'] = sig_size
            self.info['cert_chain_size'] = cert_size
            self.info['is_signed'] = sig_size > 0 or cert_size > 0
        
        # Try to identify image type from filename
        filename = self.input_path.stem.lower()
        self.info['type'] = self._identify_mbn_type(filename)
    
    def _identify_mbn_type(self, filename: str) -> str:
        """Identify MBN image type from filename."""
        type_map = {
            'sbl1': 'SBL1 (Secondary Boot Loader)',
            'rpm': 'RPM (Resource Power Manager)',
            'tz': 'TZ (TrustZone)',
            'hyp': 'HYP (Hypervisor)',
            'abl': 'ABL (Android Boot Loader)',
            'xbl': 'XBL (eXtensible Boot Loader)',
            'devcfg': 'DEVCFG (Device Configuration)',
            'aop': 'AOP (Always-On Processor)',
            'keymaster': 'Keymaster (Key Storage)',
            'cmnlib': 'CMNLIB (Common Library)',
            'storsec': 'STORSEC (Storage Security)',
            'qupfw': 'QUPFW (QUP Firmware)',
        }
        
        for key, value in type_map.items():
            if key in filename:
                return value
        return 'Qualcomm MBN Image'
    
    def extract(self) -> bool:
        """Extract bootloader information and segments."""
        try:
            # Analyze first
            self.analyze()
            
            # Create output directory
            self.output_dir.mkdir(parents=True, exist_ok=True)
            
            # Write info file
            self._write_info_file()
            
            # Extract segments if ELF
            if self.info.get('format') == 'ELF' and self.segments:
                self._extract_segments()
            
            if self.progress_callback:
                self.progress_callback(100)
            
            return True
        except Exception as e:
            logger.error(f"Failed to extract bootloader: {e}")
            return False
    
    def _write_info_file(self):
        """Write bootloader information to a text file."""
        info_path = self.output_dir / "bootloader_info.txt"
        
        with open(info_path, 'w') as f:
            f.write("Bootloader Image Analysis\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"File: {self.input_path.name}\n")
            f.write(f"Size: {self.input_path.stat().st_size:,} bytes\n\n")
            
            f.write("Image Information:\n")
            f.write("-" * 40 + "\n")
            
            for key, value in self.info.items():
                if key not in ('error',):
                    f.write(f"  {key}: {value}\n")
            
            if self.segments:
                f.write("\nProgram Segments:\n")
                f.write("-" * 40 + "\n")
                for seg in self.segments:
                    f.write(f"\n  [{seg['index']}] {seg['type']}\n")
                    f.write(f"      Offset: 0x{seg['offset']:X}\n")
                    f.write(f"      VAddr:  0x{seg['vaddr']:X}\n")
                    f.write(f"      Size:   {seg['size']:,} bytes\n")
                    flags = []
                    if seg['flags'] & 1: flags.append('X')
                    if seg['flags'] & 2: flags.append('W')
                    if seg['flags'] & 4: flags.append('R')
                    f.write(f"      Flags:  {' '.join(flags) if flags else 'None'}\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write("Note: This is a bootloader/firmware image.\n")
            f.write("Modifying bootloader images can brick your device.\n")
            f.write("These images are typically signed and verified by secure boot.\n")
        
        logger.info(f"Wrote bootloader info to: {info_path}")
    
    def _extract_segments(self):
        """Extract ELF segments to separate files."""
        with open(self.input_path, 'rb') as f:
            for seg in self.segments:
                if seg['size'] == 0:
                    continue
                
                f.seek(seg['offset'])
                data = f.read(seg['size'])
                
                type_name = seg['type'].replace(' ', '_').replace('/', '_')
                filename = f"segment_{seg['index']:02d}_{type_name}_0x{seg['vaddr']:08X}.bin"
                
                output_path = self.output_dir / filename
                with open(output_path, 'wb') as out:
                    out.write(data)
                
                logger.info(f"  Extracted: {filename} ({seg['size']:,} bytes)")


class AvbSigner:
    """AVB (Android Verified Boot) key management and signing.
    
    Supports:
    - Generating RSA key pairs (2048, 4096, 8192 bits)
    - Signing vbmeta images with custom keys
    - Exporting keys in AVB format
    
    Note: Re-signed vbmeta will only work on:
    - Unlocked bootloaders
    - Devices with custom AVB key enrolled
    - Custom ROM/recovery environments
    """
    
    # AVB algorithm IDs
    ALG_NONE = 0
    ALG_SHA256_RSA2048 = 1
    ALG_SHA256_RSA4096 = 2
    ALG_SHA256_RSA8192 = 3
    ALG_SHA512_RSA2048 = 4
    ALG_SHA512_RSA4096 = 5
    ALG_SHA512_RSA8192 = 6
    
    ALGORITHM_INFO = {
        ALG_SHA256_RSA2048: {'hash': 'sha256', 'key_bits': 2048, 'hash_size': 32, 'sig_size': 256},
        ALG_SHA256_RSA4096: {'hash': 'sha256', 'key_bits': 4096, 'hash_size': 32, 'sig_size': 512},
        ALG_SHA256_RSA8192: {'hash': 'sha256', 'key_bits': 8192, 'hash_size': 32, 'sig_size': 1024},
        ALG_SHA512_RSA2048: {'hash': 'sha512', 'key_bits': 2048, 'hash_size': 64, 'sig_size': 256},
        ALG_SHA512_RSA4096: {'hash': 'sha512', 'key_bits': 4096, 'hash_size': 64, 'sig_size': 512},
        ALG_SHA512_RSA8192: {'hash': 'sha512', 'key_bits': 8192, 'hash_size': 64, 'sig_size': 1024},
    }
    
    def __init__(self):
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required for AVB signing. "
                            "Install with: pip install cryptography")
        self.private_key = None
        self.public_key = None
        self.key_bits = 4096
    
    @staticmethod
    def is_available() -> bool:
        """Check if cryptography library is available."""
        return CRYPTO_AVAILABLE
    
    def generate_key(self, key_bits: int = 4096) -> bool:
        """Generate a new RSA key pair.
        
        Args:
            key_bits: Key size (2048, 4096, or 8192)
            
        Returns:
            True if successful
        """
        if key_bits not in (2048, 4096, 8192):
            logger.error(f"Invalid key size: {key_bits}. Must be 2048, 4096, or 8192")
            return False
        
        try:
            logger.info(f"Generating RSA-{key_bits} key pair...")
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_bits,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            self.key_bits = key_bits
            logger.info("Key pair generated successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to generate key: {e}")
            return False
    
    def load_private_key(self, key_path: str, password: Optional[bytes] = None) -> bool:
        """Load private key from PEM file.
        
        Args:
            key_path: Path to PEM private key file
            password: Optional password for encrypted keys
            
        Returns:
            True if successful
        """
        try:
            with open(key_path, 'rb') as f:
                key_data = f.read()
            
            self.private_key = serialization.load_pem_private_key(
                key_data,
                password=password,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            self.key_bits = self.private_key.key_size
            logger.info(f"Loaded RSA-{self.key_bits} private key from {key_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            return False
    
    def save_private_key(self, key_path: str, password: Optional[bytes] = None) -> bool:
        """Save private key to PEM file.
        
        Args:
            key_path: Output path for PEM file
            password: Optional password to encrypt the key
            
        Returns:
            True if successful
        """
        if not self.private_key:
            logger.error("No private key to save")
            return False
        
        try:
            if password:
                encryption = serialization.BestAvailableEncryption(password)
            else:
                encryption = serialization.NoEncryption()
            
            pem_data = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            )
            
            with open(key_path, 'wb') as f:
                f.write(pem_data)
            
            logger.info(f"Saved private key to {key_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save private key: {e}")
            return False
    
    def save_public_key(self, key_path: str) -> bool:
        """Save public key to PEM file.
        
        Args:
            key_path: Output path for PEM file
            
        Returns:
            True if successful
        """
        if not self.public_key:
            logger.error("No public key to save")
            return False
        
        try:
            pem_data = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            with open(key_path, 'wb') as f:
                f.write(pem_data)
            
            logger.info(f"Saved public key to {key_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save public key: {e}")
            return False
    
    def get_avb_public_key_blob(self) -> bytes:
        """Get public key in AVB format for embedding in vbmeta.
        
        AVB public key format:
        - 4 bytes: key length in bits (big-endian)
        - 4 bytes: n0inv (Montgomery multiplication helper)
        - key_size/8 bytes: modulus n (big-endian)
        - key_size/8 bytes: rr = (2^(key_size*2)) mod n (big-endian)
        
        Returns:
            Public key blob in AVB format
        """
        if not self.public_key:
            return b''
        
        # Get public numbers
        pub_numbers = self.public_key.public_numbers()
        n = pub_numbers.n
        
        key_bytes = self.key_bits // 8
        
        # Calculate n0inv: -1/n[0] mod 2^32
        # This is used for Montgomery multiplication optimization
        n0inv = pow(-n, -1, 2**32) & 0xFFFFFFFF
        
        # Calculate rr = (2^(key_bits*2)) mod n
        rr = pow(2, self.key_bits * 2, n)
        
        # Build the blob
        blob = struct.pack('>I', self.key_bits)  # Key size in bits
        blob += struct.pack('>I', n0inv)          # n0inv
        blob += n.to_bytes(key_bytes, 'big')      # Modulus n
        blob += rr.to_bytes(key_bytes, 'big')     # rr
        
        return blob
    
    def sign_data(self, data: bytes, algorithm_id: int) -> bytes:
        """Sign data using the private key.
        
        Args:
            data: Data to sign
            algorithm_id: AVB algorithm ID
            
        Returns:
            Signature bytes
        """
        if not self.private_key:
            raise ValueError("No private key loaded")
        
        alg_info = self.ALGORITHM_INFO.get(algorithm_id)
        if not alg_info:
            raise ValueError(f"Unknown algorithm ID: {algorithm_id}")
        
        # Select hash algorithm
        if alg_info['hash'] == 'sha256':
            hash_alg = hashes.SHA256()
        else:
            hash_alg = hashes.SHA512()
        
        # Sign with PKCS#1 v1.5 padding (what AVB uses)
        signature = self.private_key.sign(
            data,
            padding.PKCS1v15(),
            hash_alg
        )
        
        return signature
    
    def compute_hash(self, data: bytes, algorithm_id: int) -> bytes:
        """Compute hash of data.
        
        Args:
            data: Data to hash
            algorithm_id: AVB algorithm ID
            
        Returns:
            Hash bytes
        """
        alg_info = self.ALGORITHM_INFO.get(algorithm_id)
        if not alg_info:
            raise ValueError(f"Unknown algorithm ID: {algorithm_id}")
        
        if alg_info['hash'] == 'sha256':
            return hashlib.sha256(data).digest()
        else:
            return hashlib.sha512(data).digest()
    
    def get_algorithm_for_key_size(self, use_sha512: bool = False) -> int:
        """Get appropriate AVB algorithm ID for current key size.
        
        Args:
            use_sha512: Use SHA-512 instead of SHA-256
            
        Returns:
            AVB algorithm ID
        """
        if use_sha512:
            return {2048: self.ALG_SHA512_RSA2048, 
                    4096: self.ALG_SHA512_RSA4096, 
                    8192: self.ALG_SHA512_RSA8192}.get(self.key_bits, self.ALG_SHA512_RSA4096)
        else:
            return {2048: self.ALG_SHA256_RSA2048, 
                    4096: self.ALG_SHA256_RSA4096, 
                    8192: self.ALG_SHA256_RSA8192}.get(self.key_bits, self.ALG_SHA256_RSA4096)


class VbmetaPatcher:
    """Patch vbmeta images to disable verity and/or verification.
    
    This modifies the flags field in the vbmeta header to disable:
    - dm-verity (hashtree verification)
    - AVB verification (signature checking)
    
    Note: After patching, the vbmeta signature becomes invalid.
    The device bootloader must be unlocked to boot with patched vbmeta.
    
    Optional: Re-sign with a custom key for development/custom ROM use.
    """
    
    # Flag values
    FLAG_DISABLE_VERITY = 0x01        # AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED
    FLAG_DISABLE_VERIFICATION = 0x02  # AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED
    
    # Offset of flags field in vbmeta header (after 4-byte magic)
    FLAGS_OFFSET = 120  # Absolute offset from start of file
    
    # Header offsets (all big-endian)
    OFFSET_VERSION_MAJOR = 4
    OFFSET_VERSION_MINOR = 8
    OFFSET_AUTH_BLOCK_SIZE = 12
    OFFSET_AUX_BLOCK_SIZE = 20
    OFFSET_ALGORITHM = 28
    OFFSET_HASH_OFFSET = 32
    OFFSET_HASH_SIZE = 40
    OFFSET_SIG_OFFSET = 48
    OFFSET_SIG_SIZE = 56
    OFFSET_PUBKEY_OFFSET = 64
    OFFSET_PUBKEY_SIZE = 72
    
    HEADER_SIZE = 256
    
    def __init__(self, input_path: str):
        self.input_path = Path(input_path)
        
    def patch(self, output_path: str, disable_verity: bool = False, 
              disable_verification: bool = False,
              signer: Optional['AvbSigner'] = None) -> bool:
        """Patch vbmeta and optionally re-sign with custom key.
        
        Args:
            output_path: Where to save the patched vbmeta
            disable_verity: Set the HASHTREE_DISABLED flag
            disable_verification: Set the VERIFICATION_DISABLED flag
            signer: Optional AvbSigner for re-signing with custom key
            
        Returns:
            True if successful, False otherwise
        """
        if not disable_verity and not disable_verification and not signer:
            # Nothing to do, just copy
            import shutil
            shutil.copy2(self.input_path, output_path)
            return True
        
        try:
            # Read original vbmeta
            with open(self.input_path, 'rb') as f:
                data = bytearray(f.read())
            
            # Verify magic
            if data[:4] != AVB_MAGIC:
                logger.error("Invalid vbmeta magic")
                return False
            
            # Read current flags (big-endian 4 bytes at offset 120)
            current_flags = struct.unpack('>I', data[self.FLAGS_OFFSET:self.FLAGS_OFFSET+4])[0]
            
            # Apply new flags
            new_flags = current_flags
            if disable_verity:
                new_flags |= self.FLAG_DISABLE_VERITY
            if disable_verification:
                new_flags |= self.FLAG_DISABLE_VERIFICATION
            
            # Write new flags
            data[self.FLAGS_OFFSET:self.FLAGS_OFFSET+4] = struct.pack('>I', new_flags)
            
            changes = []
            if disable_verity:
                changes.append("verity disabled")
            if disable_verification:
                changes.append("verification disabled")
            
            # Re-sign if signer provided
            if signer:
                data = self._resign_vbmeta(data, signer)
                if data is None:
                    return False
                changes.append("re-signed with custom key")
            
            # Save patched vbmeta
            with open(output_path, 'wb') as f:
                f.write(data)
            
            logger.info(f"Patched vbmeta: {', '.join(changes)}")
            logger.info(f"Original flags: 0x{current_flags:08X} -> New flags: 0x{new_flags:08X}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to patch vbmeta: {e}")
            return False
    
    def _resign_vbmeta(self, data: bytearray, signer: 'AvbSigner') -> Optional[bytearray]:
        """Re-sign vbmeta with custom key.
        
        This completely rebuilds the authentication block with:
        - New hash of header + auxiliary data
        - New signature using the custom key
        - New public key blob
        """
        try:
            logger.info("Re-signing vbmeta with custom key...")
            
            # Read header fields
            auth_block_size = struct.unpack('>Q', data[self.OFFSET_AUTH_BLOCK_SIZE:self.OFFSET_AUTH_BLOCK_SIZE+8])[0]
            aux_block_size = struct.unpack('>Q', data[self.OFFSET_AUX_BLOCK_SIZE:self.OFFSET_AUX_BLOCK_SIZE+8])[0]
            original_algorithm = struct.unpack('>I', data[self.OFFSET_ALGORITHM:self.OFFSET_ALGORITHM+4])[0]
            
            # Determine new algorithm based on key size
            new_algorithm = signer.get_algorithm_for_key_size(use_sha512=(original_algorithm >= 4))
            alg_info = signer.ALGORITHM_INFO[new_algorithm]
            
            # Get the auxiliary data (descriptors, etc.)
            aux_start = self.HEADER_SIZE + auth_block_size
            aux_data = bytes(data[aux_start:aux_start + aux_block_size])
            
            # Prepare new public key blob
            pubkey_blob = signer.get_avb_public_key_blob()
            pubkey_size = len(pubkey_blob)
            
            # Calculate new sizes
            hash_size = alg_info['hash_size']
            sig_size = alg_info['sig_size']
            
            # Authentication block layout:
            # [hash] [padding to 8-byte align] [signature] [padding] [public key] [padding]
            hash_offset = 0
            sig_offset = ((hash_size + 7) // 8) * 8  # Align to 8 bytes
            pubkey_offset = sig_offset + ((sig_size + 7) // 8) * 8
            new_auth_block_size = pubkey_offset + ((pubkey_size + 7) // 8) * 8
            
            # Update header with new values
            new_header = bytearray(data[:self.HEADER_SIZE])
            
            # Update algorithm
            new_header[self.OFFSET_ALGORITHM:self.OFFSET_ALGORITHM+4] = struct.pack('>I', new_algorithm)
            
            # Update hash info
            new_header[self.OFFSET_HASH_OFFSET:self.OFFSET_HASH_OFFSET+8] = struct.pack('>Q', hash_offset)
            new_header[self.OFFSET_HASH_SIZE:self.OFFSET_HASH_SIZE+8] = struct.pack('>Q', hash_size)
            
            # Update signature info
            new_header[self.OFFSET_SIG_OFFSET:self.OFFSET_SIG_OFFSET+8] = struct.pack('>Q', sig_offset)
            new_header[self.OFFSET_SIG_SIZE:self.OFFSET_SIG_SIZE+8] = struct.pack('>Q', sig_size)
            
            # Update public key info
            new_header[self.OFFSET_PUBKEY_OFFSET:self.OFFSET_PUBKEY_OFFSET+8] = struct.pack('>Q', pubkey_offset)
            new_header[self.OFFSET_PUBKEY_SIZE:self.OFFSET_PUBKEY_SIZE+8] = struct.pack('>Q', pubkey_size)
            
            # Update auth block size
            new_header[self.OFFSET_AUTH_BLOCK_SIZE:self.OFFSET_AUTH_BLOCK_SIZE+8] = struct.pack('>Q', new_auth_block_size)
            
            # Compute hash over header + auxiliary data
            data_to_hash = bytes(new_header) + aux_data
            hash_digest = signer.compute_hash(data_to_hash, new_algorithm)
            
            # Sign the hash
            signature = signer.sign_data(data_to_hash, new_algorithm)
            
            # Build new authentication block
            new_auth_block = bytearray(new_auth_block_size)
            new_auth_block[hash_offset:hash_offset+hash_size] = hash_digest
            new_auth_block[sig_offset:sig_offset+sig_size] = signature
            new_auth_block[pubkey_offset:pubkey_offset+pubkey_size] = pubkey_blob
            
            # Assemble final vbmeta
            result = bytearray()
            result.extend(new_header)
            result.extend(new_auth_block)
            result.extend(aux_data)
            
            # Pad to original size if needed (some tools expect specific sizes)
            original_size = len(data)
            if len(result) < original_size:
                result.extend(b'\x00' * (original_size - len(result)))
            
            logger.info(f"  Algorithm: {new_algorithm} (RSA-{signer.key_bits})")
            logger.info(f"  Hash size: {hash_size} bytes")
            logger.info(f"  Signature size: {sig_size} bytes")
            logger.info(f"  Public key size: {pubkey_size} bytes")
            logger.info(f"  New auth block size: {new_auth_block_size} bytes")
            
            return result
            
        except Exception as e:
            logger.exception(f"Failed to re-sign vbmeta: {e}")
            return None
    
    @staticmethod
    def get_current_flags(input_path: str) -> dict:
        """Read current flag status from a vbmeta file."""
        try:
            with open(input_path, 'rb') as f:
                magic = f.read(4)
                if magic != AVB_MAGIC:
                    return {'error': 'Not a valid vbmeta file'}
                
                f.seek(VbmetaPatcher.FLAGS_OFFSET)
                flags = struct.unpack('>I', f.read(4))[0]
                
                return {
                    'raw_flags': flags,
                    'verity_disabled': bool(flags & VbmetaPatcher.FLAG_DISABLE_VERITY),
                    'verification_disabled': bool(flags & VbmetaPatcher.FLAG_DISABLE_VERIFICATION),
                }
        except Exception as e:
            return {'error': str(e)}


# =============================================================================
# IMAGE REPACKAGING CLASSES
# =============================================================================

class BootImagePacker:
    """Pack boot.img / recovery.img / vendor_boot.img from components.
    
    Supports:
    - Boot image v0-v4 formats (same format for recovery.img)
    - vendor_boot image v3-v4 formats
    - Custom kernel, ramdisk, DTB
    - Cmdline modification
    
    Note: boot.img and recovery.img use identical formats.
    The difference is the ramdisk contents (boot vs recovery init).
    """
    
    BOOT_MAGIC = b'ANDROID!'
    VENDOR_BOOT_MAGIC = b'VNDRBOOT'
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        self.progress_callback = progress_callback
        self.header_version = 2  # Default to v2
    
    def pack_boot_image(self, output_path: str, 
                        kernel: Optional[str] = None,
                        ramdisk: Optional[str] = None,
                        second: Optional[str] = None,
                        dtb: Optional[str] = None,
                        recovery_dtbo: Optional[str] = None,
                        cmdline: str = "",
                        extra_cmdline: str = "",
                        base_addr: int = 0x10000000,
                        kernel_offset: int = 0x00008000,
                        ramdisk_offset: int = 0x01000000,
                        second_offset: int = 0x00F00000,
                        tags_offset: int = 0x00000100,
                        dtb_offset: int = 0x01F00000,
                        page_size: int = 4096,
                        os_version: int = 0,
                        header_version: int = 2,
                        board_name: str = "") -> bool:
        """Pack a boot image from components.
        
        Args:
            output_path: Output boot.img path
            kernel: Path to kernel (zImage/Image.gz)
            ramdisk: Path to ramdisk.cpio or ramdisk.img
            second: Path to second stage bootloader (optional)
            dtb: Path to DTB (device tree blob)
            recovery_dtbo: Path to recovery DTBO (v1-v2)
            cmdline: Kernel command line
            extra_cmdline: Extra cmdline (for v3+)
            base_addr: Base address
            kernel_offset: Kernel load offset from base
            ramdisk_offset: Ramdisk load offset from base
            second_offset: Second bootloader offset
            tags_offset: Kernel tags offset
            dtb_offset: DTB offset (v2+)
            page_size: Page size (2048/4096)
            os_version: OS version packed value
            header_version: Boot image header version (0-4)
            board_name: Board/product name
            
        Returns:
            True if successful
        """
        self.header_version = header_version
        
        try:
            logger.info(f"Packing boot image v{header_version}...")
            
            # Read component files
            kernel_data = self._read_file(kernel) if kernel else b''
            ramdisk_data = self._read_file(ramdisk) if ramdisk else b''
            second_data = self._read_file(second) if second else b''
            dtb_data = self._read_file(dtb) if dtb else b''
            recovery_dtbo_data = self._read_file(recovery_dtbo) if recovery_dtbo else b''
            
            if header_version >= 3:
                # v3/v4 format - simplified header
                return self._pack_v3_v4(output_path, kernel_data, ramdisk_data,
                                        cmdline, os_version, header_version, page_size)
            else:
                # v0-v2 format - traditional header
                return self._pack_v0_v2(output_path, kernel_data, ramdisk_data,
                                        second_data, dtb_data, recovery_dtbo_data,
                                        cmdline, base_addr, kernel_offset,
                                        ramdisk_offset, second_offset, tags_offset,
                                        dtb_offset, page_size, os_version,
                                        header_version, board_name)
        except Exception as e:
            logger.error(f"Failed to pack boot image: {e}")
            return False
    
    def _read_file(self, path: str) -> bytes:
        """Read file contents."""
        with open(path, 'rb') as f:
            return f.read()
    
    def _pad_to_page(self, data: bytes, page_size: int) -> bytes:
        """Pad data to page boundary."""
        if len(data) % page_size == 0:
            return data
        padding = page_size - (len(data) % page_size)
        return data + b'\x00' * padding
    
    def _pack_v0_v2(self, output_path: str, kernel: bytes, ramdisk: bytes,
                    second: bytes, dtb: bytes, recovery_dtbo: bytes,
                    cmdline: str, base_addr: int, kernel_offset: int,
                    ramdisk_offset: int, second_offset: int, tags_offset: int,
                    dtb_offset: int, page_size: int, os_version: int,
                    header_version: int, board_name: str) -> bool:
        """Pack v0-v2 boot image."""
        
        # Build header (1648 bytes for v2, padded to page_size)
        header = bytearray(1648)
        
        # Magic
        header[0:8] = self.BOOT_MAGIC
        
        # Kernel info
        struct.pack_into('<I', header, 8, len(kernel))  # kernel_size
        struct.pack_into('<I', header, 12, base_addr + kernel_offset)  # kernel_addr
        
        # Ramdisk info
        struct.pack_into('<I', header, 16, len(ramdisk))  # ramdisk_size
        struct.pack_into('<I', header, 20, base_addr + ramdisk_offset)  # ramdisk_addr
        
        # Second bootloader
        struct.pack_into('<I', header, 24, len(second))  # second_size
        struct.pack_into('<I', header, 28, base_addr + second_offset)  # second_addr
        
        # Tags
        struct.pack_into('<I', header, 32, base_addr + tags_offset)  # tags_addr
        
        # Page size
        struct.pack_into('<I', header, 36, page_size)
        
        # Header version
        struct.pack_into('<I', header, 40, header_version)
        
        # OS version
        struct.pack_into('<I', header, 44, os_version)
        
        # Board name (16 bytes)
        board_bytes = board_name.encode('utf-8')[:16]
        header[48:48+len(board_bytes)] = board_bytes
        
        # Cmdline (512 bytes)
        cmdline_bytes = cmdline.encode('utf-8')[:512]
        header[64:64+len(cmdline_bytes)] = cmdline_bytes
        
        # ID/hash placeholder (32 bytes at offset 576)
        
        # Extra cmdline (1024 bytes at offset 608)
        
        if header_version >= 1:
            # Recovery DTBO (v1+)
            struct.pack_into('<I', header, 1632, len(recovery_dtbo))
            # recovery_dtbo_offset calculated later
            struct.pack_into('<I', header, 1640, 1648)  # header_size
        
        if header_version >= 2:
            # DTB (v2)
            struct.pack_into('<I', header, 1644, len(dtb))
            # dtb_addr
            struct.pack_into('<Q', header, 1648 - 8, base_addr + dtb_offset) if len(header) > 1648 else None
        
        # Calculate offsets
        header_pages = (len(header) + page_size - 1) // page_size
        kernel_pages = (len(kernel) + page_size - 1) // page_size if kernel else 0
        ramdisk_pages = (len(ramdisk) + page_size - 1) // page_size if ramdisk else 0
        second_pages = (len(second) + page_size - 1) // page_size if second else 0
        
        # Recovery DTBO offset (after second)
        if header_version >= 1 and recovery_dtbo:
            recovery_offset = (header_pages + kernel_pages + ramdisk_pages + second_pages) * page_size
            struct.pack_into('<Q', header, 1636, recovery_offset)
        
        # Write output
        with open(output_path, 'wb') as f:
            # Header (padded)
            f.write(self._pad_to_page(bytes(header[:1648]), page_size))
            
            # Kernel
            if kernel:
                f.write(self._pad_to_page(kernel, page_size))
            
            # Ramdisk
            if ramdisk:
                f.write(self._pad_to_page(ramdisk, page_size))
            
            # Second
            if second:
                f.write(self._pad_to_page(second, page_size))
            
            # Recovery DTBO (v1+)
            if header_version >= 1 and recovery_dtbo:
                f.write(self._pad_to_page(recovery_dtbo, page_size))
            
            # DTB (v2)
            if header_version >= 2 and dtb:
                f.write(self._pad_to_page(dtb, page_size))
        
        logger.info(f"Packed boot image v{header_version}: {output_path}")
        logger.info(f"  Kernel: {len(kernel)} bytes")
        logger.info(f"  Ramdisk: {len(ramdisk)} bytes")
        if dtb:
            logger.info(f"  DTB: {len(dtb)} bytes")
        
        return True
    
    def _pack_v3_v4(self, output_path: str, kernel: bytes, ramdisk: bytes,
                    cmdline: str, os_version: int, header_version: int,
                    page_size: int) -> bool:
        """Pack v3/v4 boot image."""
        
        # v3/v4 header is always 4096 bytes, page_size is always 4096
        page_size = 4096
        header = bytearray(4096)
        
        # Magic
        header[0:8] = self.BOOT_MAGIC
        
        # Kernel size
        struct.pack_into('<I', header, 8, len(kernel))
        
        # Ramdisk size
        struct.pack_into('<I', header, 12, len(ramdisk))
        
        # OS version
        struct.pack_into('<I', header, 16, os_version)
        
        # Header size
        struct.pack_into('<I', header, 20, 4096)
        
        # Reserved (4 words)
        
        # Header version
        struct.pack_into('<I', header, 40, header_version)
        
        # Cmdline (1536 bytes at offset 44)
        cmdline_bytes = cmdline.encode('utf-8')[:1536]
        header[44:44+len(cmdline_bytes)] = cmdline_bytes
        
        if header_version == 4:
            # v4 adds signature size at offset 1580
            struct.pack_into('<I', header, 1580, 0)  # No signature for now
        
        # Write output
        with open(output_path, 'wb') as f:
            # Header
            f.write(bytes(header))
            
            # Kernel
            f.write(self._pad_to_page(kernel, page_size))
            
            # Ramdisk
            if ramdisk:
                f.write(self._pad_to_page(ramdisk, page_size))
        
        logger.info(f"Packed boot image v{header_version}: {output_path}")
        logger.info(f"  Kernel: {len(kernel)} bytes")
        logger.info(f"  Ramdisk: {len(ramdisk)} bytes")
        
        return True
    
    def pack_vendor_boot(self, output_path: str,
                         ramdisk: Optional[str] = None,
                         dtb: Optional[str] = None,
                         vendor_cmdline: str = "",
                         base_addr: int = 0x00000000,
                         page_size: int = 4096,
                         kernel_addr: int = 0x00008000,
                         ramdisk_addr: int = 0x01000000,
                         dtb_addr: int = 0x01F00000,
                         tags_addr: int = 0x00000100,
                         board_name: str = "",
                         header_version: int = 3,
                         ramdisk_fragments: Optional[list[str]] = None) -> bool:
        """Pack a vendor_boot image.
        
        Args:
            output_path: Output vendor_boot.img path
            ramdisk: Path to vendor ramdisk
            dtb: Path to DTB
            vendor_cmdline: Vendor kernel cmdline
            header_version: 3 or 4
            ramdisk_fragments: List of ramdisk fragment paths (v4)
            
        Returns:
            True if successful
        """
        try:
            logger.info(f"Packing vendor_boot image v{header_version}...")
            
            ramdisk_data = self._read_file(ramdisk) if ramdisk else b''
            dtb_data = self._read_file(dtb) if dtb else b''
            
            # Read ramdisk fragments (v4)
            fragments_data = []
            if header_version == 4 and ramdisk_fragments:
                for frag_path in ramdisk_fragments:
                    fragments_data.append(self._read_file(frag_path))
            
            # Build header
            header_size = 2112 if header_version == 3 else 2128
            header = bytearray(header_size)
            
            # Magic
            header[0:8] = self.VENDOR_BOOT_MAGIC
            
            # Header version
            struct.pack_into('<I', header, 8, header_version)
            
            # Page size
            struct.pack_into('<I', header, 12, page_size)
            
            # Addresses
            struct.pack_into('<I', header, 16, kernel_addr)
            struct.pack_into('<I', header, 20, ramdisk_addr)
            
            # Ramdisk size
            struct.pack_into('<I', header, 24, len(ramdisk_data))
            
            # Cmdline (2048 bytes at offset 28)
            cmdline_bytes = vendor_cmdline.encode('utf-8')[:2048]
            header[28:28+len(cmdline_bytes)] = cmdline_bytes
            
            # Tags addr
            struct.pack_into('<I', header, 2076, tags_addr)
            
            # Board name (16 bytes at offset 2080)
            board_bytes = board_name.encode('utf-8')[:16]
            header[2080:2080+len(board_bytes)] = board_bytes
            
            # Header size
            struct.pack_into('<I', header, 2096, header_size)
            
            # DTB size
            struct.pack_into('<I', header, 2100, len(dtb_data))
            
            # DTB addr
            struct.pack_into('<Q', header, 2104, dtb_addr)
            
            if header_version == 4:
                # v4: vendor ramdisk table
                total_frag_size = sum(len(f) for f in fragments_data)
                struct.pack_into('<I', header, 2112, total_frag_size)
                struct.pack_into('<I', header, 2116, len(fragments_data))  # entry count
                struct.pack_into('<I', header, 2120, 16)  # entry size
                # bootconfig size at 2124
            
            # Write output
            with open(output_path, 'wb') as f:
                # Header (padded)
                f.write(self._pad_to_page(bytes(header), page_size))
                
                # Ramdisk
                if ramdisk_data:
                    f.write(self._pad_to_page(ramdisk_data, page_size))
                
                # DTB
                if dtb_data:
                    f.write(self._pad_to_page(dtb_data, page_size))
                
                # Ramdisk fragments (v4)
                for frag in fragments_data:
                    f.write(self._pad_to_page(frag, page_size))
            
            logger.info(f"Packed vendor_boot v{header_version}: {output_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to pack vendor_boot: {e}")
            return False


class SparseImageCreator:
    """Create Android sparse images from raw images.
    
    Sparse format is used for faster flashing by skipping zero blocks.
    """
    
    SPARSE_MAGIC = 0xED26FF3A
    CHUNK_TYPE_RAW = 0xCAC1
    CHUNK_TYPE_FILL = 0xCAC2
    CHUNK_TYPE_DONT_CARE = 0xCAC3
    CHUNK_TYPE_CRC32 = 0xCAC4
    
    SPARSE_HEADER_SIZE = 28
    CHUNK_HEADER_SIZE = 12
    
    def __init__(self, block_size: int = 4096, progress_callback: Optional[Callable] = None):
        self.block_size = block_size
        self.progress_callback = progress_callback
    
    def convert(self, input_path: str, output_path: str, 
                max_chunk_size: int = 256 * 1024 * 1024) -> bool:
        """Convert a raw image to sparse format.
        
        Args:
            input_path: Path to raw image
            output_path: Path for sparse output
            max_chunk_size: Maximum size of data chunks
            
        Returns:
            True if successful
        """
        try:
            input_size = os.path.getsize(input_path)
            total_blocks = (input_size + self.block_size - 1) // self.block_size
            
            logger.info(f"Converting to sparse: {input_path}")
            logger.info(f"  Input size: {input_size / (1024*1024):.2f} MB")
            logger.info(f"  Block size: {self.block_size}")
            logger.info(f"  Total blocks: {total_blocks}")
            
            # First pass: analyze blocks
            chunks = self._analyze_blocks(input_path, total_blocks)
            
            logger.info(f"  Chunks identified: {len(chunks)}")
            
            # Second pass: write sparse image
            self._write_sparse(input_path, output_path, chunks, total_blocks)
            
            output_size = os.path.getsize(output_path)
            ratio = (1 - output_size / input_size) * 100 if input_size > 0 else 0
            logger.info(f"  Output size: {output_size / (1024*1024):.2f} MB ({ratio:.1f}% reduction)")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to create sparse image: {e}")
            return False
    
    def _analyze_blocks(self, input_path: str, total_blocks: int) -> list[dict]:
        """Analyze blocks and identify chunk boundaries."""
        chunks = []
        zero_block = b'\x00' * self.block_size
        
        with open(input_path, 'rb') as f:
            current_chunk = None
            processed = 0
            
            for block_num in range(total_blocks):
                block = f.read(self.block_size)
                if len(block) < self.block_size:
                    block = block + b'\x00' * (self.block_size - len(block))
                
                # Check if block is all zeros
                is_zero = (block == zero_block)
                
                # Check if block is a fill pattern (all same 4-byte value)
                is_fill = False
                fill_value = 0
                if not is_zero and len(set(block[i:i+4] for i in range(0, len(block), 4))) == 1:
                    is_fill = True
                    fill_value = struct.unpack('<I', block[:4])[0]
                
                if is_zero:
                    chunk_type = 'dont_care'
                elif is_fill:
                    chunk_type = 'fill'
                else:
                    chunk_type = 'raw'
                
                # Continue or start new chunk
                if current_chunk is None:
                    current_chunk = {
                        'type': chunk_type,
                        'start_block': block_num,
                        'block_count': 1,
                        'fill_value': fill_value if is_fill else 0
                    }
                elif (current_chunk['type'] == chunk_type and 
                      (chunk_type != 'fill' or current_chunk['fill_value'] == fill_value)):
                    current_chunk['block_count'] += 1
                else:
                    chunks.append(current_chunk)
                    current_chunk = {
                        'type': chunk_type,
                        'start_block': block_num,
                        'block_count': 1,
                        'fill_value': fill_value if is_fill else 0
                    }
                
                processed += 1
                if self.progress_callback and processed % 1000 == 0:
                    self.progress_callback(processed, total_blocks, "Analyzing blocks...")
            
            if current_chunk:
                chunks.append(current_chunk)
        
        return chunks
    
    def _write_sparse(self, input_path: str, output_path: str, 
                      chunks: list[dict], total_blocks: int):
        """Write sparse image from chunk analysis."""
        
        with open(output_path, 'wb') as out_f:
            # Write sparse header
            header = struct.pack('<IHHHHIIII',
                self.SPARSE_MAGIC,  # magic
                1, 0,  # version major, minor
                self.SPARSE_HEADER_SIZE,  # file_hdr_sz
                self.CHUNK_HEADER_SIZE,  # chunk_hdr_sz
                self.block_size,  # blk_sz
                total_blocks,  # total_blks
                len(chunks),  # total_chunks
                0  # image_checksum (not calculated)
            )
            out_f.write(header)
            
            # Write chunks
            with open(input_path, 'rb') as in_f:
                for i, chunk in enumerate(chunks):
                    if chunk['type'] == 'raw':
                        self._write_raw_chunk(in_f, out_f, chunk)
                    elif chunk['type'] == 'fill':
                        self._write_fill_chunk(out_f, chunk)
                    elif chunk['type'] == 'dont_care':
                        self._write_dont_care_chunk(out_f, chunk)
                    
                    if self.progress_callback and i % 100 == 0:
                        self.progress_callback(i, len(chunks), "Writing sparse image...")
    
    def _write_raw_chunk(self, in_f: BinaryIO, out_f: BinaryIO, chunk: dict):
        """Write a raw data chunk."""
        data_size = chunk['block_count'] * self.block_size
        
        # Chunk header
        header = struct.pack('<HHII',
            self.CHUNK_TYPE_RAW,
            0,  # reserved
            chunk['block_count'],
            self.CHUNK_HEADER_SIZE + data_size
        )
        out_f.write(header)
        
        # Data
        in_f.seek(chunk['start_block'] * self.block_size)
        remaining = data_size
        while remaining > 0:
            read_size = min(remaining, 1024 * 1024)  # 1MB chunks
            data = in_f.read(read_size)
            out_f.write(data)
            remaining -= len(data)
    
    def _write_fill_chunk(self, out_f: BinaryIO, chunk: dict):
        """Write a fill chunk."""
        # Chunk header
        header = struct.pack('<HHII',
            self.CHUNK_TYPE_FILL,
            0,  # reserved
            chunk['block_count'],
            self.CHUNK_HEADER_SIZE + 4
        )
        out_f.write(header)
        
        # Fill value (4 bytes)
        out_f.write(struct.pack('<I', chunk['fill_value']))
    
    def _write_dont_care_chunk(self, out_f: BinaryIO, chunk: dict):
        """Write a don't care (skip) chunk."""
        # Chunk header
        header = struct.pack('<HHII',
            self.CHUNK_TYPE_DONT_CARE,
            0,  # reserved
            chunk['block_count'],
            self.CHUNK_HEADER_SIZE
        )
        out_f.write(header)


class VbmetaCreator:
    """Create vbmeta images from scratch or from descriptor configuration.
    
    Useful for:
    - Creating custom vbmeta for modified partitions
    - Building vbmeta for custom ROMs
    """
    
    def __init__(self, signer: Optional['AvbSigner'] = None):
        self.signer = signer
    
    def create_empty_vbmeta(self, output_path: str, 
                            disable_verity: bool = True,
                            disable_verification: bool = True,
                            rollback_index: int = 0,
                            release_string: str = "avbtool 1.2.0") -> bool:
        """Create an empty/disabled vbmeta image.
        
        This creates a minimal vbmeta that effectively disables AVB.
        Useful for custom ROMs that don't need verification.
        
        Args:
            output_path: Output vbmeta.img path
            disable_verity: Set HASHTREE_DISABLED flag
            disable_verification: Set VERIFICATION_DISABLED flag
            rollback_index: Rollback index value
            release_string: Release string embedded in header
            
        Returns:
            True if successful
        """
        try:
            logger.info("Creating empty vbmeta image...")
            
            # Calculate flags
            flags = 0
            if disable_verity:
                flags |= 0x01  # AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED
            if disable_verification:
                flags |= 0x02  # AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED
            
            # Determine algorithm
            if self.signer and self.signer.private_key:
                algorithm_id = self.signer.get_algorithm_for_key_size()
                pubkey_blob = self.signer.get_avb_public_key_blob()
            else:
                algorithm_id = 0  # ALG_NONE
                pubkey_blob = b''
            
            # Header is 256 bytes
            header = bytearray(256)
            
            # Magic
            header[0:4] = AVB_MAGIC
            
            # Version (1.2)
            struct.pack_into('>I', header, 4, 1)  # major
            struct.pack_into('>I', header, 8, 2)  # minor
            
            # For unsigned/disabled vbmeta, we have no auth block or aux block
            auth_block_size = 0
            aux_block_size = 0
            
            if algorithm_id != 0:
                # Calculate sizes for signed vbmeta
                alg_info = AvbSigner.ALGORITHM_INFO[algorithm_id]
                hash_size = alg_info['hash_size']
                sig_size = alg_info['sig_size']
                
                # Authentication block layout
                hash_offset = 0
                sig_offset = ((hash_size + 7) // 8) * 8
                pubkey_offset = sig_offset + ((sig_size + 7) // 8) * 8
                auth_block_size = pubkey_offset + ((len(pubkey_blob) + 7) // 8) * 8
            
            struct.pack_into('>Q', header, 12, auth_block_size)  # auth_block_size
            struct.pack_into('>Q', header, 20, aux_block_size)   # aux_block_size
            
            # Algorithm
            struct.pack_into('>I', header, 28, algorithm_id)
            
            if algorithm_id != 0:
                # Hash/sig/pubkey offsets
                struct.pack_into('>Q', header, 32, hash_offset)
                struct.pack_into('>Q', header, 40, hash_size)
                struct.pack_into('>Q', header, 48, sig_offset)
                struct.pack_into('>Q', header, 56, sig_size)
                struct.pack_into('>Q', header, 64, pubkey_offset)
                struct.pack_into('>Q', header, 72, len(pubkey_blob))
            
            # Rollback index
            struct.pack_into('>Q', header, 112, rollback_index)
            
            # Flags
            struct.pack_into('>I', header, 120, flags)
            
            # Rollback index location
            struct.pack_into('>I', header, 124, 0)
            
            # Release string (47 bytes + null at offset 128)
            release_bytes = release_string.encode('utf-8')[:47]
            header[128:128+len(release_bytes)] = release_bytes
            
            # Build authentication block if signing
            auth_block = b''
            if algorithm_id != 0 and self.signer:
                # Compute hash over header (+ aux block, but it's empty)
                data_to_hash = bytes(header)
                hash_digest = self.signer.compute_hash(data_to_hash, algorithm_id)
                signature = self.signer.sign_data(data_to_hash, algorithm_id)
                
                auth_block = bytearray(auth_block_size)
                auth_block[hash_offset:hash_offset+hash_size] = hash_digest
                auth_block[sig_offset:sig_offset+sig_size] = signature
                auth_block[pubkey_offset:pubkey_offset+len(pubkey_blob)] = pubkey_blob
            
            # Write output (pad to 4KB or 64KB for flashing)
            min_size = 4096
            total_size = 256 + auth_block_size + aux_block_size
            if total_size < min_size:
                padding = min_size - total_size
            else:
                padding = (4096 - (total_size % 4096)) % 4096
            
            with open(output_path, 'wb') as f:
                f.write(bytes(header))
                if auth_block:
                    f.write(bytes(auth_block))
                f.write(b'\x00' * padding)
            
            output_size = os.path.getsize(output_path)
            logger.info(f"Created vbmeta: {output_path}")
            logger.info(f"  Size: {output_size} bytes")
            logger.info(f"  Flags: 0x{flags:08X}")
            logger.info(f"  Algorithm: {algorithm_id} ({'signed' if algorithm_id else 'unsigned'})")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to create vbmeta: {e}")
            return False


class RamdiskPacker:
    """Create ramdisk images from directories.
    
    Supports:
    - cpio newc format (standard Android ramdisk)
    - gzip, lz4 compression
    """
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        self.progress_callback = progress_callback
    
    def pack(self, input_dir: str, output_path: str, 
             compression: str = 'gzip') -> bool:
        """Pack a directory into a ramdisk image.
        
        Args:
            input_dir: Directory containing ramdisk contents
            output_path: Output ramdisk path
            compression: 'gzip', 'lz4', or 'none'
            
        Returns:
            True if successful
        """
        try:
            logger.info(f"Packing ramdisk from: {input_dir}")
            
            # Create cpio archive
            cpio_data = self._create_cpio(input_dir)
            
            if not cpio_data:
                logger.error("Failed to create cpio archive")
                return False
            
            logger.info(f"  CPIO size: {len(cpio_data)} bytes")
            
            # Compress
            if compression == 'gzip':
                compressed = gzip.compress(cpio_data)
            elif compression == 'lz4':
                try:
                    import lz4.frame  # type: ignore
                    compressed = lz4.frame.compress(cpio_data)
                except ImportError:
                    logger.warning("lz4 not available, using gzip")
                    compressed = gzip.compress(cpio_data)
            else:
                compressed = cpio_data
            
            # Write output
            with open(output_path, 'wb') as f:
                f.write(compressed)
            
            logger.info(f"  Compressed size: {len(compressed)} bytes")
            logger.info(f"  Output: {output_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to pack ramdisk: {e}")
            return False
    
    def _create_cpio(self, input_dir: str) -> bytes:
        """Create a cpio newc format archive."""
        output = io.BytesIO()
        ino = 0
        input_path = Path(input_dir)
        
        # Collect all files and directories
        entries = []
        for path in sorted(input_path.rglob('*')):
            rel_path = path.relative_to(input_path)
            entries.append((str(rel_path), path))
        
        # Also add directories
        for path in sorted(input_path.rglob('*')):
            if path.is_dir():
                rel_path = path.relative_to(input_path)
                # Already added in rglob
        
        # Add root directory entries
        dirs_added = set()
        full_entries = []
        for rel_str, path in entries:
            # Add parent directories first
            parts = Path(rel_str).parts
            for i in range(len(parts) - 1):
                dir_path = '/'.join(parts[:i+1])
                if dir_path not in dirs_added:
                    dirs_added.add(dir_path)
                    dir_full = input_path / dir_path
                    if dir_full.is_dir():
                        full_entries.append((dir_path, dir_full))
            full_entries.append((rel_str, path))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_entries = []
        for rel_str, path in full_entries:
            if rel_str not in seen:
                seen.add(rel_str)
                unique_entries.append((rel_str, path))
        
        for rel_str, path in unique_entries:
            ino += 1
            self._write_cpio_entry(output, rel_str, path, ino)
            
            if self.progress_callback:
                self.progress_callback(ino, len(unique_entries), f"Packing: {rel_str}")
        
        # Write trailer
        self._write_cpio_trailer(output)
        
        return output.getvalue()
    
    def _write_cpio_entry(self, output: io.BytesIO, name: str, path: Path, ino: int):
        """Write a single cpio newc entry."""
        try:
            stat = path.stat()
            mode = stat.st_mode
            uid = 0  # root
            gid = 0  # root
            nlink = 1
            mtime = int(stat.st_mtime)
            
            if path.is_file():
                with open(path, 'rb') as f:
                    data = f.read()
                filesize = len(data)
            elif path.is_symlink():
                target = os.readlink(path)
                data = target.encode('utf-8')
                filesize = len(data)
                mode = (mode & ~0o170000) | 0o120000  # Set symlink mode
            elif path.is_dir():
                data = b''
                filesize = 0
                mode = (mode & ~0o170000) | 0o040000  # Set directory mode
            else:
                data = b''
                filesize = 0
        except Exception:
            data = b''
            filesize = 0
            mode = 0o100644
            uid = gid = 0
            nlink = 1
            mtime = 0
        
        # newc format header
        name_bytes = name.encode('utf-8') + b'\x00'
        namesize = len(name_bytes)
        
        header = f"070701{ino:08X}{mode:08X}{uid:08X}{gid:08X}{nlink:08X}{mtime:08X}{filesize:08X}00000000000000000000000000000000{namesize:08X}00000000"
        output.write(header.encode('ascii'))
        output.write(name_bytes)
        
        # Pad to 4-byte boundary
        pad = (4 - ((110 + namesize) % 4)) % 4
        output.write(b'\x00' * pad)
        
        # Write data
        if data:
            output.write(data)
            # Pad data to 4-byte boundary
            pad = (4 - (filesize % 4)) % 4
            output.write(b'\x00' * pad)
    
    def _write_cpio_trailer(self, output: io.BytesIO):
        """Write cpio trailer entry."""
        name = b'TRAILER!!!\x00'
        namesize = len(name)
        header = f"070701{'0'*8}{'0'*8}{'0'*8}{'0'*8}{'0'*8}{'0'*8}{'0'*8}00000000000000000000000000000000{namesize:08X}00000000"
        output.write(header.encode('ascii'))
        output.write(name)
        # Pad to 512-byte boundary for some tools
        current = output.tell()
        pad = (512 - (current % 512)) % 512
        output.write(b'\x00' * pad)


# =============================================================================
# RECOVERY PORTER / MODIFIER
# =============================================================================
#
# EDUCATIONAL NOTES: Understanding Android Recovery Partitions
# ============================================================
#
# Recovery is a minimal Linux environment for system maintenance:
# - Flashing OTA updates
# - Factory reset (wipe data)
# - Wipe cache
# - ADB sideload
# - Custom recoveries add: root, backups, custom ROMs
#
# RECOVERY IMAGE STRUCTURE (same as boot.img):
# ┌──────────────────────────────────────┐
# │ Header (v0-v4)                       │
# │   - magic: "ANDROID!"                │
# │   - kernel_size, kernel_addr         │
# │   - ramdisk_size, ramdisk_addr       │
# │   - cmdline, page_size, etc          │
# ├──────────────────────────────────────┤
# │ Kernel (zImage/Image.gz)             │
# │   - Linux kernel for recovery mode   │
# │   - Often same as boot kernel        │
# ├──────────────────────────────────────┤
# │ Ramdisk (cpio.gz)                    │
# │   - Root filesystem                  │
# │   - Contains recovery binary         │
# │   - init scripts, fstab              │
# ├──────────────────────────────────────┤
# │ DTB (optional, v2+)                  │
# │   - Device Tree Blob                 │
# │   - Hardware description             │
# └──────────────────────────────────────┘
#
# RAMDISK STRUCTURE (what's inside the cpio archive):
# /
# ├── init                    # First process (PID 1)
# ├── init.rc                 # Init script - starts services
# ├── default.prop            # System properties
# ├── fstab.*                 # Partition mount table (CRITICAL!)
# ├── sbin/
# │   ├── recovery            # Main recovery binary (TWRP/OrangeFox)
# │   ├── adbd                # ADB daemon
# │   └── ...                 # Other tools
# ├── res/                    # Resources (fonts, images)
# ├── etc/                    # Config files
# │   └── recovery.fstab      # Recovery-specific fstab
# └── system/                 # Minimal system files
#
# FSTAB FORMAT (Critical for porting):
# <mount_point> <type> <device> <device2> <flags>
# Example:
# /system      ext4  /dev/block/bootdevice/by-name/system  flags=...
# /data        ext4  /dev/block/bootdevice/by-name/userdata flags=...
# /boot        emmc  /dev/block/bootdevice/by-name/boot
#
# COMMON RECOVERY FRAMEWORKS:
# - AOSP Recovery: Basic, stock Android
# - TWRP: Touch-based, most popular custom recovery
# - OrangeFox: TWRP fork with extra features
# - SHRP: Skyhawk Recovery Project
# - PBRP: PitchBlack Recovery
# - LineageOS Recovery: Clean, simple
#
# PORTING RECOVERY TO A NEW DEVICE:
# 1. Find recovery from similar device (same SoC, similar hardware)
# 2. Extract kernel and DTB from TARGET device's boot.img
# 3. Modify fstab to match TARGET device's partition layout
# 4. Update init scripts if needed
# 5. Repack with target's kernel + modified ramdisk
#
# =============================================================================

class RecoveryPorter:
    """Port and modify Android recovery images.
    
    This class helps with:
    - Extracting recovery components
    - Analyzing ramdisk contents
    - Modifying fstab for device porting
    - Swapping kernels between devices
    - Repacking modified recovery
    
    Common use cases:
    - Port TWRP from similar device
    - Update kernel in existing recovery
    - Modify partition mappings
    - Add tools/scripts to recovery
    """
    
    # Known recovery signatures
    RECOVERY_SIGNATURES = {
        b'TWRP': 'Team Win Recovery Project',
        b'OrangeFox': 'OrangeFox Recovery',
        b'SHRP': 'Skyhawk Recovery Project',
        b'PBRP': 'PitchBlack Recovery',
        b'LineageOS': 'LineageOS Recovery',
    }
    
    # Critical fstab mount points
    CRITICAL_MOUNTS = [
        '/system', '/system_root', '/vendor', '/product',
        '/data', '/cache', '/boot', '/recovery',
        '/misc', '/persist', '/metadata'
    ]
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        self.progress_callback = progress_callback
        self.recovery_type = None
        self.ramdisk_contents = {}
        self.fstab_entries = []
        self.kernel_info = {}
        self.header_version = 0
    
    def analyze(self, recovery_path: str) -> dict:
        """Analyze a recovery image and return detailed information.
        
        Args:
            recovery_path: Path to recovery.img
            
        Returns:
            Dict with recovery analysis
        """
        info = {
            'path': recovery_path,
            'size': os.path.getsize(recovery_path),
            'format': None,
            'recovery_type': 'Unknown',
            'header_version': 0,
            'kernel_size': 0,
            'ramdisk_size': 0,
            'dtb_size': 0,
            'cmdline': '',
            'fstab': [],
            'ramdisk_files': [],
            'warnings': [],
            'can_port': True,
        }
        
        try:
            with open(recovery_path, 'rb') as f:
                magic = f.read(8)
                
                if magic == b'ANDROID!':
                    info['format'] = 'boot'
                    self._analyze_boot_format(f, info)
                elif magic == b'VNDRBOOT':
                    info['format'] = 'vendor_boot'
                    info['warnings'].append('vendor_boot format - unusual for recovery')
                else:
                    info['format'] = 'unknown'
                    info['can_port'] = False
                    info['warnings'].append(f'Unknown format: {magic[:8]}')
                    return info
            
            # Extract and analyze ramdisk
            self._analyze_ramdisk(recovery_path, info)
            
        except Exception as e:
            info['warnings'].append(f'Analysis error: {e}')
            info['can_port'] = False
        
        return info
    
    def _analyze_boot_format(self, f: BinaryIO, info: dict):
        """Parse boot image header."""
        f.seek(0)
        header = f.read(1648)
        
        # Parse header
        kernel_size = struct.unpack('<I', header[8:12])[0]
        ramdisk_size = struct.unpack('<I', header[16:20])[0]
        second_size = struct.unpack('<I', header[24:28])[0]
        page_size = struct.unpack('<I', header[36:40])[0]
        header_version = struct.unpack('<I', header[40:44])[0]
        
        # Cmdline
        cmdline_end = header[64:64+512].find(b'\x00')
        cmdline = header[64:64+cmdline_end].decode('utf-8', errors='ignore') if cmdline_end > 0 else ''
        
        info['header_version'] = header_version
        info['kernel_size'] = kernel_size
        info['ramdisk_size'] = ramdisk_size
        info['page_size'] = page_size
        info['cmdline'] = cmdline
        self.header_version = header_version
        
        # DTB size (v2+)
        if header_version >= 2 and len(header) >= 1648:
            dtb_size = struct.unpack('<I', header[1644:1648])[0]
            info['dtb_size'] = dtb_size
        
        # Board name
        board_name = header[48:64].rstrip(b'\x00').decode('utf-8', errors='ignore')
        if board_name:
            info['board_name'] = board_name
    
    def _analyze_ramdisk(self, recovery_path: str, info: dict):
        """Extract and analyze ramdisk contents."""
        import tempfile
        import subprocess
        
        # Use BootImageExtractor to get ramdisk
        extractor = BootImageExtractor()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                extracted = extractor.extract(recovery_path, tmpdir)
                
                ramdisk_path = extracted.get('ramdisk')
                if not ramdisk_path:
                    info['warnings'].append('No ramdisk found in image')
                    return
                
                # Detect compression and get raw cpio
                ramdisk_dir = Path(tmpdir) / 'ramdisk_contents'
                ramdisk_dir.mkdir()
                
                cpio_data = self._decompress_ramdisk(ramdisk_path)
                if cpio_data:
                    self._parse_cpio(cpio_data, ramdisk_dir, info)
                    self._detect_recovery_type(ramdisk_dir, info)
                    self._parse_fstab(ramdisk_dir, info)
                
            except Exception as e:
                info['warnings'].append(f'Ramdisk analysis error: {e}')
    
    def _decompress_ramdisk(self, ramdisk_path: str) -> Optional[bytes]:
        """Decompress ramdisk and return raw cpio data."""
        with open(ramdisk_path, 'rb') as f:
            data = f.read()
        
        # Detect compression
        if data[:2] == b'\x1f\x8b':  # gzip
            return gzip.decompress(data)
        elif data[:4] == b'\x04\x22\x4d\x18':  # lz4
            try:
                import lz4.frame  # type: ignore
                return lz4.frame.decompress(data)
            except ImportError:
                # Try legacy lz4
                try:
                    import lz4.block  # type: ignore
                    return lz4.block.decompress(data)
                except:
                    return None
        elif data[:6] == b'\xfd7zXZ\x00':  # xz
            return lzma.decompress(data)
        elif data[:2] == b'\x5d\x00':  # lzma
            return lzma.decompress(data)
        elif data[:6] == b'070701' or data[:6] == b'070702':  # uncompressed cpio
            return data
        else:
            return data  # Try as-is
    
    def _parse_cpio(self, cpio_data: bytes, output_dir: Path, info: dict):
        """Parse cpio archive and list contents."""
        offset = 0
        files = []
        
        while offset < len(cpio_data) - 110:
            # Check for newc format
            if cpio_data[offset:offset+6] != b'070701':
                break
            
            # Parse header
            header = cpio_data[offset:offset+110].decode('ascii')
            namesize = int(header[94:102], 16)
            filesize = int(header[54:62], 16)
            mode = int(header[14:22], 16)
            
            # Get filename
            name_start = offset + 110
            name_end = name_start + namesize - 1  # Exclude null terminator
            name = cpio_data[name_start:name_end].decode('utf-8', errors='ignore')
            
            if name == 'TRAILER!!!':
                break
            
            # Determine type
            file_type = 'file'
            if (mode & 0o170000) == 0o040000:
                file_type = 'dir'
            elif (mode & 0o170000) == 0o120000:
                file_type = 'symlink'
            
            files.append({
                'name': name,
                'size': filesize,
                'mode': mode,
                'type': file_type
            })
            
            # Calculate next entry offset
            header_pad = (4 - ((110 + namesize) % 4)) % 4
            data_pad = (4 - (filesize % 4)) % 4 if filesize > 0 else 0
            offset = name_start + namesize + header_pad + filesize + data_pad
        
        info['ramdisk_files'] = files
        self.ramdisk_contents = {f['name']: f for f in files}
    
    def _detect_recovery_type(self, ramdisk_dir: Path, info: dict):
        """Detect which recovery framework this is."""
        # Check for known binaries and signatures
        recovery_type = 'AOSP/Stock'
        
        # Common locations to check
        checks = [
            ('sbin/recovery', None),
            ('system/bin/recovery', None),
            ('res/images', 'Custom Recovery'),
        ]
        
        # Check ramdisk file list for clues
        files_str = ' '.join(f['name'] for f in info.get('ramdisk_files', []))
        
        if 'twres' in files_str or 'TWRP' in files_str:
            recovery_type = 'TWRP'
        elif 'Fox' in files_str or 'orangefox' in files_str.lower():
            recovery_type = 'OrangeFox'
        elif 'shrp' in files_str.lower():
            recovery_type = 'SHRP'
        elif 'pbrp' in files_str.lower():
            recovery_type = 'PitchBlack'
        elif 'lineage' in files_str.lower():
            recovery_type = 'LineageOS'
        
        info['recovery_type'] = recovery_type
        self.recovery_type = recovery_type
    
    def _parse_fstab(self, ramdisk_dir: Path, info: dict):
        """Find and parse fstab files."""
        fstab_entries = []
        
        # Look for fstab in ramdisk file list
        fstab_files = [f['name'] for f in info.get('ramdisk_files', []) 
                       if 'fstab' in f['name'].lower() or f['name'].endswith('.fstab')]
        
        info['fstab_files'] = fstab_files
        
        # Note: Full fstab parsing would require extracting the actual files
        # For now, we just identify which fstab files exist
        if not fstab_files:
            info['warnings'].append('No fstab found - may need manual configuration')
    
    def extract_components(self, recovery_path: str, output_dir: str) -> dict:
        """Extract all recovery components for modification.
        
        Args:
            recovery_path: Path to recovery.img
            output_dir: Where to extract components
            
        Returns:
            Dict with paths to extracted components
        """
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        
        result = {
            'kernel': None,
            'ramdisk': None,
            'ramdisk_dir': None,
            'dtb': None,
            'cmdline': '',
            'header_version': 0,
        }
        
        # Extract using BootImageExtractor
        extractor = BootImageExtractor()
        extracted = extractor.extract(recovery_path, str(output))
        
        result['kernel'] = extracted.get('kernel')
        result['ramdisk'] = extracted.get('ramdisk')
        result['dtb'] = extracted.get('dtb')
        result['header_version'] = extracted.get('header_version', 0)
        result['cmdline'] = extracted.get('cmdline', '')
        
        # Extract ramdisk contents
        if result['ramdisk']:
            ramdisk_dir = output / 'ramdisk'
            ramdisk_dir.mkdir(exist_ok=True)
            
            cpio_data = self._decompress_ramdisk(result['ramdisk'])
            if cpio_data:
                self._extract_cpio(cpio_data, ramdisk_dir)
                result['ramdisk_dir'] = str(ramdisk_dir)
        
        return result
    
    def _extract_cpio(self, cpio_data: bytes, output_dir: Path):
        """Extract cpio archive to directory."""
        offset = 0
        
        while offset < len(cpio_data) - 110:
            if cpio_data[offset:offset+6] != b'070701':
                break
            
            # Parse header
            header = cpio_data[offset:offset+110].decode('ascii')
            namesize = int(header[94:102], 16)
            filesize = int(header[54:62], 16)
            mode = int(header[14:22], 16)
            
            # Get filename
            name_start = offset + 110
            name_end = name_start + namesize - 1
            name = cpio_data[name_start:name_end].decode('utf-8', errors='ignore')
            
            if name == 'TRAILER!!!':
                break
            
            # Calculate data position
            header_pad = (4 - ((110 + namesize) % 4)) % 4
            data_start = name_start + namesize + header_pad
            data_end = data_start + filesize
            
            # Create file/directory
            out_path = output_dir / name
            
            if (mode & 0o170000) == 0o040000:  # Directory
                out_path.mkdir(parents=True, exist_ok=True)
            elif (mode & 0o170000) == 0o120000:  # Symlink
                out_path.parent.mkdir(parents=True, exist_ok=True)
                link_target = cpio_data[data_start:data_end].decode('utf-8', errors='ignore')
                # On Windows, just save as text file
                if sys.platform == 'win32':
                    out_path.write_text(f'SYMLINK -> {link_target}')
                else:
                    try:
                        out_path.symlink_to(link_target)
                    except:
                        out_path.write_text(f'SYMLINK -> {link_target}')
            else:  # Regular file
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(cpio_data[data_start:data_end])
                try:
                    out_path.chmod(mode & 0o777)
                except:
                    pass
            
            # Next entry
            data_pad = (4 - (filesize % 4)) % 4 if filesize > 0 else 0
            offset = data_end + data_pad
    
    def repack(self, components: dict, output_path: str, 
               header_version: Optional[int] = None) -> bool:
        """Repack modified components into recovery image.
        
        Args:
            components: Dict with kernel, ramdisk_dir, dtb, cmdline
            output_path: Where to save new recovery.img
            header_version: Override header version
            
        Returns:
            True if successful
        """
        try:
            kernel = components.get('kernel')
            ramdisk_dir = components.get('ramdisk_dir')
            dtb = components.get('dtb')
            cmdline = components.get('cmdline', '')
            version = header_version or components.get('header_version', 2)
            
            if not kernel:
                logger.error("Kernel is required")
                return False
            
            # Pack ramdisk if directory provided
            ramdisk_path = components.get('ramdisk')
            if ramdisk_dir and Path(ramdisk_dir).is_dir():
                import tempfile
                with tempfile.NamedTemporaryFile(suffix='.cpio.gz', delete=False) as tmp:
                    ramdisk_path = tmp.name
                
                packer = RamdiskPacker()
                if not packer.pack(ramdisk_dir, ramdisk_path, 'gzip'):
                    logger.error("Failed to pack ramdisk")
                    return False
            
            # Use BootImagePacker
            packer = BootImagePacker()
            success = packer.pack_boot_image(
                output_path,
                kernel=kernel,
                ramdisk=ramdisk_path,
                dtb=dtb if dtb and Path(dtb).exists() else None,
                cmdline=cmdline,
                header_version=version
            )
            
            if success:
                logger.info(f"Recovery image created: {output_path}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to repack recovery: {e}")
            return False
    
    @staticmethod
    def parse_fstab_file(fstab_path: str) -> list[dict]:
        """Parse a fstab file and return entries.
        
        Args:
            fstab_path: Path to fstab file
            
        Returns:
            List of fstab entries
        """
        entries = []
        
        try:
            with open(fstab_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 2:
                        entry = {
                            'mount_point': parts[0] if parts[0].startswith('/') else parts[1],
                            'type': parts[1] if parts[0].startswith('/') else parts[0],
                            'device': parts[2] if len(parts) > 2 else '',
                            'flags': ' '.join(parts[3:]) if len(parts) > 3 else '',
                            'raw': line
                        }
                        entries.append(entry)
        except Exception as e:
            logger.error(f"Failed to parse fstab: {e}")
        
        return entries
    
    @staticmethod
    def generate_fstab(entries: list[dict], output_path: str) -> bool:
        """Generate a fstab file from entries.
        
        Args:
            entries: List of fstab entry dicts
            output_path: Where to save fstab
            
        Returns:
            True if successful
        """
        try:
            with open(output_path, 'w') as f:
                f.write("# Recovery fstab - Generated by Image Anarchy\n")
                f.write("# Format: <mount_point> <type> <device> [<device2>] <flags>\n\n")
                
                for entry in entries:
                    if 'raw' in entry:
                        f.write(entry['raw'] + '\n')
                    else:
                        line = f"{entry['mount_point']}\t{entry['type']}\t{entry['device']}"
                        if entry.get('flags'):
                            line += f"\t{entry['flags']}"
                        f.write(line + '\n')
            
            return True
        except Exception as e:
            logger.error(f"Failed to write fstab: {e}")
            return False


class Ext4ImageExtractor:
    """Extract files from ext4 filesystem images."""
    
    # ext4 constants
    EXT4_SUPER_MAGIC = 0xEF53
    EXT4_S_IFMT = 0xF000
    EXT4_S_IFREG = 0x8000  # Regular file
    EXT4_S_IFDIR = 0x4000  # Directory
    EXT4_S_IFLNK = 0xA000  # Symbolic link
    
    # Extent magic
    EXT4_EXT_MAGIC = 0xF30A
    
    # Feature flags
    EXT4_FEATURE_INCOMPAT_EXTENTS = 0x0040
    EXT4_FEATURE_INCOMPAT_64BIT = 0x0080
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        self.progress_callback = progress_callback
        self.superblock = None
        self.block_size = 4096
        self.inode_size = 256
        self.inodes_per_group = 0
        self.blocks_per_group = 0
        self.desc_size = 32
        self.has_extents = False
        self.is_64bit = False
    
    def list_files(self, input_path: str) -> list[dict]:
        """List all files in an ext4 image."""
        files = []
        
        with open(input_path, 'rb') as f:
            self._read_superblock(f)
            self._list_directory(f, 2, '', files)  # Root inode is 2
        
        return files
    
    def extract(self, input_path: str, output_dir: str,
                file_list: Optional[list[str]] = None) -> dict:
        """Extract files from ext4 image."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        extracted = {}
        
        with open(input_path, 'rb') as f:
            self._read_superblock(f)
            self._extract_directory(f, 2, '', output_dir, file_list, extracted)
        
        return extracted
    
    def _read_superblock(self, f: BinaryIO):
        """Read and parse ext4 superblock."""
        f.seek(0x400)  # Superblock at offset 1024
        sb = f.read(256)
        
        # Check magic
        magic = struct.unpack('<H', sb[0x38:0x3A])[0]
        if magic != self.EXT4_SUPER_MAGIC:
            raise PayloadError(f"Invalid ext4 magic: {hex(magic)}")
        
        # Parse superblock fields
        self.inodes_count = struct.unpack('<I', sb[0x00:0x04])[0]
        self.blocks_count_lo = struct.unpack('<I', sb[0x04:0x08])[0]
        self.blocks_per_group = struct.unpack('<I', sb[0x20:0x24])[0]
        self.inodes_per_group = struct.unpack('<I', sb[0x28:0x2C])[0]
        
        log_block_size = struct.unpack('<I', sb[0x18:0x1C])[0]
        self.block_size = 1024 << log_block_size
        
        self.inode_size = struct.unpack('<H', sb[0x58:0x5A])[0]
        if self.inode_size == 0:
            self.inode_size = 128
        
        # Feature flags
        feature_incompat = struct.unpack('<I', sb[0x60:0x64])[0]
        self.has_extents = bool(feature_incompat & self.EXT4_FEATURE_INCOMPAT_EXTENTS)
        self.is_64bit = bool(feature_incompat & self.EXT4_FEATURE_INCOMPAT_64BIT)
        
        # Descriptor size for 64-bit
        if self.is_64bit:
            self.desc_size = struct.unpack('<H', sb[0xFE:0x100])[0]
            if self.desc_size == 0:
                self.desc_size = 32
        else:
            self.desc_size = 32
        
        # Group count
        self.group_count = (self.blocks_count_lo + self.blocks_per_group - 1) // self.blocks_per_group
        
        self.superblock = sb
    
    def _get_block_group_desc(self, f: BinaryIO, group: int) -> dict:
        """Get block group descriptor."""
        # Group descriptors start at block 1 (or 0 if block_size > 1024)
        if self.block_size == 1024:
            desc_block = 2
        else:
            desc_block = 1
        
        desc_offset = desc_block * self.block_size + group * self.desc_size
        f.seek(desc_offset)
        desc = f.read(self.desc_size)
        
        inode_table_lo = struct.unpack('<I', desc[0x08:0x0C])[0]
        
        if self.is_64bit and self.desc_size >= 64:
            inode_table_hi = struct.unpack('<I', desc[0x28:0x2C])[0]
            inode_table = inode_table_lo | (inode_table_hi << 32)
        else:
            inode_table = inode_table_lo
        
        return {'inode_table': inode_table}
    
    def _read_inode(self, f: BinaryIO, inode_num: int) -> dict:
        """Read an inode by number."""
        if inode_num == 0:
            return None
        
        # Calculate location
        group = (inode_num - 1) // self.inodes_per_group
        index = (inode_num - 1) % self.inodes_per_group
        
        desc = self._get_block_group_desc(f, group)
        inode_offset = desc['inode_table'] * self.block_size + index * self.inode_size
        
        f.seek(inode_offset)
        inode_data = f.read(self.inode_size)
        
        mode = struct.unpack('<H', inode_data[0x00:0x02])[0]
        size_lo = struct.unpack('<I', inode_data[0x04:0x08])[0]
        size_hi = struct.unpack('<I', inode_data[0x6C:0x70])[0] if len(inode_data) >= 0x70 else 0
        size = size_lo | (size_hi << 32)
        
        flags = struct.unpack('<I', inode_data[0x20:0x24])[0]
        
        # Block pointers or extent tree
        block_data = inode_data[0x28:0x64]  # 60 bytes for i_block
        
        return {
            'mode': mode,
            'size': size,
            'flags': flags,
            'block_data': block_data,
            'uses_extents': bool(flags & 0x80000),  # EXT4_EXTENTS_FL
        }
    
    def _read_extent_tree(self, f: BinaryIO, block_data: bytes, file_size: int) -> bytes:
        """Read file data using extent tree."""
        data = bytearray()
        
        # Parse extent header
        magic = struct.unpack('<H', block_data[0:2])[0]
        entries = struct.unpack('<H', block_data[2:4])[0]
        depth = struct.unpack('<H', block_data[6:8])[0]
        
        if magic != self.EXT4_EXT_MAGIC:
            # Fall back to reading as direct blocks
            return self._read_block_pointers(f, block_data, file_size)
        
        if depth == 0:
            # Leaf node - contains actual extents
            for i in range(entries):
                ext_offset = 12 + i * 12
                ext = block_data[ext_offset:ext_offset + 12]
                
                ee_block = struct.unpack('<I', ext[0:4])[0]  # Logical block
                ee_len = struct.unpack('<H', ext[4:6])[0]    # Length
                ee_start_hi = struct.unpack('<H', ext[6:8])[0]
                ee_start_lo = struct.unpack('<I', ext[8:12])[0]
                ee_start = ee_start_lo | (ee_start_hi << 32)
                
                # Handle uninitialized extents (high bit set in length)
                if ee_len > 32768:
                    ee_len -= 32768
                
                for blk in range(ee_len):
                    f.seek((ee_start + blk) * self.block_size)
                    data.extend(f.read(self.block_size))
        else:
            # Index node - contains pointers to lower levels
            for i in range(entries):
                idx_offset = 12 + i * 12
                idx = block_data[idx_offset:idx_offset + 12]
                
                ei_leaf_lo = struct.unpack('<I', idx[4:8])[0]
                ei_leaf_hi = struct.unpack('<H', idx[8:10])[0]
                ei_leaf = ei_leaf_lo | (ei_leaf_hi << 32)
                
                # Read the next level
                f.seek(ei_leaf * self.block_size)
                next_block = f.read(self.block_size)
                data.extend(self._read_extent_tree(f, next_block, file_size - len(data)))
        
        return bytes(data[:file_size])
    
    def _read_block_pointers(self, f: BinaryIO, block_data: bytes, file_size: int) -> bytes:
        """Read file data using traditional block pointers."""
        data = bytearray()
        blocks_needed = (file_size + self.block_size - 1) // self.block_size
        
        # Direct blocks (0-11)
        for i in range(min(12, blocks_needed)):
            block_num = struct.unpack('<I', block_data[i*4:(i+1)*4])[0]
            if block_num == 0:
                data.extend(b'\x00' * self.block_size)
            else:
                f.seek(block_num * self.block_size)
                data.extend(f.read(self.block_size))
        
        if blocks_needed <= 12:
            return bytes(data[:file_size])
        
        # Indirect block (12)
        indirect_block = struct.unpack('<I', block_data[48:52])[0]
        if indirect_block:
            data.extend(self._read_indirect(f, indirect_block, blocks_needed - 12))
        
        return bytes(data[:file_size])
    
    def _read_indirect(self, f: BinaryIO, block_num: int, max_blocks: int) -> bytes:
        """Read blocks through indirect block."""
        data = bytearray()
        ptrs_per_block = self.block_size // 4
        
        f.seek(block_num * self.block_size)
        indirect_data = f.read(self.block_size)
        
        for i in range(min(ptrs_per_block, max_blocks)):
            block = struct.unpack('<I', indirect_data[i*4:(i+1)*4])[0]
            if block == 0:
                data.extend(b'\x00' * self.block_size)
            else:
                f.seek(block * self.block_size)
                data.extend(f.read(self.block_size))
        
        return bytes(data)
    
    def _read_file_data(self, f: BinaryIO, inode: dict) -> bytes:
        """Read all data from a file inode."""
        if inode['size'] == 0:
            return b''
        
        if inode['uses_extents'] or self.has_extents:
            return self._read_extent_tree(f, inode['block_data'], inode['size'])
        else:
            return self._read_block_pointers(f, inode['block_data'], inode['size'])
    
    def _parse_directory(self, f: BinaryIO, inode: dict) -> list[dict]:
        """Parse directory entries from inode."""
        entries = []
        dir_data = self._read_file_data(f, inode)
        
        offset = 0
        while offset < len(dir_data):
            if offset + 8 > len(dir_data):
                break
            
            inode_num = struct.unpack('<I', dir_data[offset:offset+4])[0]
            rec_len = struct.unpack('<H', dir_data[offset+4:offset+6])[0]
            name_len = dir_data[offset + 6]
            file_type = dir_data[offset + 7]
            
            if rec_len == 0 or offset + rec_len > len(dir_data):
                break
            
            if inode_num != 0 and name_len > 0:
                name = dir_data[offset+8:offset+8+name_len].decode('utf-8', errors='ignore')
                entries.append({
                    'inode': inode_num,
                    'name': name,
                    'file_type': file_type,
                })
            
            offset += rec_len
        
        return entries
    
    def _list_directory(self, f: BinaryIO, inode_num: int, path: str, files: list):
        """Recursively list files in a directory."""
        inode = self._read_inode(f, inode_num)
        if not inode:
            return
        
        entries = self._parse_directory(f, inode)
        
        for entry in entries:
            if entry['name'] in ('.', '..'):
                continue
            
            full_path = f"{path}/{entry['name']}" if path else entry['name']
            
            child_inode = self._read_inode(f, entry['inode'])
            if not child_inode:
                continue
            
            mode = child_inode['mode'] & self.EXT4_S_IFMT
            
            if mode == self.EXT4_S_IFDIR:
                self._list_directory(f, entry['inode'], full_path, files)
            elif mode == self.EXT4_S_IFREG:
                files.append({
                    'name': full_path,
                    'size': child_inode['size'],
                    'type': 'file',
                    'inode': entry['inode'],
                })
            elif mode == self.EXT4_S_IFLNK:
                files.append({
                    'name': full_path,
                    'size': child_inode['size'],
                    'type': 'symlink',
                    'inode': entry['inode'],
                })
    
    def _extract_directory(self, f: BinaryIO, inode_num: int, path: str,
                           output_dir: str, file_list: Optional[list[str]], extracted: dict):
        """Recursively extract files from a directory."""
        inode = self._read_inode(f, inode_num)
        if not inode:
            return
        
        entries = self._parse_directory(f, inode)
        
        for entry in entries:
            if entry['name'] in ('.', '..'):
                continue
            
            full_path = f"{path}/{entry['name']}" if path else entry['name']
            
            child_inode = self._read_inode(f, entry['inode'])
            if not child_inode:
                continue
            
            mode = child_inode['mode'] & self.EXT4_S_IFMT
            
            if mode == self.EXT4_S_IFDIR:
                dir_path = Path(output_dir) / full_path
                dir_path.mkdir(parents=True, exist_ok=True)
                self._extract_directory(f, entry['inode'], full_path, output_dir, file_list, extracted)
            
            elif mode == self.EXT4_S_IFREG:
                if file_list is None or full_path in file_list:
                    self._extract_file(f, child_inode, full_path, output_dir, extracted)
            
            elif mode == self.EXT4_S_IFLNK:
                if file_list is None or full_path in file_list:
                    self._extract_symlink(f, child_inode, full_path, output_dir, extracted)
    
    def _extract_file(self, f: BinaryIO, inode: dict, full_path: str,
                      output_dir: str, extracted: dict):
        """Extract a regular file."""
        output_path = Path(output_dir) / full_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = self._read_file_data(f, inode)
        output_path.write_bytes(data)
        
        extracted[full_path] = str(output_path)
        logger.info(f"  Extracted: {full_path} ({inode['size']} bytes)")
    
    def _extract_symlink(self, f: BinaryIO, inode: dict, full_path: str,
                         output_dir: str, extracted: dict):
        """Extract a symbolic link."""
        output_path = Path(output_dir) / full_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # For small symlinks, target is stored inline in block pointers
        if inode['size'] <= 60:
            target = inode['block_data'][:inode['size']].decode('utf-8', errors='ignore')
        else:
            target = self._read_file_data(f, inode).decode('utf-8', errors='ignore')
        
        # Write symlink info to a text file (can't create real symlinks cross-platform)
        link_file = output_path.with_suffix(output_path.suffix + '.symlink')
        link_file.write_text(f"SYMLINK -> {target}")
        
        extracted[full_path] = str(link_file)
        logger.info(f"  Extracted symlink: {full_path} -> {target}")


class SuperImageExtractor:
    """Extract partitions from Android super (dynamic partitions) image."""
    
    LP_METADATA_GEOMETRY_MAGIC = 0x616c4467  # "gDla"
    LP_METADATA_HEADER_MAGIC = 0x414c5030   # "0PLA"
    LP_PARTITION_ATTR_READONLY = (1 << 0)
    LP_PARTITION_ATTR_SLOT_SUFFIXED = (1 << 1)
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        self.progress_callback = progress_callback
    
    def list_partitions(self, input_path: str) -> list[LpMetadataPartition]:
        """List all partitions in a super image."""
        with open(input_path, 'rb') as f:
            return self._read_metadata(f)
    
    def extract(self, input_path: str, output_dir: str, 
                partition_names: Optional[list[str]] = None) -> dict:
        """Extract partitions from super image."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        with open(input_path, 'rb') as f:
            partitions = self._read_metadata(f)
            
            if partition_names:
                partitions = [p for p in partitions if p.name in partition_names]
            
            extracted = {}
            total = len(partitions)
            
            for idx, part in enumerate(partitions):
                if part.size == 0:
                    logger.info(f"  Skipping empty partition: {part.name}")
                    continue
                
                logger.info(f"  Extracting {part.name}: {part.size / (1024*1024):.2f} MB")
                
                output_path = Path(output_dir) / f"{part.name}.img"
                
                # Calculate actual offset (sectors are 512 bytes)
                offset = part.first_sector * 512
                
                f.seek(offset)
                
                # Extract in chunks
                remaining = part.size
                chunk_size = 64 * 1024 * 1024  # 64MB chunks
                
                with open(output_path, 'wb') as f_out:
                    while remaining > 0:
                        to_read = min(chunk_size, remaining)
                        data = f.read(to_read)
                        if not data:
                            break
                        f_out.write(data)
                        remaining -= len(data)
                
                extracted[part.name] = str(output_path)
                
                if self.progress_callback:
                    self.progress_callback(idx + 1, total, f"Extracted {part.name}")
            
            return extracted
    
    def _read_metadata(self, f: BinaryIO) -> list[LpMetadataPartition]:
        """Read LP metadata and return partition list."""
        # Read geometry at offset 4096
        f.seek(4096)
        geometry = self._read_geometry(f)
        
        # Read metadata header
        f.seek(geometry['metadata_offset'])
        header = self._read_metadata_header(f)
        
        # Read partition table
        partitions = []
        
        # Seek to partitions table
        f.seek(geometry['metadata_offset'] + header['partitions_offset'])
        
        for _ in range(header['partitions_count']):
            part_data = f.read(header['partitions_entry_size'])
            if len(part_data) < 52:
                break
            
            name = part_data[:36].rstrip(b'\x00').decode('utf-8', errors='ignore')
            attrs, first_extent_idx, num_extents, group_idx = struct.unpack(
                '<IIII', part_data[36:52]
            )
            
            # Read extent info to get actual size and offset
            if num_extents > 0:
                # Save position
                pos = f.tell()
                
                # Read extent
                extent_offset = geometry['metadata_offset'] + header['extents_offset'] + \
                               first_extent_idx * header['extents_entry_size']
                f.seek(extent_offset)
                extent_data = f.read(header['extents_entry_size'])
                
                if len(extent_data) >= 24:
                    num_sectors, target_type, target_data, target_source = struct.unpack(
                        '<QIIQ', extent_data[:24]
                    )
                    
                    partitions.append(LpMetadataPartition(
                        name=name,
                        group_name="",
                        first_sector=target_data,
                        size=num_sectors * 512,
                        attributes=attrs
                    ))
                
                # Restore position
                f.seek(pos)
        
        return partitions
    
    def _read_geometry(self, f: BinaryIO) -> dict:
        """Read LP metadata geometry."""
        data = f.read(4096)
        
        magic = struct.unpack('<I', data[:4])[0]
        if magic != self.LP_METADATA_GEOMETRY_MAGIC:
            raise PayloadError(f"Invalid LP geometry magic: {hex(magic)}")
        
        struct_size, checksum = struct.unpack('<II', data[4:12])
        metadata_max_size, metadata_slot_count = struct.unpack('<II', data[12:20])
        logical_block_size = struct.unpack('<I', data[20:24])[0]
        
        return {
            'metadata_max_size': metadata_max_size,
            'metadata_slot_count': metadata_slot_count,
            'logical_block_size': logical_block_size,
            'metadata_offset': 4096 + 4096  # After geometry
        }
    
    def _read_metadata_header(self, f: BinaryIO) -> dict:
        """Read LP metadata header."""
        data = f.read(256)
        
        magic = struct.unpack('<I', data[:4])[0]
        if magic != self.LP_METADATA_HEADER_MAGIC:
            raise PayloadError(f"Invalid LP metadata magic: {hex(magic)}")
        
        major, minor = struct.unpack('<HH', data[4:8])
        header_size, header_checksum = struct.unpack('<II', data[8:16])
        tables_size, tables_checksum = struct.unpack('<II', data[16:24])
        
        partitions_offset, partitions_count, partitions_entry_size = struct.unpack(
            '<III', data[24:36]
        )
        extents_offset, extents_count, extents_entry_size = struct.unpack(
            '<III', data[36:48]
        )
        groups_offset, groups_count, groups_entry_size = struct.unpack(
            '<III', data[48:60]
        )
        
        return {
            'major': major,
            'minor': minor,
            'header_size': header_size,
            'tables_size': tables_size,
            'partitions_offset': header_size,
            'partitions_count': partitions_count,
            'partitions_entry_size': partitions_entry_size,
            'extents_offset': header_size + partitions_count * partitions_entry_size,
            'extents_count': extents_count,
            'extents_entry_size': extents_entry_size,
            'groups_offset': groups_offset,
            'groups_count': groups_count,
            'groups_entry_size': groups_entry_size,
        }


class SuperImageCreator:
    """Create Android super (dynamic partition) images.
    
    This is a pure Python implementation of lpmake functionality.
    Creates a super.img with LP metadata and partition data.
    """
    
    LP_METADATA_GEOMETRY_MAGIC = 0x616c4467  # "gDla"
    LP_METADATA_HEADER_MAGIC = 0x414c5030   # "0PLA"
    LP_SECTOR_SIZE = 512
    LP_METADATA_GEOMETRY_SIZE = 4096
    LP_METADATA_HEADER_SIZE = 256
    LP_PARTITION_ENTRY_SIZE = 52
    LP_EXTENT_ENTRY_SIZE = 24
    LP_GROUP_ENTRY_SIZE = 48
    
    # Partition attributes
    LP_PARTITION_ATTR_READONLY = (1 << 0)
    LP_PARTITION_ATTR_SLOT_SUFFIXED = (1 << 1)
    LP_PARTITION_ATTR_UPDATED = (1 << 2)
    LP_PARTITION_ATTR_DISABLED = (1 << 3)
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        self.progress_callback = progress_callback
        self.partitions = []  # List of (name, image_path, group_name, readonly)
        self.groups = {}  # group_name -> max_size
        self.metadata_size = 65536  # 64KB default
        self.metadata_slots = 2  # A/B slots
        self.block_size = 4096
        self.super_size = 0  # Will be calculated or set
        self.sparse_output = False
    
    def add_partition(self, name: str, image_path: str, group_name: str = "default", 
                      readonly: bool = True) -> 'SuperImageCreator':
        """Add a partition to the super image.
        
        Args:
            name: Partition name (e.g., 'system', 'vendor')
            image_path: Path to the partition image file
            group_name: Partition group name
            readonly: Whether partition should be read-only
        """
        self.partitions.append({
            'name': name,
            'image_path': image_path,
            'group_name': group_name,
            'readonly': readonly,
            'size': os.path.getsize(image_path) if os.path.exists(image_path) else 0
        })
        return self
    
    def add_group(self, name: str, max_size: int) -> 'SuperImageCreator':
        """Add a partition group with maximum size.
        
        Args:
            name: Group name (e.g., 'qti_dynamic_partitions')
            max_size: Maximum size for all partitions in group
        """
        self.groups[name] = max_size
        return self
    
    def set_metadata_size(self, size: int) -> 'SuperImageCreator':
        """Set metadata region size (default 65536)."""
        self.metadata_size = size
        return self
    
    def set_super_size(self, size: int) -> 'SuperImageCreator':
        """Set total super partition size."""
        self.super_size = size
        return self
    
    def set_block_size(self, size: int) -> 'SuperImageCreator':
        """Set logical block size (default 4096)."""
        self.block_size = size
        return self
    
    def set_sparse(self, sparse: bool) -> 'SuperImageCreator':
        """Output as sparse image."""
        self.sparse_output = sparse
        return self
    
    def create(self, output_path: str) -> bool:
        """Create the super.img file.
        
        Args:
            output_path: Path for output super.img
            
        Returns:
            True if successful
        """
        try:
            # Validate inputs
            if not self.partitions:
                raise PayloadError("No partitions added")
            
            # Ensure all partitions have a group
            for part in self.partitions:
                if part['group_name'] not in self.groups:
                    # Auto-create group with enough space
                    total_size = sum(p['size'] for p in self.partitions 
                                    if p['group_name'] == part['group_name'])
                    self.groups[part['group_name']] = total_size + 1024 * 1024  # Add 1MB buffer
            
            # Calculate required size
            total_partition_size = sum(p['size'] for p in self.partitions)
            metadata_region_size = self.metadata_size * self.metadata_slots * 2  # Primary + backup
            
            # Align to block size
            data_start = self._align_up(4096 + metadata_region_size, self.block_size)
            required_size = data_start + self._align_up(total_partition_size, self.block_size)
            
            if self.super_size == 0:
                # Auto-calculate with 5% buffer
                self.super_size = self._align_up(int(required_size * 1.05), self.block_size)
            elif self.super_size < required_size:
                raise PayloadError(f"Super size {self.super_size} too small for partitions ({required_size} needed)")
            
            logger.info(f"Creating super.img: {output_path}")
            logger.info(f"  Total size: {self.super_size / (1024*1024):.2f} MB")
            logger.info(f"  Partitions: {len(self.partitions)}")
            logger.info(f"  Groups: {len(self.groups)}")
            logger.info(f"  Metadata size: {self.metadata_size}")
            logger.info(f"  Data starts at: {data_start}")
            
            # Create the image
            with open(output_path, 'wb') as f:
                # Write primary geometry at offset 4096
                f.seek(4096)
                self._write_geometry(f)
                
                # Write primary metadata
                f.seek(4096 + self.LP_METADATA_GEOMETRY_SIZE)
                partition_offsets = self._write_metadata(f, data_start)
                
                # Write backup geometry
                backup_geometry_offset = 4096 + self.metadata_size
                f.seek(backup_geometry_offset)
                self._write_geometry(f)
                
                # Write backup metadata
                f.seek(backup_geometry_offset + self.LP_METADATA_GEOMETRY_SIZE)
                self._write_metadata(f, data_start)
                
                # Write partition data
                self._write_partition_data(f, partition_offsets)
                
                # Pad to super_size
                f.seek(self.super_size - 1)
                f.write(b'\x00')
            
            # Convert to sparse if requested
            if self.sparse_output:
                logger.info("Converting to sparse format...")
                sparse_path = output_path + '.sparse'
                converter = SparseImageCreator(self.block_size, self.progress_callback)
                if converter.convert(output_path, sparse_path):
                    os.replace(sparse_path, output_path)
            
            logger.info(f"Super image created: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create super image: {e}")
            if os.path.exists(output_path):
                os.remove(output_path)
            raise
    
    def _align_up(self, value: int, alignment: int) -> int:
        """Align value up to alignment boundary."""
        return ((value + alignment - 1) // alignment) * alignment
    
    def _write_geometry(self, f: BinaryIO):
        """Write LP metadata geometry."""
        # Geometry structure:
        # magic (4) + struct_size (4) + checksum (4) + 
        # metadata_max_size (4) + metadata_slot_count (4) + logical_block_size (4)
        
        geometry = struct.pack('<III',
            self.LP_METADATA_GEOMETRY_MAGIC,
            40,  # struct_size
            0    # checksum (will be calculated)
        )
        geometry += struct.pack('<III',
            self.metadata_size,
            self.metadata_slots,
            self.block_size
        )
        
        # Pad to 4096 bytes
        geometry = geometry.ljust(self.LP_METADATA_GEOMETRY_SIZE, b'\x00')
        f.write(geometry)
    
    def _write_metadata(self, f: BinaryIO, data_start: int) -> dict:
        """Write LP metadata header and tables. Returns partition offsets."""
        
        # Calculate table sizes
        partitions_count = len(self.partitions)
        extents_count = len(self.partitions)  # One extent per partition
        groups_count = len(self.groups)
        
        partitions_size = partitions_count * self.LP_PARTITION_ENTRY_SIZE
        extents_size = extents_count * self.LP_EXTENT_ENTRY_SIZE
        groups_size = groups_count * self.LP_GROUP_ENTRY_SIZE
        
        tables_size = partitions_size + extents_size + groups_size
        
        # Build partition offsets
        partition_offsets = {}
        current_offset = data_start
        
        for i, part in enumerate(self.partitions):
            aligned_size = self._align_up(part['size'], self.block_size)
            partition_offsets[part['name']] = {
                'offset': current_offset,
                'size': part['size'],
                'aligned_size': aligned_size,
                'extent_index': i
            }
            current_offset += aligned_size
        
        # Write header
        header = struct.pack('<I', self.LP_METADATA_HEADER_MAGIC)  # magic
        header += struct.pack('<HH', 10, 2)  # major, minor version
        header += struct.pack('<II', self.LP_METADATA_HEADER_SIZE, 0)  # header_size, checksum
        header += struct.pack('<II', tables_size, 0)  # tables_size, tables_checksum
        
        # Partition table info
        header += struct.pack('<III', 0, partitions_count, self.LP_PARTITION_ENTRY_SIZE)
        # Extent table info  
        header += struct.pack('<III', partitions_size, extents_count, self.LP_EXTENT_ENTRY_SIZE)
        # Group table info
        header += struct.pack('<III', partitions_size + extents_size, groups_count, self.LP_GROUP_ENTRY_SIZE)
        
        # Pad header
        header = header.ljust(self.LP_METADATA_HEADER_SIZE, b'\x00')
        f.write(header)
        
        # Write partition entries
        group_names = list(self.groups.keys())
        for i, part in enumerate(self.partitions):
            attrs = 0
            if part['readonly']:
                attrs |= self.LP_PARTITION_ATTR_READONLY
            
            group_idx = group_names.index(part['group_name']) if part['group_name'] in group_names else 0
            
            # Partition entry: name[36] + attrs(4) + first_extent_index(4) + num_extents(4) + group_index(4)
            name_bytes = part['name'].encode('utf-8')[:36].ljust(36, b'\x00')
            entry = name_bytes + struct.pack('<IIII', attrs, i, 1, group_idx)
            f.write(entry)
        
        # Write extent entries
        for part in self.partitions:
            pinfo = partition_offsets[part['name']]
            # Extent: num_sectors(8) + target_type(4) + target_data(8) + target_source(4)
            num_sectors = pinfo['aligned_size'] // self.LP_SECTOR_SIZE
            target_data = pinfo['offset'] // self.LP_SECTOR_SIZE
            extent = struct.pack('<QIQI', num_sectors, 0, target_data, 0)
            f.write(extent)
        
        # Write group entries
        for group_name, max_size in self.groups.items():
            # Group: name[36] + flags(4) + max_size(8)
            name_bytes = group_name.encode('utf-8')[:36].ljust(36, b'\x00')
            entry = name_bytes + struct.pack('<IQ', 0, max_size)
            entry = entry.ljust(self.LP_GROUP_ENTRY_SIZE, b'\x00')
            f.write(entry)
        
        return partition_offsets
    
    def _write_partition_data(self, f: BinaryIO, partition_offsets: dict):
        """Write actual partition data."""
        total = len(self.partitions)
        
        for idx, part in enumerate(self.partitions):
            pinfo = partition_offsets[part['name']]
            
            logger.info(f"  Writing {part['name']}: {part['size'] / (1024*1024):.2f} MB at offset {pinfo['offset']}")
            
            if self.progress_callback:
                self.progress_callback(idx, total, f"Writing {part['name']}...")
            
            f.seek(pinfo['offset'])
            
            # Copy partition data
            with open(part['image_path'], 'rb') as src:
                remaining = part['size']
                chunk_size = 64 * 1024 * 1024  # 64MB chunks
                
                while remaining > 0:
                    to_read = min(chunk_size, remaining)
                    data = src.read(to_read)
                    if not data:
                        break
                    f.write(data)
                    remaining -= len(data)
            
            # Pad to aligned size
            padding = pinfo['aligned_size'] - part['size']
            if padding > 0:
                f.write(b'\x00' * padding)
        
        if self.progress_callback:
            self.progress_callback(total, total, "Complete")


class AndroidImageExtractor:
    """Main class for extracting various Android image formats."""
    
    def __init__(self, input_path: Optional[str] = None, progress_callback: Optional[Callable] = None):
        self.input_path = input_path
        self.progress_callback = progress_callback
    
    def analyze(self, input_path: Optional[str] = None) -> dict:
        """Analyze an image file and return information about it."""
        path = input_path or self.input_path
        if not path:
            raise ValueError("No input path provided")
        
        img_type = detect_image_type(path)
        file_size = os.path.getsize(path)
        
        info = {
            'path': path,
            'type': img_type,
            'size': file_size,
            'size_human': f"{file_size / (1024*1024):.2f} MB"
        }
        
        if img_type == 'sparse':
            with open(path, 'rb') as f:
                header = SparseImageConverter()._read_header(f)
                info['sparse_blocks'] = header.total_blocks
                info['sparse_block_size'] = header.block_size
                info['raw_size'] = header.total_blocks * header.block_size
                info['raw_size_human'] = f"{info['raw_size'] / (1024*1024):.2f} MB"
        
        elif img_type == 'boot':
            with open(path, 'rb') as f:
                extractor = BootImageExtractor()
                boot_info = extractor._parse_header(f)
                info['header_version'] = boot_info.header_version
                info['page_size'] = boot_info.page_size
                info['kernel_size'] = boot_info.kernel_size
                info['ramdisk_size'] = boot_info.ramdisk_size
                info['cmdline'] = boot_info.cmdline[:100] + '...' if len(boot_info.cmdline) > 100 else boot_info.cmdline
        
        elif img_type == 'vendor_boot':
            with open(path, 'rb') as f:
                extractor = BootImageExtractor()
                boot_info = extractor._parse_header(f)
                info['header_version'] = boot_info.header_version
                info['page_size'] = boot_info.page_size
                info['vendor_ramdisk_size'] = boot_info.ramdisk_size
                info['dtb_size'] = boot_info.dtb_size
                info['cmdline'] = boot_info.cmdline[:100] + '...' if len(boot_info.cmdline) > 100 else boot_info.cmdline
                # Build contents list for extraction
                contents = []
                if boot_info.ramdisk_size > 0:
                    contents.append({'name': 'vendor_ramdisk', 'size': boot_info.ramdisk_size, 'type': 'ramdisk'})
                if boot_info.dtb_size > 0:
                    contents.append({'name': 'dtb', 'size': boot_info.dtb_size, 'type': 'dtb'})
                if contents:
                    info['contents'] = contents
        
        elif img_type == 'super':
            extractor = SuperImageExtractor()
            partitions = extractor.list_partitions(path)
            info['partitions'] = [
                {'name': p.name, 'size': p.size, 'size_human': f"{p.size / (1024*1024):.2f} MB"}
                for p in partitions if p.size > 0
            ]
        
        elif img_type == 'fat':
            extractor = FatImageExtractor()
            try:
                files = extractor.list_files(path)
                with open(path, 'rb') as f:
                    boot_sector = extractor._read_boot_sector(f)
                info['fat_type'] = boot_sector['fat_type']
                info['cluster_size'] = boot_sector['cluster_size']
                info['file_count'] = len(files)
                # Build contents list for extraction
                info['contents'] = [
                    {'name': f['name'], 'size': f['size'], 'type': 'file'}
                    for f in files
                ]
            except Exception as e:
                info['error'] = str(e)
        
        elif img_type == 'ext4':
            extractor = Ext4ImageExtractor()
            try:
                files = extractor.list_files(path)
                info['filesystem'] = 'ext4'
                info['file_count'] = len(files)
                # Build contents list for extraction
                info['contents'] = [
                    {'name': f['name'], 'size': f['size'], 'type': f.get('type', 'file')}
                    for f in files
                ]
            except Exception as e:
                info['error'] = str(e)
        
        elif img_type == 'erofs':
            info['filesystem'] = 'erofs'
            info['note'] = 'EROFS extraction not yet implemented'
        
        elif img_type == 'elf':
            # Parse ELF header for info
            with open(path, 'rb') as f:
                e_ident = f.read(16)
                is_64bit = e_ident[4] == 2
                is_le = e_ident[5] == 1
                endian = '<' if is_le else '>'
                
                if is_64bit:
                    f.seek(16)
                    header_data = f.read(48)
                    e_type, e_machine, _, e_entry, e_phoff, e_shoff, _, _, e_phentsize, e_phnum = struct.unpack(
                        f'{endian}HHIQQQIHH', header_data[:40])
                else:
                    f.seek(16)
                    header_data = f.read(36)
                    e_type, e_machine, _, e_entry, e_phoff, e_shoff, _, _, e_phentsize, e_phnum = struct.unpack(
                        f'{endian}HHIIIIIHH', header_data[:28])
                
                machine_names = {
                    0: "None", 3: "Intel 386", 8: "MIPS", 40: "ARM",
                    62: "x86-64", 164: "Qualcomm Hexagon", 183: "AArch64",
                }
                type_names = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
                
                info['elf_class'] = '64-bit' if is_64bit else '32-bit'
                info['elf_type'] = type_names.get(e_type, f"0x{e_type:X}")
                info['elf_machine'] = machine_names.get(e_machine, f"0x{e_machine:X}")
                info['elf_entry'] = f"0x{e_entry:X}"
                info['elf_segments'] = e_phnum
                info['note'] = 'ELF firmware/executable - can extract program segments'
        
        elif img_type == 'vbmeta':
            # Parse vbmeta header for info
            extractor = VbmetaExtractor(path, '')
            with open(path, 'rb') as f:
                extractor._parse_header(f)
                extractor._parse_descriptors(f)
            
            info['avb_version'] = f"{extractor.header['version_major']}.{extractor.header['version_minor']}"
            info['algorithm'] = extractor.header['algorithm_name']
            info['rollback_index'] = extractor.header['rollback_index']
            info['flags'] = ', '.join(extractor.header['flags_decoded'])
            info['release'] = extractor.header['release_string']
            info['descriptors'] = len(extractor.descriptors)
            
            # Get referenced partitions
            partitions = extractor.get_partition_info()
            if partitions:
                info['contents'] = [
                    {'name': p['name'], 'size': p['size'], 'type': p['type']}
                    for p in partitions
                ]
            info['note'] = 'AVB vbmeta - contains verification data for partitions'
        
        elif img_type == 'dtbo':
            # Parse DTBO (Device Tree Blob Overlay) image
            extractor = DtboExtractor()
            analysis = extractor.analyze(path)
            
            if analysis['valid']:
                info['dtbo_version'] = analysis['version']
                info['entry_count'] = analysis['entry_count']
                info['page_size'] = analysis['page_size']
                info['total_size'] = analysis['total_size']
                info['contents'] = [
                    {
                        'name': f"dtbo_{e['index']:02d}",
                        'size': e['size'],
                        'id': f"0x{e['id']:08X}",
                        'info': e['info'][:40] if e['info'] else ''
                    }
                    for e in analysis['entries']
                ]
                info['note'] = f"DTBO v{analysis['version']} - {analysis['entry_count']} device tree overlays"
            else:
                info['note'] = 'DTBO - invalid or unsupported format'
        
        elif img_type == 'abl':
            # Analyze ABL (Android Bootloader) - critical for LG, Pixel, and other devices
            analyzer = AblAnalyzer(path)
            abl_info = analyzer.analyze()
            
            info['abl_format'] = abl_info.get('format', 'Unknown')
            info['abl_size'] = abl_info.get('size', 0)
            info['is_elf'] = abl_info.get('is_elf', False)
            info['is_64bit'] = abl_info.get('is_64bit', False)
            info['unlock_checks'] = len(abl_info.get('unlock_checks', []))
            info['secure_boot_refs'] = len(abl_info.get('secure_boot', []))
            info['avb_references'] = len(abl_info.get('avb_references', []))
            info['anti_rollback_refs'] = len(abl_info.get('anti_rollback', []))
            info['lg_specific'] = len(abl_info.get('lg_specific', []))
            info['pixel_specific'] = len(abl_info.get('pixel_specific', []))
            info['fastboot_commands'] = len(abl_info.get('fastboot_commands', []))
            info['is_lg_device'] = analyzer.is_lg_device()
            info['is_pixel_device'] = analyzer.is_pixel_device()
            info['note'] = f"ABL ({abl_info.get('format', 'Unknown')}) - unlock checks, AVB, fastboot"
            if info['is_lg_device']:
                info['note'] += ' - LG device (LAF mode)'
            if info['is_pixel_device']:
                info['note'] += ' - Google Pixel/Tensor device'
        
        elif img_type == 'bootloader':
            # Analyze bootloader image
            analyzer = BootloaderImageAnalyzer(path, '')
            bl_info = analyzer.analyze()
            
            info['bl_format'] = bl_info.get('format', 'Unknown')
            info['bl_type'] = bl_info.get('type', 'Unknown')
            if 'description' in bl_info:
                info['description'] = bl_info['description']
            if 'machine' in bl_info:
                info['machine'] = bl_info['machine']
            if 'elf_class' in bl_info:
                info['elf_class'] = bl_info['elf_class']
            if 'entry_point' in bl_info:
                info['entry_point'] = bl_info['entry_point']
            if 'segments' in bl_info:
                info['segments'] = bl_info['segments']
            if 'is_signed' in bl_info:
                info['is_signed'] = bl_info['is_signed']
            if 'qcom_signed' in bl_info:
                info['qcom_signed'] = bl_info['qcom_signed']
            if 'qc_version' in bl_info:
                info['qc_version'] = bl_info['qc_version']
            if 'build_date' in bl_info:
                info['build_date'] = bl_info['build_date']
            if 'build_time' in bl_info:
                info['build_time'] = bl_info['build_time']
            info['note'] = 'Bootloader/firmware image - can extract segments and info'
        
        return info
    
    def extract(self, input_path: Optional[str] = None, output_dir: str = '', 
                partition_names: Optional[list[str]] = None) -> dict:
        """Extract contents from an Android image."""
        path = input_path or self.input_path
        if not path:
            raise ValueError("No input path provided")
        img_type = detect_image_type(path)
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Image type: {img_type}")
        
        if img_type == 'sparse':
            logger.info("Converting sparse image to raw...")
            output_path = Path(output_dir) / (Path(path).stem + '_raw.img')
            converter = SparseImageConverter(self.progress_callback)
            converter.convert(path, str(output_path))
            return {'type': 'sparse', 'output': str(output_path)}
        
        elif img_type == 'boot' or img_type == 'vendor_boot':
            logger.info("Extracting boot image components...")
            extractor = BootImageExtractor(self.progress_callback)
            extracted = extractor.extract(path, output_dir)
            return {'type': img_type, 'components': extracted}
        
        elif img_type == 'super':
            logger.info("Extracting dynamic partitions from super image...")
            extractor = SuperImageExtractor(self.progress_callback)
            extracted = extractor.extract(path, output_dir, partition_names)
            return {'type': 'super', 'partitions': extracted}
        
        elif img_type == 'fat':
            logger.info("Extracting files from FAT filesystem image...")
            extractor = FatImageExtractor(self.progress_callback)
            extracted = extractor.extract(path, output_dir, partition_names)
            return {'type': 'fat', 'files': extracted}
        
        elif img_type == 'ext4':
            logger.info("Extracting files from ext4 filesystem image...")
            extractor = Ext4ImageExtractor(self.progress_callback)
            extracted = extractor.extract(path, output_dir, partition_names)
            return {'type': 'ext4', 'files': extracted}
        
        elif img_type == 'erofs':
            logger.info(f"EROFS format - extraction not yet implemented")
            return {'type': 'erofs', 'note': 'EROFS extraction not yet implemented'}
        
        elif img_type == 'elf':
            logger.info("Extracting segments from ELF file...")
            extractor = ElfImageExtractor(path, output_dir, self.progress_callback)
            success = extractor.extract()
            if success:
                return {'type': 'elf', 'segments': len(extractor.segments), 
                        'info': extractor.header}
            else:
                return {'type': 'elf', 'error': 'Failed to extract ELF segments'}
        
        elif img_type == 'abl':
            logger.info("Analyzing ABL (Android Bootloader)...")
            analyzer = AblAnalyzer(path, output_dir, self.progress_callback)
            analysis = analyzer.analyze()
            report_path = analyzer.write_report()
            
            # Also extract ELF segments if it's an ELF file
            segments_count = 0
            if analysis.get('is_elf', False):
                elf_extractor = ElfImageExtractor(path, output_dir, self.progress_callback)
                elf_extractor.extract()
                segments_count = len(elf_extractor.segments)
            
            return {
                'type': 'abl',
                'analysis': analysis,
                'report': report_path,
                'summary': analyzer.get_summary(),
                'is_lg': analyzer.is_lg_device(),
                'unlock_checks': len(analysis.get('unlock_checks', [])),
                'segments': segments_count,
            }
        
        elif img_type == 'vbmeta':
            logger.info("Parsing AVB vbmeta image...")
            extractor = VbmetaExtractor(path, output_dir, self.progress_callback)
            success = extractor.extract()
            if success:
                return {'type': 'vbmeta', 'descriptors': len(extractor.descriptors),
                        'partitions': extractor.get_partition_info(),
                        'header': extractor.header}
            else:
                return {'type': 'vbmeta', 'error': 'Failed to parse vbmeta'}
        
        elif img_type == 'dtbo':
            logger.info("Extracting DTBO overlays...")
            extractor = DtboExtractor(self.progress_callback)
            analysis = extractor.analyze(path)
            if analysis['valid']:
                extracted = extractor.extract(path, output_dir)
                return {
                    'type': 'dtbo',
                    'version': analysis['version'],
                    'entry_count': analysis['entry_count'],
                    'extracted': extracted,
                    'entries': analysis['entries']
                }
            else:
                return {'type': 'dtbo', 'error': 'Invalid DTBO format'}
        
        elif img_type == 'bootloader':
            logger.info("Analyzing bootloader image...")
            analyzer = BootloaderImageAnalyzer(path, output_dir, self.progress_callback)
            success = analyzer.extract()
            if success:
                return {'type': 'bootloader', 'info': analyzer.info,
                        'segments': len(analyzer.segments)}
            else:
                return {'type': 'bootloader', 'error': 'Failed to analyze bootloader'}
        
        elif img_type == 'raw':
            logger.info(f"Raw/unknown format - cannot extract")
            return {'type': 'raw', 'note': 'Unknown format, cannot extract'}
        
        else:
            return {'type': 'unknown', 'error': 'Unknown image format'}


def run_image_extract(args) -> None:
    """Run image extraction from command line."""
    input_path = args.image_path
    
    if not os.path.exists(input_path):
        raise PayloadError(f"Image file not found: {input_path}")
    
    extractor = AndroidImageExtractor(
        progress_callback=lambda cur, tot, msg: logger.info(f"  [{int(cur/tot*100):3d}%] {msg}")
    )
    
    if args.analyze:
        # Just analyze
        info = extractor.analyze(input_path)
        logger.info(f"\nImage Analysis: {input_path}")
        logger.info(f"  Type: {info['type']}")
        logger.info(f"  Size: {info['size_human']}")
        
        if info['type'] == 'sparse':
            logger.info(f"  Raw size: {info['raw_size_human']}")
        elif info['type'] == 'boot':
            logger.info(f"  Header version: {info.get('header_version', 'unknown')}")
            logger.info(f"  Kernel size: {info.get('kernel_size', 0)}")
            logger.info(f"  Ramdisk size: {info.get('ramdisk_size', 0)}")
        elif info['type'] == 'super':
            logger.info(f"  Partitions:")
            for p in info.get('partitions', []):
                logger.info(f"    - {p['name']}: {p['size_human']}")
    else:
        # Extract
        partition_names = None
        if args.images:
            partition_names = [n.strip() for n in args.images.split(',')]
        
        result = extractor.extract(input_path, args.out, partition_names)
        logger.info(f"\nExtraction complete: {result['type']}")


# =============================================================================
# PLUGIN SYSTEM
# =============================================================================

@dataclass
class PluginManifest:
    """Plugin metadata from manifest.json."""
    id: str
    name: str
    version: str
    description: str
    author: str
    icon: str = "🔌"
    # Monetization
    license_type: str = "free"  # free, paid, donation
    price: float = 0.0
    currency: str = "USD"
    payment_address: str = ""  # BTC address, PayPal, etc.
    payment_type: str = ""  # btc, paypal, kofi, etc.
    # Links
    website: str = ""
    support_url: str = ""
    # Requirements
    min_version: str = "1.0"
    requirements: List[str] = None  # pip packages needed, e.g. ["requests", "pillow>=9.0"]
    # Git repository to clone (optional) - e.g. {"repo": "https://github.com/user/repo", "target": "subdir_name", "requirements_file": "requirements.txt"}
    git_clone: Dict[str, Any] = None
    # Bundled binaries that need to be downloaded (list of URLs or {url, target_path, sha256} dicts)
    bundled_binaries: List[Any] = None
    # Setup commands to run after git clone and pip install (bash-compatible)
    setup_commands: List[str] = None
    post_install: List[Dict[str, Any]] = None  # Post-install steps [{"type": "driver", "file": "..."}, {"type": "git_clone", "repo": "..."}]
    # State
    enabled: bool = True
    licensed: bool = False  # For paid plugins
    
    def __post_init__(self):
        if self.requirements is None:
            self.requirements = []
        if self.post_install is None:
            self.post_install = []
        if self.bundled_binaries is None:
            self.bundled_binaries = []
        if self.setup_commands is None:
            self.setup_commands = []
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any], plugin_id: str) -> 'PluginManifest':
        """Create manifest from dictionary."""
        return cls(
            id=plugin_id,
            name=data.get('name', plugin_id),
            version=data.get('version', '1.0'),
            description=data.get('description', ''),
            author=data.get('author', 'Unknown'),
            icon=data.get('icon', '🔌'),
            license_type=data.get('license_type', 'free'),
            price=float(data.get('price', 0.0)),
            currency=data.get('currency', 'USD'),
            payment_address=data.get('payment_address', ''),
            payment_type=data.get('payment_type', ''),
            website=data.get('website', ''),
            support_url=data.get('support_url', ''),
            min_version=data.get('min_version', '1.0'),
            requirements=data.get('requirements', []),
            git_clone=data.get('git_clone'),
            bundled_binaries=data.get('bundled_binaries', []),
            setup_commands=data.get('setup_commands', []),
            post_install=data.get('post_install', []),
            enabled=data.get('enabled', True),
            licensed=data.get('licensed', False)
        )


class PluginBase:
    """Base class for Image Anarchy plugins.
    
    To create a plugin:
    1. Create a folder in 'plugins/' with your plugin id
    2. Add manifest.json with plugin metadata
    3. Add plugin.py with a class that inherits from PluginBase
    4. Implement: get_name(), get_icon(), get_description(), create_widget()
    
    Example manifest.json:
    {
        "name": "My Plugin",
        "version": "1.0",
        "description": "Does something cool",
        "author": "Your Name",
        "icon": "🚀",
        "license_type": "donation",
        "payment_address": "bc1q...",
        "payment_type": "btc",
        "requirements": ["requests", "pillow"]
    }
    """
    
    manifest: Optional[PluginManifest] = None
    
    def get_name(self) -> str:
        """Return the plugin name."""
        return self.manifest.name if self.manifest else "Unknown Plugin"
    
    def get_icon(self) -> str:
        """Return emoji icon."""
        return self.manifest.icon if self.manifest else "🔌"
    
    def get_description(self) -> str:
        """Return plugin description."""
        return self.manifest.description if self.manifest else ""
    
    def get_version(self) -> str:
        """Return plugin version."""
        return self.manifest.version if self.manifest else "1.0"
    
    def get_author(self) -> str:
        """Return plugin author."""
        return self.manifest.author if self.manifest else "Unknown"
    
    def create_widget(self, parent_window) -> Any:
        """Create and return the main QWidget for this plugin.
        
        Args:
            parent_window: The main ImageAnarchyGUI window instance
            
        Returns:
            QWidget: The plugin's widget
        """
        raise NotImplementedError("Plugins must implement create_widget()")
    
    def on_load(self):
        """Called when plugin is loaded."""
        pass
    
    def on_unload(self):
        """Called when plugin is unloaded."""
        pass
    
    def is_licensed(self) -> bool:
        """Check if plugin is licensed (for paid plugins)."""
        if not self.manifest:
            return True
        if self.manifest.license_type == "free":
            return True
        return self.manifest.licensed
    
    def validate_license(self, license_key: str) -> bool:
        """Validate a license key. Override for custom validation."""
        # Default: accept any non-empty key
        return bool(license_key and len(license_key) > 0)


class PluginManager:
    """Manages plugin discovery, loading, and lifecycle."""
    
    PLUGINS_DIR = "plugins"
    CONFIG_FILE = "plugins_config.json"
    
    def __init__(self):
        self.plugins: Dict[str, PluginBase] = {}
        self.manifests: Dict[str, PluginManifest] = {}
        self.config: Dict[str, Any] = {}
        self._load_config()
    
    def _get_plugins_dir(self) -> str:
        """Get the plugins directory path."""
        # Check multiple locations
        if getattr(sys, 'frozen', False):
            # Running as compiled exe
            base_dir = os.path.dirname(sys.executable)
        else:
            # Running as script
            base_dir = os.path.dirname(os.path.abspath(__file__))
        
        plugins_dir = os.path.join(base_dir, self.PLUGINS_DIR)
        os.makedirs(plugins_dir, exist_ok=True)
        return plugins_dir
    
    def _get_config_path(self) -> str:
        """Get the config file path."""
        return os.path.join(self._get_plugins_dir(), self.CONFIG_FILE)
    
    def _load_config(self):
        """Load plugin configuration (enabled states, licenses)."""
        config_path = self._get_config_path()
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
            except Exception:
                self.config = {}
        else:
            self.config = {}
    
    def _save_config(self):
        """Save plugin configuration."""
        config_path = self._get_config_path()
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save plugin config: {e}")
    
    def discover_plugins(self) -> List[PluginManifest]:
        """Discover all plugins in the plugins directory."""
        plugins_dir = self._get_plugins_dir()
        discovered = []
        
        if not os.path.exists(plugins_dir):
            return discovered
        
        for item in os.listdir(plugins_dir):
            plugin_path = os.path.join(plugins_dir, item)
            manifest_path = os.path.join(plugin_path, "manifest.json")
            
            if os.path.isdir(plugin_path) and os.path.exists(manifest_path):
                try:
                    with open(manifest_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    manifest = PluginManifest.from_dict(data, item)
                    
                    # Apply saved config
                    plugin_config = self.config.get(item, {})
                    manifest.enabled = plugin_config.get('enabled', True)
                    manifest.licensed = plugin_config.get('licensed', False)
                    
                    self.manifests[item] = manifest
                    discovered.append(manifest)
                    
                except Exception as e:
                    logger.warning(f"Failed to load plugin manifest {item}: {e}")
        
        return discovered
    
    def load_plugin(self, plugin_id: str) -> Optional[PluginBase]:
        """Load a plugin by its ID."""
        if plugin_id in self.plugins:
            return self.plugins[plugin_id]
        
        plugins_dir = self._get_plugins_dir()
        plugin_path = os.path.join(plugins_dir, plugin_id)
        plugin_file = os.path.join(plugin_path, "plugin.py")
        
        if not os.path.exists(plugin_file):
            logger.warning(f"Plugin file not found: {plugin_file}")
            return None
        
        try:
            # Load the plugin module
            import importlib.util
            spec = importlib.util.spec_from_file_location(f"plugin_{plugin_id}", plugin_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[f"plugin_{plugin_id}"] = module
                spec.loader.exec_module(module)
                
                # Find the plugin class - first check for 'Plugin' export (preferred)
                plugin_class = None
                if hasattr(module, 'Plugin'):
                    plugin_class = module.Plugin
                else:
                    # Fallback: look for PluginBase subclass
                    for name, obj in module.__dict__.items():
                        if isinstance(obj, type) and issubclass(obj, PluginBase) and obj != PluginBase:
                            plugin_class = obj
                            break
                
                if plugin_class:
                    plugin = plugin_class()
                    plugin.manifest = self.manifests.get(plugin_id)
                    if hasattr(plugin, 'on_load'):
                        plugin.on_load()
                    self.plugins[plugin_id] = plugin
                    return plugin
                else:
                    logger.warning(f"No Plugin class found in {plugin_file}")
                    
        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_id}: {e}")
        
        return None
    
    def unload_plugin(self, plugin_id: str):
        """Unload a plugin."""
        if plugin_id in self.plugins:
            self.plugins[plugin_id].on_unload()
            del self.plugins[plugin_id]
    
    def enable_plugin(self, plugin_id: str, enabled: bool):
        """Enable or disable a plugin."""
        if plugin_id in self.manifests:
            self.manifests[plugin_id].enabled = enabled
            
            if plugin_id not in self.config:
                self.config[plugin_id] = {}
            self.config[plugin_id]['enabled'] = enabled
            self._save_config()
    
    def set_licensed(self, plugin_id: str, licensed: bool):
        """Set plugin license status."""
        if plugin_id in self.manifests:
            self.manifests[plugin_id].licensed = licensed
            
            if plugin_id not in self.config:
                self.config[plugin_id] = {}
            self.config[plugin_id]['licensed'] = licensed
            self._save_config()
    
    def get_plugin(self, plugin_id: str) -> Optional[PluginBase]:
        """Get a loaded plugin."""
        return self.plugins.get(plugin_id)
    
    def get_manifest(self, plugin_id: str) -> Optional[PluginManifest]:
        """Get a plugin's manifest."""
        return self.manifests.get(plugin_id)
    
    def get_all_manifests(self) -> List[PluginManifest]:
        """Get all discovered plugin manifests."""
        return list(self.manifests.values())
    
    def check_requirements(self, plugin_id: str) -> tuple:
        """Check if a plugin's requirements are installed.
        
        Returns:
            tuple: (all_installed: bool, missing: List[str], installed: List[str])
        """
        manifest = self.manifests.get(plugin_id)
        if not manifest or not manifest.requirements:
            return True, [], []
        
        missing = []
        installed = []
        
        # Use importlib.metadata for accurate package detection
        try:
            from importlib.metadata import distributions
            installed_packages = {dist.metadata['Name'].lower() for dist in distributions()}
        except ImportError:
            # Fallback for older Python
            try:
                import pkg_resources
                installed_packages = {pkg.key.lower() for pkg in pkg_resources.working_set}
            except ImportError:
                installed_packages = set()
        
        for req in manifest.requirements:
            # Parse package name (handle version specs like "requests>=2.0")
            pkg_name = req.split('>=')[0].split('<=')[0].split('==')[0].split('<')[0].split('>')[0].strip()
            
            # Check if package is installed (case-insensitive, handle underscores/hyphens)
            pkg_normalized = pkg_name.lower().replace('_', '-')
            pkg_alt = pkg_name.lower().replace('-', '_')
            
            if pkg_normalized in installed_packages or pkg_alt in installed_packages or pkg_name.lower() in installed_packages:
                installed.append(req)
            else:
                missing.append(req)
        
        return len(missing) == 0, missing, installed
    
    def install_requirements(self, requirements: List[str]) -> tuple:
        """Install pip packages to local plugin_packages directory.
        
        When running as a frozen PyInstaller exe, packages are installed to
        a local 'plugin_packages' directory using pip --target. This allows
        plugins to install their dependencies without requiring the packages
        to be bundled in the exe at build time.
        
        Returns:
            tuple: (success: bool, message: str)
        """
        if not requirements:
            return True, "No requirements to install"
        
        try:
            import subprocess
            import sys
            
            # Determine target directory for frozen exe
            if getattr(sys, 'frozen', False):
                # Running as PyInstaller exe - install to local plugin_packages
                base_dir = os.path.dirname(sys.executable)
                target_dir = os.path.join(base_dir, 'plugin_packages')
                
                # Ensure target directory exists
                os.makedirs(target_dir, exist_ok=True)
                
                # Find Python interpreter
                python_cmd = shutil.which('python') or shutil.which('python3') or shutil.which('py')
                if not python_cmd:
                    return False, (
                        "Python interpreter not found in PATH.\n\n"
                        "Please install Python and ensure it's in your PATH, then try again.\n\n"
                        f"You can try installing manually:\npip install --target \"{target_dir}\" {' '.join(requirements)}"
                    )
                
                # Install to local target directory so bundled Python can find them
                cmd = [python_cmd, '-m', 'pip', 'install', '--target', target_dir, '--upgrade'] + requirements
            else:
                # Running from source - install normally
                cmd = [sys.executable, '-m', 'pip', 'install'] + requirements
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                return True, f"Successfully installed: {', '.join(requirements)}"
            else:
                return False, f"pip error: {result.stderr}\n\nYou can try installing manually:\npip install {' '.join(requirements)}"
                
        except subprocess.TimeoutExpired:
            return False, "Installation timed out (5 minutes)"
        except Exception as e:
            return False, f"Installation failed: {str(e)}"
    
    def get_git_executable(self) -> Optional[str]:
        """Find Git executable, preferring bundled portable Git."""
        # Check for bundled portable Git first
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Check bundled git locations
        bundled_paths = [
            os.path.join(base_dir, "git", "bin", "git.exe"),
            os.path.join(base_dir, "git", "cmd", "git.exe"),
            os.path.join(base_dir, "PortableGit", "bin", "git.exe"),
            os.path.join(base_dir, "PortableGit", "cmd", "git.exe"),
        ]
        
        for git_path in bundled_paths:
            if os.path.exists(git_path):
                return git_path
        
        # Fallback to system Git
        git_in_path = shutil.which("git")
        if git_in_path:
            return git_in_path
        
        return None
    
    def run_post_install(self, plugin_id: str, progress_callback=None) -> Tuple[bool, str]:
        """Run post-install steps for a plugin.
        
        Args:
            plugin_id: The plugin identifier
            progress_callback: Optional callback(step_name: str, status: str)
            
        Returns:
            tuple: (success: bool, message: str)
        """
        manifest = self.manifests.get(plugin_id)
        if not manifest or not manifest.post_install:
            return True, "No post-install steps"
        
        plugins_dir = self._get_plugins_dir()
        plugin_dir = os.path.join(plugins_dir, plugin_id)
        
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        
        drivers_dir = os.path.join(base_dir, "drivers")
        
        errors = []
        
        for step in manifest.post_install:
            step_type = step.get('type', '')
            step_name = step.get('name', step_type)
            optional = step.get('optional', False)
            
            if progress_callback:
                progress_callback(step_name, "running")
            
            try:
                if step_type == 'driver':
                    # Install a driver (MSI or EXE)
                    filename = step.get('file', '')
                    driver_path = os.path.join(drivers_dir, filename)
                    
                    if not os.path.exists(driver_path):
                        msg = f"Driver not found: {filename}"
                        if optional:
                            if progress_callback:
                                progress_callback(step_name, f"skipped: {msg}")
                            continue
                        else:
                            errors.append(msg)
                            continue
                    
                    # Launch installer and wait
                    if filename.endswith('.msi'):
                        # MSI with quiet install
                        result = subprocess.run(
                            ['msiexec', '/i', driver_path, '/passive', '/norestart'],
                            capture_output=True, text=True, timeout=300
                        )
                    else:
                        # EXE installer
                        result = subprocess.run(
                            [driver_path, '/S', '/silent', '/quiet'],  # Common silent flags
                            capture_output=True, text=True, timeout=300
                        )
                    
                    if progress_callback:
                        progress_callback(step_name, "completed")
                        
                elif step_type == 'git_clone':
                    # Clone a git repository
                    repo = step.get('repo', '')
                    target = step.get('target', '')  # Relative to plugin dir
                    
                    if not repo:
                        errors.append("git_clone: No repository specified")
                        continue
                    
                    # Determine target directory
                    if target:
                        clone_dir = os.path.join(plugin_dir, target)
                    else:
                        # Extract repo name from URL
                        repo_name = repo.rstrip('/').split('/')[-1].replace('.git', '')
                        clone_dir = os.path.join(plugin_dir, repo_name)
                    
                    # Check if already exists
                    if os.path.exists(clone_dir):
                        if progress_callback:
                            progress_callback(step_name, "already exists - skipped")
                        continue
                    
                    # Find git executable
                    git_exe = self.get_git_executable()
                    if not git_exe:
                        msg = "Git not found. Please install Git or ensure portable Git is bundled."
                        if optional:
                            if progress_callback:
                                progress_callback(step_name, f"skipped: {msg}")
                            continue
                        else:
                            errors.append(msg)
                            continue
                    
                    # Clone the repository
                    result = subprocess.run(
                        [git_exe, 'clone', '--depth', '1', repo, clone_dir],
                        capture_output=True, text=True, timeout=600,
                        cwd=plugin_dir
                    )
                    
                    if result.returncode != 0:
                        msg = f"Git clone failed: {result.stderr}"
                        if optional:
                            if progress_callback:
                                progress_callback(step_name, f"failed (optional): {msg}")
                            continue
                        else:
                            errors.append(msg)
                            continue
                    
                    # Apply known fixes for cloned repositories
                    self._apply_repo_fixes(clone_dir, repo)
                    
                    if progress_callback:
                        progress_callback(step_name, "completed")
                        
                elif step_type == 'pip_requirements':
                    # Install pip requirements from a file in the cloned repo
                    req_file = step.get('file', 'requirements.txt')
                    target = step.get('target', '')
                    
                    if target:
                        req_path = os.path.join(plugin_dir, target, req_file)
                    else:
                        req_path = os.path.join(plugin_dir, req_file)
                    
                    if not os.path.exists(req_path):
                        msg = f"Requirements file not found: {req_path}"
                        if optional:
                            if progress_callback:
                                progress_callback(step_name, f"skipped: {msg}")
                            continue
                        else:
                            errors.append(msg)
                            continue
                    
                    python_exe = _get_python_executable()
                    if not python_exe:
                        msg = "Python interpreter not found in PATH. Please install Python."
                        if optional:
                            if progress_callback:
                                progress_callback(step_name, f"skipped: {msg}")
                            continue
                        else:
                            errors.append(msg)
                            continue
                    
                    result = subprocess.run(
                        [python_exe, '-m', 'pip', 'install', '-r', req_path],
                        capture_output=True, text=True, timeout=600
                    )
                    
                    if result.returncode != 0:
                        msg = f"pip install failed: {result.stderr}"
                        if optional:
                            if progress_callback:
                                progress_callback(step_name, f"failed (optional): {msg}")
                            continue
                        else:
                            errors.append(msg)
                            continue
                    
                    if progress_callback:
                        progress_callback(step_name, "completed")
                        
                elif step_type == 'command':
                    # Run a custom command
                    cmd = step.get('cmd', [])
                    cwd = step.get('cwd', plugin_dir)
                    
                    if isinstance(cmd, str):
                        cmd = cmd.split()
                    
                    if not cmd:
                        errors.append("command: No command specified")
                        continue
                    
                    # Resolve relative cwd
                    if not os.path.isabs(cwd):
                        cwd = os.path.join(plugin_dir, cwd)
                    
                    result = subprocess.run(
                        cmd, capture_output=True, text=True,
                        timeout=300, cwd=cwd,
                        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                    )
                    
                    if result.returncode != 0:
                        msg = f"Command failed: {result.stderr}"
                        if optional:
                            if progress_callback:
                                progress_callback(step_name, f"failed (optional): {msg}")
                            continue
                        else:
                            errors.append(msg)
                            continue
                    
                    if progress_callback:
                        progress_callback(step_name, "completed")
                        
                else:
                    errors.append(f"Unknown post-install type: {step_type}")
                    
            except subprocess.TimeoutExpired:
                msg = f"Step '{step_name}' timed out"
                if optional:
                    if progress_callback:
                        progress_callback(step_name, f"timed out (optional)")
                else:
                    errors.append(msg)
            except Exception as e:
                msg = f"Step '{step_name}' failed: {str(e)}"
                if optional:
                    if progress_callback:
                        progress_callback(step_name, f"error (optional): {str(e)}")
                else:
                    errors.append(msg)
        
        if errors:
            return False, "\n".join(errors)
        return True, "All post-install steps completed"
    
    def _apply_repo_fixes(self, clone_dir: str, repo_url: str):
        """Apply known fixes to cloned repositories.
        
        Some repositories have bugs in their requirements.txt or other files
        that need to be patched for proper installation on Windows.
        """
        # Fix mtkclient requirements.txt - has 'keystone' (OpenStack) instead of just 'keystone-engine'
        if 'mtkclient' in repo_url.lower():
            req_file = os.path.join(clone_dir, 'requirements.txt')
            if os.path.exists(req_file):
                try:
                    with open(req_file, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                    
                    # Remove 'keystone' line (OpenStack identity service)
                    # Keep 'keystone-engine' (the assembler library)
                    fixed_lines = []
                    for line in lines:
                        stripped = line.strip().lower()
                        # Skip lines that are exactly 'keystone' but keep 'keystone-engine'
                        if stripped == 'keystone':
                            continue
                        fixed_lines.append(line)
                    
                    with open(req_file, 'w', encoding='utf-8') as f:
                        f.writelines(fixed_lines)
                except Exception:
                    pass  # Best effort - if it fails, pip will just fail later
    
    def setup_plugin_dependencies(self, plugin_id: str, progress_callback=None) -> Tuple[bool, str]:
        """
        Complete setup of a plugin's dependencies AFTER extraction.
        
        Setup follows 4 phases in order:
        Phase 1: Git clone (if manifest.git_clone specified)
        Phase 2: Download binaries (if manifest.bundled_binaries has URLs)
        Phase 3: Install pip packages (manifest.requirements)
        Phase 4: Run setup commands (manifest.setup_commands like "pip install .")
        
        Args:
            plugin_id: The plugin identifier
            progress_callback: Optional callback(phase_info: str, status: str, progress: int)
                              phase_info format: "Phase X/4: Description"
            
        Returns:
            tuple: (success: bool, message: str)
        """
        # Load manifest from disk
        plugins_dir = self._get_plugins_dir()
        plugin_dir = os.path.join(plugins_dir, plugin_id)
        manifest_path = os.path.join(plugin_dir, 'manifest.json')
        
        if not os.path.exists(manifest_path):
            return False, f"manifest.json not found in {plugin_dir}"
        
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest_data = json.load(f)
        except Exception as e:
            return False, f"Failed to read manifest.json: {str(e)}"
        
        manifest = PluginManifest.from_dict(manifest_data, plugin_id)
        self.manifests[plugin_id] = manifest
        
        errors = []
        
        # Determine which phases are active
        has_git_clone = bool(manifest.git_clone and manifest.git_clone.get('repo'))
        has_binaries = bool(manifest.bundled_binaries)
        has_requirements = bool(manifest.requirements)
        has_setup_commands = bool(manifest.setup_commands)
        has_post_install = bool(manifest.post_install)
        
        # Calculate total phases and their weights for progress
        # Phase weights represent relative time/importance
        phases = []
        if has_git_clone:
            phases.append(('git_clone', 25))
        if has_binaries:
            phases.append(('binaries', 15))
        if has_requirements:
            phases.append(('pip_install', 30))
        if has_setup_commands:
            phases.append(('setup_commands', 25))
        if has_post_install:
            phases.append(('post_install', 5))
        
        total_phases = len(phases)
        if total_phases == 0:
            # No setup needed
            if progress_callback:
                progress_callback("No setup required", "completed", 100)
            return True, "No setup required"
        
        # Normalize weights to 100%
        total_weight = sum(p[1] for p in phases)
        progress_base = 0
        
        def get_phase_progress(phase_idx: int, sub_progress: float = 0.0) -> int:
            """Calculate overall progress percentage based on phase and sub-progress within phase."""
            nonlocal progress_base
            if phase_idx >= len(phases):
                return 100
            
            # Calculate base progress from completed phases
            base = sum(phases[i][1] for i in range(phase_idx)) * 100 // total_weight
            # Add sub-progress within current phase
            current_phase_weight = phases[phase_idx][1] * 100 // total_weight
            return min(99, base + int(current_phase_weight * sub_progress))
        
        phase_idx = 0
        phase_num = 0
        
        # ═══════════════════════════════════════════════════════════════════════
        # PHASE 1: Git Clone
        # ═══════════════════════════════════════════════════════════════════════
        if has_git_clone:
            phase_num += 1
            git_config = manifest.git_clone
            repo = git_config.get('repo', '')
            target = git_config.get('target', '')
            
            phase_label = f"Step {phase_num}/{total_phases}: Cloning repository"
            if progress_callback:
                progress_callback(phase_label, f"Cloning {repo.split('/')[-1]}...", get_phase_progress(phase_idx, 0.0))
            
            # Determine target directory
            if target:
                clone_dir = os.path.join(plugin_dir, target)
            else:
                repo_name = repo.rstrip('/').split('/')[-1].replace('.git', '')
                clone_dir = os.path.join(plugin_dir, repo_name)
            
            if os.path.exists(clone_dir):
                if progress_callback:
                    progress_callback(phase_label, "Already cloned ✓", get_phase_progress(phase_idx, 1.0))
            else:
                git_exe = self.get_git_executable()
                if not git_exe:
                    errors.append("Git not found. Please install Git to complete setup.")
                else:
                    try:
                        if progress_callback:
                            progress_callback(phase_label, f"Cloning {repo.split('/')[-1]}...", get_phase_progress(phase_idx, 0.3))
                        
                        result = subprocess.run(
                            [git_exe, 'clone', '--depth', '1', repo, clone_dir],
                            capture_output=True, text=True, timeout=600,
                            cwd=plugin_dir
                        )
                        if result.returncode != 0:
                            errors.append(f"Git clone failed: {result.stderr[:200]}")
                        else:
                            # Apply known fixes for specific repositories
                            self._apply_repo_fixes(clone_dir, repo)
                            if progress_callback:
                                progress_callback(phase_label, "Clone complete ✓", get_phase_progress(phase_idx, 1.0))
                    except subprocess.TimeoutExpired:
                        errors.append("Git clone timed out")
                    except Exception as e:
                        errors.append(f"Git clone error: {str(e)}")
            
            phase_idx += 1
        
        # ═══════════════════════════════════════════════════════════════════════
        # PHASE 2: Download Binaries
        # ═══════════════════════════════════════════════════════════════════════
        if has_binaries:
            import urllib.request
            import urllib.error
            
            phase_num += 1
            phase_label = f"Step {phase_num}/{total_phases}: Downloading binaries"
            
            # Filter to only URL-based binaries
            url_binaries = []
            for binary in manifest.bundled_binaries:
                if isinstance(binary, str) and binary.startswith(('http://', 'https://')):
                    url_binaries.append({'url': binary, 'target_path': os.path.basename(binary)})
                elif isinstance(binary, dict) and binary.get('url', '').startswith(('http://', 'https://')):
                    url_binaries.append(binary)
            
            if not url_binaries:
                if progress_callback:
                    progress_callback(phase_label, "No downloads needed ✓", get_phase_progress(phase_idx, 1.0))
            else:
                for i, binary in enumerate(url_binaries):
                    url = binary.get('url', '')
                    target_path = binary.get('target_path', os.path.basename(url))
                    expected_sha256 = binary.get('sha256')
                    binary_name = os.path.basename(target_path)
                    
                    sub_progress = i / len(url_binaries)
                    if progress_callback:
                        progress_callback(phase_label, f"Downloading {binary_name}...", get_phase_progress(phase_idx, sub_progress))
                    
                    full_path = os.path.join(plugin_dir, target_path)
                    os.makedirs(os.path.dirname(full_path), exist_ok=True)
                    
                    if os.path.exists(full_path):
                        continue  # Already exists
                    
                    try:
                        req = urllib.request.Request(url)
                        req.add_header('User-Agent', 'ImageAnarchy/2.0')
                        
                        with urllib.request.urlopen(req, timeout=120) as response:
                            data = response.read()
                        
                        if expected_sha256:
                            import hashlib
                            actual_sha256 = hashlib.sha256(data).hexdigest()
                            if actual_sha256.lower() != expected_sha256.lower():
                                errors.append(f"Binary {binary_name} SHA256 mismatch!")
                                continue
                        
                        with open(full_path, 'wb') as f:
                            f.write(data)
                            
                    except Exception as e:
                        errors.append(f"Failed to download {binary_name}: {str(e)}")
                
                if progress_callback:
                    progress_callback(phase_label, "Downloads complete ✓", get_phase_progress(phase_idx, 1.0))
            
            phase_idx += 1
        
        # ═══════════════════════════════════════════════════════════════════════
        # PHASE 3: Install pip packages
        # ═══════════════════════════════════════════════════════════════════════
        if has_requirements:
            phase_num += 1
            phase_label = f"Step {phase_num}/{total_phases}: Installing pip packages"
            
            if progress_callback:
                progress_callback(phase_label, "Checking installed packages...", get_phase_progress(phase_idx, 0.1))
            
            all_installed, missing, _ = self.check_requirements(plugin_id)
            
            if all_installed:
                if progress_callback:
                    progress_callback(phase_label, "All packages installed ✓", get_phase_progress(phase_idx, 1.0))
            else:
                if progress_callback:
                    pkg_list = ", ".join(missing[:3]) + ("..." if len(missing) > 3 else "")
                    progress_callback(phase_label, f"Installing {len(missing)} packages: {pkg_list}", get_phase_progress(phase_idx, 0.3))
                
                success, msg = self.install_requirements(missing)
                if not success:
                    errors.append(f"Pip install failed: {msg}")
                else:
                    if progress_callback:
                        progress_callback(phase_label, "Packages installed ✓", get_phase_progress(phase_idx, 1.0))
            
            phase_idx += 1
        
        # ═══════════════════════════════════════════════════════════════════════
        # PHASE 4: Run setup commands (e.g., "pip install .")
        # ═══════════════════════════════════════════════════════════════════════
        if has_setup_commands:
            phase_num += 1
            phase_label = f"Step {phase_num}/{total_phases}: Running setup commands"
            
            for i, cmd in enumerate(manifest.setup_commands):
                if not cmd or not isinstance(cmd, str):
                    continue
                
                cmd_display = cmd[:40] + "..." if len(cmd) > 40 else cmd
                sub_progress = i / len(manifest.setup_commands)
                
                if progress_callback:
                    progress_callback(phase_label, f"Running: {cmd_display}", get_phase_progress(phase_idx, sub_progress))
                
                try:
                    # Determine working directory
                    run_cwd = plugin_dir
                    if manifest.git_clone:
                        target = manifest.git_clone.get('target', '')
                        if target:
                            potential_cwd = os.path.join(plugin_dir, target)
                        else:
                            repo = manifest.git_clone.get('repo', '')
                            repo_name = repo.rstrip('/').split('/')[-1].replace('.git', '')
                            potential_cwd = os.path.join(plugin_dir, repo_name)
                        if os.path.exists(potential_cwd):
                            run_cwd = potential_cwd
                    
                    # Handle pip install specially
                    if os.name == 'nt' and 'pip install' in cmd.lower():
                        python_exe = _get_python_executable()
                        if python_exe and 'pip install .' in cmd:
                            if getattr(sys, 'frozen', False):
                                base_dir = os.path.dirname(sys.executable)
                                target_dir = os.path.join(base_dir, 'plugin_packages')
                                os.makedirs(target_dir, exist_ok=True)
                                win_cmd = f'"{python_exe}" -m pip install --target "{target_dir}" .'
                            else:
                                win_cmd = f'"{python_exe}" -m pip install .'
                        else:
                            win_cmd = cmd
                        
                        result = subprocess.run(
                            win_cmd, shell=True, capture_output=True, text=True,
                            timeout=600, cwd=run_cwd
                        )
                    else:
                        result = subprocess.run(
                            cmd, shell=True, capture_output=True, text=True,
                            timeout=300, cwd=run_cwd
                        )
                    
                    if result.returncode != 0:
                        stderr = result.stderr[:300] if result.stderr else "Unknown error"
                        errors.append(f"Setup command failed: {cmd_display}\n{stderr}")
                        
                except subprocess.TimeoutExpired:
                    errors.append(f"Setup command timed out: {cmd_display}")
                except Exception as e:
                    errors.append(f"Setup command error: {cmd_display}\n{str(e)}")
            
            if progress_callback:
                progress_callback(phase_label, "Setup commands complete ✓", get_phase_progress(phase_idx, 1.0))
            
            phase_idx += 1
        
        # ═══════════════════════════════════════════════════════════════════════
        # PHASE 5: Post-install (drivers, etc.) - runs last
        # ═══════════════════════════════════════════════════════════════════════
        if has_post_install:
            phase_num += 1
            phase_label = f"Step {phase_num}/{total_phases}: Post-install steps"
            
            if progress_callback:
                progress_callback(phase_label, "Running post-install...", get_phase_progress(phase_idx, 0.5))
            
            success, msg = self.run_post_install(plugin_id, lambda name, status: None)
            if not success:
                errors.append(f"Post-install: {msg}")
            
            if progress_callback:
                progress_callback(phase_label, "Post-install complete ✓", get_phase_progress(phase_idx, 1.0))
            
            phase_idx += 1
        
        # ═══════════════════════════════════════════════════════════════════════
        # FINALIZE: Mark setup complete
        # ═══════════════════════════════════════════════════════════════════════
        if progress_callback:
            progress_callback("Setup Complete", "Finalizing...", 100)
        
        # Mark setup as complete in config
        if plugin_id not in self.config:
            self.config[plugin_id] = {}
        self.config[plugin_id]['setup_complete'] = True
        self.config[plugin_id]['post_install_done'] = True
        self._save_config()
        
        if errors:
            return False, "\n".join(errors)
        return True, "Plugin setup completed successfully"
    
    def is_plugin_setup_complete(self, plugin_id: str) -> bool:
        """Check if a plugin's setup has been completed."""
        plugin_config = self.config.get(plugin_id, {})
        if plugin_config.get('setup_complete', False):
            return True
        
        # Also check if manifest has any setup requirements
        manifest = self.manifests.get(plugin_id)
        if not manifest:
            # Try to load manifest
            plugins_dir = self._get_plugins_dir()
            manifest_path = os.path.join(plugins_dir, plugin_id, 'manifest.json')
            if os.path.exists(manifest_path):
                try:
                    with open(manifest_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    manifest = PluginManifest.from_dict(data, plugin_id)
                except Exception:
                    return True  # Can't read manifest, assume setup done
        
        if not manifest:
            return True  # No manifest, assume setup done
        
        # If no setup requirements, consider it complete
        has_requirements = bool(manifest.requirements or manifest.git_clone or manifest.bundled_binaries or manifest.setup_commands or manifest.post_install)
        if not has_requirements:
            return True
        
        return False
    
    def create_example_plugin(self):
        """Create a developer guide plugin to show how to create plugins."""
        plugins_dir = self._get_plugins_dir()
        guide_dir = os.path.join(plugins_dir, "developer_guide")
        
        if os.path.exists(guide_dir):
            return  # Already exists
        
        os.makedirs(guide_dir, exist_ok=True)
        
        # Create manifest.json
        manifest = {
            "name": "Plugin Developer Guide",
            "version": "1.0",
            "description": "Learn how to create plugins for Image Anarchy - earn money doing what you love!",
            "author": "Image Anarchy",
            "icon": "🛠️",
            "license_type": "free",
            "website": "https://github.com/vehoelite/image-anarchy",
            "min_version": "1.0"
        }
        
        with open(os.path.join(guide_dir, "manifest.json"), 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2)
        
        # Create plugin.py - Developer Guide
        plugin_code = '''"""
Plugin Developer Guide for Image Anarchy
Learn how to create plugins and monetize your skills!
"""

from __main__ import PluginBase
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QTextEdit, QGroupBox, QScrollArea, QFrame
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
        hero = QLabel("Create Plugins for Image Anarchy")
        hero.setStyleSheet("font-size: 24px; font-weight: bold; color: #4fc3f7;")
        hero.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(hero)
        
        subtitle = QLabel("Build powerful tools for Android enthusiasts - and earn money doing it!")
        subtitle.setStyleSheet("font-size: 14px; color: #aaa; margin-bottom: 20px;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)
        
        # Why Create Plugins
        why_group = QGroupBox("Why Create Plugins?")
        why_layout = QVBoxLayout(why_group)
        why_items = [
            "Reach thousands of users - Image Anarchy is used by Android enthusiasts worldwide",
            "Monetize your skills - Set your price, accept BTC, PayPal, Ko-fi, or Patreon",
            "It is incredibly easy - Just 2 files: manifest.json + plugin.py",
            "Full PyQt6 power - Create any UI you can imagine",
            "Access core features - Use Image Anarchy extractors, packers, and utilities"
        ]
        for item in why_items:
            lbl = QLabel("* " + item)
            lbl.setWordWrap(True)
            lbl.setStyleSheet("font-size: 13px; padding: 4px 0;")
            why_layout.addWidget(lbl)
        layout.addWidget(why_group)
        
        # How Easy Section
        easy_group = QGroupBox("How Easy Is It? Just 3 Steps!")
        easy_layout = QVBoxLayout(easy_group)
        
        steps = [
            ("Step 1:", "Create a folder in the plugins directory"),
            ("Step 2:", "Add manifest.json with your plugin info (name, author, price)"),
            ("Step 3:", "Add plugin.py with your code - implement create_widget()"),
        ]
        for title, desc in steps:
            step_lbl = QLabel(f"<b>{title}</b> {desc}")
            step_lbl.setTextFormat(Qt.TextFormat.RichText)
            step_lbl.setStyleSheet("font-size: 13px; padding: 6px 0;")
            easy_layout.addWidget(step_lbl)
        layout.addWidget(easy_group)
        
        # Code Example
        code_group = QGroupBox("Minimal Plugin Example (plugin.py)")
        code_layout = QVBoxLayout(code_group)
        
        code_text = QTextEdit()
        code_text.setReadOnly(True)
        code_text.setMaximumHeight(260)
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
        
        # Monetization Section
        money_group = QGroupBox("Monetization Options")
        money_layout = QVBoxLayout(money_group)
        
        money_intro = QLabel("Set license_type in your manifest.json:")
        money_intro.setStyleSheet("font-size: 13px; font-weight: bold;")
        money_layout.addWidget(money_intro)
        
        license_types = [
            '"free" - Open to everyone',
            '"donation" - Free with optional tip jar shown to users',
            '"paid" - Users see your price and payment info before using',
        ]
        for lt in license_types:
            lbl = QLabel("* " + lt)
            lbl.setStyleSheet("font-size: 12px; padding: 2px 0;")
            money_layout.addWidget(lbl)
        
        payment_label = QLabel("\\nSupported payment methods:")
        payment_label.setStyleSheet("font-size: 13px; font-weight: bold;")
        money_layout.addWidget(payment_label)
        
        payments = ["Bitcoin (BTC) - Direct wallet", "PayPal - Payment links", 
                   "Ko-fi - Creator support", "Patreon - Subscriptions", "GitHub Sponsors"]
        for p in payments:
            lbl = QLabel("* " + p)
            lbl.setStyleSheet("font-size: 12px; padding: 2px 0;")
            money_layout.addWidget(lbl)
        layout.addWidget(money_group)
        
        # Requirements Section
        req_group = QGroupBox("Using pip Packages")
        req_layout = QVBoxLayout(req_group)
        
        req_intro = QLabel("Need external packages? Add them to manifest.json:")
        req_intro.setStyleSheet("font-size: 13px; font-weight: bold;")
        req_layout.addWidget(req_intro)
        
        req_example = QTextEdit()
        req_example.setReadOnly(True)
        req_example.setMaximumHeight(80)
        req_example.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a2e;
                color: #4fc3f7;
                font-family: Consolas, Courier New, monospace;
                font-size: 11px;
                padding: 8px;
                border: 1px solid #333;
            }
        """)
        req_example.setPlainText('{\n    "requirements": ["requests", "pillow>=9.0", "beautifulsoup4"]\n}')
        req_layout.addWidget(req_example)
        
        req_note = QLabel("Users will be prompted to install missing packages automatically!")
        req_note.setStyleSheet("font-size: 12px; color: #4caf50; padding: 4px 0;")
        req_layout.addWidget(req_note)
        layout.addWidget(req_group)
        
        # Plugin Ideas
        ideas_group = QGroupBox("Plugin Ideas to Get You Started")
        ideas_layout = QVBoxLayout(ideas_group)
        
        ideas = [
            "Build.prop Editor - Visual editor for system properties",
            "Boot Animation Creator - Design custom boot animations", 
            "Partition Analyzer - Deep analysis of partition contents",
            "Device Profiles - Save/restore device configurations",
            "Batch Processor - Process multiple images at once",
            "OTA Downloader - Download OTAs from manufacturers",
        ]
        for idea in ideas:
            lbl = QLabel("* " + idea)
            lbl.setStyleSheet("font-size: 12px; padding: 2px 0;")
            ideas_layout.addWidget(lbl)
        layout.addWidget(ideas_group)
        
        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        docs_btn = QPushButton("Documentation")
        docs_btn.setStyleSheet("padding: 10px 20px;")
        docs_btn.clicked.connect(lambda: webbrowser.open("https://github.com/vehoelite/image-anarchy"))
        btn_layout.addWidget(docs_btn)
        
        folder_btn = QPushButton("Open Plugins Folder")
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
    
    def _open_folder(self):
        plugins_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if sys.platform == "win32":
            os.startfile(plugins_dir)
        elif sys.platform == "darwin":
            subprocess.run(["open", plugins_dir])
        else:
            subprocess.run(["xdg-open", plugins_dir])
'''
        
        with open(os.path.join(guide_dir, "plugin.py"), 'w', encoding='utf-8') as f:
            f.write(plugin_code)
        
        # Create README
        readme = """# Plugin Developer Guide

Learn how to create plugins for Image Anarchy!

## Quick Start

1. Create a folder in `plugins/`
2. Add `manifest.json` with your plugin info
3. Add `plugin.py` with your PluginBase class
4. Restart Image Anarchy - your plugin appears automatically!

## Manifest Example

```json
{
    "name": "My Cool Plugin",
    "version": "1.0",
    "description": "Does amazing things",
    "author": "Your Name",
    "icon": "rocket",
    "license_type": "paid",
    "price": 5.00,
    "currency": "USD",
    "payment_address": "your-btc-address",
    "payment_type": "btc"
}
```

## Resources

- Documentation: https://github.com/vehoelite/image-anarchy
- Community: XDA Forums
"""
        
        with open(os.path.join(guide_dir, "README.md"), 'w', encoding='utf-8') as f:
            f.write(readme)


# Global plugin manager
plugin_manager = PluginManager()


# =============================================================================
# GUI COMPONENTS (PyQt6)
# =============================================================================

def create_gui_app():
    """Create and return the GUI application. Imports PyQt6 only when needed."""
    
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QPushButton, QFileDialog, QListWidget,
        QListWidgetItem, QProgressBar, QTextEdit, QGroupBox, QCheckBox,
        QSplitter, QStatusBar, QMessageBox, QAbstractItemView, QTabWidget,
        QComboBox, QSpinBox, QTreeWidget, QTreeWidgetItem, QHeaderView,
        QFormLayout, QRadioButton, QScrollArea, QFrame, QMenu, QDoubleSpinBox,
        QGridLayout, QDialog, QInputDialog, QSystemTrayIcon, QGraphicsOpacityEffect
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QPoint, QEasingCurve
    from PyQt6.QtGui import QFont, QDragEnterEvent, QDropEvent, QPalette, QColor, QAction, QIcon, QPixmap, QPainter

    # =========================================================================
    # ANARCHY TOAST NOTIFICATION SYSTEM
    # =========================================================================
    
    class AnarchyToast(QLabel):
        """Rebellious toast notification - burns bright and fades away."""
        
        TOAST_STYLES = {
            'success': ('🔥', '#2e7d32', '#1b5e20'),
            'error': ('💀', '#c62828', '#b71c1c'),
            'warning': ('⚠️', '#f57c00', '#e65100'),
            'info': ('Ⓐ', '#1565c0', '#0d47a1'),
            'chaos': ('🏴', '#6a1b9a', '#4a148c'),
        }
        
        def __init__(self, parent, message: str, toast_type: str = 'info', duration: int = 3000):
            super().__init__(parent)
            
            icon, bg_color, border_color = self.TOAST_STYLES.get(toast_type, self.TOAST_STYLES['info'])
            
            self.setText(f"  {icon}  {message}  ")
            self.setStyleSheet(f"""
                QLabel {{
                    background-color: {bg_color};
                    color: white;
                    padding: 12px 20px;
                    border-radius: 8px;
                    border: 2px solid {border_color};
                    font-size: 13px;
                    font-weight: bold;
                }}
            """)
            self.setWordWrap(True)
            self.setMaximumWidth(400)
            self.adjustSize()
            
            # Position at bottom-right of parent
            self._position_toast()
            
            # Fade in animation
            self.opacity_effect = QGraphicsOpacityEffect(self)
            self.setGraphicsEffect(self.opacity_effect)
            
            self.fade_in = QPropertyAnimation(self.opacity_effect, b"opacity")
            self.fade_in.setDuration(200)
            self.fade_in.setStartValue(0)
            self.fade_in.setEndValue(1)
            
            # Fade out after duration
            self.fade_out = QPropertyAnimation(self.opacity_effect, b"opacity")
            self.fade_out.setDuration(500)
            self.fade_out.setStartValue(1)
            self.fade_out.setEndValue(0)
            self.fade_out.finished.connect(self.deleteLater)
            
            # Timer to start fade out
            self.timer = QTimer(self)
            self.timer.setSingleShot(True)
            self.timer.timeout.connect(self.fade_out.start)
            self.timer.start(duration)
            
            self.show()
            self.fade_in.start()
        
        def _position_toast(self):
            """Position toast at bottom-right with offset for stacking."""
            if self.parent():
                parent_rect = self.parent().rect()
                # Count existing toasts for stacking
                existing_toasts = [c for c in self.parent().children() 
                                   if isinstance(c, AnarchyToast) and c != self and c.isVisible()]
                offset = len(existing_toasts) * 60
                
                x = parent_rect.width() - self.width() - 20
                y = parent_rect.height() - self.height() - 20 - offset
                self.move(x, max(20, y))

    # =========================================================================
    # PRE-READY CHECKLIST SPLASH SCREEN
    # =========================================================================
    
    class PreReadyChecklistDialog(QDialog):
        """Splash screen that checks user's environment before starting."""
        
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Image Anarchy - Environment Check")
            self.setMinimumSize(650, 550)
            self.setModal(True)
            
            # Get app directory for drivers
            self.app_dir = Path(__file__).parent if '__file__' in dir() else Path.cwd()
            self.drivers_dir = self.app_dir / "drivers"
            
            self._setup_ui()
            self._check_environment()
        
        def _setup_ui(self):
            layout = QVBoxLayout(self)
            layout.setSpacing(16)
            layout.setContentsMargins(24, 24, 24, 24)
            
            # Header
            header = QLabel("🔧 Pre-Ready Checklist")
            header.setStyleSheet("font-size: 22px; font-weight: bold; color: #4fc3f7;")
            header.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(header)
            
            subtitle = QLabel("Checking your environment for Android development tools...")
            subtitle.setStyleSheet("font-size: 13px; color: #aaa;")
            subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(subtitle)
            
            # OS Detection
            os_group = QGroupBox("Operating System")
            os_layout = QVBoxLayout(os_group)
            
            self.os_label = QLabel()
            self.os_label.setStyleSheet("font-size: 14px; padding: 8px;")
            os_layout.addWidget(self.os_label)
            
            layout.addWidget(os_group)
            
            # Windows-specific section
            self.windows_group = QGroupBox("Windows Driver Signing (Required for unsigned USB drivers)")
            self.windows_layout = QVBoxLayout(self.windows_group)
            
            info_label = QLabel(
                "⚠️ These commands disable driver signature enforcement.\n"
                "Required to use unsigned Android USB drivers. Run as Administrator."
            )
            info_label.setStyleSheet("color: #FFA500; font-size: 11px; padding: 4px;")
            info_label.setWordWrap(True)
            self.windows_layout.addWidget(info_label)
            
            # Command 1: nointegritychecks
            self.cmd1_layout = QHBoxLayout()
            self.cmd1_status = QLabel("⏳")
            self.cmd1_status.setFixedWidth(30)
            self.cmd1_label = QLabel("bcdedit.exe -set nointegritychecks on")
            self.cmd1_label.setStyleSheet("font-family: Consolas; font-size: 12px; padding: 4px; background: #2d2d2d; border-radius: 4px;")
            self.cmd1_btn = QPushButton("Run")
            self.cmd1_btn.setFixedWidth(80)
            self.cmd1_btn.clicked.connect(lambda: self._run_bcdedit_command("bcdedit.exe -set nointegritychecks on"))
            self.cmd1_layout.addWidget(self.cmd1_status)
            self.cmd1_layout.addWidget(self.cmd1_label, 1)
            self.cmd1_layout.addWidget(self.cmd1_btn)
            self.windows_layout.addLayout(self.cmd1_layout)
            
            # Command 2: DISABLE_INTEGRITY_CHECKS
            self.cmd2_layout = QHBoxLayout()
            self.cmd2_status = QLabel("⏳")
            self.cmd2_status.setFixedWidth(30)
            self.cmd2_label = QLabel("bcdedit.exe -set loadoptions DISABLE_INTEGRITY_CHECKS")
            self.cmd2_label.setStyleSheet("font-family: Consolas; font-size: 12px; padding: 4px; background: #2d2d2d; border-radius: 4px;")
            self.cmd2_btn = QPushButton("Run")
            self.cmd2_btn.setFixedWidth(80)
            self.cmd2_btn.clicked.connect(lambda: self._run_bcdedit_command("bcdedit.exe -set loadoptions DISABLE_INTEGRITY_CHECKS"))
            self.cmd2_layout.addWidget(self.cmd2_status)
            self.cmd2_layout.addWidget(self.cmd2_label, 1)
            self.cmd2_layout.addWidget(self.cmd2_btn)
            self.windows_layout.addLayout(self.cmd2_layout)
            
            # Command 3: TESTSIGNING
            self.cmd3_layout = QHBoxLayout()
            self.cmd3_status = QLabel("⏳")
            self.cmd3_status.setFixedWidth(30)
            self.cmd3_label = QLabel("bcdedit.exe -set TESTSIGNING ON")
            self.cmd3_label.setStyleSheet("font-family: Consolas; font-size: 12px; padding: 4px; background: #2d2d2d; border-radius: 4px;")
            self.cmd3_btn = QPushButton("Run")
            self.cmd3_btn.setFixedWidth(80)
            self.cmd3_btn.clicked.connect(lambda: self._run_bcdedit_command("bcdedit.exe -set TESTSIGNING ON"))
            self.cmd3_layout.addWidget(self.cmd3_status)
            self.cmd3_layout.addWidget(self.cmd3_label, 1)
            self.cmd3_layout.addWidget(self.cmd3_btn)
            self.windows_layout.addLayout(self.cmd3_layout)
            
            # Run All button
            run_all_btn = QPushButton("⚡ Run All Commands (Admin Required)")
            run_all_btn.setStyleSheet("padding: 10px; font-weight: bold;")
            run_all_btn.clicked.connect(self._run_all_commands)
            self.windows_layout.addWidget(run_all_btn)
            
            layout.addWidget(self.windows_group)
            
            # Drivers section
            self.drivers_group = QGroupBox("USB Drivers (Click to Install)")
            drivers_layout = QGridLayout(self.drivers_group)
            drivers_layout.setSpacing(8)
            
            # Driver buttons with their installers
            self.driver_buttons = []
            drivers = [
                ("📱 ZTE USB Drivers", "ZTE_Android_Driver.exe", "ZTE devices"),
                ("📱 Samsung USB Drivers", "SAMSUNG_USB_Driver_for_Mobile_Phones_v1.9.0.0.exe", "Samsung Galaxy"),
                ("📱 MTK USB Drivers", "MTK_Driver_Setup.exe", "MediaTek devices"),
                ("📱 Motorola USB Drivers", "Motorola_Mobile_Drivers_64bit.msi", "Motorola/Lenovo"),
                ("📱 Alcatel USB Drivers", "Mobile_Upgrade_S_Gotu2_v6.1.0_Setup.exe", "Alcatel devices"),
                ("📱 LG USB Drivers", "LG_Mobile _Driver_v4.8.0.exe", "LG devices"),
            ]
            
            for i, (name, filename, tooltip) in enumerate(drivers):
                btn = QPushButton(name)
                btn.setToolTip(f"Install drivers for {tooltip}")
                btn.setStyleSheet("padding: 10px; text-align: left;")
                driver_path = self.drivers_dir / filename
                if driver_path.exists():
                    btn.clicked.connect(lambda checked, p=str(driver_path): self._install_driver(p))
                else:
                    btn.setEnabled(False)
                    btn.setToolTip(f"Driver not found: {filename}")
                    btn.setText(f"{name} (Not found)")
                drivers_layout.addWidget(btn, i // 2, i % 2)
                self.driver_buttons.append(btn)
            
            layout.addWidget(self.drivers_group)
            
            # Buttons
            btn_layout = QHBoxLayout()
            btn_layout.addStretch()
            
            refresh_btn = QPushButton("🔄 Refresh Status")
            refresh_btn.clicked.connect(self._check_environment)
            btn_layout.addWidget(refresh_btn)
            
            skip_btn = QPushButton("Skip →")
            skip_btn.setStyleSheet("padding: 10px 20px;")
            skip_btn.clicked.connect(self.accept)
            btn_layout.addWidget(skip_btn)
            
            continue_btn = QPushButton("Continue ✓")
            continue_btn.setProperty("primary", True)
            continue_btn.setStyleSheet("padding: 10px 20px; background-color: #0078d4; color: white; font-weight: bold;")
            continue_btn.clicked.connect(self.accept)
            btn_layout.addWidget(continue_btn)
            
            layout.addLayout(btn_layout)
        
        def _check_environment(self):
            """Check the current environment and update UI."""
            is_windows = sys.platform == 'win32'
            is_linux = sys.platform.startswith('linux')
            is_mac = sys.platform == 'darwin'
            
            if is_linux:
                self.os_label.setText("🐧 Linux Detected - Good to go! No driver signing issues.")
                self.os_label.setStyleSheet("font-size: 14px; padding: 8px; color: #4CAF50; background: #1b3d1b; border-radius: 4px;")
                self.windows_group.setVisible(False)
                self.drivers_group.setVisible(False)
            elif is_mac:
                self.os_label.setText("🍎 macOS Detected - Good to go! No driver signing issues.")
                self.os_label.setStyleSheet("font-size: 14px; padding: 8px; color: #4CAF50; background: #1b3d1b; border-radius: 4px;")
                self.windows_group.setVisible(False)
                self.drivers_group.setVisible(False)
            elif is_windows:
                self.os_label.setText("🪟 Windows Detected - Driver signing configuration may be needed.")
                self.os_label.setStyleSheet("font-size: 14px; padding: 8px; color: #FFA500; background: #3d3520; border-radius: 4px;")
                self.windows_group.setVisible(True)
                self.drivers_group.setVisible(True)
                self._check_windows_signing()
            else:
                self.os_label.setText(f"❓ Unknown OS: {sys.platform}")
                self.os_label.setStyleSheet("font-size: 14px; padding: 8px;")
                self.windows_group.setVisible(False)
        
        def _check_windows_signing(self):
            """Check Windows BCD settings for driver signing."""
            try:
                # Run bcdedit to get current settings
                result = subprocess.run(
                    ['bcdedit', '/enum', '{current}'],
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                )
                output = result.stdout.lower()
                
                # Check nointegritychecks
                if 'nointegritychecks' in output and 'yes' in output:
                    self.cmd1_status.setText("✅")
                    self.cmd1_label.setStyleSheet("font-family: Consolas; font-size: 12px; padding: 4px; background: #1b3d1b; border-radius: 4px; color: #4CAF50; text-decoration: line-through;")
                    self.cmd1_btn.setEnabled(False)
                    self.cmd1_btn.setText("Done")
                else:
                    self.cmd1_status.setText("❌")
                    self.cmd1_label.setStyleSheet("font-family: Consolas; font-size: 12px; padding: 4px; background: #2d2d2d; border-radius: 4px;")
                    self.cmd1_btn.setEnabled(True)
                    self.cmd1_btn.setText("Run")
                
                # Check loadoptions DISABLE_INTEGRITY_CHECKS
                if 'disable_integrity_checks' in output:
                    self.cmd2_status.setText("✅")
                    self.cmd2_label.setStyleSheet("font-family: Consolas; font-size: 12px; padding: 4px; background: #1b3d1b; border-radius: 4px; color: #4CAF50; text-decoration: line-through;")
                    self.cmd2_btn.setEnabled(False)
                    self.cmd2_btn.setText("Done")
                else:
                    self.cmd2_status.setText("❌")
                    self.cmd2_label.setStyleSheet("font-family: Consolas; font-size: 12px; padding: 4px; background: #2d2d2d; border-radius: 4px;")
                    self.cmd2_btn.setEnabled(True)
                    self.cmd2_btn.setText("Run")
                
                # Check TESTSIGNING
                if 'testsigning' in output and 'yes' in output:
                    self.cmd3_status.setText("✅")
                    self.cmd3_label.setStyleSheet("font-family: Consolas; font-size: 12px; padding: 4px; background: #1b3d1b; border-radius: 4px; color: #4CAF50; text-decoration: line-through;")
                    self.cmd3_btn.setEnabled(False)
                    self.cmd3_btn.setText("Done")
                else:
                    self.cmd3_status.setText("❌")
                    self.cmd3_label.setStyleSheet("font-family: Consolas; font-size: 12px; padding: 4px; background: #2d2d2d; border-radius: 4px;")
                    self.cmd3_btn.setEnabled(True)
                    self.cmd3_btn.setText("Run")
                    
            except Exception as e:
                # Can't check - likely not admin
                self.cmd1_status.setText("❓")
                self.cmd2_status.setText("❓")
                self.cmd3_status.setText("❓")
        
        def _run_bcdedit_command(self, command):
            """Run a bcdedit command with admin privileges."""
            try:
                if sys.platform == 'win32':
                    # Use PowerShell Start-Process with -Verb RunAs for elevation
                    ps_command = f'Start-Process cmd -ArgumentList "/c {command}" -Verb RunAs -Wait'
                    subprocess.run(['powershell', '-Command', ps_command], check=False)
                    # Refresh status after command
                    QTimer.singleShot(1000, self._check_windows_signing)
                    QMessageBox.information(self, "Command Executed", 
                        f"Command executed. A reboot may be required for changes to take effect.\n\n{command}")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to run command:\n{e}")
        
        def _run_all_commands(self):
            """Run all bcdedit commands at once."""
            try:
                if sys.platform == 'win32':
                    commands = [
                        "bcdedit.exe -set nointegritychecks on",
                        "bcdedit.exe -set loadoptions DISABLE_INTEGRITY_CHECKS",
                        "bcdedit.exe -set TESTSIGNING ON"
                    ]
                    combined = " && ".join(commands)
                    ps_command = f'Start-Process cmd -ArgumentList "/c {combined}" -Verb RunAs -Wait'
                    subprocess.run(['powershell', '-Command', ps_command], check=False)
                    QTimer.singleShot(1000, self._check_windows_signing)
                    QMessageBox.information(self, "Commands Executed",
                        "All commands executed. A reboot is required for changes to take effect.")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to run commands:\n{e}")
        
        def _install_driver(self, driver_path):
            """Install a driver package."""
            try:
                if sys.platform == 'win32':
                    if driver_path.endswith('.msi'):
                        # MSI installer
                        subprocess.Popen(['msiexec', '/i', driver_path], creationflags=subprocess.CREATE_NO_WINDOW)
                    else:
                        # EXE installer - run with elevation
                        ps_command = f'Start-Process "{driver_path}" -Verb RunAs'
                        subprocess.run(['powershell', '-Command', ps_command], check=False)
                    QMessageBox.information(self, "Driver Installer", 
                        f"Driver installer launched:\n{Path(driver_path).name}\n\nFollow the on-screen instructions.")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to launch installer:\n{e}")

    @dataclass
    class PartitionDisplayInfo:
        """Information about a partition for display in the UI."""
        name: str
        size: int
        operations_count: int

    class PayloadAnalyzerThread(QThread):
        """Thread for analyzing payload files without blocking the UI."""
        
        finished = pyqtSignal(list)
        error = pyqtSignal(str)
        status = pyqtSignal(str)
        
        def __init__(self, payload_path: str):
            super().__init__()
            self.payload_path = payload_path
        
        def run(self):
            try:
                self.status.emit("Opening payload file...")
                with PayloadFile(self.payload_path) as payload_file:
                    self.status.emit("Reading manifest...")
                    
                    magic = payload_file.read(4)
                    if magic != PAYLOAD_MAGIC:
                        raise PayloadError("Invalid payload file")
                    
                    format_version = unpack_u64(payload_file.read(8))
                    if format_version != SUPPORTED_FORMAT_VERSION:
                        raise PayloadError(f"Unsupported format version: {format_version}")
                    
                    manifest_size = unpack_u64(payload_file.read(8))
                    metadata_signature_size = unpack_u32(payload_file.read(4))
                    manifest_data = payload_file.read(manifest_size)
                    
                    manifest = DeltaArchiveManifest()
                    manifest.ParseFromString(manifest_data)
                    
                    partitions = []
                    for part in manifest.partitions:
                        size = sum(
                            ext.num_blocks * manifest.block_size 
                            for op in part.operations 
                            for ext in op.dst_extents
                        )
                        partitions.append(PartitionDisplayInfo(
                            name=part.partition_name,
                            size=size,
                            operations_count=len(part.operations)
                        ))
                    
                    self.status.emit(f"Found {len(partitions)} partitions")
                    self.finished.emit(partitions)
                    
            except Exception as e:
                self.error.emit(str(e))

    class ExtractionThread(QThread):
        """Thread for extracting partitions without blocking the UI."""
        
        progress = pyqtSignal(int, int)
        partition_started = pyqtSignal(str)
        partition_finished = pyqtSignal(str)
        log = pyqtSignal(str)
        error = pyqtSignal(str)
        finished = pyqtSignal()
        
        def __init__(self, payload_path: str, output_dir: str, 
                     partitions: list[str], old_dir: Optional[str] = None,
                     extract_super: bool = False):
            super().__init__()
            self.payload_path = payload_path
            self.output_dir = output_dir
            self.partitions = partitions
            self.old_dir = old_dir
            self.extract_super = extract_super
            self._cancelled = False
            self._extracted_super_path = None
        
        def cancel(self):
            self._cancelled = True
        
        def run(self):
            try:
                Path(self.output_dir).mkdir(parents=True, exist_ok=True)
                
                with PayloadFile(self.payload_path) as payload_file:
                    magic = payload_file.read(4)
                    format_version = unpack_u64(payload_file.read(8))
                    manifest_size = unpack_u64(payload_file.read(8))
                    metadata_signature_size = unpack_u32(payload_file.read(4))
                    
                    manifest_data = payload_file.read(manifest_size)
                    payload_file.read(metadata_signature_size)
                    data_offset = payload_file.tell()
                    
                    manifest = DeltaArchiveManifest()
                    manifest.ParseFromString(manifest_data)
                    
                    handler = OperationHandler(payload_file, data_offset, manifest.block_size)
                    
                    parts_to_extract = [
                        p for p in manifest.partitions 
                        if p.partition_name in self.partitions
                    ]
                    
                    total_ops = sum(len(p.operations) for p in parts_to_extract)
                    current_op = 0
                    
                    for partition in parts_to_extract:
                        if self._cancelled:
                            self.log.emit("Extraction cancelled")
                            return
                        
                        name = partition.partition_name
                        self.partition_started.emit(name)
                        self.log.emit(f"Extracting {name}...")
                        
                        output_path = Path(self.output_dir) / f"{name}.img"
                        old_file = None
                        
                        if self.old_dir:
                            old_path = Path(self.old_dir) / f"{name}.img"
                            if old_path.exists():
                                old_file = open(old_path, 'rb')
                            else:
                                self.log.emit(f"  Warning: Original image not found for {name}")
                        
                        try:
                            with open(output_path, 'wb') as out_file:
                                for op in partition.operations:
                                    if self._cancelled:
                                        return
                                    handler.process(op, out_file, old_file)
                                    current_op += 1
                                    self.progress.emit(current_op, total_ops)
                        finally:
                            if old_file:
                                old_file.close()
                        
                        self.partition_finished.emit(name)
                        self.log.emit(f"  Done: {output_path}")
                        
                        # Track super partition for post-extraction
                        if name == 'super' and self.extract_super:
                            self._extracted_super_path = str(output_path)
                    
                    # Extract super partition contents if requested
                    if self._extracted_super_path and self.extract_super:
                        self._extract_super_contents()
                    
                    self.log.emit("\nExtraction complete!")
                    self.finished.emit()
                    
            except Exception as e:
                self.error.emit(str(e))
        
        def _extract_super_contents(self):
            """Extract partitions from super.img after payload extraction."""
            if not self._extracted_super_path or not Path(self._extracted_super_path).exists():
                return
            
            self.log.emit("\n" + "="*50)
            self.log.emit("Extracting super partition contents...")
            self.log.emit("="*50)
            
            try:
                # Check if it's a valid super image
                img_type = detect_image_type(self._extracted_super_path)
                
                if img_type == 'sparse':
                    # First convert sparse to raw
                    self.log.emit("Super image is sparse, converting to raw first...")
                    raw_path = self._extracted_super_path.replace('.img', '_raw.img')
                    converter = SparseImageConverter()
                    converter.convert(self._extracted_super_path, raw_path)
                    self.log.emit(f"  Converted to: {raw_path}")
                    super_path = raw_path
                else:
                    super_path = self._extracted_super_path
                
                # Check again for super partition magic
                img_type = detect_image_type(super_path)
                
                if img_type != 'super':
                    self.log.emit(f"Warning: super.img is not a dynamic partition image (type: {img_type})")
                    self.log.emit("Skipping super extraction")
                    return
                
                # Create output directory for super contents
                super_output_dir = Path(self.output_dir) / "super_extracted"
                super_output_dir.mkdir(parents=True, exist_ok=True)
                
                # List partitions in super image
                extractor = SuperImageExtractor()
                partitions = extractor.list_partitions(super_path)
                
                if not partitions:
                    self.log.emit("No partitions found in super image")
                    return
                
                valid_partitions = [p for p in partitions if p.size > 0]
                self.log.emit(f"Found {len(valid_partitions)} partition(s) in super image:")
                
                for p in valid_partitions:
                    self.log.emit(f"  - {p.name}: {p.size / (1024*1024):.2f} MB")
                
                # Extract all partitions
                self.log.emit("\nExtracting partitions from super image...")
                results = extractor.extract(super_path, str(super_output_dir))
                
                for name, path in results.items():
                    self.log.emit(f"  Extracted: {name} -> {path}")
                    
                    # Detect and report sub-partition types
                    if Path(path).exists():
                        sub_type = detect_image_type(path)
                        if sub_type != 'raw':
                            self.log.emit(f"    (Type: {sub_type})")
                
                self.log.emit(f"\nSuper partition contents extracted to: {super_output_dir}")
                
            except Exception as e:
                self.log.emit(f"Error extracting super partition: {e}")

    class CreationThread(QThread):
        """Thread for creating payload files without blocking the UI."""
        
        progress = pyqtSignal(int, int, str)  # current, total, message
        log = pyqtSignal(str)
        error = pyqtSignal(str)
        finished = pyqtSignal(str)  # output path
        
        def __init__(self, image_paths: list[str], output_path: str,
                     compression: str, compression_level: int):
            super().__init__()
            self.image_paths = image_paths
            self.output_path = output_path
            self.compression = compression
            self.compression_level = compression_level
            self._cancelled = False
        
        def cancel(self):
            self._cancelled = True
        
        def run(self):
            try:
                def progress_callback(current, total, msg):
                    if self._cancelled:
                        raise InterruptedError("Cancelled")
                    self.progress.emit(current, total, msg)
                    self.log.emit(f"  {msg}")
                
                self.log.emit(f"Creating payload: {self.output_path}")
                self.log.emit(f"Compression: {self.compression} (level {self.compression_level})")
                self.log.emit(f"Processing {len(self.image_paths)} partition(s)...\n")
                
                creator = PayloadCreator(
                    output_path=self.output_path,
                    compression=self.compression,
                    compression_level=self.compression_level,
                    progress_callback=progress_callback
                )
                creator.create(self.image_paths)
                
                size_mb = Path(self.output_path).stat().st_size / (1024 * 1024)
                self.log.emit(f"\nPayload created: {self.output_path}")
                self.log.emit(f"Size: {size_mb:.2f} MB")
                self.finished.emit(self.output_path)
                
            except InterruptedError:
                self.log.emit("\nCreation cancelled")
            except Exception as e:
                self.error.emit(str(e))

    class DropLineEdit(QLineEdit):
        """Line edit that accepts drag and drop of files."""
        
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setAcceptDrops(True)
            self.setPlaceholderText("Enter path, URL, or drag & drop a file...")
        
        def dragEnterEvent(self, event: QDragEnterEvent):
            if event.mimeData().hasUrls():
                event.acceptProposedAction()
        
        def dropEvent(self, event: QDropEvent):
            urls = event.mimeData().urls()
            if urls:
                self.setText(urls[0].toLocalFile())

    class ImageAnarchyGUI(QMainWindow):
        """Main application window."""
        
        STYLESHEET = """
            QMainWindow, QWidget {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-size: 13px;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #3c3c3c;
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
            }
            QLineEdit, QListWidget, QTextEdit {
                padding: 8px;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                background-color: #2d2d2d;
                selection-background-color: #264f78;
            }
            QLineEdit:focus {
                border-color: #0078d4;
            }
            QPushButton {
                padding: 8px 16px;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                background-color: #2d2d2d;
            }
            QPushButton:hover {
                background-color: #3c3c3c;
            }
            QPushButton:pressed {
                background-color: #1e1e1e;
            }
            QPushButton:disabled {
                color: #6d6d6d;
            }
            QPushButton[primary="true"] {
                background-color: #0078d4;
                border-color: #0078d4;
                color: white;
            }
            QPushButton[primary="true"]:hover {
                background-color: #1084d8;
            }
            QPushButton[primary="true"]:disabled {
                background-color: #2d5a7b;
                color: #8a8a8a;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #3c3c3c;
            }
            QListWidget::item:selected {
                background-color: #264f78;
            }
            QListWidget::item:hover {
                background-color: #3c3c3c;
            }
            QProgressBar {
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                background-color: #2d2d2d;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #0078d4;
                border-radius: 3px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 1px solid #3c3c3c;
                border-radius: 3px;
                background-color: #2d2d2d;
            }
            QCheckBox::indicator:checked {
                background-color: #0078d4;
                border-color: #0078d4;
            }
            QStatusBar {
                background-color: #007acc;
                color: white;
            }
            QSplitter::handle {
                background-color: #3c3c3c;
            }
            QScrollBar:vertical {
                background-color: #1e1e1e;
                width: 12px;
            }
            QScrollBar::handle:vertical {
                background-color: #424242;
                border-radius: 6px;
                min-height: 20px;
                margin: 2px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #525252;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
            }
        """
        
        def __init__(self):
            super().__init__()
            self.analyzer_thread: Optional[PayloadAnalyzerThread] = None
            self.extraction_thread: Optional[ExtractionThread] = None
            self.creation_thread: Optional[CreationThread] = None
            self.partitions: list[PartitionDisplayInfo] = []
            self.repack_images: list[str] = []
            
            self._force_quit = False  # Flag to allow actual quit vs minimize to tray
            self._setup_ui()
            self._apply_styles()
            self._setup_system_tray()
            self._setup_drag_drop()
        
        def _setup_system_tray(self):
            """Setup the rebellious system tray icon."""
            self.tray_icon = QSystemTrayIcon(self)
            
            # Create anarchy icon programmatically
            pixmap = QPixmap(64, 64)
            pixmap.fill(Qt.GlobalColor.transparent)
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            
            # Draw circle-A anarchy symbol
            from PyQt6.QtGui import QPen, QBrush
            from PyQt6.QtCore import QRectF
            
            # Outer circle
            pen = QPen(QColor('#ff4444'))
            pen.setWidth(4)
            painter.setPen(pen)
            painter.drawEllipse(QRectF(4, 4, 56, 56))
            
            # The 'A'
            pen.setWidth(5)
            painter.setPen(pen)
            # Left leg
            painter.drawLine(32, 8, 12, 52)
            # Right leg  
            painter.drawLine(32, 8, 52, 52)
            # Crossbar
            painter.drawLine(18, 36, 46, 36)
            # Extended bottom (the anarchy style)
            painter.drawLine(32, 8, 32, 58)
            
            painter.end()
            self.tray_icon.setIcon(QIcon(pixmap))
            
            # Create context menu
            tray_menu = QMenu()
            tray_menu.setStyleSheet("""
                QMenu {
                    background-color: #2d2d2d;
                    color: #d4d4d4;
                    border: 1px solid #3c3c3c;
                    padding: 4px;
                }
                QMenu::item {
                    padding: 8px 20px;
                }
                QMenu::item:selected {
                    background-color: #c62828;
                }
            """)
            
            # Actions with anarchy flair
            show_action = QAction("🏴 Unleash Anarchy", self)
            show_action.triggered.connect(self._tray_show_window)
            tray_menu.addAction(show_action)
            
            tray_menu.addSeparator()
            
            extract_action = QAction("💣 Quick Extract", self)
            extract_action.triggered.connect(self._tray_quick_extract)
            tray_menu.addAction(extract_action)
            
            tray_menu.addSeparator()
            
            quit_action = QAction("💀 Burn It Down", self)
            quit_action.triggered.connect(self._force_quit_app)
            tray_menu.addAction(quit_action)
            
            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.setToolTip("Image Anarchy - Right-click for chaos")
            self.tray_icon.activated.connect(self._tray_activated)
            self.tray_icon.show()
        
        def _setup_drag_drop(self):
            """Enable drag and drop for the main window."""
            self.setAcceptDrops(True)
        
        def dragEnterEvent(self, event: QDragEnterEvent):
            """Accept drags with file URLs."""
            if event.mimeData().hasUrls():
                # Check if any file is a supported type
                for url in event.mimeData().urls():
                    path = url.toLocalFile().lower()
                    if any(path.endswith(ext) for ext in ['.bin', '.img', '.zip', '.payload']):
                        event.acceptProposedAction()
                        self._show_toast("💣 Drop it like it's hot!", 'chaos')
                        return
            event.ignore()
        
        def dropEvent(self, event: QDropEvent):
            """Handle dropped files - route to appropriate handler."""
            files = [url.toLocalFile() for url in event.mimeData().urls()]
            
            for file_path in files:
                lower_path = file_path.lower()
                
                if lower_path.endswith('.bin') or 'payload' in lower_path:
                    # Payload file - go to extract tab
                    self.tab_widget.setCurrentIndex(0)  # Extract tab
                    self.path_input.setText(file_path)
                    self._show_toast(f"🔥 Payload locked and loaded!", 'success')
                    self._load_payload()
                    break
                    
                elif lower_path.endswith('.img'):
                    # Image file - go to Image Extract tab
                    for i in range(self.tab_widget.count()):
                        if 'Image' in self.tab_widget.tabText(i):
                            self.tab_widget.setCurrentIndex(i)
                            break
                    if hasattr(self, 'image_path_input'):
                        self.image_path_input.setText(file_path)
                        self._show_toast(f"🛠️ Image ready for destruction!", 'success')
                    break
                    
                elif lower_path.endswith('.zip'):
                    # ZIP file - could be OTA
                    self.tab_widget.setCurrentIndex(0)
                    self.path_input.setText(file_path)
                    self._show_toast(f"📦 OTA package detected - unleashing!", 'success')
                    self._load_payload()
                    break
            
            event.acceptProposedAction()
        
        def _tray_activated(self, reason):
            """Handle tray icon activation."""
            if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
                self._tray_show_window()
        
        def _tray_show_window(self):
            """Show and raise the main window."""
            self.showNormal()
            self.activateWindow()
            self.raise_()
        
        def _tray_quick_extract(self):
            """Open file dialog for quick extraction from tray."""
            self._tray_show_window()
            self._browse_payload()
        
        def _show_toast(self, message: str, toast_type: str = 'info'):
            """Show a rebellious toast notification."""
            AnarchyToast(self, message, toast_type)
        
        def _show_tray_notification(self, title: str, message: str, icon_type: str = 'info'):
            """Show a system notification from tray."""
            icons = {
                'info': QSystemTrayIcon.MessageIcon.Information,
                'warning': QSystemTrayIcon.MessageIcon.Warning,
                'error': QSystemTrayIcon.MessageIcon.Critical,
            }
            self.tray_icon.showMessage(title, message, icons.get(icon_type, icons['info']), 3000)
        
        def _force_quit_app(self):
            """Force quit the application - no minimize to tray."""
            self._force_quit = True
            # Hide tray icon first to prevent orphaned icons
            self.tray_icon.hide()
            # Close the application
            QApplication.instance().quit()
        
        def closeEvent(self, event):
            """Minimize to tray instead of closing, unless force quit."""
            if self._force_quit:
                # User chose to quit - actually close
                self.tray_icon.hide()  # Ensure tray icon is removed
                event.accept()
            elif self.tray_icon.isVisible():
                self._show_toast("👻 Anarchy lurks in the shadows...", 'chaos')
                self.hide()
                self._show_tray_notification(
                    "Image Anarchy",
                    "Still running in the tray. Right-click to unleash chaos!",
                    'info'
                )
                event.ignore()
            else:
                event.accept()
        
        def _setup_ui(self):
            self.setWindowTitle("Image Anarchy 2.0 - Android Image Swiss Army Knife")
            self.setMinimumSize(1100, 800)
            self.resize(1200, 900)
            
            central = QWidget()
            self.setCentralWidget(central)
            main_layout = QVBoxLayout(central)
            main_layout.setSpacing(12)
            main_layout.setContentsMargins(16, 16, 16, 16)
            
            # Tab widget for Extract/Repack modes
            self.tab_widget = QTabWidget()
            self.tab_widget.setDocumentMode(True)
            
            # ===================== EXTRACT TAB =====================
            extract_tab = QWidget()
            layout = QVBoxLayout(extract_tab)
            layout.setSpacing(12)
            layout.setContentsMargins(8, 12, 8, 8)
            
            # Input section
            input_group = QGroupBox("Payload Source")
            input_layout = QVBoxLayout(input_group)
            
            path_layout = QHBoxLayout()
            self.path_input = DropLineEdit()
            self.browse_btn = QPushButton("Browse...")
            self.browse_btn.clicked.connect(self._browse_payload)
            self.load_btn = QPushButton("Load")
            self.load_btn.setProperty("primary", True)
            self.load_btn.clicked.connect(self._load_payload)
            
            path_layout.addWidget(self.path_input, 1)
            path_layout.addWidget(self.browse_btn)
            path_layout.addWidget(self.load_btn)
            input_layout.addLayout(path_layout)
            layout.addWidget(input_group)
            
            # Main splitter
            splitter = QSplitter(Qt.Orientation.Horizontal)
            
            # Partitions list
            partitions_group = QGroupBox("Partitions")
            partitions_layout = QVBoxLayout(partitions_group)
            
            self.partitions_list = QListWidget()
            self.partitions_list.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
            self.partitions_list.setAlternatingRowColors(True)
            partitions_layout.addWidget(self.partitions_list)
            
            selection_layout = QHBoxLayout()
            self.select_all_btn = QPushButton("Select All")
            self.select_all_btn.clicked.connect(self._select_all)
            self.select_none_btn = QPushButton("Select None")
            self.select_none_btn.clicked.connect(self._select_none)
            selection_layout.addWidget(self.select_all_btn)
            selection_layout.addWidget(self.select_none_btn)
            selection_layout.addStretch()
            partitions_layout.addLayout(selection_layout)
            
            splitter.addWidget(partitions_group)
            
            # Right panel
            right_panel = QWidget()
            right_layout = QVBoxLayout(right_panel)
            right_layout.setContentsMargins(0, 0, 0, 0)
            
            # Output settings
            output_group = QGroupBox("Output Settings")
            output_layout = QVBoxLayout(output_group)
            
            out_dir_layout = QHBoxLayout()
            out_dir_layout.addWidget(QLabel("Output Directory:"))
            self.output_input = QLineEdit("output")
            self.output_browse_btn = QPushButton("Browse...")
            self.output_browse_btn.clicked.connect(self._browse_output)
            out_dir_layout.addWidget(self.output_input, 1)
            out_dir_layout.addWidget(self.output_browse_btn)
            output_layout.addLayout(out_dir_layout)
            
            self.diff_checkbox = QCheckBox("Differential OTA (requires original images)")
            self.diff_checkbox.toggled.connect(self._toggle_diff)
            output_layout.addWidget(self.diff_checkbox)
            
            # Super partition extraction option
            self.extract_super_checkbox = QCheckBox("Extract super partition contents (system, vendor, etc.)")
            self.extract_super_checkbox.setToolTip(
                "If super.img is extracted, automatically extract its sub-partitions\n"
                "(system, vendor, product, odm, etc.) to a 'super_extracted' subfolder"
            )
            output_layout.addWidget(self.extract_super_checkbox)
            
            old_dir_layout = QHBoxLayout()
            self.old_dir_label = QLabel("Original Images:")
            self.old_dir_input = QLineEdit("old")
            self.old_dir_browse_btn = QPushButton("Browse...")
            self.old_dir_browse_btn.clicked.connect(self._browse_old_dir)
            old_dir_layout.addWidget(self.old_dir_label)
            old_dir_layout.addWidget(self.old_dir_input, 1)
            old_dir_layout.addWidget(self.old_dir_browse_btn)
            output_layout.addLayout(old_dir_layout)
            
            self.old_dir_label.setVisible(False)
            self.old_dir_input.setVisible(False)
            self.old_dir_browse_btn.setVisible(False)
            
            right_layout.addWidget(output_group)
            
            # Log output
            log_group = QGroupBox("Log")
            log_layout = QVBoxLayout(log_group)
            self.log_output = QTextEdit()
            self.log_output.setReadOnly(True)
            self.log_output.setFont(QFont("Consolas", 9))
            log_layout.addWidget(self.log_output)
            right_layout.addWidget(log_group, 1)
            
            splitter.addWidget(right_panel)
            splitter.setSizes([300, 500])
            layout.addWidget(splitter, 1)
            
            # Progress
            progress_layout = QHBoxLayout()
            self.progress_bar = QProgressBar()
            self.progress_bar.setMinimumHeight(24)
            self.progress_label = QLabel("Ready")
            progress_layout.addWidget(self.progress_bar, 1)
            progress_layout.addWidget(self.progress_label)
            layout.addLayout(progress_layout)
            
            # Actions
            action_layout = QHBoxLayout()
            action_layout.addStretch()
            
            self.extract_btn = QPushButton("Extract Selected")
            self.extract_btn.setProperty("primary", True)
            self.extract_btn.setMinimumWidth(150)
            self.extract_btn.clicked.connect(self._start_extraction)
            self.extract_btn.setEnabled(False)
            
            self.cancel_btn = QPushButton("Cancel")
            self.cancel_btn.clicked.connect(self._cancel_extraction)
            self.cancel_btn.setEnabled(False)
            self.cancel_btn.setVisible(False)
            
            action_layout.addWidget(self.cancel_btn)
            action_layout.addWidget(self.extract_btn)
            layout.addLayout(action_layout)
            
            self.tab_widget.addTab(extract_tab, "📦 Extract")
            
            # ===================== REPACK TAB =====================
            repack_tab = QWidget()
            repack_layout = QVBoxLayout(repack_tab)
            repack_layout.setSpacing(12)
            repack_layout.setContentsMargins(8, 12, 8, 8)
            
            # Input images section
            input_group = QGroupBox("Partition Images")
            input_layout = QVBoxLayout(input_group)
            
            input_dir_layout = QHBoxLayout()
            input_dir_layout.addWidget(QLabel("Images Directory:"))
            self.repack_input_dir = QLineEdit("output")
            self.repack_input_dir.setPlaceholderText("Directory containing .img files...")
            self.repack_browse_input_btn = QPushButton("Browse...")
            self.repack_browse_input_btn.clicked.connect(self._browse_repack_input)
            self.repack_scan_btn = QPushButton("Scan")
            self.repack_scan_btn.setProperty("primary", True)
            self.repack_scan_btn.clicked.connect(self._scan_images)
            input_dir_layout.addWidget(self.repack_input_dir, 1)
            input_dir_layout.addWidget(self.repack_browse_input_btn)
            input_dir_layout.addWidget(self.repack_scan_btn)
            input_layout.addLayout(input_dir_layout)
            repack_layout.addWidget(input_group)
            
            # Repack splitter
            repack_splitter = QSplitter(Qt.Orientation.Horizontal)
            
            # Images list
            images_group = QGroupBox("Found Images")
            images_layout = QVBoxLayout(images_group)
            
            self.repack_images_list = QListWidget()
            self.repack_images_list.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
            self.repack_images_list.setAlternatingRowColors(True)
            images_layout.addWidget(self.repack_images_list)
            
            repack_sel_layout = QHBoxLayout()
            self.repack_select_all_btn = QPushButton("Select All")
            self.repack_select_all_btn.clicked.connect(self._repack_select_all)
            self.repack_select_none_btn = QPushButton("Select None")
            self.repack_select_none_btn.clicked.connect(self._repack_select_none)
            repack_sel_layout.addWidget(self.repack_select_all_btn)
            repack_sel_layout.addWidget(self.repack_select_none_btn)
            repack_sel_layout.addStretch()
            images_layout.addLayout(repack_sel_layout)
            
            repack_splitter.addWidget(images_group)
            
            # Repack settings panel
            repack_right = QWidget()
            repack_right_layout = QVBoxLayout(repack_right)
            repack_right_layout.setContentsMargins(0, 0, 0, 0)
            
            # Output settings
            repack_output_group = QGroupBox("Output Settings")
            repack_output_layout = QVBoxLayout(repack_output_group)
            
            out_file_layout = QHBoxLayout()
            out_file_layout.addWidget(QLabel("Output File:"))
            self.repack_output_path = QLineEdit("payload.bin")
            self.repack_browse_output_btn = QPushButton("Browse...")
            self.repack_browse_output_btn.clicked.connect(self._browse_repack_output)
            out_file_layout.addWidget(self.repack_output_path, 1)
            out_file_layout.addWidget(self.repack_browse_output_btn)
            repack_output_layout.addLayout(out_file_layout)
            
            # Compression settings
            compress_layout = QHBoxLayout()
            compress_layout.addWidget(QLabel("Compression:"))
            self.compression_combo = QComboBox()
            self.compression_combo.addItems(["zstd", "xz", "bz2", "none"])
            self.compression_combo.setCurrentText("zstd")
            compress_layout.addWidget(self.compression_combo)
            compress_layout.addWidget(QLabel("Level:"))
            self.compression_level = QSpinBox()
            self.compression_level.setRange(1, 22)
            self.compression_level.setValue(9)
            compress_layout.addWidget(self.compression_level)
            compress_layout.addStretch()
            repack_output_layout.addLayout(compress_layout)
            
            repack_right_layout.addWidget(repack_output_group)
            
            # Repack log
            repack_log_group = QGroupBox("Log")
            repack_log_layout = QVBoxLayout(repack_log_group)
            self.repack_log_output = QTextEdit()
            self.repack_log_output.setReadOnly(True)
            self.repack_log_output.setFont(QFont("Consolas", 9))
            repack_log_layout.addWidget(self.repack_log_output)
            repack_right_layout.addWidget(repack_log_group, 1)
            
            repack_splitter.addWidget(repack_right)
            repack_splitter.setSizes([300, 500])
            repack_layout.addWidget(repack_splitter, 1)
            
            # Repack progress
            repack_progress_layout = QHBoxLayout()
            self.repack_progress_bar = QProgressBar()
            self.repack_progress_bar.setMinimumHeight(24)
            self.repack_progress_label = QLabel("Ready")
            repack_progress_layout.addWidget(self.repack_progress_bar, 1)
            repack_progress_layout.addWidget(self.repack_progress_label)
            repack_layout.addLayout(repack_progress_layout)
            
            # Repack actions
            repack_action_layout = QHBoxLayout()
            repack_action_layout.addStretch()
            
            self.repack_btn = QPushButton("Create Payload")
            self.repack_btn.setProperty("primary", True)
            self.repack_btn.setMinimumWidth(150)
            self.repack_btn.clicked.connect(self._start_repack)
            self.repack_btn.setEnabled(False)
            
            self.repack_cancel_btn = QPushButton("Cancel")
            self.repack_cancel_btn.clicked.connect(self._cancel_repack)
            self.repack_cancel_btn.setEnabled(False)
            self.repack_cancel_btn.setVisible(False)
            
            repack_action_layout.addWidget(self.repack_cancel_btn)
            repack_action_layout.addWidget(self.repack_btn)
            repack_layout.addLayout(repack_action_layout)
            
            self.tab_widget.addTab(repack_tab, "🔧 Repack")
            
            # =========================================
            # Tab 3: Image Extract
            # =========================================
            image_tab = QWidget()
            image_layout = QVBoxLayout(image_tab)
            image_layout.setContentsMargins(16, 16, 16, 16)
            image_layout.setSpacing(12)
            
            # Image input
            image_input_layout = QHBoxLayout()
            image_input_layout.addWidget(QLabel("Image File:"))
            self.image_path_input = QLineEdit()
            self.image_path_input.setPlaceholderText("Select an Android image file (sparse, boot, super, ext4, erofs)...")
            self.image_browse_btn = QPushButton("Browse...")
            self.image_browse_btn.clicked.connect(self._browse_image)
            self.image_analyze_btn = QPushButton("Analyze")
            self.image_analyze_btn.setProperty("primary", True)
            self.image_analyze_btn.clicked.connect(self._analyze_image)
            image_input_layout.addWidget(self.image_path_input, 1)
            image_input_layout.addWidget(self.image_browse_btn)
            image_input_layout.addWidget(self.image_analyze_btn)
            image_layout.addLayout(image_input_layout)
            
            # Splitter for details and log
            image_splitter = QSplitter(Qt.Orientation.Horizontal)
            
            # Left side - Image info and partitions
            image_left = QWidget()
            image_left_layout = QVBoxLayout(image_left)
            image_left_layout.setContentsMargins(0, 0, 0, 0)
            
            # Image info
            image_info_group = QGroupBox("Image Information")
            image_info_layout = QFormLayout(image_info_group)
            self.image_type_label = QLabel("-")
            self.image_size_label = QLabel("-")
            self.image_details_label = QLabel("-")
            self.image_details_label.setWordWrap(True)
            image_info_layout.addRow("Type:", self.image_type_label)
            image_info_layout.addRow("Size:", self.image_size_label)
            image_info_layout.addRow("Details:", self.image_details_label)
            image_left_layout.addWidget(image_info_group)
            
            # Partitions tree (for super images)
            image_parts_group = QGroupBox("Partitions / Contents")
            image_parts_layout = QVBoxLayout(image_parts_group)
            self.image_tree = QTreeWidget()
            self.image_tree.setHeaderLabels(["Name", "Size", "Type"])
            self.image_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            self.image_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            self.image_tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            image_parts_layout.addWidget(self.image_tree)
            
            # Select all/none buttons
            image_select_layout = QHBoxLayout()
            image_select_all_btn = QPushButton("Select All")
            image_select_all_btn.clicked.connect(lambda: self._toggle_image_tree_selection(True))
            image_select_none_btn = QPushButton("Select None")
            image_select_none_btn.clicked.connect(lambda: self._toggle_image_tree_selection(False))
            image_select_layout.addWidget(image_select_all_btn)
            image_select_layout.addWidget(image_select_none_btn)
            image_select_layout.addStretch()
            image_parts_layout.addLayout(image_select_layout)
            
            image_left_layout.addWidget(image_parts_group, 1)
            image_splitter.addWidget(image_left)
            
            # Right side - Output and log
            image_right = QWidget()
            image_right_layout = QVBoxLayout(image_right)
            image_right_layout.setContentsMargins(0, 0, 0, 0)
            
            # Output settings
            image_output_group = QGroupBox("Output Settings")
            image_output_layout = QVBoxLayout(image_output_group)
            
            image_out_layout = QHBoxLayout()
            image_out_layout.addWidget(QLabel("Output:"))
            self.image_output_dir = QLineEdit()
            self.image_output_dir.setText(str(Path.cwd() / "extracted_images"))
            self.image_browse_output_btn = QPushButton("Browse...")
            self.image_browse_output_btn.clicked.connect(self._browse_image_output)
            image_out_layout.addWidget(self.image_output_dir, 1)
            image_out_layout.addWidget(self.image_browse_output_btn)
            image_output_layout.addLayout(image_out_layout)
            
            # Options
            image_options_layout = QHBoxLayout()
            self.convert_sparse_check = QCheckBox("Convert sparse to raw")
            self.convert_sparse_check.setChecked(True)
            self.extract_boot_check = QCheckBox("Extract boot components")
            self.extract_boot_check.setChecked(True)
            image_options_layout.addWidget(self.convert_sparse_check)
            image_options_layout.addWidget(self.extract_boot_check)
            image_options_layout.addStretch()
            image_output_layout.addLayout(image_options_layout)
            
            # vbmeta patching options (hidden by default)
            self.vbmeta_options_group = QGroupBox("vbmeta Patching Options")
            vbmeta_options_layout = QVBoxLayout(self.vbmeta_options_group)
            
            vbmeta_info_label = QLabel(
                "⚠️ Warning: Patching vbmeta invalidates the signature.\n"
                "Device bootloader must be unlocked to use patched vbmeta."
            )
            vbmeta_info_label.setStyleSheet("color: #FFA500; font-size: 11px;")
            vbmeta_options_layout.addWidget(vbmeta_info_label)
            
            vbmeta_check_layout = QHBoxLayout()
            self.disable_verity_check = QCheckBox("Disable dm-verity (--disable-verity)")
            self.disable_verity_check.setToolTip(
                "Disables dm-verity hashtree verification.\n"
                "Allows modifying system/vendor partitions without boot failure."
            )
            self.disable_verification_check = QCheckBox("Disable AVB verification (--disable-verification)")
            self.disable_verification_check.setToolTip(
                "Disables Android Verified Boot signature checking.\n"
                "Required when using modified boot/system images."
            )
            vbmeta_check_layout.addWidget(self.disable_verity_check)
            vbmeta_check_layout.addWidget(self.disable_verification_check)
            vbmeta_check_layout.addStretch()
            vbmeta_options_layout.addLayout(vbmeta_check_layout)
            
            # Current flags display
            self.vbmeta_current_flags = QLabel("Current flags: -")
            self.vbmeta_current_flags.setStyleSheet("color: #888; font-size: 10px;")
            vbmeta_options_layout.addWidget(self.vbmeta_current_flags)
            
            # Re-signing options
            signing_layout = QHBoxLayout()
            self.resign_vbmeta_check = QCheckBox("Re-sign with custom key")
            self.resign_vbmeta_check.setToolTip(
                "Re-sign the patched vbmeta with a custom AVB key.\n"
                "Only useful for:\n"
                "- Custom ROM developers\n"
                "- Devices with enrolled custom keys\n"
                "- Development/testing environments"
            )
            self.resign_vbmeta_check.stateChanged.connect(self._toggle_signing_options)
            signing_layout.addWidget(self.resign_vbmeta_check)
            
            # Check if cryptography is available
            if not CRYPTO_AVAILABLE:
                self.resign_vbmeta_check.setEnabled(False)
                self.resign_vbmeta_check.setToolTip(
                    "cryptography library not installed.\n"
                    "Install with: pip install cryptography"
                )
            
            signing_layout.addStretch()
            vbmeta_options_layout.addLayout(signing_layout)
            
            # Key selection (hidden by default)
            self.signing_options_widget = QWidget()
            signing_opts_layout = QVBoxLayout(self.signing_options_widget)
            signing_opts_layout.setContentsMargins(20, 0, 0, 0)
            
            # Key source selection
            key_source_layout = QHBoxLayout()
            self.key_generate_radio = QRadioButton("Generate new key")
            self.key_load_radio = QRadioButton("Load existing key")
            self.key_generate_radio.setChecked(True)
            key_source_layout.addWidget(self.key_generate_radio)
            key_source_layout.addWidget(self.key_load_radio)
            key_source_layout.addStretch()
            signing_opts_layout.addLayout(key_source_layout)
            
            # Key size selection (for generation)
            self.key_size_widget = QWidget()
            key_size_layout = QHBoxLayout(self.key_size_widget)
            key_size_layout.setContentsMargins(0, 0, 0, 0)
            key_size_layout.addWidget(QLabel("Key size:"))
            self.key_size_combo = QComboBox()
            self.key_size_combo.addItems(["RSA-2048", "RSA-4096", "RSA-8192"])
            self.key_size_combo.setCurrentIndex(1)  # Default to 4096
            key_size_layout.addWidget(self.key_size_combo)
            self.save_key_check = QCheckBox("Save generated key")
            self.save_key_check.setToolTip("Save the generated key pair for future use")
            key_size_layout.addWidget(self.save_key_check)
            key_size_layout.addStretch()
            signing_opts_layout.addWidget(self.key_size_widget)
            
            # Key file selection (for loading)
            self.key_file_widget = QWidget()
            key_file_layout = QHBoxLayout(self.key_file_widget)
            key_file_layout.setContentsMargins(0, 0, 0, 0)
            key_file_layout.addWidget(QLabel("Private key:"))
            self.key_file_edit = QLineEdit()
            self.key_file_edit.setPlaceholderText("Path to PEM private key file...")
            key_file_layout.addWidget(self.key_file_edit, 1)
            self.key_file_browse_btn = QPushButton("Browse...")
            self.key_file_browse_btn.clicked.connect(self._browse_key_file)
            key_file_layout.addWidget(self.key_file_browse_btn)
            signing_opts_layout.addWidget(self.key_file_widget)
            self.key_file_widget.setVisible(False)
            
            # Connect radio buttons
            self.key_generate_radio.toggled.connect(self._toggle_key_source)
            
            self.signing_options_widget.setVisible(False)
            vbmeta_options_layout.addWidget(self.signing_options_widget)
            
            # Signing status
            self.signing_status_label = QLabel("")
            self.signing_status_label.setStyleSheet("color: #888; font-size: 10px;")
            vbmeta_options_layout.addWidget(self.signing_status_label)
            
            self.vbmeta_options_group.setVisible(False)
            image_output_layout.addWidget(self.vbmeta_options_group)
            
            image_right_layout.addWidget(image_output_group)
            
            # Image log
            image_log_group = QGroupBox("Log")
            image_log_layout = QVBoxLayout(image_log_group)
            self.image_log_output = QTextEdit()
            self.image_log_output.setReadOnly(True)
            self.image_log_output.setFont(QFont("Consolas", 9))
            image_log_layout.addWidget(self.image_log_output)
            image_right_layout.addWidget(image_log_group, 1)
            
            image_splitter.addWidget(image_right)
            image_splitter.setSizes([300, 500])
            image_layout.addWidget(image_splitter, 1)
            
            # Image progress
            image_progress_layout = QHBoxLayout()
            self.image_progress_bar = QProgressBar()
            self.image_progress_bar.setMinimumHeight(24)
            self.image_progress_label = QLabel("Ready")
            image_progress_layout.addWidget(self.image_progress_bar, 1)
            image_progress_layout.addWidget(self.image_progress_label)
            image_layout.addLayout(image_progress_layout)
            
            # Image actions
            image_action_layout = QHBoxLayout()
            image_action_layout.addStretch()
            
            self.image_extract_btn = QPushButton("Extract Image")
            self.image_extract_btn.setProperty("primary", True)
            self.image_extract_btn.setMinimumWidth(150)
            self.image_extract_btn.clicked.connect(self._start_image_extract)
            self.image_extract_btn.setEnabled(False)
            
            self.image_cancel_btn = QPushButton("Cancel")
            self.image_cancel_btn.clicked.connect(self._cancel_image_extract)
            self.image_cancel_btn.setEnabled(False)
            self.image_cancel_btn.setVisible(False)
            
            image_action_layout.addWidget(self.image_cancel_btn)
            image_action_layout.addWidget(self.image_extract_btn)
            image_layout.addLayout(image_action_layout)
            
            self.tab_widget.addTab(image_tab, "🔍 Image Extract")
            
            # =============================================================
            # TAB 4: IMAGE REPACK
            # =============================================================
            repack_img_tab = QWidget()
            repack_img_layout = QVBoxLayout(repack_img_tab)
            
            # Repack type selector
            repack_type_group = QGroupBox("Image Type to Create")
            repack_type_layout = QVBoxLayout(repack_type_group)
            
            self.repack_type_combo = QComboBox()
            self.repack_type_combo.addItems([
                "Boot Image (boot.img / recovery.img)",
                "Vendor Boot Image (vendor_boot.img)",
                "Sparse Image (from raw)",
                "vbmeta Image (disabled AVB)",
                "Ramdisk (from directory)",
                "Super Partition (dynamic partitions)"
            ])
            self.repack_type_combo.currentIndexChanged.connect(self._on_repack_type_changed)
            repack_type_layout.addWidget(self.repack_type_combo)
            
            repack_img_layout.addWidget(repack_type_group)
            
            # Stacked widget for different repack options
            self.repack_stack = QWidget()
            self.repack_stack_layout = QVBoxLayout(self.repack_stack)
            
            # === Boot Image Options ===
            self.boot_repack_widget = QWidget()
            boot_layout = QVBoxLayout(self.boot_repack_widget)
            
            # Header version
            boot_ver_layout = QHBoxLayout()
            boot_ver_layout.addWidget(QLabel("Header Version:"))
            self.boot_version_combo = QComboBox()
            self.boot_version_combo.addItems(["v0", "v1", "v2", "v3", "v4"])
            self.boot_version_combo.setCurrentIndex(2)  # Default v2
            self.boot_version_combo.currentIndexChanged.connect(self._on_boot_version_changed)
            boot_ver_layout.addWidget(self.boot_version_combo)
            boot_ver_layout.addStretch()
            boot_layout.addLayout(boot_ver_layout)
            
            # Kernel
            kernel_layout = QHBoxLayout()
            kernel_layout.addWidget(QLabel("Kernel:"))
            self.boot_kernel_edit = QLineEdit()
            self.boot_kernel_edit.setPlaceholderText("Path to kernel (Image/zImage)...")
            kernel_layout.addWidget(self.boot_kernel_edit, 1)
            self.boot_kernel_browse = QPushButton("Browse...")
            self.boot_kernel_browse.clicked.connect(lambda: self._browse_repack_file(self.boot_kernel_edit, "Kernel"))
            kernel_layout.addWidget(self.boot_kernel_browse)
            boot_layout.addLayout(kernel_layout)
            
            # Ramdisk
            ramdisk_layout = QHBoxLayout()
            ramdisk_layout.addWidget(QLabel("Ramdisk:"))
            self.boot_ramdisk_edit = QLineEdit()
            self.boot_ramdisk_edit.setPlaceholderText("Path to ramdisk.cpio.gz...")
            ramdisk_layout.addWidget(self.boot_ramdisk_edit, 1)
            self.boot_ramdisk_browse = QPushButton("Browse...")
            self.boot_ramdisk_browse.clicked.connect(lambda: self._browse_repack_file(self.boot_ramdisk_edit, "Ramdisk"))
            ramdisk_layout.addWidget(self.boot_ramdisk_browse)
            boot_layout.addLayout(ramdisk_layout)
            
            # DTB (v2)
            self.boot_dtb_widget = QWidget()
            dtb_layout = QHBoxLayout(self.boot_dtb_widget)
            dtb_layout.setContentsMargins(0, 0, 0, 0)
            dtb_layout.addWidget(QLabel("DTB:"))
            self.boot_dtb_edit = QLineEdit()
            self.boot_dtb_edit.setPlaceholderText("Path to DTB (optional)...")
            dtb_layout.addWidget(self.boot_dtb_edit, 1)
            self.boot_dtb_browse = QPushButton("Browse...")
            self.boot_dtb_browse.clicked.connect(lambda: self._browse_repack_file(self.boot_dtb_edit, "DTB"))
            dtb_layout.addWidget(self.boot_dtb_browse)
            boot_layout.addWidget(self.boot_dtb_widget)
            
            # Cmdline
            cmdline_layout = QHBoxLayout()
            cmdline_layout.addWidget(QLabel("Cmdline:"))
            self.boot_cmdline_edit = QLineEdit()
            self.boot_cmdline_edit.setPlaceholderText("Kernel command line (optional)...")
            cmdline_layout.addWidget(self.boot_cmdline_edit, 1)
            boot_layout.addLayout(cmdline_layout)
            
            # Page size
            page_layout = QHBoxLayout()
            page_layout.addWidget(QLabel("Page Size:"))
            self.boot_page_size = QComboBox()
            self.boot_page_size.addItems(["2048", "4096"])
            self.boot_page_size.setCurrentIndex(1)
            page_layout.addWidget(self.boot_page_size)
            page_layout.addStretch()
            boot_layout.addLayout(page_layout)
            
            boot_layout.addStretch()
            self.repack_stack_layout.addWidget(self.boot_repack_widget)
            
            # === Vendor Boot Options ===
            self.vendor_boot_widget = QWidget()
            vendor_layout = QVBoxLayout(self.vendor_boot_widget)
            
            # Version
            vb_ver_layout = QHBoxLayout()
            vb_ver_layout.addWidget(QLabel("Header Version:"))
            self.vb_version_combo = QComboBox()
            self.vb_version_combo.addItems(["v3", "v4"])
            vb_ver_layout.addWidget(self.vb_version_combo)
            vb_ver_layout.addStretch()
            vendor_layout.addLayout(vb_ver_layout)
            
            # Vendor Ramdisk
            vb_ramdisk_layout = QHBoxLayout()
            vb_ramdisk_layout.addWidget(QLabel("Vendor Ramdisk:"))
            self.vb_ramdisk_edit = QLineEdit()
            self.vb_ramdisk_edit.setPlaceholderText("Path to vendor ramdisk...")
            vb_ramdisk_layout.addWidget(self.vb_ramdisk_edit, 1)
            self.vb_ramdisk_browse = QPushButton("Browse...")
            self.vb_ramdisk_browse.clicked.connect(lambda: self._browse_repack_file(self.vb_ramdisk_edit, "Vendor Ramdisk"))
            vb_ramdisk_layout.addWidget(self.vb_ramdisk_browse)
            vendor_layout.addLayout(vb_ramdisk_layout)
            
            # DTB
            vb_dtb_layout = QHBoxLayout()
            vb_dtb_layout.addWidget(QLabel("DTB:"))
            self.vb_dtb_edit = QLineEdit()
            self.vb_dtb_edit.setPlaceholderText("Path to DTB...")
            vb_dtb_layout.addWidget(self.vb_dtb_edit, 1)
            self.vb_dtb_browse = QPushButton("Browse...")
            self.vb_dtb_browse.clicked.connect(lambda: self._browse_repack_file(self.vb_dtb_edit, "DTB"))
            vb_dtb_layout.addWidget(self.vb_dtb_browse)
            vendor_layout.addLayout(vb_dtb_layout)
            
            # Cmdline
            vb_cmdline_layout = QHBoxLayout()
            vb_cmdline_layout.addWidget(QLabel("Cmdline:"))
            self.vb_cmdline_edit = QLineEdit()
            self.vb_cmdline_edit.setPlaceholderText("Vendor kernel cmdline...")
            vb_cmdline_layout.addWidget(self.vb_cmdline_edit, 1)
            vendor_layout.addLayout(vb_cmdline_layout)
            
            vendor_layout.addStretch()
            self.vendor_boot_widget.setVisible(False)
            self.repack_stack_layout.addWidget(self.vendor_boot_widget)
            
            # === Sparse Image Options ===
            self.sparse_widget = QWidget()
            sparse_layout = QVBoxLayout(self.sparse_widget)
            
            sparse_info = QLabel(
                "Convert a raw image to Android sparse format.\n"
                "Sparse images are smaller and faster to flash."
            )
            sparse_info.setStyleSheet("color: #888; font-style: italic;")
            sparse_layout.addWidget(sparse_info)
            
            # Input raw image
            sparse_input_layout = QHBoxLayout()
            sparse_input_layout.addWidget(QLabel("Raw Image:"))
            self.sparse_input_edit = QLineEdit()
            self.sparse_input_edit.setPlaceholderText("Path to raw .img file...")
            sparse_input_layout.addWidget(self.sparse_input_edit, 1)
            self.sparse_input_browse = QPushButton("Browse...")
            self.sparse_input_browse.clicked.connect(lambda: self._browse_repack_file(self.sparse_input_edit, "Raw Image"))
            sparse_input_layout.addWidget(self.sparse_input_browse)
            sparse_layout.addLayout(sparse_input_layout)
            
            # Block size
            sparse_block_layout = QHBoxLayout()
            sparse_block_layout.addWidget(QLabel("Block Size:"))
            self.sparse_block_size = QComboBox()
            self.sparse_block_size.addItems(["4096", "2048", "1024"])
            sparse_block_layout.addWidget(self.sparse_block_size)
            sparse_block_layout.addStretch()
            sparse_layout.addLayout(sparse_block_layout)
            
            sparse_layout.addStretch()
            self.sparse_widget.setVisible(False)
            self.repack_stack_layout.addWidget(self.sparse_widget)
            
            # === vbmeta Options ===
            self.vbmeta_widget = QWidget()
            vbmeta_layout = QVBoxLayout(self.vbmeta_widget)
            
            vbmeta_info = QLabel(
                "Create an empty/disabled vbmeta image.\n"
                "This effectively disables Android Verified Boot."
            )
            vbmeta_info.setStyleSheet("color: #FFA500; font-style: italic;")
            vbmeta_layout.addWidget(vbmeta_info)
            
            # Flags
            self.vbmeta_disable_verity_create = QCheckBox("Disable dm-verity")
            self.vbmeta_disable_verity_create.setChecked(True)
            self.vbmeta_disable_verification_create = QCheckBox("Disable verification")
            self.vbmeta_disable_verification_create.setChecked(True)
            vbmeta_layout.addWidget(self.vbmeta_disable_verity_create)
            vbmeta_layout.addWidget(self.vbmeta_disable_verification_create)
            
            # Signing option
            self.vbmeta_sign_create = QCheckBox("Sign with custom key")
            self.vbmeta_sign_create.setEnabled(CRYPTO_AVAILABLE)
            if not CRYPTO_AVAILABLE:
                self.vbmeta_sign_create.setToolTip("cryptography library not installed")
            vbmeta_layout.addWidget(self.vbmeta_sign_create)
            
            vbmeta_layout.addStretch()
            self.vbmeta_widget.setVisible(False)
            self.repack_stack_layout.addWidget(self.vbmeta_widget)
            
            # === Ramdisk Options ===
            self.ramdisk_widget = QWidget()
            ramdisk_layout = QVBoxLayout(self.ramdisk_widget)
            
            ramdisk_info = QLabel(
                "Pack a directory into a ramdisk image (cpio + compression)."
            )
            ramdisk_info.setStyleSheet("color: #888; font-style: italic;")
            ramdisk_layout.addWidget(ramdisk_info)
            
            # Input directory
            rd_input_layout = QHBoxLayout()
            rd_input_layout.addWidget(QLabel("Input Directory:"))
            self.ramdisk_input_edit = QLineEdit()
            self.ramdisk_input_edit.setPlaceholderText("Path to directory to pack...")
            rd_input_layout.addWidget(self.ramdisk_input_edit, 1)
            self.ramdisk_input_browse = QPushButton("Browse...")
            self.ramdisk_input_browse.clicked.connect(self._browse_ramdisk_dir)
            rd_input_layout.addWidget(self.ramdisk_input_browse)
            ramdisk_layout.addLayout(rd_input_layout)
            
            # Compression
            rd_comp_layout = QHBoxLayout()
            rd_comp_layout.addWidget(QLabel("Compression:"))
            self.ramdisk_compression = QComboBox()
            self.ramdisk_compression.addItems(["gzip", "lz4", "none"])
            rd_comp_layout.addWidget(self.ramdisk_compression)
            rd_comp_layout.addStretch()
            ramdisk_layout.addLayout(rd_comp_layout)
            
            ramdisk_layout.addStretch()
            self.ramdisk_widget.setVisible(False)
            self.repack_stack_layout.addWidget(self.ramdisk_widget)
            
            # === Super Partition Options ===
            self.super_widget = QWidget()
            super_layout = QVBoxLayout(self.super_widget)
            
            super_info = QLabel(
                "🔥 Create a super.img (dynamic partition) from individual partition images.\n"
                "Add partitions like system, vendor, product, odm, etc."
            )
            super_info.setStyleSheet("color: #FF6B35; font-style: italic;")
            super_info.setWordWrap(True)
            super_layout.addWidget(super_info)
            
            # Partition list with add/remove
            super_parts_group = QGroupBox("Partitions")
            super_parts_layout = QVBoxLayout(super_parts_group)
            
            self.super_partitions_list = QListWidget()
            self.super_partitions_list.setAlternatingRowColors(True)
            self.super_partitions_list.setMinimumHeight(120)
            super_parts_layout.addWidget(self.super_partitions_list)
            
            super_part_btns = QHBoxLayout()
            self.super_add_part_btn = QPushButton("+ Add Partition")
            self.super_add_part_btn.clicked.connect(self._super_add_partition)
            self.super_remove_part_btn = QPushButton("- Remove")
            self.super_remove_part_btn.clicked.connect(self._super_remove_partition)
            self.super_scan_parts_btn = QPushButton("📁 Scan Directory")
            self.super_scan_parts_btn.clicked.connect(self._super_scan_directory)
            super_part_btns.addWidget(self.super_add_part_btn)
            super_part_btns.addWidget(self.super_remove_part_btn)
            super_part_btns.addWidget(self.super_scan_parts_btn)
            super_part_btns.addStretch()
            super_parts_layout.addLayout(super_part_btns)
            
            super_layout.addWidget(super_parts_group)
            
            # Group configuration
            super_group_layout = QHBoxLayout()
            super_group_layout.addWidget(QLabel("Partition Group:"))
            self.super_group_name = QLineEdit("qti_dynamic_partitions")
            self.super_group_name.setPlaceholderText("Group name (e.g., qti_dynamic_partitions)")
            super_group_layout.addWidget(self.super_group_name, 1)
            super_layout.addLayout(super_group_layout)
            
            # Size settings
            super_size_group = QGroupBox("Size Configuration")
            super_size_layout = QFormLayout(super_size_group)
            
            # Super size
            super_size_row = QHBoxLayout()
            self.super_size_spin = QSpinBox()
            self.super_size_spin.setRange(1, 32768)  # 1MB to 32GB
            self.super_size_spin.setValue(8192)  # Default 8GB
            self.super_size_spin.setSuffix(" MB")
            self.super_size_spin.setToolTip("Total size of super.img (0 = auto-calculate)")
            super_size_row.addWidget(self.super_size_spin)
            self.super_size_auto = QCheckBox("Auto-calculate")
            self.super_size_auto.setChecked(True)
            self.super_size_auto.toggled.connect(lambda checked: self.super_size_spin.setEnabled(not checked))
            self.super_size_spin.setEnabled(False)
            super_size_row.addWidget(self.super_size_auto)
            super_size_row.addStretch()
            super_size_layout.addRow("Super Size:", super_size_row)
            
            # Group max size
            group_size_row = QHBoxLayout()
            self.super_group_size_spin = QSpinBox()
            self.super_group_size_spin.setRange(1, 32768)
            self.super_group_size_spin.setValue(8000)  # Default ~8GB
            self.super_group_size_spin.setSuffix(" MB")
            self.super_group_size_spin.setToolTip("Maximum size for partition group (0 = auto)")
            group_size_row.addWidget(self.super_group_size_spin)
            self.super_group_size_auto = QCheckBox("Auto-calculate")
            self.super_group_size_auto.setChecked(True)
            self.super_group_size_auto.toggled.connect(lambda checked: self.super_group_size_spin.setEnabled(not checked))
            self.super_group_size_spin.setEnabled(False)
            group_size_row.addStretch()
            super_size_layout.addRow("Group Max Size:", group_size_row)
            
            # Metadata size
            metadata_row = QHBoxLayout()
            self.super_metadata_size = QComboBox()
            self.super_metadata_size.addItems(["65536 (64KB)", "131072 (128KB)", "262144 (256KB)"])
            self.super_metadata_size.setToolTip("Metadata region size")
            metadata_row.addWidget(self.super_metadata_size)
            metadata_row.addStretch()
            super_size_layout.addRow("Metadata Size:", metadata_row)
            
            super_layout.addWidget(super_size_group)
            
            # Options
            super_opts_layout = QHBoxLayout()
            self.super_sparse_check = QCheckBox("Output as sparse image")
            self.super_sparse_check.setToolTip("Create sparse super.img (smaller, faster to flash)")
            self.super_sparse_check.setChecked(True)
            self.super_readonly_check = QCheckBox("Read-only partitions")
            self.super_readonly_check.setToolTip("Mark all partitions as read-only")
            self.super_readonly_check.setChecked(True)
            super_opts_layout.addWidget(self.super_sparse_check)
            super_opts_layout.addWidget(self.super_readonly_check)
            super_opts_layout.addStretch()
            super_layout.addLayout(super_opts_layout)
            
            # Calculated size display
            self.super_calc_label = QLabel("Total partition size: 0 MB")
            self.super_calc_label.setStyleSheet("color: #888; font-size: 11px;")
            super_layout.addWidget(self.super_calc_label)
            
            super_layout.addStretch()
            self.super_widget.setVisible(False)
            self.repack_stack_layout.addWidget(self.super_widget)
            
            repack_img_layout.addWidget(self.repack_stack)
            
            # Output section
            repack_output_group = QGroupBox("Output")
            repack_output_layout = QHBoxLayout(repack_output_group)
            repack_output_layout.addWidget(QLabel("Save to:"))
            self.repack_img_output_edit = QLineEdit()
            self.repack_img_output_edit.setPlaceholderText("Output file path...")
            repack_output_layout.addWidget(self.repack_img_output_edit, 1)
            self.repack_img_output_browse = QPushButton("Browse...")
            self.repack_img_output_browse.clicked.connect(self._browse_repack_output_file)
            repack_output_layout.addWidget(self.repack_img_output_browse)
            repack_img_layout.addWidget(repack_output_group)
            
            # Log
            repack_log_group = QGroupBox("Log")
            repack_log_layout = QVBoxLayout(repack_log_group)
            self.repack_img_log = QTextEdit()
            self.repack_img_log.setReadOnly(True)
            self.repack_img_log.setFont(QFont("Consolas", 9))
            self.repack_img_log.setMaximumHeight(200)
            repack_log_layout.addWidget(self.repack_img_log)
            repack_img_layout.addWidget(repack_log_group, 1)
            
            # Progress and actions
            repack_progress_layout = QHBoxLayout()
            self.repack_img_progress = QProgressBar()
            self.repack_img_progress.setMinimumHeight(24)
            self.repack_img_progress_label = QLabel("Ready")
            repack_progress_layout.addWidget(self.repack_img_progress, 1)
            repack_progress_layout.addWidget(self.repack_img_progress_label)
            repack_img_layout.addLayout(repack_progress_layout)
            
            repack_action_layout = QHBoxLayout()
            repack_action_layout.addStretch()
            self.repack_img_btn = QPushButton("Create Image")
            self.repack_img_btn.setProperty("primary", True)
            self.repack_img_btn.setMinimumWidth(150)
            self.repack_img_btn.clicked.connect(self._start_image_repack)
            repack_action_layout.addWidget(self.repack_img_btn)
            repack_img_layout.addLayout(repack_action_layout)
            
            self.tab_widget.addTab(repack_img_tab, "🔨 Image Repack")
            
            # =============================================================
            # TAB 5: RECOVERY PORTER
            # =============================================================
            recovery_tab = QWidget()
            recovery_layout = QVBoxLayout(recovery_tab)
            
            # Info banner
            recovery_info = QLabel(
                "🔧 Recovery Porter - Port custom recoveries (TWRP, OrangeFox) between devices\n"
                "Load a recovery.img to analyze, modify, swap kernel, edit fstab, and repack."
            )
            recovery_info.setStyleSheet("color: #FFA500; padding: 10px; background-color: #2d2d2d; border-radius: 4px;")
            recovery_info.setWordWrap(True)
            recovery_layout.addWidget(recovery_info)
            
            # Splitter for left/right panels
            recovery_splitter = QSplitter(Qt.Orientation.Horizontal)
            
            # Left panel - Source and components
            recovery_left = QWidget()
            recovery_left_layout = QVBoxLayout(recovery_left)
            recovery_left_layout.setContentsMargins(0, 0, 0, 0)
            
            # Source recovery
            source_group = QGroupBox("Source Recovery")
            source_layout = QVBoxLayout(source_group)
            
            source_input_layout = QHBoxLayout()
            self.recovery_source_edit = QLineEdit()
            self.recovery_source_edit.setPlaceholderText("Path to recovery.img...")
            source_input_layout.addWidget(self.recovery_source_edit, 1)
            self.recovery_browse_btn = QPushButton("Browse...")
            self.recovery_browse_btn.clicked.connect(self._browse_recovery_source)
            source_input_layout.addWidget(self.recovery_browse_btn)
            source_layout.addLayout(source_input_layout)
            
            self.recovery_analyze_btn = QPushButton("Analyze Recovery")
            self.recovery_analyze_btn.clicked.connect(self._analyze_recovery)
            source_layout.addWidget(self.recovery_analyze_btn)
            
            recovery_left_layout.addWidget(source_group)
            
            # Recovery info display
            info_group = QGroupBox("Recovery Information")
            info_layout = QVBoxLayout(info_group)
            
            self.recovery_info_tree = QTreeWidget()
            self.recovery_info_tree.setHeaderLabels(["Property", "Value"])
            self.recovery_info_tree.setAlternatingRowColors(True)
            info_layout.addWidget(self.recovery_info_tree)
            
            recovery_left_layout.addWidget(info_group, 1)
            
            # Component modifications
            mods_group = QGroupBox("Modifications")
            mods_layout = QVBoxLayout(mods_group)
            
            # Kernel swap
            kernel_layout = QHBoxLayout()
            kernel_layout.addWidget(QLabel("Replace Kernel:"))
            self.recovery_kernel_edit = QLineEdit()
            self.recovery_kernel_edit.setPlaceholderText("Leave empty to keep original...")
            kernel_layout.addWidget(self.recovery_kernel_edit, 1)
            self.recovery_kernel_browse = QPushButton("...")
            self.recovery_kernel_browse.setMaximumWidth(30)
            self.recovery_kernel_browse.clicked.connect(self._browse_recovery_kernel)
            kernel_layout.addWidget(self.recovery_kernel_browse)
            mods_layout.addLayout(kernel_layout)
            
            # DTB swap
            dtb_layout = QHBoxLayout()
            dtb_layout.addWidget(QLabel("Replace DTB:"))
            self.recovery_dtb_edit = QLineEdit()
            self.recovery_dtb_edit.setPlaceholderText("Leave empty to keep original...")
            dtb_layout.addWidget(self.recovery_dtb_edit, 1)
            self.recovery_dtb_browse = QPushButton("...")
            self.recovery_dtb_browse.setMaximumWidth(30)
            self.recovery_dtb_browse.clicked.connect(self._browse_recovery_dtb)
            dtb_layout.addWidget(self.recovery_dtb_browse)
            mods_layout.addLayout(dtb_layout)
            
            # Cmdline
            cmdline_layout = QHBoxLayout()
            cmdline_layout.addWidget(QLabel("Cmdline:"))
            self.recovery_cmdline_edit = QLineEdit()
            self.recovery_cmdline_edit.setPlaceholderText("Kernel command line...")
            cmdline_layout.addWidget(self.recovery_cmdline_edit, 1)
            mods_layout.addLayout(cmdline_layout)
            
            recovery_left_layout.addWidget(mods_group)
            
            recovery_splitter.addWidget(recovery_left)
            
            # Right panel - Ramdisk contents
            recovery_right = QWidget()
            recovery_right_layout = QVBoxLayout(recovery_right)
            recovery_right_layout.setContentsMargins(0, 0, 0, 0)
            
            ramdisk_group = QGroupBox("Ramdisk Contents")
            ramdisk_layout = QVBoxLayout(ramdisk_group)
            
            self.ramdisk_tree = QTreeWidget()
            self.ramdisk_tree.setHeaderLabels(["Name", "Size", "Type"])
            self.ramdisk_tree.setAlternatingRowColors(True)
            self.ramdisk_tree.itemDoubleClicked.connect(self._on_ramdisk_item_double_click)
            ramdisk_layout.addWidget(self.ramdisk_tree)
            
            # Ramdisk actions
            ramdisk_btn_layout = QHBoxLayout()
            self.ramdisk_extract_btn = QPushButton("Extract All")
            self.ramdisk_extract_btn.clicked.connect(self._extract_ramdisk)
            self.ramdisk_extract_btn.setEnabled(False)
            ramdisk_btn_layout.addWidget(self.ramdisk_extract_btn)
            
            self.ramdisk_edit_fstab_btn = QPushButton("Edit fstab")
            self.ramdisk_edit_fstab_btn.clicked.connect(self._edit_fstab)
            self.ramdisk_edit_fstab_btn.setEnabled(False)
            ramdisk_btn_layout.addWidget(self.ramdisk_edit_fstab_btn)
            
            ramdisk_btn_layout.addStretch()
            ramdisk_layout.addLayout(ramdisk_btn_layout)
            
            recovery_right_layout.addWidget(ramdisk_group, 1)
            
            # Log
            recovery_log_group = QGroupBox("Log")
            recovery_log_layout = QVBoxLayout(recovery_log_group)
            self.recovery_log = QTextEdit()
            self.recovery_log.setReadOnly(True)
            self.recovery_log.setFont(QFont("Consolas", 9))
            self.recovery_log.setMaximumHeight(150)
            recovery_log_layout.addWidget(self.recovery_log)
            recovery_right_layout.addWidget(recovery_log_group)
            
            recovery_splitter.addWidget(recovery_right)
            recovery_splitter.setSizes([400, 400])
            
            recovery_layout.addWidget(recovery_splitter, 1)
            
            # Output and actions
            recovery_output_layout = QHBoxLayout()
            recovery_output_layout.addWidget(QLabel("Output:"))
            self.recovery_output_edit = QLineEdit()
            self.recovery_output_edit.setPlaceholderText("Path for new recovery.img...")
            recovery_output_layout.addWidget(self.recovery_output_edit, 1)
            self.recovery_output_browse = QPushButton("Browse...")
            self.recovery_output_browse.clicked.connect(self._browse_recovery_output)
            recovery_output_layout.addWidget(self.recovery_output_browse)
            recovery_layout.addLayout(recovery_output_layout)
            
            # Progress and build button
            recovery_action_layout = QHBoxLayout()
            self.recovery_progress = QProgressBar()
            self.recovery_progress.setMaximumWidth(200)
            recovery_action_layout.addWidget(self.recovery_progress)
            recovery_action_layout.addStretch()
            
            self.recovery_build_btn = QPushButton("Build Recovery")
            self.recovery_build_btn.setProperty("primary", True)
            self.recovery_build_btn.setMinimumWidth(150)
            self.recovery_build_btn.clicked.connect(self._build_recovery)
            self.recovery_build_btn.setEnabled(False)
            recovery_action_layout.addWidget(self.recovery_build_btn)
            recovery_layout.addLayout(recovery_action_layout)
            
            self.tab_widget.addTab(recovery_tab, "🔄 Recovery Porter")
            
            main_layout.addWidget(self.tab_widget)
            
            # Status bar
            self.status_bar = QStatusBar()
            self.setStatusBar(self.status_bar)
            self.status_bar.showMessage("Ready - Ⓐ Image Anarchy | Extract, create, and manipulate Android images")
        
        def _apply_styles(self):
            self.setStyleSheet(self.STYLESHEET + """
                QTabWidget::pane {
                    border: 1px solid #3c3c3c;
                    border-radius: 4px;
                    background-color: #1e1e1e;
                }
                QTabBar::tab {
                    background-color: #2d2d2d;
                    color: #d4d4d4;
                    padding: 10px 20px;
                    border: 1px solid #3c3c3c;
                    border-bottom: none;
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                }
                QTabBar::tab:selected {
                    background-color: #1e1e1e;
                    border-bottom: 1px solid #1e1e1e;
                }
                QTabBar::tab:hover:!selected {
                    background-color: #3c3c3c;
                }
                QComboBox {
                    padding: 6px 12px;
                    border: 1px solid #3c3c3c;
                    border-radius: 4px;
                    background-color: #2d2d2d;
                    min-width: 80px;
                }
                QComboBox::drop-down {
                    border: none;
                    width: 20px;
                }
                QComboBox::down-arrow {
                    image: none;
                    border-left: 5px solid transparent;
                    border-right: 5px solid transparent;
                    border-top: 5px solid #d4d4d4;
                    margin-right: 5px;
                }
                QSpinBox {
                    padding: 6px;
                    border: 1px solid #3c3c3c;
                    border-radius: 4px;
                    background-color: #2d2d2d;
                    min-width: 60px;
                }
            """)
            self.load_btn.style().polish(self.load_btn)
            self.extract_btn.style().polish(self.extract_btn)
            self.repack_scan_btn.style().polish(self.repack_scan_btn)
            self.repack_btn.style().polish(self.repack_btn)
            self.image_analyze_btn.style().polish(self.image_analyze_btn)
            self.image_extract_btn.style().polish(self.image_extract_btn)
        
        def _log(self, message: str):
            self.log_output.append(message)
            scrollbar = self.log_output.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
        
        def _repack_log(self, message: str):
            self.repack_log_output.append(message)
            scrollbar = self.repack_log_output.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
        
        def _browse_payload(self):
            path, _ = QFileDialog.getOpenFileName(
                self, "Select Payload File", "",
                "Payload Files (*.bin *.zip);;All Files (*.*)"
            )
            if path:
                self.path_input.setText(path)
        
        def _browse_output(self):
            path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
            if path:
                self.output_input.setText(path)
        
        def _browse_old_dir(self):
            path = QFileDialog.getExistingDirectory(self, "Select Original Images Directory")
            if path:
                self.old_dir_input.setText(path)
        
        def _toggle_diff(self, checked: bool):
            self.old_dir_label.setVisible(checked)
            self.old_dir_input.setVisible(checked)
            self.old_dir_browse_btn.setVisible(checked)
        
        def _load_payload(self):
            path = self.path_input.text().strip()
            if not path:
                QMessageBox.warning(self, "Error", "Please enter a payload file path or URL")
                return
            
            self.partitions_list.clear()
            self.partitions = []
            self.extract_btn.setEnabled(False)
            self.load_btn.setEnabled(False)
            self.progress_bar.setRange(0, 0)
            
            self.analyzer_thread = PayloadAnalyzerThread(path)
            self.analyzer_thread.finished.connect(self._on_payload_loaded)
            self.analyzer_thread.error.connect(self._on_load_error)
            self.analyzer_thread.status.connect(self.status_bar.showMessage)
            self.analyzer_thread.start()
        
        def _on_payload_loaded(self, partitions: list[PartitionDisplayInfo]):
            self.partitions = partitions
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            self.load_btn.setEnabled(True)
            
            self._log(f"Loaded payload with {len(partitions)} partitions:")
            
            for part in partitions:
                size_mb = part.size / (1024 * 1024)
                item = QListWidgetItem(f"{part.name}  ({size_mb:.1f} MB)")
                item.setData(Qt.ItemDataRole.UserRole, part.name)
                self.partitions_list.addItem(item)
                self._log(f"  • {part.name}: {size_mb:.1f} MB ({part.operations_count} operations)")
            
            self._select_all()
            self.extract_btn.setEnabled(True)
            self.status_bar.showMessage(f"Loaded {len(partitions)} partitions")
            self._show_toast(f"⚡ {len(partitions)} partitions ready for liberation!", 'success')
        
        def _on_load_error(self, error: str):
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            self.load_btn.setEnabled(True)
            self._log(f"Error: {error}")
            self.status_bar.showMessage("Error loading payload")
            self._show_toast("💀 Failed to crack the payload!", 'error')
            QMessageBox.critical(self, "Error", f"Failed to load payload:\n{error}")
        
        def _select_all(self):
            for i in range(self.partitions_list.count()):
                self.partitions_list.item(i).setSelected(True)
        
        def _select_none(self):
            for i in range(self.partitions_list.count()):
                self.partitions_list.item(i).setSelected(False)
        
        def _get_selected_partitions(self) -> list[str]:
            return [
                item.data(Qt.ItemDataRole.UserRole) 
                for item in self.partitions_list.selectedItems()
            ]
        
        def _start_extraction(self):
            selected = self._get_selected_partitions()
            if not selected:
                QMessageBox.warning(self, "Error", "Please select at least one partition")
                return
            
            output_dir = self.output_input.text().strip()
            if not output_dir:
                QMessageBox.warning(self, "Error", "Please specify an output directory")
                return
            
            old_dir = None
            if self.diff_checkbox.isChecked():
                old_dir = self.old_dir_input.text().strip()
                if not old_dir:
                    QMessageBox.warning(self, "Error", "Please specify the original images directory")
                    return
            
            self._set_extraction_mode(True)
            self.log_output.clear()
            self._log(f"Starting extraction of {len(selected)} partition(s)...\n")
            
            # Check if super extraction is requested
            extract_super = self.extract_super_checkbox.isChecked() and 'super' in selected
            if extract_super:
                self._log("Super partition contents will be extracted automatically.\n")
            
            self.extraction_thread = ExtractionThread(
                self.path_input.text().strip(),
                output_dir,
                selected,
                old_dir,
                extract_super
            )
            self.extraction_thread.progress.connect(self._on_progress)
            self.extraction_thread.partition_started.connect(
                lambda name: self.status_bar.showMessage(f"Extracting {name}...")
            )
            self.extraction_thread.log.connect(self._log)
            self.extraction_thread.error.connect(self._on_extraction_error)
            self.extraction_thread.finished.connect(self._on_extraction_finished)
            self.extraction_thread.start()
        
        def _set_extraction_mode(self, extracting: bool):
            self.extract_btn.setEnabled(not extracting)
            self.extract_btn.setVisible(not extracting)
            self.cancel_btn.setEnabled(extracting)
            self.cancel_btn.setVisible(extracting)
            self.load_btn.setEnabled(not extracting)
            self.path_input.setEnabled(not extracting)
            self.browse_btn.setEnabled(not extracting)
            self.partitions_list.setEnabled(not extracting)
        
        def _cancel_extraction(self):
            if self.extraction_thread:
                self.extraction_thread.cancel()
                self._log("\nCancelling extraction...")
        
        def _on_progress(self, current: int, total: int):
            self.progress_bar.setRange(0, total)
            self.progress_bar.setValue(current)
            self.progress_label.setText(f"{current}/{total}")
        
        def _on_extraction_error(self, error: str):
            self._set_extraction_mode(False)
            self._log(f"\nError: {error}")
            self.status_bar.showMessage("Extraction failed")
            self._show_toast(f"💀 Extraction failed! The system fought back.", 'error')
            QMessageBox.critical(self, "Error", f"Extraction failed:\n{error}")
        
        def _on_extraction_finished(self):
            self._set_extraction_mode(False)
            self.progress_bar.setValue(self.progress_bar.maximum())
            self.progress_label.setText("Complete")
            self.status_bar.showMessage("Extraction complete!")
            
            # Anarchy toast and tray notification
            self._show_toast("🔥 Extraction complete! Partitions liberated!", 'success')
            self._show_tray_notification("Image Anarchy", "💣 Extraction complete! The system has been dismantled.", 'info')
            
            result = QMessageBox.question(
                self, "Extraction Complete",
                "All partitions extracted successfully!\n\nOpen output directory?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if result == QMessageBox.StandardButton.Yes:
                output_dir = self.output_input.text().strip()
                if sys.platform == 'win32':
                    os.startfile(output_dir)
                elif sys.platform == 'darwin':
                    os.system(f'open "{output_dir}"')
                else:
                    os.system(f'xdg-open "{output_dir}"')
        
        # =================== REPACK METHODS ===================
        
        def _browse_repack_input(self):
            path = QFileDialog.getExistingDirectory(self, "Select Images Directory")
            if path:
                self.repack_input_dir.setText(path)
        
        def _browse_repack_output(self):
            path, _ = QFileDialog.getSaveFileName(
                self, "Save Payload File", "payload.bin",
                "Payload Files (*.bin);;All Files (*.*)"
            )
            if path:
                self.repack_output_path.setText(path)
        
        def _scan_images(self):
            input_dir = self.repack_input_dir.text().strip()
            if not input_dir:
                QMessageBox.warning(self, "Error", "Please specify an images directory")
                return
            
            input_path = Path(input_dir)
            if not input_path.exists():
                QMessageBox.warning(self, "Error", f"Directory not found: {input_dir}")
                return
            
            self.repack_images_list.clear()
            self.repack_images = []
            
            image_files = sorted(input_path.glob("*.img"))
            
            if not image_files:
                QMessageBox.warning(self, "No Images", f"No .img files found in {input_dir}")
                return
            
            self._repack_log(f"Found {len(image_files)} partition image(s):")
            
            for img in image_files:
                size_mb = img.stat().st_size / (1024 * 1024)
                name = img.stem
                item = QListWidgetItem(f"{name}  ({size_mb:.1f} MB)")
                item.setData(Qt.ItemDataRole.UserRole, str(img))
                self.repack_images_list.addItem(item)
                self.repack_images.append(str(img))
                self._repack_log(f"  • {name}: {size_mb:.1f} MB")
            
            self._repack_select_all()
            self.repack_btn.setEnabled(True)
            self.status_bar.showMessage(f"Found {len(image_files)} images ready for repacking")
        
        def _repack_select_all(self):
            for i in range(self.repack_images_list.count()):
                self.repack_images_list.item(i).setSelected(True)
        
        def _repack_select_none(self):
            for i in range(self.repack_images_list.count()):
                self.repack_images_list.item(i).setSelected(False)
        
        def _get_selected_images(self) -> list[str]:
            return [
                item.data(Qt.ItemDataRole.UserRole) 
                for item in self.repack_images_list.selectedItems()
            ]
        
        def _start_repack(self):
            selected = self._get_selected_images()
            if not selected:
                QMessageBox.warning(self, "Error", "Please select at least one image")
                return
            
            output_path = self.repack_output_path.text().strip()
            if not output_path:
                QMessageBox.warning(self, "Error", "Please specify an output file path")
                return
            
            self._set_repack_mode(True)
            self.repack_log_output.clear()
            
            compression = self.compression_combo.currentText()
            level = self.compression_level.value()
            
            self.creation_thread = CreationThread(
                selected,
                output_path,
                compression,
                level
            )
            self.creation_thread.progress.connect(self._on_repack_progress)
            self.creation_thread.log.connect(self._repack_log)
            self.creation_thread.error.connect(self._on_repack_error)
            self.creation_thread.finished.connect(self._on_repack_finished)
            self.creation_thread.start()
        
        def _set_repack_mode(self, repacking: bool):
            self.repack_btn.setEnabled(not repacking)
            self.repack_btn.setVisible(not repacking)
            self.repack_cancel_btn.setEnabled(repacking)
            self.repack_cancel_btn.setVisible(repacking)
            self.repack_scan_btn.setEnabled(not repacking)
            self.repack_input_dir.setEnabled(not repacking)
            self.repack_browse_input_btn.setEnabled(not repacking)
            self.repack_images_list.setEnabled(not repacking)
            if repacking:
                self.repack_progress_bar.setRange(0, 0)
        
        def _cancel_repack(self):
            if self.creation_thread:
                self.creation_thread.cancel()
                self._repack_log("\nCancelling...")
        
        def _on_repack_progress(self, current: int, total: int, msg: str):
            self.repack_progress_bar.setRange(0, total)
            self.repack_progress_bar.setValue(current)
            pct = int(current / total * 100) if total > 0 else 0
            self.repack_progress_label.setText(f"{pct}%")
            self.status_bar.showMessage(msg)
        
        def _on_repack_error(self, error: str):
            self._set_repack_mode(False)
            self._repack_log(f"\nError: {error}")
            self.status_bar.showMessage("Payload creation failed")
            QMessageBox.critical(self, "Error", f"Payload creation failed:\n{error}")
        
        def _on_repack_finished(self, output_path: str):
            self._set_repack_mode(False)
            self.repack_progress_bar.setValue(self.repack_progress_bar.maximum())
            self.repack_progress_label.setText("Complete")
            self.status_bar.showMessage("Payload created successfully!")
            
            result = QMessageBox.question(
                self, "Payload Created",
                f"Payload created successfully!\n\n{output_path}\n\nOpen containing folder?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if result == QMessageBox.StandardButton.Yes:
                folder = str(Path(output_path).parent)
                if sys.platform == 'win32':
                    os.startfile(folder)
                elif sys.platform == 'darwin':
                    os.system(f'open "{folder}"')
                else:
                    os.system(f'xdg-open "{folder}"')
        
        # ==========================================
        # Image Extract Tab Methods
        # ==========================================
        
        def _image_log(self, message: str):
            self.image_log_output.append(message)
            scrollbar = self.image_log_output.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
        
        def _browse_image(self):
            path, _ = QFileDialog.getOpenFileName(
                self, "Select Android Image File", "",
                "Image Files (*.img *.bin);;All Files (*.*)"
            )
            if path:
                self.image_path_input.setText(path)
        
        def _browse_image_output(self):
            path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
            if path:
                self.image_output_dir.setText(path)
        
        def _toggle_image_tree_selection(self, select: bool):
            for i in range(self.image_tree.topLevelItemCount()):
                item = self.image_tree.topLevelItem(i)
                if item:
                    item.setCheckState(0, Qt.CheckState.Checked if select else Qt.CheckState.Unchecked)
        
        def _analyze_image(self):
            path = self.image_path_input.text().strip()
            if not path:
                QMessageBox.warning(self, "Error", "Please enter an image file path")
                return
            
            if not Path(path).exists():
                QMessageBox.warning(self, "Error", f"File not found: {path}")
                return
            
            self.image_tree.clear()
            self.image_log_output.clear()
            self.image_extract_btn.setEnabled(False)
            
            self._image_log(f"Analyzing: {path}")
            
            try:
                extractor = AndroidImageExtractor(path)
                info = extractor.analyze()
                
                # Update info labels
                file_size = Path(path).stat().st_size
                self.image_type_label.setText(info['type'].upper())
                self.image_size_label.setText(f"{file_size / (1024*1024):.2f} MB ({file_size:,} bytes)")
                
                details = []
                for key, value in info.items():
                    if key not in ('type', 'partitions', 'contents'):
                        if isinstance(value, int) and value > 10000:
                            details.append(f"{key}: {value:,}")
                        else:
                            details.append(f"{key}: {value}")
                self.image_details_label.setText("\n".join(details) if details else "-")
                
                # Populate tree
                if 'partitions' in info:
                    for part in info['partitions']:
                        item = QTreeWidgetItem([
                            part.get('name', 'unknown'),
                            f"{part.get('size', 0) / (1024*1024):.2f} MB",
                            part.get('type', '-')
                        ])
                        item.setCheckState(0, Qt.CheckState.Checked)
                        item.setData(0, Qt.ItemDataRole.UserRole, part)
                        self.image_tree.addTopLevelItem(item)
                
                elif 'contents' in info:
                    for content in info['contents']:
                        item = QTreeWidgetItem([
                            content.get('name', 'unknown'),
                            f"{content.get('size', 0) / 1024:.2f} KB",
                            content.get('type', '-')
                        ])
                        item.setCheckState(0, Qt.CheckState.Checked)
                        item.setData(0, Qt.ItemDataRole.UserRole, content)
                        self.image_tree.addTopLevelItem(item)
                
                else:
                    # Single file extraction (sparse or simple image)
                    item = QTreeWidgetItem([
                        Path(path).stem,
                        f"{file_size / (1024*1024):.2f} MB",
                        info['type']
                    ])
                    item.setCheckState(0, Qt.CheckState.Checked)
                    item.setData(0, Qt.ItemDataRole.UserRole, {'name': Path(path).stem, 'type': info['type']})
                    self.image_tree.addTopLevelItem(item)
                
                self._image_log(f"Image type: {info['type']}")
                self._image_log(f"Found {self.image_tree.topLevelItemCount()} extractable item(s)")
                
                # Show/hide vbmeta options based on image type
                is_vbmeta = info['type'] == 'vbmeta'
                self.vbmeta_options_group.setVisible(is_vbmeta)
                
                if is_vbmeta:
                    # Get current flags and display
                    flags = VbmetaPatcher.get_current_flags(path)
                    if 'error' not in flags:
                        flag_status = []
                        if flags['verity_disabled']:
                            flag_status.append("verity DISABLED")
                        else:
                            flag_status.append("verity enabled")
                        if flags['verification_disabled']:
                            flag_status.append("verification DISABLED")
                        else:
                            flag_status.append("verification enabled")
                        self.vbmeta_current_flags.setText(
                            f"Current flags: 0x{flags['raw_flags']:08X} ({', '.join(flag_status)})"
                        )
                        # Pre-check boxes if already disabled
                        self.disable_verity_check.setChecked(flags['verity_disabled'])
                        self.disable_verification_check.setChecked(flags['verification_disabled'])
                    else:
                        self.vbmeta_current_flags.setText(f"Current flags: {flags['error']}")
                        self.disable_verity_check.setChecked(False)
                        self.disable_verification_check.setChecked(False)
                
                self.image_extract_btn.setEnabled(True)
                self.current_image_info = info
                self.current_image_path = path
                self.status_bar.showMessage(f"Analyzed: {info['type']} image")
                
            except Exception as e:
                self._image_log(f"Error: {e}")
                QMessageBox.critical(self, "Error", f"Failed to analyze image:\n{e}")
                self.image_type_label.setText("Error")
                self.image_size_label.setText("-")
                self.image_details_label.setText(str(e))
        
        def _get_selected_image_items(self) -> list[dict]:
            selected = []
            for i in range(self.image_tree.topLevelItemCount()):
                item = self.image_tree.topLevelItem(i)
                if item and item.checkState(0) == Qt.CheckState.Checked:
                    data = item.data(0, Qt.ItemDataRole.UserRole)
                    if data:
                        selected.append(data)
            return selected
        
        def _toggle_signing_options(self, state):
            """Show/hide signing options based on checkbox."""
            show = state == Qt.CheckState.Checked.value
            self.signing_options_widget.setVisible(show)
            if show:
                self._update_signing_status()
        
        def _toggle_key_source(self, generate: bool):
            """Toggle between generate and load key modes."""
            self.key_size_widget.setVisible(generate)
            self.key_file_widget.setVisible(not generate)
            self._update_signing_status()
        
        def _browse_key_file(self):
            """Browse for private key file."""
            path, _ = QFileDialog.getOpenFileName(
                self, "Select Private Key",
                "",
                "PEM Files (*.pem);;All Files (*.*)"
            )
            if path:
                self.key_file_edit.setText(path)
                self._update_signing_status()
        
        def _update_signing_status(self):
            """Update the signing status label."""
            if self.key_generate_radio.isChecked():
                key_size = self.key_size_combo.currentText()
                self.signing_status_label.setText(f"Will generate new {key_size} key for signing")
                self.signing_status_label.setStyleSheet("color: #4CAF50; font-size: 10px;")
            else:
                key_path = self.key_file_edit.text().strip()
                if key_path:
                    if os.path.exists(key_path):
                        self.signing_status_label.setText(f"Will use key: {Path(key_path).name}")
                        self.signing_status_label.setStyleSheet("color: #4CAF50; font-size: 10px;")
                    else:
                        self.signing_status_label.setText("Key file not found!")
                        self.signing_status_label.setStyleSheet("color: #F44336; font-size: 10px;")
                else:
                    self.signing_status_label.setText("Please select a key file")
                    self.signing_status_label.setStyleSheet("color: #FFA500; font-size: 10px;")
        
        # ===== Image Repack Tab Methods =====
        def _on_repack_type_changed(self, index: int):
            """Handle repack type selection change."""
            # Hide all widgets
            self.boot_repack_widget.setVisible(False)
            self.vendor_boot_widget.setVisible(False)
            self.sparse_widget.setVisible(False)
            self.vbmeta_widget.setVisible(False)
            self.ramdisk_widget.setVisible(False)
            self.super_widget.setVisible(False)
            
            # Show selected widget and set default output filename
            if index == 0:  # Boot Image
                self.boot_repack_widget.setVisible(True)
                if not self.repack_img_output_edit.text():
                    self.repack_img_output_edit.setText("boot.img")
            elif index == 1:  # Vendor Boot
                self.vendor_boot_widget.setVisible(True)
                if not self.repack_img_output_edit.text():
                    self.repack_img_output_edit.setText("vendor_boot.img")
            elif index == 2:  # Sparse
                self.sparse_widget.setVisible(True)
            elif index == 3:  # vbmeta
                self.vbmeta_widget.setVisible(True)
                if not self.repack_img_output_edit.text():
                    self.repack_img_output_edit.setText("vbmeta.img")
            elif index == 4:  # Ramdisk
                self.ramdisk_widget.setVisible(True)
                if not self.repack_img_output_edit.text():
                    self.repack_img_output_edit.setText("ramdisk.cpio.gz")
            elif index == 5:  # Super Partition
                self.super_widget.setVisible(True)
                if not self.repack_img_output_edit.text():
                    self.repack_img_output_edit.setText("super.img")
        
        def _on_boot_version_changed(self, index: int):
            """Handle boot image version change."""
            version = index  # 0=v0, 1=v1, 2=v2, 3=v3, 4=v4
            # DTB is only for v2
            self.boot_dtb_widget.setVisible(version == 2)
        
        def _browse_repack_file(self, edit_widget: QLineEdit, file_type: str):
            """Browse for a repack input file."""
            path, _ = QFileDialog.getOpenFileName(
                self, f"Select {file_type}",
                "",
                "All Files (*.*)"
            )
            if path:
                edit_widget.setText(path)
        
        def _browse_ramdisk_dir(self):
            """Browse for ramdisk input directory."""
            path = QFileDialog.getExistingDirectory(
                self, "Select Ramdisk Directory"
            )
            if path:
                self.ramdisk_input_edit.setText(path)
        
        def _browse_repack_output_file(self):
            """Browse for repack output file."""
            repack_type = self.repack_type_combo.currentIndex()
            
            if repack_type == 0:
                default_name = "boot.img"
            elif repack_type == 1:
                default_name = "vendor_boot.img"
            elif repack_type == 2:
                default_name = "output_sparse.img"
            elif repack_type == 3:
                default_name = "vbmeta.img"
            elif repack_type == 4:
                default_name = "ramdisk.cpio.gz"
            else:
                default_name = "output.img"
            
            path, _ = QFileDialog.getSaveFileName(
                self, "Save Image As",
                default_name,
                "Image Files (*.img);;All Files (*.*)"
            )
            if path:
                self.repack_img_output_edit.setText(path)
        
        def _repack_log(self, msg: str):
            """Add message to repack log."""
            self.repack_img_log.append(msg)
        
        def _start_image_repack(self):
            """Start image repack operation."""
            output_path = self.repack_img_output_edit.text().strip()
            if not output_path:
                QMessageBox.warning(self, "Error", "Please specify an output file path")
                return
            
            repack_type = self.repack_type_combo.currentIndex()
            self.repack_img_log.clear()
            
            try:
                if repack_type == 0:
                    self._repack_boot_image(output_path)
                elif repack_type == 1:
                    self._repack_vendor_boot(output_path)
                elif repack_type == 2:
                    self._repack_sparse(output_path)
                elif repack_type == 3:
                    self._repack_vbmeta(output_path)
                elif repack_type == 4:
                    self._repack_ramdisk(output_path)
                elif repack_type == 5:
                    self._repack_super(output_path)
            except Exception as e:
                self._repack_log(f"Error: {e}")
                QMessageBox.critical(self, "Error", f"Failed to create image:\n{e}")
        
        def _repack_boot_image(self, output_path: str):
            """Repack boot image."""
            kernel_path = self.boot_kernel_edit.text().strip()
            ramdisk_path = self.boot_ramdisk_edit.text().strip()
            dtb_path = self.boot_dtb_edit.text().strip() if self.boot_dtb_widget.isVisible() else ""
            cmdline = self.boot_cmdline_edit.text().strip()
            page_size = int(self.boot_page_size.currentText())
            version = self.boot_version_combo.currentIndex()
            
            if not kernel_path:
                QMessageBox.warning(self, "Error", "Please select a kernel file")
                return
            
            self._repack_log(f"Creating boot.img v{version}...")
            self._repack_log(f"  Kernel: {kernel_path}")
            if ramdisk_path:
                self._repack_log(f"  Ramdisk: {ramdisk_path}")
            if dtb_path:
                self._repack_log(f"  DTB: {dtb_path}")
            self._repack_log(f"  Page size: {page_size}")
            
            self.repack_img_progress.setRange(0, 0)  # Indeterminate
            
            packer = BootImagePacker()
            success = packer.pack_boot_image(
                output_path,
                kernel=kernel_path,
                ramdisk=ramdisk_path if ramdisk_path else None,
                dtb=dtb_path if dtb_path else None,
                cmdline=cmdline,
                page_size=page_size,
                header_version=version
            )
            
            self.repack_img_progress.setRange(0, 100)
            self.repack_img_progress.setValue(100 if success else 0)
            
            if success:
                size = os.path.getsize(output_path)
                self._repack_log(f"\n✅ Boot image created successfully!")
                self._repack_log(f"  Output: {output_path}")
                self._repack_log(f"  Size: {size / (1024*1024):.2f} MB")
                self.repack_img_progress_label.setText("Complete")
                QMessageBox.information(self, "Success", f"Boot image created:\n{output_path}")
            else:
                self._repack_log("❌ Failed to create boot image")
                self.repack_img_progress_label.setText("Failed")
        
        def _repack_vendor_boot(self, output_path: str):
            """Repack vendor_boot image."""
            ramdisk_path = self.vb_ramdisk_edit.text().strip()
            dtb_path = self.vb_dtb_edit.text().strip()
            cmdline = self.vb_cmdline_edit.text().strip()
            version = 3 + self.vb_version_combo.currentIndex()
            
            self._repack_log(f"Creating vendor_boot.img v{version}...")
            if ramdisk_path:
                self._repack_log(f"  Vendor Ramdisk: {ramdisk_path}")
            if dtb_path:
                self._repack_log(f"  DTB: {dtb_path}")
            
            self.repack_img_progress.setRange(0, 0)
            
            packer = BootImagePacker()
            success = packer.pack_vendor_boot(
                output_path,
                ramdisk=ramdisk_path if ramdisk_path else None,
                dtb=dtb_path if dtb_path else None,
                vendor_cmdline=cmdline,
                header_version=version
            )
            
            self.repack_img_progress.setRange(0, 100)
            self.repack_img_progress.setValue(100 if success else 0)
            
            if success:
                size = os.path.getsize(output_path)
                self._repack_log(f"\n✅ Vendor boot image created!")
                self._repack_log(f"  Output: {output_path}")
                self._repack_log(f"  Size: {size / (1024*1024):.2f} MB")
                self.repack_img_progress_label.setText("Complete")
                QMessageBox.information(self, "Success", f"Vendor boot image created:\n{output_path}")
            else:
                self._repack_log("❌ Failed to create vendor boot image")
                self.repack_img_progress_label.setText("Failed")
        
        def _repack_sparse(self, output_path: str):
            """Convert raw image to sparse."""
            input_path = self.sparse_input_edit.text().strip()
            if not input_path:
                QMessageBox.warning(self, "Error", "Please select a raw image file")
                return
            
            if not os.path.exists(input_path):
                QMessageBox.warning(self, "Error", f"Input file not found:\n{input_path}")
                return
            
            block_size = int(self.sparse_block_size.currentText())
            
            self._repack_log(f"Converting to sparse format...")
            self._repack_log(f"  Input: {input_path}")
            self._repack_log(f"  Block size: {block_size}")
            
            input_size = os.path.getsize(input_path)
            self._repack_log(f"  Input size: {input_size / (1024*1024):.2f} MB")
            
            def progress_callback(current, total, msg):
                pct = int(current / total * 100) if total > 0 else 0
                self.repack_img_progress.setValue(pct)
                self.repack_img_progress_label.setText(msg)
            
            self.repack_img_progress.setRange(0, 100)
            
            creator = SparseImageCreator(block_size, progress_callback)
            success = creator.convert(input_path, output_path)
            
            if success:
                output_size = os.path.getsize(output_path)
                ratio = (1 - output_size / input_size) * 100 if input_size > 0 else 0
                self._repack_log(f"\n✅ Sparse image created!")
                self._repack_log(f"  Output: {output_path}")
                self._repack_log(f"  Output size: {output_size / (1024*1024):.2f} MB")
                self._repack_log(f"  Size reduction: {ratio:.1f}%")
                self.repack_img_progress_label.setText("Complete")
                QMessageBox.information(self, "Success", 
                    f"Sparse image created:\n{output_path}\n\nSize reduction: {ratio:.1f}%")
            else:
                self._repack_log("❌ Failed to create sparse image")
                self.repack_img_progress_label.setText("Failed")
        
        def _repack_vbmeta(self, output_path: str):
            """Create empty/disabled vbmeta."""
            disable_verity = self.vbmeta_disable_verity_create.isChecked()
            disable_verification = self.vbmeta_disable_verification_create.isChecked()
            sign_with_key = self.vbmeta_sign_create.isChecked() and CRYPTO_AVAILABLE
            
            self._repack_log("Creating vbmeta image...")
            self._repack_log(f"  Disable verity: {disable_verity}")
            self._repack_log(f"  Disable verification: {disable_verification}")
            self._repack_log(f"  Sign with key: {sign_with_key}")
            
            self.repack_img_progress.setRange(0, 0)
            
            signer = None
            if sign_with_key:
                signer = AvbSigner()
                self._repack_log("  Generating RSA-4096 signing key...")
                signer.generate_key(4096)
                
                # Save the key next to the vbmeta
                key_path = output_path.replace('.img', '_key.pem')
                signer.save_private_key(key_path)
                self._repack_log(f"  Signing key saved: {key_path}")
            
            creator = VbmetaCreator(signer)
            success = creator.create_empty_vbmeta(
                output_path,
                disable_verity=disable_verity,
                disable_verification=disable_verification
            )
            
            self.repack_img_progress.setRange(0, 100)
            self.repack_img_progress.setValue(100 if success else 0)
            
            if success:
                size = os.path.getsize(output_path)
                self._repack_log(f"\n✅ vbmeta image created!")
                self._repack_log(f"  Output: {output_path}")
                self._repack_log(f"  Size: {size} bytes")
                self.repack_img_progress_label.setText("Complete")
                QMessageBox.information(self, "Success", f"vbmeta image created:\n{output_path}")
            else:
                self._repack_log("❌ Failed to create vbmeta image")
                self.repack_img_progress_label.setText("Failed")
        
        def _repack_ramdisk(self, output_path: str):
            """Pack directory into ramdisk."""
            input_dir = self.ramdisk_input_edit.text().strip()
            if not input_dir:
                QMessageBox.warning(self, "Error", "Please select an input directory")
                return
            
            if not os.path.isdir(input_dir):
                QMessageBox.warning(self, "Error", f"Directory not found:\n{input_dir}")
                return
            
            compression = self.ramdisk_compression.currentText()
            
            self._repack_log(f"Creating ramdisk from directory...")
            self._repack_log(f"  Input: {input_dir}")
            self._repack_log(f"  Compression: {compression}")
            
            # Count files
            file_count = sum(1 for _ in Path(input_dir).rglob('*'))
            self._repack_log(f"  Files/dirs: {file_count}")
            
            def progress_callback(current, total, msg):
                pct = int(current / total * 100) if total > 0 else 0
                self.repack_img_progress.setValue(pct)
            
            self.repack_img_progress.setRange(0, 100)
            
            packer = RamdiskPacker(progress_callback)
            success = packer.pack(input_dir, output_path, compression)
            
            if success:
                size = os.path.getsize(output_path)
                self._repack_log(f"\n✅ Ramdisk created!")
                self._repack_log(f"  Output: {output_path}")
                self._repack_log(f"  Size: {size / 1024:.2f} KB")
                self.repack_img_progress_label.setText("Complete")
                QMessageBox.information(self, "Success", f"Ramdisk created:\n{output_path}")
            else:
                self._repack_log("❌ Failed to create ramdisk")
                self.repack_img_progress_label.setText("Failed")
        
        # ===== Super Partition Methods =====
        def _super_add_partition(self):
            """Add a partition image to the super list."""
            paths, _ = QFileDialog.getOpenFileNames(
                self, "Select Partition Image(s)",
                "",
                "Image Files (*.img);;All Files (*.*)"
            )
            for path in paths:
                # Extract partition name from filename
                name = Path(path).stem
                # Remove common suffixes
                for suffix in ['_a', '_b', '-sign', '.raw', '_raw']:
                    if name.endswith(suffix):
                        name = name[:-len(suffix)]
                
                size = os.path.getsize(path)
                size_mb = size / (1024 * 1024)
                
                item = QListWidgetItem(f"{name}: {size_mb:.2f} MB - {path}")
                item.setData(Qt.ItemDataRole.UserRole, {'name': name, 'path': path, 'size': size})
                self.super_partitions_list.addItem(item)
            
            self._super_update_calc()
        
        def _super_remove_partition(self):
            """Remove selected partition from the super list."""
            for item in self.super_partitions_list.selectedItems():
                self.super_partitions_list.takeItem(self.super_partitions_list.row(item))
            self._super_update_calc()
        
        def _super_scan_directory(self):
            """Scan a directory for partition images."""
            dir_path = QFileDialog.getExistingDirectory(
                self, "Select Directory with Partition Images",
                str(Path.cwd())
            )
            if not dir_path:
                return
            
            # Common partition names to look for
            partition_names = [
                'system', 'system_ext', 'vendor', 'product', 'odm', 
                'vendor_dlkm', 'odm_dlkm', 'system_dlkm'
            ]
            
            found = 0
            for img_file in Path(dir_path).glob('*.img'):
                name = img_file.stem.lower()
                # Check if it's a known partition or just add any .img
                base_name = name
                for suffix in ['_a', '_b', '-sign', '.raw', '_raw']:
                    if base_name.endswith(suffix):
                        base_name = base_name[:-len(suffix)]
                
                size = img_file.stat().st_size
                if size > 0:  # Skip empty files
                    size_mb = size / (1024 * 1024)
                    item = QListWidgetItem(f"{base_name}: {size_mb:.2f} MB - {img_file}")
                    item.setData(Qt.ItemDataRole.UserRole, {
                        'name': base_name, 
                        'path': str(img_file), 
                        'size': size
                    })
                    self.super_partitions_list.addItem(item)
                    found += 1
            
            self._super_update_calc()
            
            if found > 0:
                self._repack_log(f"Found {found} partition image(s) in {dir_path}")
            else:
                QMessageBox.information(self, "Scan Complete", 
                    f"No .img files found in:\n{dir_path}")
        
        def _super_update_calc(self):
            """Update the calculated total size display."""
            total_size = 0
            for i in range(self.super_partitions_list.count()):
                item = self.super_partitions_list.item(i)
                data = item.data(Qt.ItemDataRole.UserRole)
                if data:
                    total_size += data.get('size', 0)
            
            total_mb = total_size / (1024 * 1024)
            self.super_calc_label.setText(f"Total partition size: {total_mb:.2f} MB ({self.super_partitions_list.count()} partitions)")
        
        def _repack_super(self, output_path: str):
            """Create super.img from partition images."""
            if self.super_partitions_list.count() == 0:
                QMessageBox.warning(self, "Error", "Please add at least one partition image")
                return
            
            # Get settings
            group_name = self.super_group_name.text().strip() or "default"
            sparse_output = self.super_sparse_check.isChecked()
            readonly = self.super_readonly_check.isChecked()
            
            # Get metadata size
            metadata_text = self.super_metadata_size.currentText()
            metadata_size = int(metadata_text.split()[0])
            
            # Calculate or get sizes
            if self.super_size_auto.isChecked():
                super_size = 0  # Auto-calculate
            else:
                super_size = self.super_size_spin.value() * 1024 * 1024
            
            if self.super_group_size_auto.isChecked():
                group_max_size = 0  # Auto-calculate
            else:
                group_max_size = self.super_group_size_spin.value() * 1024 * 1024
            
            self._repack_log(f"\ud83d\udd25 Creating super.img (dynamic partition)...")
            self._repack_log(f"  Group: {group_name}")
            self._repack_log(f"  Partitions: {self.super_partitions_list.count()}")
            self._repack_log(f"  Metadata size: {metadata_size}")
            self._repack_log(f"  Sparse output: {sparse_output}")
            self._repack_log(f"  Read-only: {readonly}")
            
            def progress_callback(current, total, msg):
                pct = int(current / total * 100) if total > 0 else 0
                self.repack_img_progress.setValue(pct)
                self.repack_img_progress_label.setText(msg)
            
            self.repack_img_progress.setRange(0, 100)
            self.repack_img_progress.setValue(0)
            
            try:
                creator = SuperImageCreator(progress_callback)
                creator.set_metadata_size(metadata_size)
                creator.set_sparse(sparse_output)
                
                if super_size > 0:
                    creator.set_super_size(super_size)
                
                # Add partitions
                total_size = 0
                for i in range(self.super_partitions_list.count()):
                    item = self.super_partitions_list.item(i)
                    data = item.data(Qt.ItemDataRole.UserRole)
                    if data:
                        creator.add_partition(
                            data['name'], 
                            data['path'], 
                            group_name, 
                            readonly
                        )
                        total_size += data['size']
                        self._repack_log(f"  + {data['name']}: {data['size'] / (1024*1024):.2f} MB")
                
                # Set group max size
                if group_max_size > 0:
                    creator.add_group(group_name, group_max_size)
                else:
                    # Auto: total size + 10% buffer
                    creator.add_group(group_name, int(total_size * 1.1))
                
                self._repack_log(f"\nBuilding super.img...")
                
                # Create the image
                success = creator.create(output_path)
                
                if success:
                    size = os.path.getsize(output_path)
                    self._repack_log(f"\n🔥 Super image created successfully!")
                    self._repack_log(f"  Output: {output_path}")
                    self._repack_log(f"  Size: {size / (1024*1024):.2f} MB")
                    self.repack_img_progress.setValue(100)
                    self.repack_img_progress_label.setText("Complete")
                    self._show_toast(f"Super.img created: {size / (1024*1024):.0f} MB", 'success')
                    QMessageBox.information(self, "Success", 
                        f"Super partition image created!\n\n"
                        f"Output: {output_path}\n"
                        f"Size: {size / (1024*1024):.2f} MB\n"
                        f"Partitions: {self.super_partitions_list.count()}")
                else:
                    self._repack_log("💀 Failed to create super image")
                    self.repack_img_progress_label.setText("Failed")
                    
            except Exception as e:
                self._repack_log(f"💀 Error: {e}")
                self.repack_img_progress_label.setText("Failed")
                raise
        
        # ===== Recovery Porter Methods =====
        def _recovery_log(self, msg: str):
            """Add message to recovery log."""
            self.recovery_log.append(msg)
        
        def _browse_recovery_source(self):
            """Browse for source recovery image."""
            path, _ = QFileDialog.getOpenFileName(
                self, "Select Recovery Image",
                "",
                "Image Files (*.img);;All Files (*.*)"
            )
            if path:
                self.recovery_source_edit.setText(path)
        
        def _browse_recovery_kernel(self):
            """Browse for replacement kernel."""
            path, _ = QFileDialog.getOpenFileName(
                self, "Select Kernel",
                "",
                "All Files (*.*)"
            )
            if path:
                self.recovery_kernel_edit.setText(path)
        
        def _browse_recovery_dtb(self):
            """Browse for replacement DTB."""
            path, _ = QFileDialog.getOpenFileName(
                self, "Select DTB",
                "",
                "DTB Files (*.dtb);;All Files (*.*)"
            )
            if path:
                self.recovery_dtb_edit.setText(path)
        
        def _browse_recovery_output(self):
            """Browse for recovery output path."""
            path, _ = QFileDialog.getSaveFileName(
                self, "Save Recovery As",
                "recovery_ported.img",
                "Image Files (*.img);;All Files (*.*)"
            )
            if path:
                self.recovery_output_edit.setText(path)
        
        def _analyze_recovery(self):
            """Analyze the source recovery image."""
            source = self.recovery_source_edit.text().strip()
            if not source:
                QMessageBox.warning(self, "Error", "Please select a recovery image")
                return
            
            if not os.path.exists(source):
                QMessageBox.warning(self, "Error", f"File not found:\n{source}")
                return
            
            self.recovery_log.clear()
            self._recovery_log(f"Analyzing: {Path(source).name}")
            self._recovery_log("")
            
            self.recovery_progress.setRange(0, 0)  # Indeterminate
            
            try:
                porter = RecoveryPorter()
                info = porter.analyze(source)
                
                # Clear and populate info tree
                self.recovery_info_tree.clear()
                
                # Basic info
                basic = QTreeWidgetItem(["Basic Info", ""])
                basic.addChild(QTreeWidgetItem(["Recovery Type", info.get('recovery_type', 'Unknown')]))
                basic.addChild(QTreeWidgetItem(["Format", info.get('format', 'Unknown')]))
                basic.addChild(QTreeWidgetItem(["Header Version", str(info.get('header_version', 0))]))
                basic.addChild(QTreeWidgetItem(["Size", f"{info.get('size', 0) / (1024*1024):.2f} MB"]))
                if info.get('board_name'):
                    basic.addChild(QTreeWidgetItem(["Board Name", info['board_name']]))
                self.recovery_info_tree.addTopLevelItem(basic)
                basic.setExpanded(True)
                
                # Components
                components = QTreeWidgetItem(["Components", ""])
                components.addChild(QTreeWidgetItem(["Kernel", f"{info.get('kernel_size', 0) / 1024:.1f} KB"]))
                components.addChild(QTreeWidgetItem(["Ramdisk", f"{info.get('ramdisk_size', 0) / 1024:.1f} KB"]))
                if info.get('dtb_size', 0) > 0:
                    components.addChild(QTreeWidgetItem(["DTB", f"{info['dtb_size'] / 1024:.1f} KB"]))
                self.recovery_info_tree.addTopLevelItem(components)
                components.setExpanded(True)
                
                # Cmdline
                if info.get('cmdline'):
                    cmdline_item = QTreeWidgetItem(["Cmdline", info['cmdline'][:50] + "..." if len(info.get('cmdline', '')) > 50 else info['cmdline']])
                    self.recovery_info_tree.addTopLevelItem(cmdline_item)
                    self.recovery_cmdline_edit.setText(info['cmdline'])
                
                # Fstab files
                if info.get('fstab_files'):
                    fstab = QTreeWidgetItem(["Fstab Files", ""])
                    for f in info['fstab_files']:
                        fstab.addChild(QTreeWidgetItem([f, ""]))
                    self.recovery_info_tree.addTopLevelItem(fstab)
                    fstab.setExpanded(True)
                
                # Warnings
                if info.get('warnings'):
                    warnings = QTreeWidgetItem(["⚠️ Warnings", ""])
                    for w in info['warnings']:
                        warnings.addChild(QTreeWidgetItem([w, ""]))
                    self.recovery_info_tree.addTopLevelItem(warnings)
                    warnings.setExpanded(True)
                
                # Populate ramdisk tree
                self.ramdisk_tree.clear()
                ramdisk_files = info.get('ramdisk_files', [])
                
                # Group by directory
                dir_items = {}
                for f in ramdisk_files:
                    name = f['name']
                    parts = name.split('/')
                    
                    if len(parts) == 1:
                        # Root level
                        item = QTreeWidgetItem([name, f"{f['size']}" if f['size'] > 0 else "", f['type']])
                        self.ramdisk_tree.addTopLevelItem(item)
                    else:
                        # In subdirectory - simplified flat view with full path
                        item = QTreeWidgetItem([name, f"{f['size']}" if f['size'] > 0 else "", f['type']])
                        self.ramdisk_tree.addTopLevelItem(item)
                
                self._recovery_log(f"Recovery Type: {info.get('recovery_type', 'Unknown')}")
                self._recovery_log(f"Header Version: {info.get('header_version', 0)}")
                self._recovery_log(f"Kernel: {info.get('kernel_size', 0) / 1024:.1f} KB")
                self._recovery_log(f"Ramdisk: {info.get('ramdisk_size', 0) / 1024:.1f} KB")
                self._recovery_log(f"Ramdisk files: {len(ramdisk_files)}")
                
                if info.get('can_port', True):
                    self._recovery_log("\n✅ Recovery can be ported/modified")
                    self.recovery_build_btn.setEnabled(True)
                    self.ramdisk_extract_btn.setEnabled(True)
                    self.ramdisk_edit_fstab_btn.setEnabled(bool(info.get('fstab_files')))
                else:
                    self._recovery_log("\n❌ Recovery format not supported for porting")
                
                # Store for later use
                self._current_recovery_info = info
                self._current_recovery_path = source
                
            except Exception as e:
                self._recovery_log(f"Error: {e}")
                QMessageBox.critical(self, "Error", f"Failed to analyze recovery:\n{e}")
            finally:
                self.recovery_progress.setRange(0, 100)
                self.recovery_progress.setValue(100)
        
        def _on_ramdisk_item_double_click(self, item, column):
            """Handle double-click on ramdisk item."""
            name = item.text(0)
            file_type = item.text(2)
            self._recovery_log(f"Selected: {name} ({file_type})")
        
        def _extract_ramdisk(self):
            """Extract ramdisk contents to a directory."""
            if not hasattr(self, '_current_recovery_path'):
                return
            
            output_dir = QFileDialog.getExistingDirectory(
                self, "Select Output Directory for Ramdisk"
            )
            if not output_dir:
                return
            
            self._recovery_log(f"\nExtracting ramdisk to: {output_dir}")
            self.recovery_progress.setRange(0, 0)
            
            try:
                porter = RecoveryPorter()
                result = porter.extract_components(self._current_recovery_path, output_dir)
                
                if result.get('ramdisk_dir'):
                    self._recovery_log(f"✅ Ramdisk extracted to: {result['ramdisk_dir']}")
                    self._recovery_log(f"   Kernel: {result.get('kernel', 'N/A')}")
                    
                    # Store for repacking
                    self._extracted_components = result
                    
                    QMessageBox.information(self, "Success", 
                        f"Ramdisk extracted to:\n{result['ramdisk_dir']}\n\n"
                        "You can now modify files and rebuild.")
                else:
                    self._recovery_log("❌ Failed to extract ramdisk")
                    
            except Exception as e:
                self._recovery_log(f"Error: {e}")
                QMessageBox.critical(self, "Error", f"Extraction failed:\n{e}")
            finally:
                self.recovery_progress.setRange(0, 100)
                self.recovery_progress.setValue(100)
        
        def _edit_fstab(self):
            """Open fstab editor dialog."""
            if not hasattr(self, '_current_recovery_info'):
                return
            
            fstab_files = self._current_recovery_info.get('fstab_files', [])
            if not fstab_files:
                QMessageBox.information(self, "Info", "No fstab files found in recovery")
                return
            
            # For now, show info about fstab editing
            QMessageBox.information(self, "Fstab Editor",
                f"Found fstab files:\n" + "\n".join(f"• {f}" for f in fstab_files) +
                "\n\nTo edit fstab:\n"
                "1. Click 'Extract All' to extract ramdisk\n"
                "2. Edit the fstab file(s) in the extracted directory\n"
                "3. Modify partition paths for your target device\n"
                "4. Click 'Build Recovery' to repack\n\n"
                "Common fstab modifications:\n"
                "• Change /dev/block/bootdevice paths\n"
                "• Update partition names (system, vendor, data)\n"
                "• Adjust filesystem types (ext4, f2fs, erofs)")
        
        def _build_recovery(self):
            """Build the modified recovery image."""
            output_path = self.recovery_output_edit.text().strip()
            if not output_path:
                QMessageBox.warning(self, "Error", "Please specify an output path")
                return
            
            if not hasattr(self, '_current_recovery_path'):
                QMessageBox.warning(self, "Error", "Please analyze a recovery first")
                return
            
            self._recovery_log("\n" + "="*50)
            self._recovery_log("Building recovery image...")
            self.recovery_progress.setRange(0, 0)
            
            try:
                porter = RecoveryPorter()
                
                # Extract if not already extracted
                if not hasattr(self, '_extracted_components'):
                    import tempfile
                    temp_dir = tempfile.mkdtemp(prefix='recovery_')
                    self._recovery_log(f"Extracting to temp: {temp_dir}")
                    self._extracted_components = porter.extract_components(
                        self._current_recovery_path, temp_dir)
                
                components = self._extracted_components.copy()
                
                # Apply modifications
                new_kernel = self.recovery_kernel_edit.text().strip()
                if new_kernel and os.path.exists(new_kernel):
                    components['kernel'] = new_kernel
                    self._recovery_log(f"Using replacement kernel: {Path(new_kernel).name}")
                
                new_dtb = self.recovery_dtb_edit.text().strip()
                if new_dtb and os.path.exists(new_dtb):
                    components['dtb'] = new_dtb
                    self._recovery_log(f"Using replacement DTB: {Path(new_dtb).name}")
                
                new_cmdline = self.recovery_cmdline_edit.text().strip()
                if new_cmdline:
                    components['cmdline'] = new_cmdline
                    self._recovery_log(f"Using cmdline: {new_cmdline[:50]}...")
                
                # Build
                success = porter.repack(components, output_path)
                
                if success:
                    size = os.path.getsize(output_path)
                    self._recovery_log(f"\n✅ Recovery built successfully!")
                    self._recovery_log(f"   Output: {output_path}")
                    self._recovery_log(f"   Size: {size / (1024*1024):.2f} MB")
                    
                    QMessageBox.information(self, "Success",
                        f"Recovery image created:\n{output_path}\n\n"
                        f"Size: {size / (1024*1024):.2f} MB\n\n"
                        "Flash with:\n"
                        "fastboot flash recovery recovery.img")
                else:
                    self._recovery_log("❌ Failed to build recovery")
                    QMessageBox.critical(self, "Error", "Failed to build recovery image")
                    
            except Exception as e:
                self._recovery_log(f"Error: {e}")
                QMessageBox.critical(self, "Error", f"Build failed:\n{e}")
            finally:
                self.recovery_progress.setRange(0, 100)
                self.recovery_progress.setValue(100 if 'success' in dir() and success else 0)
        
        def _start_image_extract(self):
            if not hasattr(self, 'current_image_path'):
                QMessageBox.warning(self, "Error", "Please analyze an image first")
                return
            
            selected = self._get_selected_image_items()
            if not selected:
                QMessageBox.warning(self, "Error", "Please select at least one item to extract")
                return
            
            output_dir = self.image_output_dir.text().strip()
            if not output_dir:
                QMessageBox.warning(self, "Error", "Please specify an output directory")
                return
            
            # Get vbmeta patching options
            disable_verity = self.disable_verity_check.isChecked()
            disable_verification = self.disable_verification_check.isChecked()
            
            # Get signing options
            signing_options = None
            if self.resign_vbmeta_check.isChecked() and CRYPTO_AVAILABLE:
                if self.key_generate_radio.isChecked():
                    # Generate new key
                    key_size_text = self.key_size_combo.currentText()
                    key_size = int(key_size_text.replace("RSA-", ""))
                    signing_options = {
                        'mode': 'generate',
                        'key_size': key_size,
                        'save_key': self.save_key_check.isChecked()
                    }
                else:
                    # Load existing key
                    key_path = self.key_file_edit.text().strip()
                    if not key_path:
                        QMessageBox.warning(self, "Error", "Please select a private key file for signing")
                        return
                    if not os.path.exists(key_path):
                        QMessageBox.warning(self, "Error", f"Private key file not found:\n{key_path}")
                        return
                    signing_options = {
                        'mode': 'load',
                        'key_path': key_path
                    }
            
            self._set_image_mode(True)
            self.image_log_output.clear()
            
            self.image_extract_thread = ImageExtractThread(
                self.current_image_path,
                output_dir,
                self.current_image_info,
                selected,
                self.convert_sparse_check.isChecked(),
                self.extract_boot_check.isChecked(),
                disable_verity,
                disable_verification,
                signing_options
            )
            self.image_extract_thread.progress.connect(self._on_image_progress)
            self.image_extract_thread.log.connect(self._image_log)
            self.image_extract_thread.error.connect(self._on_image_error)
            self.image_extract_thread.finished.connect(self._on_image_finished)
            self.image_extract_thread.start()
        
        def _set_image_mode(self, extracting: bool):
            self.image_extract_btn.setEnabled(not extracting)
            self.image_extract_btn.setVisible(not extracting)
            self.image_cancel_btn.setEnabled(extracting)
            self.image_cancel_btn.setVisible(extracting)
            self.image_analyze_btn.setEnabled(not extracting)
            self.image_browse_btn.setEnabled(not extracting)
            self.image_path_input.setEnabled(not extracting)
            if extracting:
                self.image_progress_bar.setRange(0, 0)
        
        def _cancel_image_extract(self):
            if hasattr(self, 'image_extract_thread') and self.image_extract_thread:
                self.image_extract_thread.cancel()
                self._image_log("\nCancelling...")
        
        def _on_image_progress(self, current: int, total: int, msg: str):
            self.image_progress_bar.setRange(0, total)
            self.image_progress_bar.setValue(current)
            pct = int(current / total * 100) if total > 0 else 0
            self.image_progress_label.setText(f"{pct}%")
            self.status_bar.showMessage(msg)
        
        def _on_image_error(self, error: str):
            self._set_image_mode(False)
            self._image_log(f"\nError: {error}")
            self.status_bar.showMessage("Image extraction failed")
            QMessageBox.critical(self, "Error", f"Image extraction failed:\n{error}")
        
        def _on_image_finished(self, output_dir: str):
            self._set_image_mode(False)
            self.image_progress_bar.setValue(self.image_progress_bar.maximum())
            self.image_progress_label.setText("Complete")
            self.status_bar.showMessage("Image extraction completed!")
            
            result = QMessageBox.question(
                self, "Extraction Complete",
                f"Image extraction completed!\n\n{output_dir}\n\nOpen output folder?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if result == QMessageBox.StandardButton.Yes:
                if sys.platform == 'win32':
                    os.startfile(output_dir)
                elif sys.platform == 'darwin':
                    os.system(f'open "{output_dir}"')
                else:
                    os.system(f'xdg-open "{output_dir}"')

    class PluginUploadThread(QThread):
        """Thread for uploading plugins without blocking the UI."""
        
        finished = pyqtSignal(dict)  # Emits result dict
        progress = pyqtSignal(str)   # Emits status message
        
        def __init__(self, api, manifest: dict, file_path: str, screenshots: list = None):
            super().__init__()
            self.api = api
            self.manifest = manifest
            self.file_path = file_path
            self.screenshots = screenshots or []
        
        def run(self):
            try:
                self.progress.emit("📤 Uploading plugin file...")
                result = self.api.submit_plugin(self.manifest, self.file_path, self.screenshots)
                self.finished.emit(result)
            except Exception as e:
                self.finished.emit({'error': str(e)})

    class ImageExtractThread(QThread):
        """Thread for extracting Android images without blocking the UI."""
        
        progress = pyqtSignal(int, int, str)
        log = pyqtSignal(str)
        error = pyqtSignal(str)
        finished = pyqtSignal(str)
        
        def __init__(self, image_path: str, output_dir: str, image_info: dict,
                     selected_items: list[dict], convert_sparse: bool, extract_boot: bool,
                     disable_verity: bool = False, disable_verification: bool = False,
                     signing_options: Optional[dict] = None):
            super().__init__()
            self.image_path = image_path
            self.output_dir = output_dir
            self.image_info = image_info
            self.selected_items = selected_items
            self.convert_sparse = convert_sparse
            self.extract_boot = extract_boot
            self.disable_verity = disable_verity
            self.disable_verification = disable_verification
            self.signing_options = signing_options
            self._cancelled = False
        
        def cancel(self):
            self._cancelled = True
        
        def run(self):
            try:
                Path(self.output_dir).mkdir(parents=True, exist_ok=True)
                image_type = self.image_info.get('type', 'raw')
                total = len(self.selected_items)
                
                self.log.emit(f"Extracting {total} item(s) from {image_type} image...")
                
                if image_type == 'sparse':
                    self._extract_sparse()
                elif image_type in ('boot', 'vendor_boot'):
                    self._extract_boot()
                elif image_type == 'super':
                    self._extract_super()
                elif image_type == 'fat':
                    self._extract_fat()
                elif image_type == 'ext4':
                    self._extract_ext4()
                elif image_type == 'elf':
                    self._extract_elf()
                elif image_type == 'vbmeta':
                    self._extract_vbmeta()
                elif image_type == 'bootloader':
                    self._extract_bootloader()
                else:
                    self._copy_raw()
                
                if not self._cancelled:
                    self.finished.emit(self.output_dir)
                    
            except Exception as e:
                self.error.emit(str(e))
        
        def _extract_sparse(self):
            if self.convert_sparse:
                self.progress.emit(0, 1, "Converting sparse image to raw...")
                self.log.emit("Converting sparse image to raw format...")
                
                converter = SparseImageConverter()
                output_path = Path(self.output_dir) / f"{Path(self.image_path).stem}_raw.img"
                converter.convert(self.image_path, str(output_path))
                
                self.log.emit(f"Converted to: {output_path}")
                self.progress.emit(1, 1, "Conversion complete")
            else:
                self._copy_raw()
        
        def _extract_boot(self):
            if self.extract_boot:
                self.progress.emit(0, 1, "Extracting boot image components...")
                self.log.emit("Extracting kernel, ramdisk, DTB...")
                
                extractor = BootImageExtractor()
                results = extractor.extract(self.image_path, self.output_dir)
                
                for name, path in results.items():
                    self.log.emit(f"  Extracted: {name} -> {path}")
                
                self.progress.emit(1, 1, "Boot extraction complete")
            else:
                self._copy_raw()
        
        def _extract_super(self):
            self.log.emit("Extracting partitions from super image...")
            
            extractor = SuperImageExtractor()
            partition_names = [item.get('name') for item in self.selected_items if item.get('name')]
            
            self.progress.emit(0, len(partition_names), "Extracting partitions...")
            
            try:
                results = extractor.extract(self.image_path, self.output_dir, partition_names)
                
                for name, path in results.items():
                    self.log.emit(f"  Extracted: {name} -> {path}")
                
                self.progress.emit(len(results), len(results), "Super extraction complete")
            except Exception as e:
                self.log.emit(f"  Error: {e}")
                raise
        
        def _extract_fat(self):
            self.log.emit("Extracting files from FAT filesystem image...")
            
            extractor = FatImageExtractor()
            file_names = [item.get('name') for item in self.selected_items if item.get('name')]
            
            total = len(file_names) if file_names else 1
            self.progress.emit(0, total, "Extracting files...")
            
            try:
                # Extract all files if none selected, otherwise only selected
                results = extractor.extract(
                    self.image_path, 
                    self.output_dir, 
                    file_names if file_names else None
                )
                
                for name, path in results.items():
                    self.log.emit(f"  Extracted: {name}")
                
                self.log.emit(f"\nExtracted {len(results)} file(s)")
                self.progress.emit(len(results), len(results), "FAT extraction complete")
            except Exception as e:
                self.log.emit(f"  Error: {e}")
                raise
        
        def _extract_ext4(self):
            self.log.emit("Extracting files from ext4 filesystem image...")
            
            extractor = Ext4ImageExtractor()
            file_names = [item.get('name') for item in self.selected_items if item.get('name')]
            
            total = len(file_names) if file_names else 1
            self.progress.emit(0, total, "Extracting files...")
            
            try:
                # Extract all files if none selected, otherwise only selected
                results = extractor.extract(
                    self.image_path, 
                    self.output_dir, 
                    file_names if file_names else None
                )
                
                for name, path in results.items():
                    self.log.emit(f"  Extracted: {name}")
                
                self.log.emit(f"\nExtracted {len(results)} file(s)")
                self.progress.emit(len(results), len(results), "ext4 extraction complete")
            except Exception as e:
                self.log.emit(f"  Error: {e}")
                raise
        
        def _extract_elf(self):
            self.log.emit("Extracting segments from ELF file...")
            self.log.emit("ELF files contain program segments (code/data for firmware).")
            
            self.progress.emit(0, 1, "Extracting ELF segments...")
            
            try:
                extractor = ElfImageExtractor(
                    self.image_path, 
                    self.output_dir
                )
                success = extractor.extract()
                
                if success:
                    self.log.emit(f"\nELF Header Info:")
                    self.log.emit(f"  Class: {extractor.header.get('class', 'Unknown')}")
                    self.log.emit(f"  Type: {extractor.header.get('type_name', 'Unknown')}")
                    self.log.emit(f"  Machine: {extractor.header.get('machine_name', 'Unknown')}")
                    self.log.emit(f"\nExtracted {len(extractor.segments)} segment(s)")
                    self.log.emit(f"See elf_info.txt for detailed segment information")
                else:
                    self.log.emit("Failed to extract ELF segments")
                
                self.progress.emit(1, 1, "ELF extraction complete")
            except Exception as e:
                self.log.emit(f"  Error: {e}")
                raise
        
        def _extract_vbmeta(self):
            self.log.emit("Processing AVB vbmeta image...")
            self.log.emit("vbmeta contains cryptographic verification data for partitions.")
            
            # Check if patching is requested
            need_patch = self.disable_verity or self.disable_verification
            need_sign = self.signing_options is not None and CRYPTO_AVAILABLE
            
            if need_patch:
                self.log.emit("\n⚠️ Patching requested:")
                if self.disable_verity:
                    self.log.emit("  - Will DISABLE dm-verity")
                if self.disable_verification:
                    self.log.emit("  - Will DISABLE AVB verification")
            
            if need_sign:
                self.log.emit("\n🔐 Re-signing requested:")
                if self.signing_options.get('mode') == 'generate':
                    key_size = self.signing_options.get('key_size', 4096)
                    self.log.emit(f"  - Will generate RSA-{key_size} key")
                    if self.signing_options.get('save_key'):
                        self.log.emit(f"  - Will save generated key")
                else:
                    self.log.emit(f"  - Will use existing key: {self.signing_options.get('key_path', 'Unknown')}")
            
            self.log.emit("")
            
            total_steps = 1
            if need_patch or need_sign:
                total_steps += 1
            if need_sign and self.signing_options.get('mode') == 'generate':
                total_steps += 1  # Key generation step
            
            self.progress.emit(0, total_steps, "Parsing vbmeta...")
            
            try:
                # First, parse and extract info
                extractor = VbmetaExtractor(
                    self.image_path, 
                    self.output_dir
                )
                success = extractor.extract()
                current_step = 1
                
                if success:
                    self.log.emit(f"\nAVB vbmeta Info:")
                    self.log.emit(f"  Version: {extractor.header.get('version_major', '?')}.{extractor.header.get('version_minor', '?')}")
                    self.log.emit(f"  Algorithm: {extractor.header.get('algorithm_name', 'Unknown')}")
                    self.log.emit(f"  Rollback Index: {extractor.header.get('rollback_index', 0)}")
                    self.log.emit(f"  Original Flags: {', '.join(extractor.header.get('flags_decoded', ['Unknown']))}")
                    self.log.emit(f"  Release: {extractor.header.get('release_string', 'Unknown')}")
                    
                    self.log.emit(f"\nDescriptors ({len(extractor.descriptors)}):")
                    for desc in extractor.descriptors:
                        part_name = desc.get('partition_name', '')
                        if part_name:
                            size = desc.get('image_size', 0)
                            self.log.emit(f"  - {part_name}: {desc['tag_name']} ({size/(1024*1024):.2f} MB)")
                        elif 'cmdline' in desc:
                            self.log.emit(f"  - Kernel cmdline: {desc['cmdline'][:50]}...")
                    
                    self.log.emit(f"\nSee vbmeta_info.txt for detailed information")
                    
                    # Apply patching/signing if requested
                    if need_patch or need_sign:
                        self.log.emit("\n" + "="*50)
                        
                        # Prepare signer if needed
                        signer = None
                        if need_sign:
                            self.log.emit("Preparing AVB signing key...")
                            signer = AvbSigner()
                            
                            if self.signing_options.get('mode') == 'generate':
                                key_size = self.signing_options.get('key_size', 4096)
                                current_step += 1
                                self.progress.emit(current_step, total_steps, f"Generating RSA-{key_size} key...")
                                self.log.emit(f"Generating RSA-{key_size} key pair...")
                                
                                if not signer.generate_key(key_size):
                                    self.log.emit("❌ Failed to generate key")
                                    signer = None
                                else:
                                    self.log.emit("✅ Key generated successfully")
                                    
                                    # Save key if requested
                                    if self.signing_options.get('save_key'):
                                        key_base = Path(self.output_dir) / "avb_custom_key"
                                        priv_path = str(key_base) + ".pem"
                                        pub_path = str(key_base) + "_pub.pem"
                                        
                                        signer.save_private_key(priv_path)
                                        signer.save_public_key(pub_path)
                                        self.log.emit(f"  Private key saved: {Path(priv_path).name}")
                                        self.log.emit(f"  Public key saved: {Path(pub_path).name}")
                            else:
                                # Load existing key
                                key_path = self.signing_options.get('key_path', '')
                                self.log.emit(f"Loading private key: {Path(key_path).name}")
                                if not signer.load_private_key(key_path):
                                    self.log.emit("❌ Failed to load private key")
                                    signer = None
                                else:
                                    self.log.emit(f"✅ Loaded RSA-{signer.key_bits} key")
                        
                        current_step += 1
                        self.progress.emit(current_step, total_steps, "Patching vbmeta...")
                        
                        if need_patch:
                            self.log.emit("Applying vbmeta patches...")
                        if signer:
                            self.log.emit("Re-signing with custom key...")
                        
                        patcher = VbmetaPatcher(self.image_path)
                        output_name = Path(self.image_path).stem + "_patched.img"
                        output_path = Path(self.output_dir) / output_name
                        
                        patch_success = patcher.patch(
                            str(output_path),
                            disable_verity=self.disable_verity,
                            disable_verification=self.disable_verification,
                            signer=signer
                        )
                        
                        if patch_success:
                            self.log.emit(f"\n✅ Patched vbmeta saved to: {output_name}")
                            
                            # Show new flags
                            new_flags = VbmetaPatcher.get_current_flags(str(output_path))
                            if 'error' not in new_flags:
                                flag_list = []
                                if new_flags['verity_disabled']:
                                    flag_list.append("VERITY_DISABLED")
                                if new_flags['verification_disabled']:
                                    flag_list.append("VERIFICATION_DISABLED")
                                self.log.emit(f"  New flags: 0x{new_flags['raw_flags']:08X} ({', '.join(flag_list) if flag_list else 'NONE'})")
                            
                            if signer:
                                self.log.emit(f"\n🔐 Image re-signed with RSA-{signer.key_bits} key")
                                self.log.emit("   Note: This will only work with:")
                                self.log.emit("   - Unlocked bootloader")
                                self.log.emit("   - Custom AVB key enrolled in bootloader")
                                self.log.emit("   - Custom ROM/recovery that doesn't verify signatures")
                            else:
                                self.log.emit("\n⚠️ Warning: The patched vbmeta signature is now invalid.")
                                self.log.emit("   Your bootloader must be UNLOCKED to use this image.")
                        else:
                            self.log.emit("❌ Failed to patch vbmeta")
                else:
                    self.log.emit("Failed to parse vbmeta")
                
                self.progress.emit(total_steps, total_steps, "vbmeta processing complete")
            except Exception as e:
                self.log.emit(f"  Error: {e}")
                raise
        
        def _extract_bootloader(self):
            self.log.emit("Analyzing bootloader image...")
            self.log.emit("Bootloader images contain firmware for device initialization.")
            
            self.progress.emit(0, 1, "Analyzing bootloader...")
            
            try:
                analyzer = BootloaderImageAnalyzer(
                    self.image_path, 
                    self.output_dir
                )
                success = analyzer.extract()
                
                if success:
                    info = analyzer.info
                    self.log.emit(f"\nBootloader Information:")
                    self.log.emit(f"  Format: {info.get('format', 'Unknown')}")
                    self.log.emit(f"  Type: {info.get('type', 'Unknown')}")
                    if 'description' in info:
                        self.log.emit(f"  Description: {info['description']}")
                    if 'machine' in info:
                        self.log.emit(f"  Architecture: {info['machine']}")
                    if 'elf_class' in info:
                        self.log.emit(f"  Class: {info['elf_class']}")
                    if 'entry_point' in info:
                        self.log.emit(f"  Entry Point: {info['entry_point']}")
                    
                    if info.get('is_signed') or info.get('qcom_signed'):
                        self.log.emit(f"\n🔒 This image is signed (secure boot protected)")
                    
                    if 'qc_version' in info:
                        self.log.emit(f"  QC Version: {info['qc_version']}")
                    if 'build_date' in info:
                        self.log.emit(f"  Build Date: {info['build_date']}")
                    if 'build_time' in info:
                        self.log.emit(f"  Build Time: {info['build_time']}")
                    
                    if analyzer.segments:
                        self.log.emit(f"\nExtracted {len(analyzer.segments)} segment(s)")
                    
                    self.log.emit(f"\nSee bootloader_info.txt for detailed information")
                    self.log.emit("\n⚠️ Warning: Modifying bootloader images can brick your device!")
                else:
                    self.log.emit("Failed to analyze bootloader")
                
                self.progress.emit(1, 1, "Bootloader analysis complete")
            except Exception as e:
                self.log.emit(f"  Error: {e}")
                raise
        
        def _copy_raw(self):
            import shutil
            
            src_path = Path(self.image_path).resolve()
            dst_path = (Path(self.output_dir) / Path(self.image_path).name).resolve()
            
            # Check if source and destination are the same
            if src_path == dst_path:
                self.log.emit(f"Image is already in output directory: {src_path}")
                self.log.emit("No extraction needed - this appears to be a raw/proprietary image format.")
                self.progress.emit(1, 1, "Complete (no action needed)")
                return
            
            self.progress.emit(0, 1, "Copying raw image...")
            self.log.emit(f"Raw/proprietary image format detected.")
            self.log.emit(f"This image type cannot be further extracted (modem, firmware, etc.)")
            self.log.emit(f"Copying to output directory...")
            
            shutil.copy2(self.image_path, dst_path)
            
            self.log.emit(f"Copied to: {dst_path}")
            self.progress.emit(1, 1, "Copy complete")

    # =========================================================================
    # PLUGIN STORE API CLIENT
    # =========================================================================
    
    # Plugin Store URL - set via environment variable or change here
    PLUGIN_STORE_URL = os.environ.get('PLUGIN_STORE_URL', 'https://plugins.imageanarchy.com')
    
    class PluginStoreAPI:
        """API client for the Image Anarchy Plugin Store."""
        
        def __init__(self, base_url: str = None):
            self.base_url = base_url or PLUGIN_STORE_URL
            self.token = None
            self.user = None
            self._load_auth()
        
        def _load_auth(self):
            """Load saved authentication from config."""
            try:
                config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'plugin_store_auth.json')
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        data = json.load(f)
                        self.token = data.get('token')
                        self.user = data.get('user')
            except Exception:
                pass
        
        def _save_auth(self):
            """Save authentication to config."""
            try:
                config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'plugin_store_auth.json')
                with open(config_file, 'w') as f:
                    json.dump({'token': self.token, 'user': self.user}, f)
            except Exception:
                pass
        
        def _request(self, method: str, endpoint: str, data: dict = None, files: list = None) -> dict:
            """Make an API request.
            
            Args:
                method: HTTP method (GET, POST, etc.)
                endpoint: API endpoint
                data: Dictionary of form data
                files: List of tuples: [(field_name, filename, filedata), ...]
            """
            import urllib.request
            import urllib.error
            import urllib.parse
            import hashlib
            import time
            
            url = f"{self.base_url}{endpoint}"
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'ImageAnarchy/2.0'
            }
            
            # Add request signature for security
            timestamp = str(int(time.time() * 1000))
            app_secret = 'ImageAnarchy-Plugin-Store-2026'
            hourly_key = int(timestamp) // (60 * 60 * 1000)
            sig_data = f"{app_secret}:{hourly_key}:{endpoint}"
            signature = hashlib.sha256(sig_data.encode()).hexdigest()[:16]
            headers['X-App-Signature'] = signature
            headers['X-App-Timestamp'] = timestamp
            
            if self.token:
                headers['Authorization'] = f'Bearer {self.token}'
            
            try:
                if files:
                    # Multipart form upload
                    import mimetypes
                    boundary = '----WebKitFormBoundary' + str(uuid.uuid4()).replace('-', '')[:16]
                    headers['Content-Type'] = f'multipart/form-data; boundary={boundary}'
                    
                    body = b''
                    for key, value in (data or {}).items():
                        body += f'--{boundary}\r\n'.encode()
                        body += f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode()
                        # JSON serialize lists and dicts
                        if isinstance(value, (list, dict)):
                            value = json.dumps(value)
                        body += f'{value}\r\n'.encode()
                    
                    # Support multiple files with same field name
                    for field_name, filename, filedata in files:
                        mime_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
                        body += f'--{boundary}\r\n'.encode()
                        body += f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode()
                        body += f'Content-Type: {mime_type}\r\n\r\n'.encode()
                        body += filedata + b'\r\n'
                    
                    body += f'--{boundary}--\r\n'.encode()
                    
                    req = urllib.request.Request(url, data=body, headers=headers, method=method)
                elif data:
                    body = json.dumps(data).encode('utf-8')
                    req = urllib.request.Request(url, data=body, headers=headers, method=method)
                else:
                    if method == 'GET':
                        headers.pop('Content-Type', None)
                    req = urllib.request.Request(url, headers=headers, method=method)
                
                # Use longer timeout for uploads (files present), shorter for regular API calls
                request_timeout = 300 if files else 30  # 5 minutes for uploads, 30s otherwise
                with urllib.request.urlopen(req, timeout=request_timeout) as response:
                    return json.loads(response.read().decode('utf-8'))
                    
            except urllib.error.HTTPError as e:
                try:
                    error_body = json.loads(e.read().decode('utf-8'))
                    return {'error': error_body.get('error', str(e))}
                except:
                    return {'error': str(e)}
            except urllib.error.URLError as e:
                return {'error': f'Connection failed: {e.reason}'}
            except Exception as e:
                return {'error': str(e)}
        
        def get_plugins(self, category: str = None, search: str = None) -> list:
            """Get list of approved plugins from the store."""
            endpoint = '/api/plugins'
            if search:
                endpoint = f'/api/search?q={urllib.parse.quote(search)}'
            elif category:
                endpoint = f'/api/plugins?category={urllib.parse.quote(category)}'
            
            result = self._request('GET', endpoint)
            if 'error' in result:
                return []
            return result.get('plugins', result) if isinstance(result, dict) else result
        
        def get_plugin(self, plugin_id: str) -> dict:
            """Get plugin details."""
            return self._request('GET', f'/api/plugins/{plugin_id}')
        
        def get_categories(self) -> list:
            """Get list of categories."""
            result = self._request('GET', '/api/categories')
            return result.get('categories', []) if isinstance(result, dict) else []
        
        def download_plugin(self, plugin_id: str, save_path: str) -> tuple:
            """Download a plugin zip file.
            
            Returns:
                tuple: (success: bool, message: str)
            """
            import urllib.request
            import urllib.error
            
            url = f"{self.base_url}/api/plugins/{plugin_id}/download"
            
            try:
                req = urllib.request.Request(url)
                req.add_header('User-Agent', 'ImageAnarchy/2.0')
                with urllib.request.urlopen(req, timeout=60) as response:
                    with open(save_path, 'wb') as f:
                        f.write(response.read())
                return True, save_path
            except Exception as e:
                return False, str(e)
        
        def register(self, username: str, email: str, password: str) -> dict:
            """Register a new developer account."""
            result = self._request('POST', '/api/auth/register', {
                'username': username,
                'email': email,
                'password': password
            })
            
            if 'token' in result:
                self.token = result['token']
                self.user = result.get('user', {'username': username})
                self._save_auth()
            
            return result
        
        def login(self, username: str, password: str) -> dict:
            """Login to developer account."""
            result = self._request('POST', '/api/auth/login', {
                'username': username,
                'password': password
            })
            
            if 'token' in result:
                self.token = result['token']
                self.user = result.get('user', {'username': username})
                self._save_auth()
            
            return result
        
        def logout(self):
            """Logout and clear saved auth."""
            self.token = None
            self.user = None
            try:
                config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'plugin_store_auth.json')
                if os.path.exists(config_file):
                    os.remove(config_file)
            except Exception:
                pass
        
        def is_logged_in(self) -> bool:
            """Check if user is logged in."""
            return self.token is not None
        
        def submit_plugin(self, manifest: dict, zip_path: str, screenshots: list = None) -> dict:
            """Submit a plugin to the store with optional screenshots."""
            if not self.token:
                return {'error': 'Not logged in'}
            
            with open(zip_path, 'rb') as f:
                zip_data = f.read()
            
            # Build files list: [(field_name, filename, data), ...]
            files = [('plugin', os.path.basename(zip_path), zip_data)]
            
            # Add screenshots
            if screenshots:
                for ss_path in screenshots:
                    if os.path.exists(ss_path):
                        with open(ss_path, 'rb') as ss_file:
                            ss_data = ss_file.read()
                            files.append(('screenshots', os.path.basename(ss_path), ss_data))
            
            result = self._request('POST', '/api/plugins/submit', manifest, files)
            
            # Return screenshot count and external deps count in result
            if 'error' not in result:
                result['screenshots'] = len(screenshots) if screenshots else 0
                result['external_deps'] = len(manifest.get('external_dependencies', []))
            
            return result
        
        # =====================================================================
        # Feedback, Rating & Bug Report API Methods
        # =====================================================================
        
        def get_feedback(self, plugin_id: str) -> dict:
            """Get feedback and ratings for a plugin."""
            return self._request('GET', f'/api/plugins/{plugin_id}/feedback')
        
        def submit_rating(self, plugin_id: str, rating: int, comment: str = None) -> dict:
            """Submit a rating for a plugin (requires login)."""
            if not self.token:
                return {'error': 'Not logged in'}
            data = {'rating': rating}
            if comment:
                data['comment'] = comment
            return self._request('POST', f'/api/plugins/{plugin_id}/rate', data)
        
        def submit_feedback(self, plugin_id: str, content: str) -> dict:
            """Submit feedback for a plugin (requires login)."""
            if not self.token:
                return {'error': 'Not logged in'}
            return self._request('POST', f'/api/plugins/{plugin_id}/feedback', {'content': content})
        
        def submit_bug_report(self, plugin_id: str, content: str, email: str = None, 
                              name: str = None, captcha_answer: str = None) -> dict:
            """Submit a bug report for a plugin (no login required)."""
            data = {
                'content': content,
                'captchaAnswer': captcha_answer or ''
            }
            if email:
                data['email'] = email
            if name:
                data['name'] = name
            return self._request('POST', f'/api/plugins/{plugin_id}/bug-report', data)
        
        def get_bug_reports(self, plugin_id: str) -> dict:
            """Get bug reports for a plugin (plugin author only)."""
            if not self.token:
                return {'error': 'Not logged in'}
            return self._request('GET', f'/api/plugins/{plugin_id}/bugs')
        
        def respond_to_bug(self, bug_id: int, response: str, status: str = 'in-progress') -> dict:
            """Respond to a bug report (plugin author only)."""
            if not self.token:
                return {'error': 'Not logged in'}
            return self._request('POST', f'/api/bugs/{bug_id}/respond', {
                'response': response,
                'status': status
            })
        
        # =====================================================================
        # Admin API Methods
        # =====================================================================
        
        def get_pending_plugins(self) -> dict:
            """Get list of pending plugins (admin only)."""
            return self._request('GET', '/api/admin/pending')
        
        def get_all_admin_plugins(self) -> dict:
            """Get all plugins for admin view."""
            return self._request('GET', '/api/admin/plugins')
        
        def approve_plugin(self, plugin_id: str) -> dict:
            """Approve a pending plugin (admin only)."""
            return self._request('POST', f'/api/admin/approve/{plugin_id}')
        
        def reject_plugin(self, plugin_id: str, reason: str = "") -> dict:
            """Reject a pending plugin (admin only)."""
            return self._request('POST', f'/api/admin/reject/{plugin_id}', {'reason': reason})
        
        def delete_plugin(self, plugin_id: str) -> dict:
            """Delete a plugin (admin only)."""
            return self._request('DELETE', f'/api/admin/plugins/{plugin_id}')
        
        def get_plugin_review_details(self, plugin_id: str) -> dict:
            """Get detailed plugin info for admin review (admin only)."""
            return self._request('GET', f'/api/admin/review/{plugin_id}')
    
    # Global plugin store API instance
    plugin_store_api = PluginStoreAPI()

    # =========================================================================
    # PLUGINS MANAGEMENT TAB
    # =========================================================================
    
    class PluginsTab(QWidget):
        """Tab for managing plugins - browse, enable/disable, view info, open."""
        
        def __init__(self, parent_window):
            super().__init__()
            self.parent_window = parent_window
            self.loaded_widgets: Dict[str, QWidget] = {}
            self.loaded_plugins: Dict[str, Any] = {}  # Track plugin instances for cleanup
            self.active_plugin_id: Optional[str] = None  # Currently open plugin
            self.builtin_plugins = {}
            
            self._setup_ui()
            self._load_plugins()
        
        def _log(self, message: str):
            """Log a plugin message."""
            logger.debug(f"[Plugins] {message}")
        
        def _setup_ui(self):
            layout = QVBoxLayout(self)
            layout.setSpacing(8)
            layout.setContentsMargins(8, 8, 8, 8)
            
            # Main tab widget for Installed / Store views
            self.view_tabs = QTabWidget()
            self.view_tabs.setStyleSheet("""
                QTabWidget::pane { border: 1px solid #444; border-radius: 4px; }
                QTabBar::tab { padding: 8px 20px; }
                QTabBar::tab:selected { background: #3a3a3a; }
            """)
            
            # Auto-refresh store when switching to Store tab
            self._store_loaded = False
            def on_tab_changed(index):
                tab_text = self.view_tabs.tabText(index)
                if "Store" in tab_text and not self._store_loaded:
                    self._refresh_store()
                    self._store_loaded = True
            self.view_tabs.currentChanged.connect(on_tab_changed)
            
            # =====================================================================
            # INSTALLED PLUGINS TAB
            # =====================================================================
            installed_widget = QWidget()
            installed_layout = QVBoxLayout(installed_widget)
            installed_layout.setContentsMargins(8, 12, 8, 8)
            
            # Header
            header_layout = QHBoxLayout()
            title = QLabel("🔌 Plugin Manager")
            title.setStyleSheet("font-size: 16px; font-weight: bold;")
            header_layout.addWidget(title)
            header_layout.addStretch()
            
            refresh_btn = QPushButton("🔄 Refresh")
            refresh_btn.clicked.connect(self._load_plugins)
            header_layout.addWidget(refresh_btn)
            
            open_folder_btn = QPushButton("📁 Open Plugins Folder")
            open_folder_btn.clicked.connect(self._open_plugins_folder)
            header_layout.addWidget(open_folder_btn)
            
            installed_layout.addLayout(header_layout)
            
            # Splitter for plugin list and details
            splitter = QSplitter(Qt.Orientation.Horizontal)
            
            # Plugin list
            list_widget = QWidget()
            list_layout = QVBoxLayout(list_widget)
            list_layout.setContentsMargins(0, 0, 0, 0)
            
            list_label = QLabel("Installed Plugins")
            list_label.setStyleSheet("font-weight: bold;")
            list_layout.addWidget(list_label)
            
            self.plugin_list = QListWidget()
            self.plugin_list.setMinimumWidth(250)
            self.plugin_list.currentItemChanged.connect(self._on_plugin_selected)
            self.plugin_list.itemDoubleClicked.connect(self._open_plugin)
            list_layout.addWidget(self.plugin_list)
            
            splitter.addWidget(list_widget)
            
            # Plugin details
            details_widget = QWidget()
            details_layout = QVBoxLayout(details_widget)
            details_layout.setContentsMargins(0, 0, 0, 0)
            
            details_label = QLabel("Plugin Details")
            details_label.setStyleSheet("font-weight: bold;")
            details_layout.addWidget(details_label)
            
            self.details_group = QGroupBox()
            self.details_layout = QVBoxLayout(self.details_group)
            
            # Plugin info labels
            self.plugin_icon = QLabel("🔌")
            self.plugin_icon.setStyleSheet("font-size: 48px;")
            self.plugin_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.details_layout.addWidget(self.plugin_icon)
            
            self.plugin_name = QLabel("Select a plugin")
            self.plugin_name.setStyleSheet("font-size: 18px; font-weight: bold;")
            self.plugin_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.details_layout.addWidget(self.plugin_name)
            
            self.plugin_version = QLabel("")
            self.plugin_version.setStyleSheet("color: #888;")
            self.plugin_version.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.details_layout.addWidget(self.plugin_version)
            
            self.plugin_author = QLabel("")
            self.plugin_author.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.details_layout.addWidget(self.plugin_author)
            
            self.plugin_desc = QLabel("")
            self.plugin_desc.setWordWrap(True)
            self.plugin_desc.setStyleSheet("margin: 10px;")
            self.details_layout.addWidget(self.plugin_desc)
            
            # License/Payment info
            self.payment_group = QGroupBox("Support the Developer")
            payment_layout = QVBoxLayout(self.payment_group)
            
            self.license_label = QLabel("")
            self.license_label.setWordWrap(True)
            payment_layout.addWidget(self.license_label)
            
            self.payment_btn = QPushButton("💰 Support / Purchase")
            self.payment_btn.clicked.connect(self._open_payment)
            self.payment_btn.setVisible(False)
            payment_layout.addWidget(self.payment_btn)
            
            self.payment_group.setVisible(False)
            self.details_layout.addWidget(self.payment_group)
            
            self.details_layout.addStretch()
            
            # Action buttons
            btn_layout = QHBoxLayout()
            
            self.enable_btn = QPushButton("✓ Enable")
            self.enable_btn.clicked.connect(self._toggle_enable)
            self.enable_btn.setEnabled(False)
            btn_layout.addWidget(self.enable_btn)
            
            self.open_btn = QPushButton("▶ Open Plugin")
            self.open_btn.setProperty("primary", True)
            self.open_btn.clicked.connect(self._open_plugin)
            self.open_btn.setEnabled(False)
            btn_layout.addWidget(self.open_btn)
            
            self.uninstall_btn = QPushButton("🗑️ Uninstall")
            self.uninstall_btn.setStyleSheet("background-color: #c62828; color: white;")
            self.uninstall_btn.clicked.connect(self._uninstall_plugin)
            self.uninstall_btn.setEnabled(False)
            btn_layout.addWidget(self.uninstall_btn)
            
            self.details_layout.addLayout(btn_layout)
            
            details_layout.addWidget(self.details_group)
            splitter.addWidget(details_widget)
            
            splitter.setSizes([300, 500])
            installed_layout.addWidget(splitter)
            
            # Info label at bottom
            info_label = QLabel(
                "💡 Drop plugins into the 'plugins' folder to install them. "
                "Double-click a plugin to open it."
            )
            info_label.setStyleSheet("color: #888; font-style: italic;")
            installed_layout.addWidget(info_label)
            
            # Store reference to main view for installed tab
            self.main_view = splitter
            
            self.view_tabs.addTab(installed_widget, "📦 Installed")
            
            # =====================================================================
            # PLUGIN STORE TAB
            # =====================================================================
            store_widget = QWidget()
            store_layout = QVBoxLayout(store_widget)
            store_layout.setContentsMargins(8, 12, 8, 8)
            
            # Store Header with search and auth
            store_header = QHBoxLayout()
            
            store_title = QLabel("🛒 Plugin Store")
            store_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #4fc3f7;")
            store_header.addWidget(store_title)
            
            store_header.addStretch()
            
            # Search
            self.store_search = QLineEdit()
            self.store_search.setPlaceholderText("Search plugins...")
            self.store_search.setMinimumWidth(220)
            self.store_search.setMaximumWidth(280)
            self.store_search.setStyleSheet("""
                QLineEdit {
                    background-color: #2a2a3a;
                    border: 1px solid #3a3a4a;
                    border-radius: 16px;
                    padding: 6px 14px;
                    color: #ffffff;
                    font-size: 12px;
                }
                QLineEdit:focus {
                    border-color: #4fc3f7;
                }
            """)
            self.store_search.returnPressed.connect(self._search_store)
            store_header.addWidget(self.store_search)
            
            search_btn = QPushButton("🔍")
            search_btn.setFixedSize(32, 32)
            search_btn.setStyleSheet("""
                QPushButton {
                    background-color: #3a3a4a;
                    border-radius: 16px;
                    border: none;
                    font-size: 16px;
                }
                QPushButton:hover {
                    background-color: #4fc3f7;
                }
            """)
            search_btn.clicked.connect(self._search_store)
            store_header.addWidget(search_btn)
            
            refresh_store_btn = QPushButton("🔄")
            refresh_store_btn.setFixedSize(32, 32)
            refresh_store_btn.setToolTip("Refresh store")
            refresh_store_btn.setStyleSheet("""
                QPushButton {
                    background-color: #3a3a4a;
                    border-radius: 16px;
                    border: none;
                    font-size: 16px;
                }
                QPushButton:hover {
                    background-color: #4fc3f7;
                }
            """)
            refresh_store_btn.clicked.connect(self._refresh_store)
            store_header.addWidget(refresh_store_btn)
            
            # Auth buttons
            self.login_btn = QPushButton("🔑 Login")
            self.login_btn.setStyleSheet("""
                QPushButton {
                    background-color: #3a3a4a;
                    border-radius: 14px;
                    padding: 6px 14px;
                    border: none;
                }
                QPushButton:hover {
                    background-color: #4fc3f7;
                    color: #000;
                }
            """)
            self.login_btn.clicked.connect(self._show_login_dialog)
            store_header.addWidget(self.login_btn)
            
            self.user_menu_btn = QPushButton()
            self.user_menu_btn.setVisible(False)
            self.user_menu_btn.setStyleSheet("""
                QPushButton {
                    background-color: #2e7d32;
                    border-radius: 14px;
                    padding: 6px 14px;
                    border: none;
                    color: #fff;
                }
                QPushButton:hover {
                    background-color: #4CAF50;
                }
            """)
            self.user_menu_btn.clicked.connect(self._show_user_menu)
            store_header.addWidget(self.user_menu_btn)
            
            store_layout.addLayout(store_header)
            
            # Category filter
            cat_layout = QHBoxLayout()
            cat_label = QLabel("Category:")
            cat_label.setStyleSheet("color: #888; font-size: 12px;")
            cat_layout.addWidget(cat_label)
            
            self.category_combo = QComboBox()
            self.category_combo.addItems(["All", "Tools", "Extraction", "Modification", "ADB", "Fastboot", "Utilities", "Other"])
            self.category_combo.currentTextChanged.connect(self._filter_store_category)
            self.category_combo.setMinimumWidth(140)
            self.category_combo.setStyleSheet("""
                QComboBox {
                    background-color: #2a2a3a;
                    border: 1px solid #3a3a4a;
                    border-radius: 12px;
                    padding: 5px 12px;
                    color: #ffffff;
                }
                QComboBox:hover {
                    border-color: #4fc3f7;
                }
                QComboBox::drop-down {
                    border: none;
                    padding-right: 8px;
                }
            """)
            cat_layout.addWidget(self.category_combo)
            cat_layout.addStretch()
            
            # Developer upload button (visible when logged in)
            self.upload_btn = QPushButton("📤 Upload Plugin")
            self.upload_btn.clicked.connect(self._show_upload_dialog)
            self.upload_btn.setVisible(False)
            self.upload_btn.setStyleSheet("""
                QPushButton {
                    background-color: #4CAF50;
                    color: #fff;
                    font-weight: bold;
                    padding: 8px 16px;
                    border-radius: 14px;
                    border: none;
                }
                QPushButton:hover {
                    background-color: #66bb6a;
                }
            """)
            cat_layout.addWidget(self.upload_btn)
            
            store_layout.addLayout(cat_layout)
            
            # Store plugin grid (using scroll area with grid)
            self.store_scroll = QScrollArea()
            self.store_scroll.setWidgetResizable(True)
            self.store_scroll.setFrameShape(QFrame.Shape.NoFrame)
            
            self.store_grid_widget = QWidget()
            self.store_grid_layout = QGridLayout(self.store_grid_widget)
            self.store_grid_layout.setSpacing(16)
            self.store_grid_layout.setContentsMargins(8, 8, 8, 8)
            self.store_grid_layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            
            self.store_scroll.setWidget(self.store_grid_widget)
            store_layout.addWidget(self.store_scroll)
            
            # Store status
            self.store_status = QLabel("Connect to the Plugin Store to browse available plugins.")
            self.store_status.setStyleSheet("color: #6a6a8a; font-size: 12px; padding: 8px;")
            self.store_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
            store_layout.addWidget(self.store_status)
            
            self.view_tabs.addTab(store_widget, "🛒 Store")
            
            # =====================================================================
            # PLUGIN PLAYGROUND TAB (Coming Soon)
            # =====================================================================
            playground_widget = QWidget()
            playground_layout = QVBoxLayout(playground_widget)
            playground_layout.setContentsMargins(0, 0, 0, 0)
            
            # Scroll area for content
            playground_scroll = QScrollArea()
            playground_scroll.setWidgetResizable(True)
            playground_scroll.setFrameShape(QFrame.Shape.NoFrame)
            playground_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            
            playground_scroll_widget = QWidget()
            playground_scroll_layout = QVBoxLayout(playground_scroll_widget)
            playground_scroll_layout.setContentsMargins(0, 20, 0, 20)
            playground_scroll_layout.setSpacing(10)
            playground_scroll_layout.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            
            # Icon
            playground_icon = QLabel("🧪")
            playground_icon.setStyleSheet("font-size: 48px;")
            playground_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            playground_scroll_layout.addWidget(playground_icon)
            
            # Title
            playground_title = QLabel("Plugin Playground")
            playground_title.setStyleSheet("font-size: 22px; font-weight: bold; color: #4fc3f7;")
            playground_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            playground_scroll_layout.addWidget(playground_title)
            
            # Coming Soon badge
            coming_badge = QLabel("🚧 COMING SOON 🚧")
            coming_badge.setStyleSheet("""
                QLabel {
                    background-color: rgba(255, 152, 0, 0.2);
                    color: #ff9800;
                    font-weight: bold;
                    font-size: 11px;
                    padding: 5px 16px;
                    border-radius: 10px;
                }
            """)
            coming_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            playground_scroll_layout.addWidget(coming_badge)
            
            # Description
            playground_desc = QLabel(
                "Test your plugins before submitting them to the store!\n\n"
                "Features coming in a future update:\n"
                "✨ Load and preview plugins from any folder\n"
                "✅ Real-time manifest.json validation\n"
                "🐛 Live error console with full tracebacks\n"
                "📋 Dependency checker (pip packages, git repos)\n"
                "🎯 \"Ready to Submit\" checklist\n"
                "🔄 Hot-reload your changes instantly"
            )
            playground_desc.setStyleSheet("color: #bbb; font-size: 12px;")
            playground_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
            playground_desc.setWordWrap(True)
            playground_desc.setMaximumWidth(450)
            playground_scroll_layout.addWidget(playground_desc, 0, Qt.AlignmentFlag.AlignCenter)
            
            # Tip
            playground_tip = QLabel(
                "💡 For now, test plugins by placing them in the plugins/ folder and restarting."
            )
            playground_tip.setStyleSheet("""
                QLabel {
                    color: #999;
                    font-size: 11px;
                    background-color: rgba(79, 195, 247, 0.1);
                    padding: 10px 16px;
                    border-radius: 8px;
                }
            """)
            playground_tip.setAlignment(Qt.AlignmentFlag.AlignCenter)
            playground_tip.setWordWrap(True)
            playground_tip.setMaximumWidth(450)
            playground_scroll_layout.addWidget(playground_tip, 0, Qt.AlignmentFlag.AlignCenter)
            
            playground_scroll_layout.addStretch()
            
            playground_scroll.setWidget(playground_scroll_widget)
            playground_layout.addWidget(playground_scroll)
            
            self.view_tabs.addTab(playground_widget, "🧪 Playground")
            
            # =====================================================================
            # VISUAL PLUGIN MAKER TAB (Coming Soon)
            # =====================================================================
            maker_widget = QWidget()
            maker_layout = QVBoxLayout(maker_widget)
            maker_layout.setContentsMargins(0, 0, 0, 0)
            
            # Scroll area for content
            maker_scroll = QScrollArea()
            maker_scroll.setWidgetResizable(True)
            maker_scroll.setFrameShape(QFrame.Shape.NoFrame)
            maker_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            
            maker_scroll_widget = QWidget()
            maker_scroll_layout = QVBoxLayout(maker_scroll_widget)
            maker_scroll_layout.setContentsMargins(0, 20, 0, 20)
            maker_scroll_layout.setSpacing(10)
            maker_scroll_layout.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            
            # Icon
            maker_icon = QLabel("🎨")
            maker_icon.setStyleSheet("font-size: 48px;")
            maker_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            maker_scroll_layout.addWidget(maker_icon)
            
            # Title
            maker_title = QLabel("Visual Plugin Maker")
            maker_title.setStyleSheet("font-size: 22px; font-weight: bold; color: #e91e63;")
            maker_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            maker_scroll_layout.addWidget(maker_title)
            
            # Coming Soon badge
            maker_badge = QLabel("🚧 COMING SOON 🚧")
            maker_badge.setStyleSheet("""
                QLabel {
                    background-color: rgba(255, 152, 0, 0.2);
                    color: #ff9800;
                    font-weight: bold;
                    font-size: 11px;
                    padding: 5px 16px;
                    border-radius: 10px;
                }
            """)
            maker_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            maker_scroll_layout.addWidget(maker_badge)
            
            # Description
            maker_desc = QLabel(
                "Create plugins without writing code!\n\n"
                "Drag-and-drop interface for building plugin UIs:\n"
                "🖱️ Drag & drop buttons, labels, inputs, and more\n"
                "🎨 Visual style editor with live preview\n"
                "⚡ Pre-built action blocks (run ADB, extract, pack)\n"
                "🔗 Connect UI elements to actions visually\n"
                "📝 Auto-generates clean Python code\n"
                "📦 One-click export to plugin package\n"
                "🧠 AI-assisted logic suggestions"
            )
            maker_desc.setStyleSheet("color: #bbb; font-size: 12px;")
            maker_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
            maker_desc.setWordWrap(True)
            maker_desc.setMaximumWidth(450)
            maker_scroll_layout.addWidget(maker_desc, 0, Qt.AlignmentFlag.AlignCenter)
            
            # Tip
            maker_tip = QLabel(
                "💡 No coding experience? No problem! The Visual Plugin Maker will let anyone create powerful plugins."
            )
            maker_tip.setStyleSheet("""
                QLabel {
                    color: #999;
                    font-size: 11px;
                    background-color: rgba(233, 30, 99, 0.1);
                    padding: 10px 16px;
                    border-radius: 8px;
                }
            """)
            maker_tip.setAlignment(Qt.AlignmentFlag.AlignCenter)
            maker_tip.setWordWrap(True)
            maker_tip.setMaximumWidth(450)
            maker_scroll_layout.addWidget(maker_tip, 0, Qt.AlignmentFlag.AlignCenter)
            
            maker_scroll_layout.addStretch()
            
            maker_scroll.setWidget(maker_scroll_widget)
            maker_layout.addWidget(maker_scroll)
            
            self.view_tabs.addTab(maker_widget, "🎨 Creator")
            
            layout.addWidget(self.view_tabs)
            
            # Plugin content area (shown when a plugin is opened)
            self.plugin_container = QWidget()
            self.plugin_container_layout = QVBoxLayout(self.plugin_container)
            self.plugin_container_layout.setContentsMargins(0, 0, 0, 0)
            
            # Back button header
            back_header = QHBoxLayout()
            self.back_btn = QPushButton("← Back to Plugins")
            self.back_btn.clicked.connect(self._close_plugin)
            back_header.addWidget(self.back_btn)
            
            self.active_plugin_label = QLabel("")
            self.active_plugin_label.setStyleSheet("font-weight: bold; font-size: 14px;")
            back_header.addWidget(self.active_plugin_label)
            back_header.addStretch()
            self.plugin_container_layout.addLayout(back_header)
            
            # Plugin widget holder
            self.plugin_widget_holder = QWidget()
            self.plugin_widget_layout = QVBoxLayout(self.plugin_widget_holder)
            self.plugin_widget_layout.setContentsMargins(0, 0, 0, 0)
            self.plugin_container_layout.addWidget(self.plugin_widget_holder)
            
            self.plugin_container.setVisible(False)
            layout.addWidget(self.plugin_container)
            
            # Update auth UI
            self._update_auth_ui()
        
        def _load_plugins(self):
            """Load and display all available plugins."""
            self.plugin_list.clear()
            
            # Create example plugin if plugins folder is empty
            plugin_manager.create_example_plugin()
            
            # Discover external plugins
            external_plugins = plugin_manager.discover_plugins()
            
            # Add built-in plugins first (if any)
            for plugin_id, plugin in self.builtin_plugins.items():
                manifest = plugin.manifest
                item = QListWidgetItem(f"{manifest.icon} {manifest.name}")
                item.setData(Qt.ItemDataRole.UserRole, {
                    'id': plugin_id,
                    'builtin': True,
                    'manifest': manifest
                })
                if manifest.license_type == "free":
                    item.setToolTip("Free (built-in)")
                self.plugin_list.addItem(item)
            
            # Add external plugins
            for manifest in external_plugins:
                icon = manifest.icon
                if not manifest.enabled:
                    icon = "⭕"  # Disabled indicator
                
                item = QListWidgetItem(f"{icon} {manifest.name}")
                item.setData(Qt.ItemDataRole.UserRole, {
                    'id': manifest.id,
                    'builtin': False,
                    'manifest': manifest
                })
                
                # Tooltip with license info
                tip = f"v{manifest.version} by {manifest.author}"
                if manifest.license_type == "paid":
                    tip += f" - ${manifest.price} {manifest.currency}"
                elif manifest.license_type == "donation":
                    tip += " - Donations welcome"
                item.setToolTip(tip)
                
                self.plugin_list.addItem(item)
        
        def _on_plugin_selected(self, current, previous):
            """Show details for selected plugin."""
            if not current:
                return
            
            data = current.data(Qt.ItemDataRole.UserRole)
            manifest = data['manifest']
            
            self.plugin_icon.setText(manifest.icon)
            self.plugin_name.setText(manifest.name)
            self.plugin_version.setText(f"Version {manifest.version}")
            self.plugin_author.setText(f"by {manifest.author}")
            self.plugin_desc.setText(manifest.description)
            
            # Update enable button
            if data['builtin']:
                self.enable_btn.setText("✓ Built-in")
                self.enable_btn.setEnabled(False)
            else:
                if manifest.enabled:
                    self.enable_btn.setText("✓ Enabled")
                else:
                    self.enable_btn.setText("○ Disabled")
                self.enable_btn.setEnabled(True)
            
            # Only developer_guide cannot be uninstalled
            if data['id'] == 'developer_guide':
                self.uninstall_btn.setEnabled(False)
                self.uninstall_btn.setToolTip("Developer Guide cannot be uninstalled")
            else:
                self.uninstall_btn.setEnabled(True)
                self.uninstall_btn.setToolTip("Remove this plugin")
            
            self.open_btn.setEnabled(manifest.enabled)
            
            # Payment/license info
            if manifest.license_type in ("paid", "donation"):
                self.payment_group.setVisible(True)
                
                if manifest.license_type == "paid":
                    if manifest.licensed:
                        self.license_label.setText("✓ Licensed - Thank you for your support!")
                        self.payment_btn.setText("💝 Tip the Developer")
                    else:
                        self.license_label.setText(
                            f"This plugin costs ${manifest.price:.2f} {manifest.currency}.\n"
                            "Please support the developer to unlock all features."
                        )
                        self.payment_btn.setText(f"💰 Purchase (${manifest.price:.2f})")
                else:
                    self.license_label.setText(
                        "This plugin is free, but donations help the developer\n"
                        "continue creating great tools!"
                    )
                    self.payment_btn.setText("💝 Donate")
                
                self.payment_btn.setVisible(bool(manifest.payment_address))
                self._current_payment_info = {
                    'address': manifest.payment_address,
                    'type': manifest.payment_type,
                    'price': manifest.price
                }
            else:
                self.payment_group.setVisible(False)
        
        def _toggle_enable(self):
            """Toggle the selected plugin's enabled state."""
            current = self.plugin_list.currentItem()
            if not current:
                return
            
            data = current.data(Qt.ItemDataRole.UserRole)
            if data['builtin']:
                return
            
            manifest = data['manifest']
            new_state = not manifest.enabled
            plugin_manager.enable_plugin(manifest.id, new_state)
            
            # Refresh list
            self._load_plugins()
        
        def _uninstall_plugin(self):
            """Uninstall the selected plugin."""
            current = self.plugin_list.currentItem()
            if not current:
                return
            
            data = current.data(Qt.ItemDataRole.UserRole)
            plugin_id = data['id']
            
            # Only developer_guide is protected
            if plugin_id == 'developer_guide':
                QMessageBox.warning(
                    self,
                    "Cannot Uninstall",
                    "The Plugin Developer's Guide cannot be uninstalled."
                )
                return
            
            manifest = data['manifest']
            
            # Confirm uninstall
            reply = QMessageBox.question(
                self,
                "Confirm Uninstall",
                f"Are you sure you want to uninstall '{manifest.name}'?\n\n"
                "This will delete the plugin folder and all its files.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply != QMessageBox.StandardButton.Yes:
                return
            
            # Get plugin path and delete
            plugins_dir = plugin_manager._get_plugins_dir()
            plugin_path = os.path.join(plugins_dir, plugin_id)
            
            if os.path.exists(plugin_path):
                try:
                    self._force_remove_directory(plugin_path, plugin_id)
                    
                    QMessageBox.information(
                        self,
                        "Plugin Uninstalled",
                        f"'{manifest.name}' has been successfully uninstalled."
                    )
                    
                    # Refresh the plugin list
                    self._load_plugins()
                    
                    # Clear details panel
                    self.plugin_icon.setText("🔌")
                    self.plugin_name.setText("Select a plugin")
                    self.plugin_version.setText("")
                    self.plugin_author.setText("")
                    self.plugin_desc.setText("")
                    self.payment_group.setVisible(False)
                    self.enable_btn.setEnabled(False)
                    self.open_btn.setEnabled(False)
                    self.uninstall_btn.setEnabled(False)
                    
                except Exception as e:
                    QMessageBox.critical(
                        self,
                        "Uninstall Failed",
                        f"Failed to uninstall plugin:\n{str(e)}"
                    )
            else:
                QMessageBox.warning(
                    self,
                    "Plugin Not Found",
                    f"Plugin folder not found at:\n{plugin_path}"
                )
        
        def _force_remove_directory(self, path: str, plugin_id: str):
            """Forcefully remove a directory, handling locked files and read-only attributes."""
            import shutil
            import stat
            import subprocess
            import time
            
            # Kill processes that might be locking files
            processes_to_kill = ['adb.exe', 'fastboot.exe', 'mtk_client.exe', 'python.exe']
            plugin_path_lower = path.lower()
            
            # Try to kill any processes that might be using files in this plugin
            try:
                if sys.platform == 'win32':
                    # Use tasklist to find processes and check if they're from this plugin folder
                    result = subprocess.run(
                        ['tasklist', '/FO', 'CSV', '/V'],
                        capture_output=True, text=True, timeout=10
                    )
                    # Look for adb.exe or fastboot.exe specifically
                    for proc_name in ['adb.exe', 'fastboot.exe']:
                        if proc_name in result.stdout.lower():
                            # Check if this is from our plugin directory by trying to kill gracefully
                            subprocess.run(
                                ['taskkill', '/F', '/IM', proc_name],
                                capture_output=True, timeout=5
                            )
                            time.sleep(0.5)  # Give time for process to fully terminate
            except Exception:
                pass  # Best effort - continue even if this fails
            
            def on_rm_error(func, filepath, exc_info):
                """Error handler for shutil.rmtree - handles read-only and permission errors."""
                try:
                    # Clear the read-only flag
                    os.chmod(filepath, stat.S_IWRITE | stat.S_IREAD)
                    # Try again
                    func(filepath)
                except Exception as e:
                    # If still failing, try one more approach on Windows
                    if sys.platform == 'win32':
                        try:
                            # Use attrib to clear all attributes
                            subprocess.run(
                                ['attrib', '-R', '-H', '-S', filepath],
                                capture_output=True, timeout=5
                            )
                            func(filepath)
                        except Exception:
                            raise e
                    else:
                        raise e
            
            # First pass: try to make all files writable
            for root, dirs, files in os.walk(path):
                for name in files:
                    filepath = os.path.join(root, name)
                    try:
                        os.chmod(filepath, stat.S_IWRITE | stat.S_IREAD)
                    except Exception:
                        pass
                for name in dirs:
                    dirpath = os.path.join(root, name)
                    try:
                        os.chmod(dirpath, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
                    except Exception:
                        pass
            
            # Try rmtree with error handler
            try:
                shutil.rmtree(path, onerror=on_rm_error)
            except Exception as e:
                # Last resort on Windows: use rd /s /q
                if sys.platform == 'win32':
                    try:
                        # Use Windows rd command which can be more forceful
                        result = subprocess.run(
                            ['cmd', '/c', 'rd', '/s', '/q', path],
                            capture_output=True, text=True, timeout=30
                        )
                        if os.path.exists(path):
                            raise Exception(f"Directory still exists after rd command: {result.stderr}")
                    except subprocess.TimeoutExpired:
                        raise Exception("Timeout while removing directory")
                    except Exception as rd_error:
                        raise Exception(f"Failed to remove directory: {str(e)}. rd also failed: {str(rd_error)}")
                else:
                    raise
        
        def _open_payment(self):
            """Open payment link or show payment address."""
            if not hasattr(self, '_current_payment_info'):
                return
            
            info = self._current_payment_info
            if info['type'] == 'btc':
                # Show BTC address with copy option
                QMessageBox.information(
                    self,
                    "Bitcoin Payment",
                    f"Send payment to:\n\n{info['address']}\n\n"
                    "After payment, the developer will provide a license key."
                )
            elif info['type'] in ('paypal', 'kofi', 'patreon', 'github'):
                # Open URL
                import webbrowser
                webbrowser.open(info['address'])
            else:
                QMessageBox.information(
                    self,
                    "Payment",
                    f"Payment address:\n{info['address']}"
                )
        
        def _open_plugin(self, item=None):
            """Open the selected plugin."""
            # Handle case where called from button click (passes bool) vs double-click (passes item)
            if item is None or isinstance(item, bool):
                item = self.plugin_list.currentItem()
            if not item:
                return
            
            data = item.data(Qt.ItemDataRole.UserRole)
            if not data:
                return
            
            manifest = data['manifest']
            plugin_id = data['id']
            
            if not manifest.enabled:
                QMessageBox.warning(
                    self,
                    "Plugin Disabled",
                    "This plugin is disabled. Enable it first to use it."
                )
                return
            
            # Check for post-install steps (drivers, git clones, etc.)
            if not data['builtin'] and manifest.post_install:
                # Check if post-install has already been completed
                plugin_config = plugin_manager.config.get(plugin_id, {})
                if not plugin_config.get('post_install_done', False):
                    # Build description of what will happen
                    steps_desc = []
                    for step in manifest.post_install:
                        step_type = step.get('type', '')
                        step_name = step.get('name', step_type)
                        if step_type == 'driver':
                            steps_desc.append(f"• Install driver: {step.get('file', 'Unknown')}")
                        elif step_type == 'git_clone':
                            steps_desc.append(f"• Clone repository: {step.get('repo', 'Unknown')}")
                        elif step_type == 'pip_requirements':
                            steps_desc.append(f"• Install pip requirements from cloned repo")
                        elif step_type == 'command':
                            steps_desc.append(f"• Run setup command")
                    
                    if steps_desc:
                        msg = (
                            f"Plugin '{manifest.name}' requires additional setup:\n\n"
                            + "\n".join(steps_desc) + "\n\n"
                            "Would you like to run the setup now?\n"
                            "(This may take a few minutes)"
                        )
                        
                        reply = QMessageBox.question(
                            self,
                            "Plugin Setup Required",
                            msg,
                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                        )
                        
                        if reply == QMessageBox.StandardButton.Yes:
                            # Create progress dialog
                            from PyQt6.QtWidgets import QProgressDialog
                            progress = QProgressDialog(
                                "Running plugin setup...", "Cancel", 0, len(manifest.post_install), self
                            )
                            progress.setWindowModality(Qt.WindowModality.WindowModal)
                            progress.setMinimumDuration(0)
                            progress.setValue(0)
                            progress.setWindowTitle("Plugin Setup")
                            
                            step_idx = [0]  # Use list for closure
                            
                            def progress_callback(step_name: str, status: str):
                                progress.setLabelText(f"Step: {step_name}\nStatus: {status}")
                                step_idx[0] += 1
                                progress.setValue(min(step_idx[0], len(manifest.post_install)))
                                QApplication.processEvents()
                            
                            self._log(f"Running post-install setup for {manifest.name}...")
                            QApplication.processEvents()
                            
                            success, message = plugin_manager.run_post_install(plugin_id, progress_callback)
                            progress.close()
                            
                            if success:
                                self._log(f"✓ Post-install setup complete")
                                # Mark as done
                                if plugin_id not in plugin_manager.config:
                                    plugin_manager.config[plugin_id] = {}
                                plugin_manager.config[plugin_id]['post_install_done'] = True
                                plugin_manager._save_config()
                                
                                QMessageBox.information(
                                    self,
                                    "Setup Complete",
                                    f"Plugin '{manifest.name}' setup completed successfully!"
                                )
                            else:
                                self._log(f"✗ Post-install setup failed: {message}")
                                QMessageBox.warning(
                                    self,
                                    "Setup Issues",
                                    f"Some setup steps had issues:\n\n{message}\n\n"
                                    "The plugin may still work, but some features might be unavailable.\n"
                                    "You can try the manual setup in the plugin's Setup tab."
                                )
                        else:
                            # User declined - show info about manual setup
                            QMessageBox.information(
                                self,
                                "Setup Skipped",
                                "You can run the setup later from the plugin's Setup tab.\n\n"
                                "Some features may not work until setup is complete."
                            )
            
            # Generic check: if plugin has git_clone or other setup requirements not yet completed
            if not data['builtin']:
                plugin_config = plugin_manager.config.get(plugin_id, {})
                if not plugin_config.get('setup_complete', False):
                    # Check if plugin has setup requirements
                    has_git_clone = manifest.git_clone is not None
                    has_bundled_binaries = bool(manifest.bundled_binaries)
                    
                    if has_git_clone or has_bundled_binaries:
                        # Run setup
                        from PyQt6.QtWidgets import QProgressDialog
                        progress_dialog = QProgressDialog(
                            f"Setting up {manifest.name}...",
                            "Cancel",
                            0, 100,
                            self
                        )
                        progress_dialog.setWindowTitle("Plugin Setup")
                        progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
                        progress_dialog.setMinimumDuration(0)
                        progress_dialog.setValue(0)
                        
                        def setup_progress(step_name: str, status: str, progress: int):
                            if progress_dialog.wasCanceled():
                                return
                            progress_dialog.setLabelText(f"{step_name}\n{status}")
                            progress_dialog.setValue(progress)
                            QApplication.processEvents()
                        
                        success, message = plugin_manager.setup_plugin_dependencies(plugin_id, setup_progress)
                        progress_dialog.close()
                        
                        if not success:
                            reply = QMessageBox.warning(
                                self,
                                "Setup Issues",
                                f"Some setup steps had issues:\n\n{message}\n\n"
                                "Would you like to continue loading the plugin anyway?",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                            )
                            if reply != QMessageBox.StandardButton.Yes:
                                return
            
            # Load plugin if not already loaded
            if plugin_id in self.loaded_widgets:
                widget = self.loaded_widgets[plugin_id]
            else:
                if data['builtin']:
                    plugin = self.builtin_plugins[plugin_id]
                else:
                    plugin = plugin_manager.load_plugin(plugin_id)
                
                if not plugin:
                    QMessageBox.critical(
                        self,
                        "Error",
                        f"Failed to load plugin: {manifest.name}"
                    )
                    return
                
                try:
                    widget = plugin.create_widget(self.parent_window)
                    if widget is None:
                        QMessageBox.critical(
                            self,
                            "Error",
                            f"Plugin '{manifest.name}' returned no widget."
                        )
                        return
                    self.loaded_widgets[plugin_id] = widget
                    self.loaded_plugins[plugin_id] = plugin  # Track plugin for cleanup
                except Exception as e:
                    logger.exception(f"Failed to create plugin widget: {e}")
                    QMessageBox.critical(
                        self,
                        "Error",
                        f"Failed to create plugin widget:\n{str(e)}"
                    )
                    return
            
            # Track active plugin for cleanup
            self.active_plugin_id = plugin_id
            
            # Show plugin view
            self.view_tabs.setVisible(False)
            
            # Clear old widget from layout (but don't destroy it)
            while self.plugin_widget_layout.count():
                child = self.plugin_widget_layout.takeAt(0)
                if child.widget():
                    child.widget().setParent(None)
            
            # Add widget to layout
            self.plugin_widget_layout.addWidget(widget)
            widget.setVisible(True)
            self.active_plugin_label.setText(f"{manifest.icon} {manifest.name}")
            self.plugin_container.setVisible(True)
        
        def _close_plugin(self):
            """Close the current plugin and return to list."""
            # Call cleanup on the active plugin if it has one
            if self.active_plugin_id and self.active_plugin_id in self.loaded_plugins:
                plugin = self.loaded_plugins[self.active_plugin_id]
                if hasattr(plugin, 'cleanup') and callable(plugin.cleanup):
                    try:
                        plugin.cleanup()
                    except Exception as e:
                        logger.warning(f"[Plugins] Cleanup error for {self.active_plugin_id}: {e}")
            
            self.active_plugin_id = None
            self.plugin_container.setVisible(False)
            self.view_tabs.setVisible(True)
        
        def _open_plugins_folder(self):
            """Open the plugins folder in file explorer."""
            plugins_dir = plugin_manager._get_plugins_dir()
            os.makedirs(plugins_dir, exist_ok=True)
            
            if sys.platform == 'win32':
                os.startfile(plugins_dir)
            elif sys.platform == 'darwin':
                subprocess.run(['open', plugins_dir])
            else:
                subprocess.run(['xdg-open', plugins_dir])
        
        # =====================================================================
        # PLUGIN STORE METHODS
        # =====================================================================
        
        def _update_auth_ui(self):
            """Update the auth UI based on login status."""
            if plugin_store_api.is_logged_in():
                self.login_btn.setVisible(False)
                self.user_menu_btn.setVisible(True)
                self.user_menu_btn.setText(f"👤 {plugin_store_api.user.get('username', 'User')}")
                self.upload_btn.setVisible(True)
            else:
                self.login_btn.setVisible(True)
                self.user_menu_btn.setVisible(False)
                self.upload_btn.setVisible(False)
        
        def _refresh_store(self):
            """Refresh the plugin store listing."""
            self.store_status.setText("Loading plugins from store...")
            QApplication.processEvents()
            
            # Clear existing grid
            while self.store_grid_layout.count():
                item = self.store_grid_layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            
            # Fetch plugins
            plugins = plugin_store_api.get_plugins()
            
            if not plugins:
                self.store_status.setText(
                    "No plugins found or unable to connect to store.\n"
                    f"Server: {plugin_store_api.base_url}"
                )
                return
            
            self.store_status.setText(f"Found {len(plugins)} plugins")
            self._store_plugins = plugins
            self._display_store_plugins(plugins)
        
        def _display_store_plugins(self, plugins: list):
            """Display plugins in the store grid."""
            # Clear existing
            while self.store_grid_layout.count():
                item = self.store_grid_layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            
            row, col = 0, 0
            max_cols = 3
            
            for plugin in plugins:
                card = self._create_store_plugin_card(plugin)
                self.store_grid_layout.addWidget(card, row, col)
                col += 1
                if col >= max_cols:
                    col = 0
                    row += 1
        
        def _create_store_plugin_card(self, plugin: dict) -> QWidget:
            """Create a modern card widget for a store plugin."""
            card = QFrame()
            card.setFrameShape(QFrame.Shape.StyledPanel)
            card.setStyleSheet("""
                QFrame {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #2d2d3a, stop:1 #1e1e28);
                    border: 1px solid #3a3a4a;
                    border-radius: 12px;
                    padding: 0px;
                }
                QFrame:hover {
                    border: 2px solid #4fc3f7;
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #353545, stop:1 #252530);
                }
            """)
            card.setFixedSize(280, 220)
            
            layout = QVBoxLayout(card)
            layout.setSpacing(8)
            layout.setContentsMargins(14, 14, 14, 12)
            
            # Header with icon and name
            header = QHBoxLayout()
            header.setSpacing(12)
            
            # Icon with background
            icon_container = QFrame()
            icon_container.setFixedSize(50, 50)
            icon_container.setStyleSheet("""
                QFrame {
                    background-color: rgba(79, 195, 247, 0.15);
                    border-radius: 10px;
                    border: none;
                }
            """)
            icon_layout = QVBoxLayout(icon_container)
            icon_layout.setContentsMargins(0, 0, 0, 0)
            icon_label = QLabel(plugin.get('icon', '🔌'))
            icon_label.setStyleSheet("font-size: 28px; background: transparent; border: none;")
            icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            icon_layout.addWidget(icon_label)
            header.addWidget(icon_container)
            
            # Name and author column
            name_col = QVBoxLayout()
            name_col.setSpacing(2)
            
            name_label = QLabel(plugin.get('name', 'Unknown'))
            name_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #ffffff; background: transparent; border: none;")
            name_label.setWordWrap(True)
            name_col.addWidget(name_label)
            
            info_label = QLabel(f"by {plugin.get('author_name', 'Unknown')} • v{plugin.get('version', '1.0')}")
            info_label.setStyleSheet("color: #8888aa; font-size: 11px; background: transparent; border: none;")
            name_col.addWidget(info_label)
            
            header.addLayout(name_col, 1)
            layout.addLayout(header)
            
            # Description - now with more space
            desc = plugin.get('description', 'No description available')
            if len(desc) > 120:
                desc = desc[:117] + '...'
            desc_label = QLabel(desc)
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet("color: #aaaacc; font-size: 12px; line-height: 1.4; background: transparent; border: none;")
            desc_label.setMinimumHeight(50)
            desc_label.setMaximumHeight(60)
            layout.addWidget(desc_label)
            
            layout.addStretch()
            
            # Footer with license badge, downloads, and button
            footer = QHBoxLayout()
            footer.setSpacing(8)
            
            # License/Price badge with pill style
            license_type = plugin.get('license_type', 'free')
            price_badge = QLabel()
            if license_type == 'free':
                price_badge.setText("FREE")
                price_badge.setStyleSheet("""
                    QLabel {
                        background-color: rgba(76, 175, 80, 0.2);
                        color: #4CAF50;
                        font-weight: bold;
                        font-size: 10px;
                        padding: 4px 10px;
                        border-radius: 10px;
                        border: none;
                    }
                """)
            elif license_type == 'donation':
                price_badge.setText("☕ TIP")
                price_badge.setStyleSheet("""
                    QLabel {
                        background-color: rgba(255, 152, 0, 0.2);
                        color: #ff9800;
                        font-weight: bold;
                        font-size: 10px;
                        padding: 4px 10px;
                        border-radius: 10px;
                        border: none;
                    }
                """)
            else:
                price = plugin.get('price', 0)
                price_badge.setText(f"${price:.2f}")
                price_badge.setStyleSheet("""
                    QLabel {
                        background-color: rgba(244, 67, 54, 0.2);
                        color: #f44336;
                        font-weight: bold;
                        font-size: 10px;
                        padding: 4px 10px;
                        border-radius: 10px;
                        border: none;
                    }
                """)
            footer.addWidget(price_badge)
            
            # Downloads count with icon
            downloads = plugin.get('downloads', 0)
            dl_label = QLabel(f"⬇ {downloads}")
            dl_label.setStyleSheet("color: #666688; font-size: 11px; background: transparent; border: none;")
            footer.addWidget(dl_label)
            
            footer.addStretch()
            
            # Details button - modern style
            details_btn = QPushButton("Details")
            details_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            details_btn.setStyleSheet("""
                QPushButton {
                    background-color: #4fc3f7;
                    color: #000000;
                    font-weight: bold;
                    font-size: 11px;
                    padding: 6px 16px;
                    border-radius: 12px;
                    border: none;
                }
                QPushButton:hover {
                    background-color: #81d4fa;
                }
                QPushButton:pressed {
                    background-color: #29b6f6;
                }
            """)
            details_btn.clicked.connect(lambda checked, p=plugin: self._show_plugin_details(p))
            footer.addWidget(details_btn)
            
            layout.addLayout(footer)
            
            return card
        
        def _show_plugin_details(self, plugin: dict):
            """Show detailed view of a plugin with HTML description."""
            from PyQt6.QtWidgets import QTextBrowser
            
            plugin_id = plugin.get('id')
            plugin_name = plugin.get('name', 'Unknown')
            
            # Fetch full plugin details from API (includes long_description)
            self.store_status.setText(f"Loading details for {plugin_name}...")
            QApplication.processEvents()
            
            full_plugin = plugin_store_api.get_plugin(plugin_id)
            if 'error' in full_plugin:
                QMessageBox.warning(self, "Error", f"Failed to load plugin details:\n{full_plugin['error']}")
                self.store_status.setText("Failed to load details")
                return
            
            self.store_status.setText("")
            
            dialog = QDialog(self)
            dialog.setWindowTitle(f"{full_plugin.get('icon', '🔌')} {plugin_name}")
            dialog.setMinimumSize(650, 550)
            
            layout = QVBoxLayout(dialog)
            
            # Header
            header = QHBoxLayout()
            
            icon_label = QLabel(full_plugin.get('icon', '🔌'))
            icon_label.setStyleSheet("font-size: 48px;")
            header.addWidget(icon_label)
            
            header_info = QVBoxLayout()
            
            name_label = QLabel(f"<b style='font-size: 18px;'>{plugin_name}</b>")
            name_label.setTextFormat(Qt.TextFormat.RichText)
            header_info.addWidget(name_label)
            
            author_label = QLabel(f"by <b>{full_plugin.get('author_name', 'Unknown')}</b> • v{full_plugin.get('version', '1.0')}")
            author_label.setStyleSheet("color: #888;")
            header_info.addWidget(author_label)
            
            stats_label = QLabel(f"⬇️ {full_plugin.get('downloads', 0)} downloads • ⭐ {full_plugin.get('rating', 0):.1f} ({full_plugin.get('rating_count', 0)} reviews)")
            stats_label.setStyleSheet("color: #666; font-size: 11px;")
            header_info.addWidget(stats_label)
            
            header.addLayout(header_info, 1)
            
            # Price badge
            license_type = full_plugin.get('license_type', 'free')
            if license_type == 'free':
                price_badge = QLabel("FREE")
                price_badge.setStyleSheet("background: #4CAF50; color: white; padding: 8px 16px; border-radius: 4px; font-weight: bold;")
            elif license_type == 'donation':
                price_badge = QLabel("DONATION")
                price_badge.setStyleSheet("background: #ff9800; color: white; padding: 8px 16px; border-radius: 4px; font-weight: bold;")
            else:
                price = full_plugin.get('price', 0)
                price_badge = QLabel(f"${price:.2f}")
                price_badge.setStyleSheet("background: #f44336; color: white; padding: 8px 16px; border-radius: 4px; font-weight: bold;")
            header.addWidget(price_badge)
            
            layout.addLayout(header)
            
            # Category and tags
            tags_layout = QHBoxLayout()
            
            cat_label = QLabel(f"📁 {full_plugin.get('category', 'other')}")
            cat_label.setStyleSheet("background: #333; padding: 4px 8px; border-radius: 4px; font-size: 11px;")
            tags_layout.addWidget(cat_label)
            
            tags = full_plugin.get('tags', [])
            if isinstance(tags, str):
                try:
                    tags = json.loads(tags)
                except:
                    tags = []
            
            for tag in tags[:5]:
                tag_label = QLabel(f"🏷️ {tag}")
                tag_label.setStyleSheet("background: #2a4a6a; padding: 4px 8px; border-radius: 4px; font-size: 11px;")
                tags_layout.addWidget(tag_label)
            
            tags_layout.addStretch()
            layout.addLayout(tags_layout)
            
            # Screenshots button (if screenshots available)
            screenshots = full_plugin.get('screenshots', [])
            if isinstance(screenshots, str):
                try:
                    screenshots = json.loads(screenshots)
                except:
                    screenshots = []
            
            if screenshots:
                screenshots_btn = QPushButton(f"🖼️ View Screenshots ({len(screenshots)})")
                screenshots_btn.setStyleSheet("background: #2196F3; padding: 8px 16px;")
                screenshots_btn.clicked.connect(lambda: self._show_screenshots_dialog(plugin_name, plugin_id, screenshots))
                layout.addWidget(screenshots_btn)
            
            # Description area with HTML support
            desc_group = QGroupBox("Description")
            desc_layout = QVBoxLayout(desc_group)
            
            desc_browser = QTextBrowser()
            desc_browser.setOpenExternalLinks(True)
            desc_browser.setStyleSheet("""
                QTextBrowser {
                    background-color: #1a1a1a;
                    border: 1px solid #333;
                    border-radius: 4px;
                    padding: 10px;
                }
            """)
            
            # Build HTML content
            long_desc = full_plugin.get('long_description', '')
            short_desc = full_plugin.get('description', '')
            
            html_content = f"""
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; color: #e0e0e0; line-height: 1.6; }}
                h1, h2, h3 {{ color: #4fc3f7; }}
                a {{ color: #4fc3f7; }}
                code {{ background: #333; padding: 2px 6px; border-radius: 3px; }}
                pre {{ background: #1a1a2e; padding: 10px; border-radius: 6px; overflow-x: auto; }}
                ul, ol {{ margin-left: 20px; }}
                .highlight {{ background: #4fc3f720; padding: 10px; border-left: 3px solid #4fc3f7; margin: 10px 0; }}
            </style>
            <p>{short_desc}</p>
            <hr style="border-color: #333;">
            {long_desc if long_desc else '<p style="color: #666;"><i>No detailed description provided.</i></p>'}
            """
            
            desc_browser.setHtml(html_content)
            desc_layout.addWidget(desc_browser)
            layout.addWidget(desc_group)
            
            # Requirements info
            min_version = full_plugin.get('min_app_version', '1.0')
            req_label = QLabel(f"📋 Requires Image Anarchy v{min_version} or later")
            req_label.setStyleSheet("color: #888; font-size: 11px;")
            layout.addWidget(req_label)
            
            # Feedback, Rating, Bug Report Section
            feedback_tabs = QTabWidget()
            feedback_tabs.setMaximumHeight(200)
            
            # Tab 1: Reviews/Ratings
            reviews_tab = QWidget()
            reviews_layout = QVBoxLayout(reviews_tab)
            reviews_layout.setContentsMargins(5, 5, 5, 5)
            
            reviews_list = QTextEdit()
            reviews_list.setReadOnly(True)
            reviews_list.setMaximumHeight(120)
            
            # Populate reviews
            reviews = full_plugin.get('reviews', [])
            if reviews:
                reviews_html = ""
                for r in reviews[:10]:
                    stars = "⭐" * r.get('rating', 0) + "☆" * (5 - r.get('rating', 0))
                    reviews_html += f"<p><b>{r.get('username', 'User')}</b> {stars}<br>"
                    reviews_html += f"<span style='color:#aaa;'>{r.get('comment', '')}</span></p><hr>"
                reviews_list.setHtml(reviews_html)
            else:
                reviews_list.setHtml("<p style='color:#888;'>No reviews yet. Be the first to rate this plugin!</p>")
            reviews_layout.addWidget(reviews_list)
            
            # Rate button
            rate_btn = QPushButton("⭐ Rate This Plugin")
            rate_btn.clicked.connect(lambda: self._show_rate_dialog(plugin_id, plugin_name))
            reviews_layout.addWidget(rate_btn)
            
            feedback_tabs.addTab(reviews_tab, "⭐ Reviews")
            
            # Tab 2: Feedback
            feedback_tab = QWidget()
            feedback_layout = QVBoxLayout(feedback_tab)
            feedback_layout.setContentsMargins(5, 5, 5, 5)
            
            feedback_label = QLabel("Share your thoughts with the developer:")
            feedback_label.setStyleSheet("color: #888;")
            feedback_layout.addWidget(feedback_label)
            
            feedback_btn = QPushButton("💬 Leave Feedback")
            feedback_btn.clicked.connect(lambda: self._show_feedback_dialog(plugin_id, plugin_name))
            feedback_layout.addWidget(feedback_btn)
            feedback_layout.addStretch()
            
            feedback_tabs.addTab(feedback_tab, "💬 Feedback")
            
            # Tab 3: Bug Report
            bug_tab = QWidget()
            bug_layout = QVBoxLayout(bug_tab)
            bug_layout.setContentsMargins(5, 5, 5, 5)
            
            bug_label = QLabel("Found a bug? Report it here (no login required):")
            bug_label.setStyleSheet("color: #888;")
            bug_layout.addWidget(bug_label)
            
            bug_btn = QPushButton("🐛 Report Bug")
            bug_btn.clicked.connect(lambda: self._show_bug_report_dialog(plugin_id, plugin_name))
            bug_layout.addWidget(bug_btn)
            bug_layout.addStretch()
            
            feedback_tabs.addTab(bug_tab, "🐛 Report Bug")
            
            layout.addWidget(feedback_tabs)
            
            # Buttons
            btn_layout = QHBoxLayout()
            
            if full_plugin.get('homepage'):
                homepage_btn = QPushButton("🌐 Homepage")
                homepage_btn.clicked.connect(lambda: webbrowser.open(full_plugin.get('homepage')))
                btn_layout.addWidget(homepage_btn)
            
            if full_plugin.get('repository'):
                repo_btn = QPushButton("📦 Repository")
                repo_btn.clicked.connect(lambda: webbrowser.open(full_plugin.get('repository')))
                btn_layout.addWidget(repo_btn)
            
            btn_layout.addStretch()
            
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.reject)
            btn_layout.addWidget(close_btn)
            
            install_btn = QPushButton("⬇️ Install Plugin")
            install_btn.setStyleSheet("background-color: #4CAF50; padding: 10px 24px; font-size: 14px;")
            install_btn.clicked.connect(lambda: self._install_from_details(dialog, full_plugin))
            btn_layout.addWidget(install_btn)
            
            layout.addLayout(btn_layout)
            
            dialog.exec()
        
        def _install_from_details(self, dialog, plugin: dict):
            """Install plugin from the details dialog."""
            dialog.accept()
            self._download_store_plugin(plugin)
        
        def _show_screenshots_dialog(self, plugin_name: str, plugin_id: str, screenshots: list):
            """Show dialog with all plugin screenshots."""
            from PyQt6.QtGui import QPixmap
            from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkRequest
            from PyQt6.QtCore import QUrl
            
            dialog = QDialog(self)
            dialog.setWindowTitle(f"🖼️ Screenshots - {plugin_name}")
            dialog.setMinimumSize(800, 600)
            
            layout = QVBoxLayout(dialog)
            
            # Header
            header = QLabel(f"<b>Screenshots for {plugin_name}</b> ({len(screenshots)} image(s))")
            header.setStyleSheet("font-size: 14px; padding: 10px;")
            layout.addWidget(header)
            
            # Scroll area for screenshots
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            
            scroll_content = QWidget()
            scroll_layout = QVBoxLayout(scroll_content)
            scroll_layout.setSpacing(20)
            
            # Status label for loading
            self._screenshot_status = QLabel("Loading screenshots...")
            self._screenshot_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
            scroll_layout.addWidget(self._screenshot_status)
            
            # Store references for loading
            self._screenshot_labels = []
            self._screenshot_manager = QNetworkAccessManager()
            
            # Base URL for screenshots
            base_url = plugin_store_api.base_url
            
            # Load each screenshot
            for i, ss_filename in enumerate(screenshots):
                # Container for each screenshot
                ss_container = QWidget()
                ss_container_layout = QVBoxLayout(ss_container)
                ss_container_layout.setContentsMargins(0, 0, 0, 0)
                
                # Screenshot label (placeholder)
                ss_label = QLabel(f"⏳ Loading screenshot {i+1}...")
                ss_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                ss_label.setMinimumHeight(300)
                ss_label.setStyleSheet("background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 10px;")
                ss_container_layout.addWidget(ss_label)
                
                # Caption
                caption = QLabel(f"Screenshot {i+1} of {len(screenshots)}")
                caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
                caption.setStyleSheet("color: #888; font-size: 11px;")
                ss_container_layout.addWidget(caption)
                
                scroll_layout.addWidget(ss_container)
                self._screenshot_labels.append(ss_label)
                
                # Load image asynchronously
                ss_url = f"{base_url}/screenshots/{ss_filename}"
                self._load_screenshot_async(ss_label, ss_url, i)
            
            scroll_layout.addStretch()
            scroll.setWidget(scroll_content)
            layout.addWidget(scroll)
            
            # Update status
            self._screenshot_status.setText(f"Loaded {len(screenshots)} screenshot(s)")
            
            # Close button
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.accept)
            layout.addWidget(close_btn)
            
            dialog.exec()
        
        def _load_screenshot_async(self, label, url: str, index: int):
            """Load a screenshot image asynchronously."""
            import urllib.request
            from PyQt6.QtGui import QPixmap
            from PyQt6.QtCore import QByteArray
            
            def load_image():
                try:
                    req = urllib.request.Request(url, headers={'User-Agent': 'ImageAnarchy/1.1'})
                    with urllib.request.urlopen(req, timeout=15) as response:
                        data = response.read()
                        
                        pixmap = QPixmap()
                        pixmap.loadFromData(QByteArray(data))
                        
                        if not pixmap.isNull():
                            # Scale to fit nicely (max 750px wide)
                            if pixmap.width() > 750:
                                pixmap = pixmap.scaledToWidth(750, Qt.TransformationMode.SmoothTransformation)
                            label.setPixmap(pixmap)
                            label.setMinimumHeight(pixmap.height())
                        else:
                            label.setText(f"❌ Failed to load image {index+1}")
                except Exception as e:
                    label.setText(f"❌ Error loading screenshot {index+1}:\n{str(e)[:50]}")
            
            # Run in thread to avoid blocking UI
            import threading
            thread = threading.Thread(target=load_image, daemon=True)
            thread.start()

        def _show_rate_dialog(self, plugin_id: str, plugin_name: str):
            """Show dialog to rate a plugin."""
            if not plugin_store_api.is_logged_in():
                QMessageBox.information(
                    self,
                    "Login Required",
                    "You need to be logged in to rate plugins.\n\n"
                    "Click 'Login' in the Plugin Store to create an account or sign in."
                )
                return
            
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Rate {plugin_name}")
            dialog.setFixedWidth(400)
            
            layout = QVBoxLayout(dialog)
            
            # Star rating selector
            rating_label = QLabel("Select your rating:")
            layout.addWidget(rating_label)
            
            stars_layout = QHBoxLayout()
            star_buttons = []
            selected_rating = [0]  # Using list to allow modification in nested function
            
            def set_rating(rating):
                selected_rating[0] = rating
                for i, btn in enumerate(star_buttons):
                    if i < rating:
                        btn.setText("⭐")
                        btn.setStyleSheet("font-size: 28px; border: none; background: transparent;")
                    else:
                        btn.setText("☆")
                        btn.setStyleSheet("font-size: 28px; border: none; background: transparent; color: #666;")
            
            for i in range(5):
                star_btn = QPushButton("☆")
                star_btn.setStyleSheet("font-size: 28px; border: none; background: transparent; color: #666;")
                star_btn.setFixedSize(40, 40)
                star_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                star_btn.clicked.connect(lambda checked, r=i+1: set_rating(r))
                star_buttons.append(star_btn)
                stars_layout.addWidget(star_btn)
            
            stars_layout.addStretch()
            layout.addLayout(stars_layout)
            
            # Comment
            comment_label = QLabel("Add a comment (optional):")
            layout.addWidget(comment_label)
            
            comment_edit = QTextEdit()
            comment_edit.setMaximumHeight(80)
            comment_edit.setPlaceholderText("Share your experience with this plugin...")
            layout.addWidget(comment_edit)
            
            # Status
            status_label = QLabel("")
            status_label.setStyleSheet("color: #f44336;")
            layout.addWidget(status_label)
            
            # Buttons
            btn_layout = QHBoxLayout()
            btn_layout.addStretch()
            
            cancel_btn = QPushButton("Cancel")
            cancel_btn.clicked.connect(dialog.reject)
            btn_layout.addWidget(cancel_btn)
            
            def submit_rating():
                if selected_rating[0] == 0:
                    status_label.setText("Please select a rating")
                    return
                
                comment = comment_edit.toPlainText().strip()
                result = plugin_store_api.submit_rating(plugin_id, selected_rating[0], comment)
                
                if 'error' in result:
                    status_label.setText(result['error'])
                else:
                    dialog.accept()
                    QMessageBox.information(self, "Success", "Thank you for your rating!")
            
            submit_btn = QPushButton("⭐ Submit Rating")
            submit_btn.setStyleSheet("background-color: #4CAF50;")
            submit_btn.clicked.connect(submit_rating)
            btn_layout.addWidget(submit_btn)
            
            layout.addLayout(btn_layout)
            dialog.exec()
        
        def _show_feedback_dialog(self, plugin_id: str, plugin_name: str):
            """Show dialog to leave feedback on a plugin."""
            if not plugin_store_api.is_logged_in():
                QMessageBox.information(
                    self,
                    "Login Required",
                    "You need to be logged in to leave feedback.\n\n"
                    "Click 'Login' in the Plugin Store to create an account or sign in."
                )
                return
            
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Feedback for {plugin_name}")
            dialog.setFixedWidth(450)
            
            layout = QVBoxLayout(dialog)
            
            info_label = QLabel("Share your thoughts with the developer:")
            layout.addWidget(info_label)
            
            feedback_edit = QTextEdit()
            feedback_edit.setMinimumHeight(120)
            feedback_edit.setPlaceholderText(
                "Share your experience, suggestions, or feature requests...\n\n"
                "Your feedback helps developers improve their plugins!"
            )
            layout.addWidget(feedback_edit)
            
            char_count = QLabel("0/2000 characters")
            char_count.setStyleSheet("color: #888; font-size: 10px;")
            feedback_edit.textChanged.connect(
                lambda: char_count.setText(f"{len(feedback_edit.toPlainText())}/2000 characters")
            )
            layout.addWidget(char_count)
            
            # Status
            status_label = QLabel("")
            status_label.setStyleSheet("color: #f44336;")
            layout.addWidget(status_label)
            
            # Buttons
            btn_layout = QHBoxLayout()
            btn_layout.addStretch()
            
            cancel_btn = QPushButton("Cancel")
            cancel_btn.clicked.connect(dialog.reject)
            btn_layout.addWidget(cancel_btn)
            
            def submit_feedback():
                content = feedback_edit.toPlainText().strip()
                if len(content) < 10:
                    status_label.setText("Feedback must be at least 10 characters")
                    return
                if len(content) > 2000:
                    status_label.setText("Feedback must be under 2000 characters")
                    return
                
                result = plugin_store_api.submit_feedback(plugin_id, content)
                
                if 'error' in result:
                    status_label.setText(result['error'])
                else:
                    dialog.accept()
                    QMessageBox.information(self, "Success", "Thank you for your feedback!")
            
            submit_btn = QPushButton("💬 Submit Feedback")
            submit_btn.setStyleSheet("background-color: #4CAF50;")
            submit_btn.clicked.connect(submit_feedback)
            btn_layout.addWidget(submit_btn)
            
            layout.addLayout(btn_layout)
            dialog.exec()
        
        def _show_bug_report_dialog(self, plugin_id: str, plugin_name: str):
            """Show dialog to report a bug (no login required)."""
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Report Bug in {plugin_name}")
            dialog.setFixedWidth(500)
            
            layout = QVBoxLayout(dialog)
            
            info_label = QLabel(
                "🐛 <b>Report a Bug</b><br>"
                "<span style='color:#888;'>No login required. The developer will review your report.</span>"
            )
            info_label.setTextFormat(Qt.TextFormat.RichText)
            layout.addWidget(info_label)
            
            # Name (optional)
            name_layout = QHBoxLayout()
            name_label = QLabel("Your name (optional):")
            name_layout.addWidget(name_label)
            name_edit = QLineEdit()
            name_edit.setPlaceholderText("Anonymous")
            name_layout.addWidget(name_edit)
            layout.addLayout(name_layout)
            
            # Email (optional)
            email_layout = QHBoxLayout()
            email_label = QLabel("Email (optional):")
            email_layout.addWidget(email_label)
            email_edit = QLineEdit()
            email_edit.setPlaceholderText("For follow-up if needed")
            email_layout.addWidget(email_edit)
            layout.addLayout(email_layout)
            
            # Bug description
            desc_label = QLabel("Describe the bug:")
            layout.addWidget(desc_label)
            
            bug_edit = QTextEdit()
            bug_edit.setMinimumHeight(150)
            bug_edit.setPlaceholderText(
                "Please describe:\n"
                "1. What you expected to happen\n"
                "2. What actually happened\n"
                "3. Steps to reproduce the bug\n\n"
                "Include any error messages if applicable."
            )
            layout.addWidget(bug_edit)
            
            char_count = QLabel("0/5000 characters (min 20)")
            char_count.setStyleSheet("color: #888; font-size: 10px;")
            bug_edit.textChanged.connect(
                lambda: char_count.setText(f"{len(bug_edit.toPlainText())}/5000 characters (min 20)")
            )
            layout.addWidget(char_count)
            
            # Simple captcha
            captcha_layout = QHBoxLayout()
            
            # Generate simple math captcha
            import random
            a = random.randint(1, 10)
            b = random.randint(1, 10)
            captcha_answer = a + b
            
            captcha_label = QLabel(f"🤖 Captcha: What is {a} + {b}?")
            captcha_layout.addWidget(captcha_label)
            
            captcha_edit = QLineEdit()
            captcha_edit.setFixedWidth(60)
            captcha_edit.setPlaceholderText("?")
            captcha_layout.addWidget(captcha_edit)
            captcha_layout.addStretch()
            layout.addLayout(captcha_layout)
            
            # Status
            status_label = QLabel("")
            status_label.setWordWrap(True)
            status_label.setStyleSheet("color: #f44336;")
            layout.addWidget(status_label)
            
            # Buttons
            btn_layout = QHBoxLayout()
            btn_layout.addStretch()
            
            cancel_btn = QPushButton("Cancel")
            cancel_btn.clicked.connect(dialog.reject)
            btn_layout.addWidget(cancel_btn)
            
            def submit_bug_report():
                content = bug_edit.toPlainText().strip()
                if len(content) < 20:
                    status_label.setText("Bug report must be at least 20 characters")
                    return
                if len(content) > 5000:
                    status_label.setText("Bug report must be under 5000 characters")
                    return
                
                # Verify captcha
                try:
                    user_answer = int(captcha_edit.text().strip())
                    if user_answer != captcha_answer:
                        status_label.setText("Incorrect captcha answer. Please try again.")
                        return
                except ValueError:
                    status_label.setText("Please enter a valid number for the captcha")
                    return
                
                email = email_edit.text().strip()
                if email and '@' not in email:
                    status_label.setText("Please enter a valid email or leave it blank")
                    return
                
                name = name_edit.text().strip() or "Anonymous"
                
                result = plugin_store_api.submit_bug_report(plugin_id, content, email, name, str(user_answer))
                
                if 'error' in result:
                    status_label.setText(result['error'])
                else:
                    dialog.accept()
                    QMessageBox.information(
                        self, 
                        "Bug Report Submitted",
                        "Thank you for reporting this bug!\n\n"
                        "The developer will review your report and may follow up if you provided an email."
                    )
            
            submit_btn = QPushButton("🐛 Submit Bug Report")
            submit_btn.setStyleSheet("background-color: #ff9800;")
            submit_btn.clicked.connect(submit_bug_report)
            btn_layout.addWidget(submit_btn)
            
            layout.addLayout(btn_layout)
            dialog.exec()
        
        def _search_store(self):
            """Search the plugin store."""
            query = self.store_search.text().strip()
            if not query:
                self._refresh_store()
                return
            
            self.store_status.setText(f"Searching for '{query}'...")
            QApplication.processEvents()
            
            plugins = plugin_store_api.get_plugins(search=query)
            
            if not plugins:
                self.store_status.setText(f"No plugins found for '{query}'")
                self._display_store_plugins([])
                return
            
            self.store_status.setText(f"Found {len(plugins)} plugins matching '{query}'")
            self._display_store_plugins(plugins)
        
        def _filter_store_category(self, category: str):
            """Filter store by category."""
            if category == "All":
                self._refresh_store()
                return
            
            if hasattr(self, '_store_plugins'):
                filtered = [p for p in self._store_plugins if p.get('category', '').lower() == category.lower()]
                self._display_store_plugins(filtered)
                self.store_status.setText(f"Showing {len(filtered)} plugins in '{category}'")
        
        def _download_store_plugin(self, plugin: dict):
            """Download and install a plugin from the store."""
            plugin_id = plugin.get('id')
            plugin_name = plugin.get('name', plugin_id)
            
            reply = QMessageBox.question(
                self,
                "Install Plugin",
                f"Download and install '{plugin_name}'?\n\n"
                f"Author: {plugin.get('author_name', 'Unknown')}\n"
                f"Version: {plugin.get('version', '1.0')}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply != QMessageBox.StandardButton.Yes:
                return
            
            # Download to temp file
            import tempfile
            temp_dir = tempfile.mkdtemp()
            zip_path = os.path.join(temp_dir, f"{plugin_id}.zip")
            
            self.store_status.setText(f"Downloading {plugin_name}...")
            QApplication.processEvents()
            
            success, result = plugin_store_api.download_plugin(plugin_id, zip_path)
            
            if not success:
                QMessageBox.critical(self, "Download Failed", f"Failed to download plugin:\n{result}")
                self.store_status.setText("Download failed")
                return
            
            # Extract to plugins folder
            try:
                import zipfile
                plugins_dir = plugin_manager._get_plugins_dir()
                
                # Create plugin subdirectory using plugin ID
                plugin_install_dir = os.path.join(plugins_dir, plugin_id)
                os.makedirs(plugin_install_dir, exist_ok=True)
                
                self.store_status.setText(f"Extracting {plugin_name}...")
                QApplication.processEvents()
                
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    # Check if the zip has a root folder or files at root
                    namelist = zf.namelist()
                    
                    # Check if all files are in a subdirectory already
                    has_root_folder = False
                    if namelist:
                        first_part = namelist[0].split('/')[0]
                        has_root_folder = all(n.startswith(first_part + '/') or n == first_part for n in namelist)
                    
                    if has_root_folder:
                        # Extract and move contents from the root folder
                        zf.extractall(plugins_dir)
                        # The extracted folder might have a different name, rename if needed
                        extracted_folder = os.path.join(plugins_dir, first_part)
                        if extracted_folder != plugin_install_dir and os.path.exists(extracted_folder):
                            # Remove target if exists, then rename
                            if os.path.exists(plugin_install_dir):
                                import shutil
                                shutil.rmtree(plugin_install_dir)
                            os.rename(extracted_folder, plugin_install_dir)
                    else:
                        # Files are at root level, extract to plugin subdirectory
                        zf.extractall(plugin_install_dir)
                
                # Clean up temp file
                os.remove(zip_path)
                os.rmdir(temp_dir)
                
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Extraction Failed",
                    f"Failed to extract plugin:\n{str(e)}"
                )
                self.store_status.setText("Installation failed")
                return
            
            # Run plugin setup (pip install, git clone, binary downloads, etc.)
            self.store_status.setText(f"Setting up {plugin_name}...")
            QApplication.processEvents()
            
            # Show progress dialog for setup
            from PyQt6.QtWidgets import QProgressDialog
            progress_dialog = QProgressDialog(
                f"Setting up {plugin_name}...",
                "Cancel",
                0, 100,
                self
            )
            progress_dialog.setWindowTitle("Plugin Setup")
            progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
            progress_dialog.setMinimumDuration(0)
            progress_dialog.setValue(0)
            
            setup_errors = []
            
            def setup_progress(step_name: str, status: str, progress: int):
                if progress_dialog.wasCanceled():
                    return
                progress_dialog.setLabelText(f"{step_name}\n{status}")
                progress_dialog.setValue(progress)
                QApplication.processEvents()
            
            try:
                success, message = plugin_manager.setup_plugin_dependencies(plugin_id, setup_progress)
                progress_dialog.close()
                
                if not success:
                    setup_errors.append(message)
            except Exception as e:
                progress_dialog.close()
                setup_errors.append(str(e))
            
            # Show result
            if setup_errors:
                QMessageBox.warning(
                    self,
                    "Plugin Installed with Warnings",
                    f"'{plugin_name}' was installed but some setup steps had issues:\n\n"
                    f"{chr(10).join(setup_errors)}\n\n"
                    "The plugin may still work, or you can try setup again from the plugin."
                )
            else:
                QMessageBox.information(
                    self,
                    "Plugin Installed",
                    f"'{plugin_name}' has been installed and configured successfully!\n\n"
                    "Go to the Installed tab to use it."
                )
            
            self.store_status.setText(f"Installed {plugin_name}")
            
            # Refresh installed plugins
            self._load_plugins()
        
        def _show_login_dialog(self):
            """Show login/register dialog."""
            dialog = QDialog(self)
            dialog.setWindowTitle("Plugin Store Login")
            dialog.setMinimumWidth(350)
            
            layout = QVBoxLayout(dialog)
            
            # Tab for Login / Register
            tabs = QTabWidget()
            
            # Login tab
            login_widget = QWidget()
            login_layout = QFormLayout(login_widget)
            
            login_user = QLineEdit()
            login_user.setPlaceholderText("Username")
            login_layout.addRow("Username:", login_user)
            
            login_pass = QLineEdit()
            login_pass.setPlaceholderText("Password")
            login_pass.setEchoMode(QLineEdit.EchoMode.Password)
            login_layout.addRow("Password:", login_pass)
            
            login_btn = QPushButton("Login")
            login_layout.addRow(login_btn)
            
            login_status = QLabel("")
            login_status.setStyleSheet("color: #f44336;")
            login_layout.addRow(login_status)
            
            def do_login():
                username = login_user.text().strip()
                password = login_pass.text()
                
                if not username or not password:
                    login_status.setText("Please enter username and password")
                    return
                
                login_status.setText("Logging in...")
                login_status.setStyleSheet("color: #888;")
                QApplication.processEvents()
                
                result = plugin_store_api.login(username, password)
                
                if 'error' in result:
                    login_status.setText(result['error'])
                    login_status.setStyleSheet("color: #f44336;")
                else:
                    dialog.accept()
                    self._update_auth_ui()
                    QMessageBox.information(self, "Login Successful", f"Welcome, {username}!")
            
            login_btn.clicked.connect(do_login)
            login_pass.returnPressed.connect(do_login)
            
            tabs.addTab(login_widget, "Login")
            
            # Register tab
            reg_widget = QWidget()
            reg_layout = QFormLayout(reg_widget)
            
            reg_user = QLineEdit()
            reg_user.setPlaceholderText("Choose a username")
            reg_layout.addRow("Username:", reg_user)
            
            reg_email = QLineEdit()
            reg_email.setPlaceholderText("your@email.com")
            reg_layout.addRow("Email:", reg_email)
            
            reg_pass = QLineEdit()
            reg_pass.setPlaceholderText("Min 6 characters")
            reg_pass.setEchoMode(QLineEdit.EchoMode.Password)
            reg_layout.addRow("Password:", reg_pass)
            
            reg_pass2 = QLineEdit()
            reg_pass2.setPlaceholderText("Confirm password")
            reg_pass2.setEchoMode(QLineEdit.EchoMode.Password)
            reg_layout.addRow("Confirm:", reg_pass2)
            
            reg_btn = QPushButton("Create Account")
            reg_layout.addRow(reg_btn)
            
            reg_status = QLabel("")
            reg_status.setStyleSheet("color: #f44336;")
            reg_status.setWordWrap(True)
            reg_layout.addRow(reg_status)
            
            def do_register():
                username = reg_user.text().strip()
                email = reg_email.text().strip()
                password = reg_pass.text()
                password2 = reg_pass2.text()
                
                if not username or not email or not password:
                    reg_status.setText("Please fill in all fields")
                    return
                
                if password != password2:
                    reg_status.setText("Passwords don't match")
                    return
                
                if len(password) < 6:
                    reg_status.setText("Password must be at least 6 characters")
                    return
                
                reg_status.setText("Creating account...")
                reg_status.setStyleSheet("color: #888;")
                QApplication.processEvents()
                
                result = plugin_store_api.register(username, email, password)
                
                if 'error' in result:
                    reg_status.setText(result['error'])
                    reg_status.setStyleSheet("color: #f44336;")
                else:
                    dialog.accept()
                    self._update_auth_ui()
                    QMessageBox.information(
                        self,
                        "Account Created",
                        f"Welcome, {username}!\n\n"
                        "You can now upload plugins to the store."
                    )
            
            reg_btn.clicked.connect(do_register)
            
            tabs.addTab(reg_widget, "Register")
            
            layout.addWidget(tabs)
            
            # Note about why register
            note = QLabel(
                "💡 Registration is only required for plugin developers who want to upload plugins.\n"
                "Browsing and downloading plugins is free for everyone!"
            )
            note.setStyleSheet("color: #888; font-style: italic; font-size: 11px;")
            note.setWordWrap(True)
            layout.addWidget(note)
            
            dialog.exec()
        
        def _show_user_menu(self):
            """Show user menu with logout option."""
            menu = QMenu(self)
            
            user = plugin_store_api.user or {}
            username = user.get('username', 'User')
            is_admin = user.get('is_admin', False)
            
            # User info
            if is_admin:
                user_action = menu.addAction(f"👤 {username} (Admin)")
            else:
                user_action = menu.addAction(f"👤 Logged in as {username}")
            user_action.setEnabled(False)
            
            menu.addSeparator()
            
            # Admin panel (only for admins)
            if is_admin:
                admin_action = menu.addAction("⚙️ Admin Panel")
                admin_action.triggered.connect(self._show_admin_panel)
                menu.addSeparator()
            
            # Upload plugin
            upload_action = menu.addAction("📤 Upload Plugin")
            upload_action.triggered.connect(self._show_upload_dialog)
            
            menu.addSeparator()
            
            # Logout
            logout_action = menu.addAction("🚪 Logout")
            logout_action.triggered.connect(self._logout)
            
            # Show menu at button
            menu.exec(self.user_menu_btn.mapToGlobal(self.user_menu_btn.rect().bottomLeft()))
        
        def _logout(self):
            """Logout from plugin store."""
            plugin_store_api.logout()
            self._update_auth_ui()
            QMessageBox.information(self, "Logged Out", "You have been logged out.")
        
        def _show_admin_panel(self):
            """Show admin panel for managing pending plugins."""
            dialog = QDialog(self)
            dialog.setWindowTitle("⚙️ Plugin Store Admin Panel")
            dialog.setMinimumWidth(800)
            dialog.setMinimumHeight(600)
            
            layout = QVBoxLayout(dialog)
            
            # Header
            header = QLabel("⚙️ <b>Admin Panel</b> - Review and manage plugin submissions")
            header.setTextFormat(Qt.TextFormat.RichText)
            header.setStyleSheet("font-size: 16px; padding: 10px; background: #ff9800; color: #1a1a1a; border-radius: 6px;")
            layout.addWidget(header)
            
            # Tabs
            tabs = QTabWidget()
            
            # Pending plugins tab
            pending_widget = QWidget()
            pending_layout = QVBoxLayout(pending_widget)
            
            pending_label = QLabel("📋 Pending plugins awaiting review:")
            pending_label.setStyleSheet("font-weight: bold;")
            pending_layout.addWidget(pending_label)
            
            self._admin_pending_list = QListWidget()
            self._admin_pending_list.setStyleSheet("""
                QListWidget::item { padding: 10px; border-bottom: 1px solid #333; }
                QListWidget::item:selected { background: #2d4a2d; }
            """)
            pending_layout.addWidget(self._admin_pending_list)
            
            # Action buttons
            btn_layout = QHBoxLayout()
            
            refresh_btn = QPushButton("🔄 Refresh")
            refresh_btn.clicked.connect(lambda: self._load_pending_plugins(dialog))
            btn_layout.addWidget(refresh_btn)
            
            review_btn = QPushButton("🔍 Review Details")
            review_btn.setStyleSheet("background: #2196F3; padding: 8px 16px;")
            review_btn.clicked.connect(lambda: self._review_selected_plugin(dialog))
            btn_layout.addWidget(review_btn)
            
            btn_layout.addStretch()
            
            approve_btn = QPushButton("✅ Approve Selected")
            approve_btn.setStyleSheet("background: #4CAF50; padding: 8px 16px;")
            approve_btn.clicked.connect(lambda: self._approve_selected_plugin(dialog))
            btn_layout.addWidget(approve_btn)
            
            reject_btn = QPushButton("❌ Reject Selected")
            reject_btn.setStyleSheet("background: #f44336; padding: 8px 16px;")
            reject_btn.clicked.connect(lambda: self._reject_selected_plugin(dialog))
            btn_layout.addWidget(reject_btn)
            
            pending_layout.addLayout(btn_layout)
            tabs.addTab(pending_widget, "📋 Pending")
            
            # All plugins tab
            all_widget = QWidget()
            all_layout = QVBoxLayout(all_widget)
            
            all_label = QLabel("📦 All plugins in the store:")
            all_label.setStyleSheet("font-weight: bold;")
            all_layout.addWidget(all_label)
            
            self._admin_all_list = QListWidget()
            self._admin_all_list.setStyleSheet("""
                QListWidget::item { padding: 8px; border-bottom: 1px solid #333; }
            """)
            all_layout.addWidget(self._admin_all_list)
            
            all_btn_layout = QHBoxLayout()
            refresh_all_btn = QPushButton("🔄 Refresh")
            refresh_all_btn.clicked.connect(lambda: self._load_all_admin_plugins(dialog))
            all_btn_layout.addWidget(refresh_all_btn)
            
            review_all_btn = QPushButton("🔍 Review Details")
            review_all_btn.setStyleSheet("background: #2196F3; padding: 8px 16px;")
            review_all_btn.clicked.connect(lambda: self._review_all_selected_plugin(dialog))
            all_btn_layout.addWidget(review_all_btn)
            
            all_btn_layout.addStretch()
            
            delete_btn = QPushButton("🗑️ Delete Selected")
            delete_btn.setStyleSheet("background: #f44336; padding: 8px 16px;")
            delete_btn.clicked.connect(lambda: self._delete_selected_plugin(dialog))
            all_btn_layout.addWidget(delete_btn)
            
            all_layout.addLayout(all_btn_layout)
            tabs.addTab(all_widget, "📦 All Plugins")
            
            # Connect tab change to load data
            tabs.currentChanged.connect(lambda idx: self._load_all_admin_plugins(dialog) if idx == 1 else None)
            
            layout.addWidget(tabs)
            
            # Status
            self._admin_status = QLabel("")
            self._admin_status.setWordWrap(True)
            layout.addWidget(self._admin_status)
            
            # Close button
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.accept)
            layout.addWidget(close_btn)
            
            # Load pending plugins
            self._load_pending_plugins(dialog)
            
            dialog.exec()
        
        def _load_pending_plugins(self, dialog):
            """Load pending plugins from server."""
            self._admin_pending_list.clear()
            self._admin_status.setText("Loading pending plugins...")
            self._admin_status.setStyleSheet("color: #888;")
            QApplication.processEvents()
            
            result = plugin_store_api.get_pending_plugins()
            
            if 'error' in result:
                self._admin_status.setText(f"Error: {result['error']}")
                self._admin_status.setStyleSheet("color: #f44336;")
                return
            
            plugins = result.get('plugins', [])
            
            if not plugins:
                self._admin_status.setText("🎉 No pending plugins to review!")
                self._admin_status.setStyleSheet("color: #4CAF50;")
                return
            
            for p in plugins:
                item = QListWidgetItem()
                item.setData(Qt.ItemDataRole.UserRole, p)
                
                status_icon = "⏳"
                text = f"{p.get('icon', '📦')} {p.get('name', 'Unknown')} v{p.get('version', '?')}\n"
                text += f"   by {p.get('author_name', 'Unknown')} | {p.get('category', 'other')}\n"
                text += f"   {p.get('description', '')[:100]}..."
                item.setText(text)
                
                self._admin_pending_list.addItem(item)
            
            self._admin_status.setText(f"Found {len(plugins)} pending plugin(s)")
            self._admin_status.setStyleSheet("color: #4fc3f7;")
        
        def _load_all_admin_plugins(self, dialog):
            """Load all plugins from server."""
            self._admin_all_list.clear()
            self._admin_status.setText("Loading all plugins...")
            QApplication.processEvents()
            
            result = plugin_store_api.get_all_admin_plugins()
            
            if 'error' in result:
                self._admin_status.setText(f"Error: {result['error']}")
                self._admin_status.setStyleSheet("color: #f44336;")
                return
            
            plugins = result.get('plugins', [])
            
            for p in plugins:
                item = QListWidgetItem()
                item.setData(Qt.ItemDataRole.UserRole, p)
                
                status = p.get('status', 'unknown')
                status_icon = "✅" if status == 'approved' else "⏳" if status == 'pending' else "❌"
                
                text = f"{status_icon} {p.get('icon', '📦')} {p.get('name', 'Unknown')} v{p.get('version', '?')} [{status}]\n"
                text += f"   by {p.get('author_name', 'Unknown')} | ⬇️ {p.get('downloads', 0)} downloads"
                item.setText(text)
                
                self._admin_all_list.addItem(item)
            
            self._admin_status.setText(f"Found {len(plugins)} plugin(s)")
            self._admin_status.setStyleSheet("color: #4fc3f7;")
        
        def _approve_selected_plugin(self, dialog):
            """Approve the selected pending plugin."""
            item = self._admin_pending_list.currentItem()
            if not item:
                QMessageBox.warning(dialog, "No Selection", "Please select a plugin to approve.")
                return
            
            plugin = item.data(Qt.ItemDataRole.UserRole)
            plugin_id = plugin.get('id')
            plugin_name = plugin.get('name', 'Unknown')
            
            reply = QMessageBox.question(
                dialog,
                "Approve Plugin",
                f"Approve '{plugin_name}'?\n\nIt will become publicly visible in the store.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply != QMessageBox.StandardButton.Yes:
                return
            
            self._admin_status.setText(f"Approving {plugin_name}...")
            QApplication.processEvents()
            
            result = plugin_store_api.approve_plugin(plugin_id)
            
            if 'error' in result:
                self._admin_status.setText(f"Error: {result['error']}")
                self._admin_status.setStyleSheet("color: #f44336;")
            else:
                self._admin_status.setText(f"✅ {plugin_name} approved!")
                self._admin_status.setStyleSheet("color: #4CAF50;")
                self._load_pending_plugins(dialog)
                self._refresh_store()  # Refresh main store view
        
        def _reject_selected_plugin(self, dialog):
            """Reject the selected pending plugin."""
            item = self._admin_pending_list.currentItem()
            if not item:
                QMessageBox.warning(dialog, "No Selection", "Please select a plugin to reject.")
                return
            
            plugin = item.data(Qt.ItemDataRole.UserRole)
            plugin_id = plugin.get('id')
            plugin_name = plugin.get('name', 'Unknown')
            
            reason, ok = QInputDialog.getText(
                dialog,
                "Rejection Reason",
                f"Reason for rejecting '{plugin_name}':\n(This will be sent to the developer)"
            )
            
            if not ok:
                return
            
            self._admin_status.setText(f"Rejecting {plugin_name}...")
            QApplication.processEvents()
            
            result = plugin_store_api.reject_plugin(plugin_id, reason)
            
            if 'error' in result:
                self._admin_status.setText(f"Error: {result['error']}")
                self._admin_status.setStyleSheet("color: #f44336;")
            else:
                self._admin_status.setText(f"❌ {plugin_name} rejected")
                self._admin_status.setStyleSheet("color: #ff9800;")
                self._load_pending_plugins(dialog)
        
        def _delete_selected_plugin(self, dialog):
            """Delete the selected plugin."""
            item = self._admin_all_list.currentItem()
            if not item:
                QMessageBox.warning(dialog, "No Selection", "Please select a plugin to delete.")
                return
            
            plugin = item.data(Qt.ItemDataRole.UserRole)
            plugin_id = plugin.get('id')
            plugin_name = plugin.get('name', 'Unknown')
            
            reply = QMessageBox.warning(
                dialog,
                "Delete Plugin",
                f"⚠️ DELETE '{plugin_name}'?\n\nThis cannot be undone!",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply != QMessageBox.StandardButton.Yes:
                return
            
            self._admin_status.setText(f"Deleting {plugin_name}...")
            QApplication.processEvents()
            
            result = plugin_store_api.delete_plugin(plugin_id)
            
            if 'error' in result:
                self._admin_status.setText(f"Error: {result['error']}")
                self._admin_status.setStyleSheet("color: #f44336;")
            else:
                self._admin_status.setText(f"🗑️ {plugin_name} deleted")
                self._admin_status.setStyleSheet("color: #ff9800;")
                self._load_all_admin_plugins(dialog)
                self._refresh_store()

        def _review_selected_plugin(self, dialog):
            """Review detailed info for a pending plugin."""
            item = self._admin_pending_list.currentItem()
            if not item:
                QMessageBox.warning(dialog, "No Selection", "Please select a plugin to review.")
                return
            plugin = item.data(Qt.ItemDataRole.UserRole)
            self._show_plugin_review_dialog(dialog, plugin.get('id'), plugin.get('name', 'Unknown'))
        
        def _review_all_selected_plugin(self, dialog):
            """Review detailed info for a plugin from all plugins list."""
            item = self._admin_all_list.currentItem()
            if not item:
                QMessageBox.warning(dialog, "No Selection", "Please select a plugin to review.")
                return
            plugin = item.data(Qt.ItemDataRole.UserRole)
            self._show_plugin_review_dialog(dialog, plugin.get('id'), plugin.get('name', 'Unknown'))
        
        def _show_plugin_review_dialog(self, parent, plugin_id, plugin_name):
            """Show detailed review dialog for a plugin."""
            review_dialog = QDialog(parent)
            review_dialog.setWindowTitle(f"🔍 Review: {plugin_name}")
            review_dialog.setMinimumWidth(900)
            review_dialog.setMinimumHeight(700)
            
            layout = QVBoxLayout(review_dialog)
            
            # Loading
            status_label = QLabel("⏳ Loading plugin details...")
            status_label.setStyleSheet("font-size: 14px; padding: 10px;")
            layout.addWidget(status_label)
            
            QApplication.processEvents()
            
            # Fetch details
            result = plugin_store_api.get_plugin_review_details(plugin_id)
            
            if 'error' in result:
                status_label.setText(f"❌ Error: {result['error']}")
                status_label.setStyleSheet("color: #f44336;")
                return
            
            # Remove loading label
            layout.removeWidget(status_label)
            status_label.deleteLater()
            
            plugin = result.get('plugin', {})
            scan_results = result.get('scanResults', [])
            binaries = result.get('binaries', [])
            all_files = result.get('allFiles', [])
            external_deps = result.get('externalDependencies', [])
            summary = result.get('summary', {})
            
            # Create scrollable content
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll_content = QWidget()
            scroll_layout = QVBoxLayout(scroll_content)
            
            # ---- Plugin Info Section ----
            info_group = QGroupBox("📦 Plugin Information")
            info_layout = QFormLayout(info_group)
            
            info_layout.addRow("ID:", QLabel(f"<code>{plugin.get('id', '?')}</code>"))
            info_layout.addRow("Name:", QLabel(f"<b>{plugin.get('name', '?')}</b>"))
            info_layout.addRow("Version:", QLabel(plugin.get('version', '?')))
            info_layout.addRow("Author:", QLabel(f"{plugin.get('author_name', '?')} ({plugin.get('author_email', '?')})"))
            info_layout.addRow("Category:", QLabel(plugin.get('category', '?')))
            info_layout.addRow("License:", QLabel(plugin.get('license_type', '?')))
            info_layout.addRow("Status:", QLabel(f"<b>{plugin.get('status', '?').upper()}</b>"))
            info_layout.addRow("File Size:", QLabel(f"{plugin.get('file_size', 0) / 1024:.1f} KB"))
            info_layout.addRow("Submitted:", QLabel(plugin.get('created_at', '?')))
            
            scroll_layout.addWidget(info_group)
            
            # ---- Description Section ----
            desc_group = QGroupBox("📝 Description")
            desc_layout = QVBoxLayout(desc_group)
            
            short_desc = QLabel(plugin.get('description', 'No description'))
            short_desc.setWordWrap(True)
            short_desc.setStyleSheet("font-weight: bold;")
            desc_layout.addWidget(short_desc)
            
            long_desc = plugin.get('long_description', '')
            if long_desc:
                long_desc_edit = QTextEdit()
                long_desc_edit.setReadOnly(True)
                long_desc_edit.setHtml(long_desc)
                long_desc_edit.setMaximumHeight(200)
                desc_layout.addWidget(long_desc_edit)
            
            scroll_layout.addWidget(desc_group)
            
            # ---- Dependencies & Git Clone Section ----
            deps_info_group = QGroupBox("📦 Plugin Dependencies")
            deps_info_layout = QVBoxLayout(deps_info_group)
            
            # Pip requirements
            requirements = plugin.get('requirements', [])
            if requirements:
                req_label = QLabel(f"<b>📋 Pip Requirements ({len(requirements)}):</b>")
                deps_info_layout.addWidget(req_label)
                req_list = QLabel("<code>" + ", ".join(requirements) + "</code>")
                req_list.setWordWrap(True)
                req_list.setStyleSheet("padding: 5px; background: rgba(33, 150, 243, 0.1); border-radius: 4px;")
                deps_info_layout.addWidget(req_list)
            else:
                deps_info_layout.addWidget(QLabel("📋 No pip requirements"))
            
            # Git clone
            git_clone = plugin.get('git_clone', {})
            if git_clone:
                git_label = QLabel("<b>📦 Git Repository Clone:</b>")
                git_label.setStyleSheet("margin-top: 10px;")
                deps_info_layout.addWidget(git_label)
                
                git_info_text = f"<b>Repo:</b> <code>{git_clone.get('repo', '?')}</code><br>"
                git_info_text += f"<b>Target Directory:</b> <code>{git_clone.get('target', 'repo root')}</code>"
                if git_clone.get('requirements_file'):
                    git_info_text += f"<br><b>Requirements File:</b> <code>{git_clone.get('requirements_file')}</code>"
                
                git_info_label = QLabel(git_info_text)
                git_info_label.setWordWrap(True)
                git_info_label.setStyleSheet("padding: 8px; background: rgba(76, 175, 80, 0.1); border-radius: 4px;")
                deps_info_layout.addWidget(git_info_label)
                
                # Warning about git clone
                git_warning = QLabel("⚠️ <span style='color:#ff9800;'>Plugin will clone this repository when installed. Verify the source!</span>")
                git_warning.setTextFormat(Qt.TextFormat.RichText)
                git_warning.setStyleSheet("margin-top: 5px;")
                deps_info_layout.addWidget(git_warning)
            else:
                no_git_label = QLabel("📦 No git clone required")
                no_git_label.setStyleSheet("margin-top: 10px;")
                deps_info_layout.addWidget(no_git_label)
            
            # Bundled binaries from manifest
            bundled_bins = plugin.get('bundled_binaries', [])
            if bundled_bins:
                bundled_label = QLabel(f"<b>📁 Bundled Binaries ({len(bundled_bins)}):</b>")
                bundled_label.setStyleSheet("margin-top: 10px;")
                deps_info_layout.addWidget(bundled_label)
                for bb in bundled_bins:
                    bb_label = QLabel(f"• <code>{bb}</code>")
                    bb_label.setStyleSheet("padding-left: 10px;")
                    deps_info_layout.addWidget(bb_label)
            
            # Setup commands from manifest
            setup_commands = plugin.get('setup_commands', [])
            if setup_commands:
                cmd_label = QLabel(f"<b>⚡ Setup Commands ({len(setup_commands)}):</b>")
                cmd_label.setStyleSheet("margin-top: 10px;")
                deps_info_layout.addWidget(cmd_label)
                for cmd in setup_commands:
                    cmd_display = QLabel(f"• <code>{cmd}</code>")
                    cmd_display.setStyleSheet("padding-left: 10px;")
                    deps_info_layout.addWidget(cmd_display)
                
                # Warning about setup commands
                cmd_warning = QLabel("⚠️ <span style='color:#ff9800;'>Review these commands carefully! They will run during plugin setup.</span>")
                cmd_warning.setTextFormat(Qt.TextFormat.RichText)
                cmd_warning.setStyleSheet("margin-top: 5px;")
                deps_info_layout.addWidget(cmd_warning)
            
            scroll_layout.addWidget(deps_info_group)
            
            # ---- Security Scan Section ----
            scan_group = QGroupBox(f"🔒 Security Scan Results ({len(scan_results)} scan(s))")
            scan_layout = QVBoxLayout(scan_group)
            
            if scan_results:
                for scan in scan_results:
                    scan_text = f"<b>File:</b> {scan.get('file_name', '?')}<br>"
                    scan_text += f"<b>Safe:</b> {'✅ Yes' if scan.get('is_safe') else '❌ NO - THREATS DETECTED'}<br>"
                    scan_text += f"<b>Context:</b> {scan.get('scan_context', '?')}<br>"
                    scan_text += f"<b>ClamAV:</b> {scan.get('clamav_result') or '✅ Clean'}<br>"
                    scan_text += f"<b>VirusTotal:</b> {scan.get('virustotal_detections', 0)}/{scan.get('virustotal_total', 0)} detections"
                    if scan.get('virustotal_scan_id'):
                        scan_text += f" (ID: {scan.get('virustotal_scan_id')[:16]}...)"
                    
                    threats = scan.get('threats', [])
                    if threats:
                        scan_text += f"<br><b style='color: #f44336;'>Threats:</b> {', '.join(threats)}"
                    
                    scan_label = QLabel(scan_text)
                    scan_label.setWordWrap(True)
                    scan_label.setStyleSheet("padding: 8px; background: rgba(0,0,0,0.2); border-radius: 4px; margin-bottom: 5px;")
                    scan_layout.addWidget(scan_label)
            else:
                scan_layout.addWidget(QLabel("No scan results available"))
            
            scroll_layout.addWidget(scan_group)
            
            # ---- Binaries Section ----
            bin_group = QGroupBox(f"⚙️ Binaries/Executables ({len(binaries)})")
            bin_layout = QVBoxLayout(bin_group)
            
            if binaries:
                for b in binaries:
                    size_kb = b.get('size', 0) / 1024
                    bin_label = QLabel(f"📁 <code>{b.get('path', '?')}</code> ({size_kb:.1f} KB)")
                    bin_label.setStyleSheet("padding: 3px;")
                    bin_layout.addWidget(bin_label)
            else:
                bin_layout.addWidget(QLabel("✅ No binaries found in package"))
            
            scroll_layout.addWidget(bin_group)
            
            # ---- All Files Section ----
            files_group = QGroupBox(f"📂 All Files ({len(all_files)})")
            files_layout = QVBoxLayout(files_group)
            
            files_list = QListWidget()
            files_list.setMaximumHeight(150)
            for f in all_files[:50]:  # Limit to 50
                size_kb = f.get('size', 0) / 1024
                files_list.addItem(f"{f.get('path', '?')} ({size_kb:.1f} KB)")
            if len(all_files) > 50:
                files_list.addItem(f"... and {len(all_files) - 50} more files")
            files_layout.addWidget(files_list)
            
            scroll_layout.addWidget(files_group)
            
            # ---- External Dependencies Section ----
            if external_deps:
                deps_group = QGroupBox(f"🌐 External Dependencies ({len(external_deps)})")
                deps_layout = QVBoxLayout(deps_group)
                
                deps_status = plugin.get('deps_status', 'unknown')
                deps_label = QLabel(f"<b>Status:</b> {deps_status.upper()}")
                deps_layout.addWidget(deps_label)
                
                for dep in external_deps:
                    dep_text = f"<b>{dep.get('name', '?')}</b><br>"
                    dep_text += f"URL: <code>{dep.get('url', '?')[:80]}...</code><br>"
                    dep_text += f"Target: {dep.get('targetPath', './')}"
                    dep_label = QLabel(dep_text)
                    dep_label.setWordWrap(True)
                    dep_label.setStyleSheet("padding: 5px; background: rgba(255,152,0,0.1); border-radius: 4px; margin: 2px 0;")
                    deps_layout.addWidget(dep_label)
                
                scroll_layout.addWidget(deps_group)
            
            # ---- Summary Section ----
            summary_group = QGroupBox("📊 Summary")
            summary_layout = QFormLayout(summary_group)
            summary_layout.addRow("Total Files:", QLabel(str(summary.get('totalFiles', 0))))
            summary_layout.addRow("Binaries:", QLabel(str(summary.get('totalBinaries', 0))))
            summary_layout.addRow("Scans Performed:", QLabel(str(summary.get('totalScans', 0))))
            summary_layout.addRow("Has Threats:", QLabel("❌ YES" if summary.get('hasThreats') else "✅ No"))
            summary_layout.addRow("Pending Deps:", QLabel("⏳ Yes" if summary.get('hasPendingDeps') else "✅ No"))
            summary_layout.addRow("Git Clone:", QLabel("📦 Yes" if summary.get('hasGitClone') else "No"))
            summary_layout.addRow("Pip Requirements:", QLabel("📋 Yes" if summary.get('hasRequirements') else "No"))
            scroll_layout.addWidget(summary_group)
            
            scroll_layout.addStretch()
            scroll.setWidget(scroll_content)
            layout.addWidget(scroll)
            
            # Close button
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(review_dialog.accept)
            layout.addWidget(close_btn)
            
            review_dialog.exec()

        def _show_upload_dialog(self):
            """Show dialog to upload a plugin."""
            if not plugin_store_api.is_logged_in():
                QMessageBox.warning(
                    self,
                    "Login Required",
                    "You must be logged in to upload plugins.\n"
                    "Click 'Login' to create an account or sign in."
                )
                return
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Upload Plugin to Store")
            dialog.setMinimumWidth(600)
            dialog.setMinimumHeight(800)
            
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            
            scroll_widget = QWidget()
            layout = QVBoxLayout(scroll_widget)
            
            # Instructions
            intro = QLabel(
                "📤 <b>Upload Your Plugin to the Image Anarchy Store</b><br><br>"
                "Package your plugin as a ZIP file containing:<br>"
                "• <code>manifest.json</code> - Plugin metadata and configuration<br>"
                "• Your main Python file with a <code>Plugin</code> class<br><br>"
                "Your plugin will be reviewed before appearing in the store."
            )
            intro.setTextFormat(Qt.TextFormat.RichText)
            intro.setWordWrap(True)
            layout.addWidget(intro)
            
            # Manifest requirements info box
            manifest_info = QFrame()
            manifest_info.setStyleSheet("""
                QFrame {
                    background-color: #2a4a6a;
                    border: 1px solid #4fc3f7;
                    border-radius: 6px;
                    padding: 10px;
                }
            """)
            manifest_info_layout = QVBoxLayout(manifest_info)
            manifest_label = QLabel(
                "<b>📋 manifest.json Requirements</b><br><br>"
                "<b>Required fields:</b> id, name, version, description, author<br><br>"
                "<b>📦 Python Dependencies:</b> Add pip packages your plugin needs:<br>"
                "<code style='background:#1a1a1a;padding:4px;'>"
                '&nbsp;&nbsp;"requirements": ["package1", "package2>=1.0"]'
                "</code><br><br>"
                "<b>Example manifest.json:</b><br>"
                "<code style='background:#1a1a1a;padding:4px;font-size:10px;'>"
                '{<br>'
                '&nbsp;&nbsp;"id": "my_plugin",<br>'
                '&nbsp;&nbsp;"name": "My Plugin",<br>'
                '&nbsp;&nbsp;"version": "1.0.0",<br>'
                '&nbsp;&nbsp;"author": "Your Name",<br>'
                '&nbsp;&nbsp;"description": "Short description",<br>'
                '&nbsp;&nbsp;"icon": "🔧",<br>'
                '&nbsp;&nbsp;"category": "tools",<br>'
                '&nbsp;&nbsp;"requirements": ["requests", "pillow>=9.0"],<br>'
                '&nbsp;&nbsp;"license_type": "free"<br>'
                '}'
                "</code>"
            )
            manifest_label.setTextFormat(Qt.TextFormat.RichText)
            manifest_label.setWordWrap(True)
            manifest_label.setStyleSheet("color: #e0e0e0; font-size: 11px;")
            manifest_info_layout.addWidget(manifest_label)
            layout.addWidget(manifest_info)
            
            layout.addSpacing(10)
            
            # Plugin file selector
            file_group = QGroupBox("Plugin File")
            file_group_layout = QVBoxLayout(file_group)
            
            file_layout = QHBoxLayout()
            self._upload_file_path = QLineEdit()
            self._upload_file_path.setReadOnly(True)
            self._upload_file_path.setPlaceholderText("Select your plugin.zip file...")
            file_layout.addWidget(self._upload_file_path)
            
            browse_btn = QPushButton("Browse...")
            browse_btn.clicked.connect(lambda: self._browse_upload_file(dialog))
            file_layout.addWidget(browse_btn)
            file_group_layout.addLayout(file_layout)
            
            layout.addWidget(file_group)
            
            # Screenshots
            screenshots_group = QGroupBox("Screenshots (Optional, up to 5)")
            screenshots_layout = QVBoxLayout(screenshots_group)
            
            self._screenshot_list = QListWidget()
            self._screenshot_list.setMaximumHeight(80)
            screenshots_layout.addWidget(self._screenshot_list)
            
            ss_btn_layout = QHBoxLayout()
            add_ss_btn = QPushButton("➕ Add Screenshot")
            add_ss_btn.clicked.connect(lambda: self._add_screenshot(dialog))
            ss_btn_layout.addWidget(add_ss_btn)
            
            remove_ss_btn = QPushButton("➖ Remove")
            remove_ss_btn.clicked.connect(self._remove_screenshot)
            ss_btn_layout.addWidget(remove_ss_btn)
            ss_btn_layout.addStretch()
            screenshots_layout.addLayout(ss_btn_layout)
            
            ss_note = QLabel("Screenshots help users understand your plugin. Max 5MB each, JPG/PNG/GIF/WebP.")
            ss_note.setStyleSheet("color: #888; font-size: 11px;")
            screenshots_layout.addWidget(ss_note)
            
            layout.addWidget(screenshots_group)
            
            # Manifest override fields (optional)
            override_group = QGroupBox("Plugin Details (auto-filled from manifest.json)")
            override_layout = QFormLayout(override_group)
            
            self._upload_name = QLineEdit()
            self._upload_name.setPlaceholderText("Auto-filled from manifest")
            override_layout.addRow("Name:", self._upload_name)
            
            self._upload_version = QLineEdit()
            self._upload_version.setPlaceholderText("1.0.0")
            override_layout.addRow("Version:", self._upload_version)
            
            self._upload_desc = QTextEdit()
            self._upload_desc.setMaximumHeight(60)
            self._upload_desc.setPlaceholderText("Brief description (plain text)...")
            override_layout.addRow("Short Desc:", self._upload_desc)
            
            # Long description with HTML support
            long_desc_label = QLabel("Long Description (HTML supported):")
            override_layout.addRow(long_desc_label)
            
            self._upload_long_desc = QTextEdit()
            self._upload_long_desc.setMaximumHeight(100)
            self._upload_long_desc.setPlaceholderText(
                "Detailed description of your plugin. You can use HTML tags like:\n"
                "<b>bold</b>, <i>italic</i>, <ul><li>lists</li></ul>, <a href=''>links</a>, etc."
            )
            override_layout.addRow("", self._upload_long_desc)
            
            self._upload_category = QComboBox()
            self._upload_category.addItems(["tools", "extraction", "modification", "adb", "fastboot", "utilities", "other"])
            override_layout.addRow("Category:", self._upload_category)
            
            # Icon selector
            icon_layout = QHBoxLayout()
            
            # Available icons organized by category
            plugin_icons = [
                # Tools & Utilities
                "🔧", "⚙️", "🛠️", "🔩", "⚡", "🔌",
                # Package & Plugin
                "🧩", "📦", "📥", "📤", "💾", "🗃️",
                # Android & Mobile
                "📱", "🤖", "💻", "🖥️", "📟", "🔋",
                # Files & Data
                "📁", "📂", "🗂️", "📄", "📝", "🔍",
                # Security & Development
                "🔒", "🔓", "🔑", "🛡️", "🐛", "💡",
                # Action & Status
                "🚀", "✨", "🔥", "💫", "⭐", "🎯",
                # Communication
                "📡", "🌐", "🔗", "📶", "🔔", "💬",
                # Creative
                "🎨", "🎬", "🖼️", "📸", "🎵", "🎮"
            ]
            
            self._upload_icon = QLineEdit()
            self._upload_icon.setMaximumWidth(50)
            self._upload_icon.setPlaceholderText("🔧")
            self._upload_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._upload_icon.setStyleSheet("font-size: 20px;")
            icon_layout.addWidget(self._upload_icon)
            
            # Icon picker button
            icon_picker_btn = QPushButton("Choose Icon...")
            icon_picker_btn.setMaximumWidth(100)
            
            def show_icon_picker():
                icon_dialog = QDialog(dialog)
                icon_dialog.setWindowTitle("Select Plugin Icon")
                icon_dialog.setMinimumSize(520, 480)
                icon_dlg_layout = QVBoxLayout(icon_dialog)
                
                icon_label = QLabel("Select an icon for your plugin:")
                icon_label.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 10px;")
                icon_dlg_layout.addWidget(icon_label)
                
                # Create grid of icons
                icon_scroll = QScrollArea()
                icon_scroll.setWidgetResizable(True)
                icon_scroll.setFrameShape(QFrame.Shape.NoFrame)
                
                icon_grid_widget = QWidget()
                icon_grid = QGridLayout(icon_grid_widget)
                icon_grid.setSpacing(8)
                
                cols = 6
                for i, icon in enumerate(plugin_icons):
                    btn = QPushButton(icon)
                    btn.setFixedSize(70, 70)
                    btn.setStyleSheet("""
                        QPushButton {
                            font-size: 36px;
                            border: 2px solid #444;
                            border-radius: 8px;
                            background-color: #2a2a2a;
                        }
                        QPushButton:hover {
                            background-color: #3a3a3a;
                            border-color: #4fc3f7;
                        }
                        QPushButton:pressed {
                            background-color: #4fc3f7;
                        }
                    """)
                    btn.clicked.connect(lambda checked, ic=icon: (
                        self._upload_icon.setText(ic),
                        icon_dialog.accept()
                    ))
                    icon_grid.addWidget(btn, i // cols, i % cols)
                
                icon_scroll.setWidget(icon_grid_widget)
                icon_dlg_layout.addWidget(icon_scroll)
                
                # Custom icon input
                custom_layout = QHBoxLayout()
                custom_label = QLabel("Or enter custom emoji:")
                custom_label.setStyleSheet("font-size: 13px;")
                custom_layout.addWidget(custom_label)
                custom_input = QLineEdit()
                custom_input.setMaximumWidth(80)
                custom_input.setPlaceholderText("🔧")
                custom_input.setStyleSheet("font-size: 28px; padding: 4px;")
                custom_layout.addWidget(custom_input)
                custom_btn = QPushButton("Use")
                custom_btn.setStyleSheet("padding: 8px 16px;")
                custom_btn.clicked.connect(lambda: (
                    self._upload_icon.setText(custom_input.text()) if custom_input.text() else None,
                    icon_dialog.accept() if custom_input.text() else None
                ))
                custom_layout.addWidget(custom_btn)
                custom_layout.addStretch()
                icon_dlg_layout.addLayout(custom_layout)
                
                # Close button
                close_btn = QPushButton("Cancel")
                close_btn.setStyleSheet("padding: 8px 20px;")
                close_btn.clicked.connect(icon_dialog.reject)
                icon_dlg_layout.addWidget(close_btn)
                
                icon_dialog.exec()
            
            icon_picker_btn.clicked.connect(show_icon_picker)
            icon_layout.addWidget(icon_picker_btn)
            
            icon_hint = QLabel("(Emoji displayed in plugin store)")
            icon_hint.setStyleSheet("color: #888; font-size: 11px;")
            icon_layout.addWidget(icon_hint)
            icon_layout.addStretch()
            
            override_layout.addRow("Icon:", icon_layout)
            
            # License with coming soon labels
            license_layout = QHBoxLayout()
            self._upload_license = QComboBox()
            self._upload_license.addItems(["free", "donation"])
            license_layout.addWidget(self._upload_license)
            
            paid_label = QLabel("💰 Paid (coming soon)")
            paid_label.setStyleSheet("color: #888; font-style: italic;")
            license_layout.addWidget(paid_label)
            license_layout.addStretch()
            override_layout.addRow("License:", license_layout)
            
            # Price with coming soon
            price_layout = QHBoxLayout()
            self._upload_price = QDoubleSpinBox()
            self._upload_price.setRange(0, 1000)
            self._upload_price.setPrefix("$ ")
            self._upload_price.setEnabled(False)
            price_layout.addWidget(self._upload_price)
            
            price_soon = QLabel("(coming soon)")
            price_soon.setStyleSheet("color: #888; font-style: italic;")
            price_layout.addWidget(price_soon)
            price_layout.addStretch()
            override_layout.addRow("Price:", price_layout)
            
            layout.addWidget(override_group)
            
            # External Dependencies Section (Binaries)
            deps_group = QGroupBox("🔧 External Dependencies (Optional)")
            deps_layout = QVBoxLayout(deps_group)
            
            deps_info = QLabel(
                "<b>If your plugin needs external binaries (like ADB, Fastboot, etc.):</b><br>"
                "Add direct download URLs below. The server will download and package them with your plugin.<br>"
                "<span style='color:#ff9800;'>⚠️ Only direct download URLs are accepted (not pages with download buttons)</span>"
            )
            deps_info.setTextFormat(Qt.TextFormat.RichText)
            deps_info.setWordWrap(True)
            deps_info.setStyleSheet("font-size: 11px; margin-bottom: 10px;")
            deps_layout.addWidget(deps_info)
            
            # Dependencies list
            self._ext_deps_list = QListWidget()
            self._ext_deps_list.setMaximumHeight(120)
            self._ext_deps_list.setStyleSheet("QListWidget::item { padding: 4px; }")
            deps_layout.addWidget(self._ext_deps_list)
            
            # Add dependency form
            add_dep_layout = QHBoxLayout()
            
            self._dep_name = QLineEdit()
            self._dep_name.setPlaceholderText("Name (e.g., adb.exe)")
            self._dep_name.setMaximumWidth(150)
            add_dep_layout.addWidget(self._dep_name)
            
            self._dep_url = QLineEdit()
            self._dep_url.setPlaceholderText("Direct download URL (https://...)")
            add_dep_layout.addWidget(self._dep_url)
            
            self._dep_path = QLineEdit()
            self._dep_path.setPlaceholderText("Target path (e.g., platform-tools/)")
            self._dep_path.setMaximumWidth(150)
            add_dep_layout.addWidget(self._dep_path)
            
            add_dep_btn = QPushButton("➕ Add")
            add_dep_btn.clicked.connect(self._add_external_dep)
            add_dep_layout.addWidget(add_dep_btn)
            
            deps_layout.addLayout(add_dep_layout)
            
            # Remove and Validate buttons
            dep_btn_layout = QHBoxLayout()
            
            remove_dep_btn = QPushButton("➖ Remove Selected")
            remove_dep_btn.clicked.connect(self._remove_external_dep)
            dep_btn_layout.addWidget(remove_dep_btn)
            
            validate_deps_btn = QPushButton("🔍 Validate URLs")
            validate_deps_btn.setToolTip("Check if all URLs are valid and downloadable")
            validate_deps_btn.clicked.connect(self._validate_external_deps)
            dep_btn_layout.addWidget(validate_deps_btn)
            
            dep_btn_layout.addStretch()
            deps_layout.addLayout(dep_btn_layout)
            
            # Validation status
            self._deps_status = QLabel("")
            self._deps_status.setWordWrap(True)
            self._deps_status.setStyleSheet("font-size: 11px;")
            deps_layout.addWidget(self._deps_status)
            
            # Example
            deps_example = QLabel(
                "<b>Examples:</b><br>"
                "• Name: <code>adb.exe</code> | URL: <code>https://dl.google.com/.../adb.exe</code> | Path: <code>platform-tools/</code><br>"
                "• Name: <code>mtkclient.zip</code> | URL: <code>https://github.com/.../archive/refs/heads/main.zip</code> | Path: <code>./</code>"
            )
            deps_example.setTextFormat(Qt.TextFormat.RichText)
            deps_example.setWordWrap(True)
            deps_example.setStyleSheet("color: #888; font-size: 10px; background: #1a1a1a; padding: 8px; border-radius: 4px;")
            deps_layout.addWidget(deps_example)
            
            layout.addWidget(deps_group)
            
            # Initialize external deps list
            self._external_deps = []
            
            # Git Clone Section (for cloning repos at install time)
            git_group = QGroupBox("📦 Git Repository Clone (Optional)")
            git_layout = QVBoxLayout(git_group)
            
            git_info = QLabel(
                "<b>Clone a Git repository when your plugin is installed:</b><br>"
                "The repository will be cloned to a subfolder in your plugin directory.<br>"
                "<span style='color:#4fc3f7;'>💡 Ideal for tools like mtkclient that need their own repo structure.</span><br>"
                "<span style='color:#ff9800;'>⚠️ List ALL pip packages in manifest.json <code>requirements</code> field - not here!</span>"
            )
            git_info.setTextFormat(Qt.TextFormat.RichText)
            git_info.setWordWrap(True)
            git_info.setStyleSheet("font-size: 11px; margin-bottom: 10px;")
            git_layout.addWidget(git_info)
            
            git_form = QFormLayout()
            
            self._git_repo_url = QLineEdit()
            self._git_repo_url.setPlaceholderText("https://github.com/user/repo.git")
            git_form.addRow("Repository URL:", self._git_repo_url)
            
            self._git_target_dir = QLineEdit()
            self._git_target_dir.setPlaceholderText("e.g., mtkclient (subfolder in plugin dir)")
            git_form.addRow("Target Directory:", self._git_target_dir)
            
            git_layout.addLayout(git_form)
            
            git_example = QLabel(
                "<b>Example manifest.json with git_clone:</b><br>"
                "<code style='font-size:10px;'>{<br>"
                "&nbsp;&nbsp;\"requirements\": [\"pyusb\", \"pycryptodome\"],<br>"
                "&nbsp;&nbsp;\"git_clone\": {<br>"
                "&nbsp;&nbsp;&nbsp;&nbsp;\"repo\": \"https://github.com/bkerler/mtkclient.git\",<br>"
                "&nbsp;&nbsp;&nbsp;&nbsp;\"target\": \"mtkclient\"<br>"
                "&nbsp;&nbsp;}<br>"
                "}</code>"
            )
            git_example.setTextFormat(Qt.TextFormat.RichText)
            git_example.setWordWrap(True)
            git_example.setStyleSheet("color: #888; font-size: 10px; background: #1a1a1a; padding: 8px; border-radius: 4px;")
            git_layout.addWidget(git_example)
            
            layout.addWidget(git_group)
            
            # Setup Commands Section (commands to run after git clone and pip install)
            setup_cmd_group = QGroupBox("⚡ Setup Commands (Optional)")
            setup_cmd_layout = QVBoxLayout(setup_cmd_group)
            
            setup_cmd_info = QLabel(
                "<b>Commands to run after git clone and pip install:</b><br>"
                "These bash-compatible commands run in the plugin directory after dependencies are installed.<br>"
                "<span style='color:#4fc3f7;'>💡 Useful for 'pip install .' to install cloned repos as packages.</span><br>"
                "<span style='color:#ff9800;'>⚠️ All commands are reviewed before your plugin is approved.</span>"
            )
            setup_cmd_info.setTextFormat(Qt.TextFormat.RichText)
            setup_cmd_info.setWordWrap(True)
            setup_cmd_info.setStyleSheet("font-size: 11px; margin-bottom: 10px;")
            setup_cmd_layout.addWidget(setup_cmd_info)
            
            self._setup_commands = QTextEdit()
            self._setup_commands.setMaximumHeight(80)
            self._setup_commands.setPlaceholderText(
                "Enter one command per line, e.g.:\n"
                "pip install .\n"
                "python setup.py build"
            )
            setup_cmd_layout.addWidget(self._setup_commands)
            
            setup_cmd_example = QLabel(
                "<b>Example manifest.json with setup_commands:</b><br>"
                "<code style='font-size:10px;'>{<br>"
                "&nbsp;&nbsp;\"git_clone\": {\"repo\": \"https://github.com/bkerler/mtkclient.git\", \"target\": \"mtkclient\"},<br>"
                "&nbsp;&nbsp;\"setup_commands\": [\"pip install .\"]<br>"
                "}</code>"
            )
            setup_cmd_example.setTextFormat(Qt.TextFormat.RichText)
            setup_cmd_example.setWordWrap(True)
            setup_cmd_example.setStyleSheet("color: #888; font-size: 10px; background: #1a1a1a; padding: 8px; border-radius: 4px;")
            setup_cmd_layout.addWidget(setup_cmd_example)
            
            layout.addWidget(setup_cmd_group)
            
            # Legal Agreement Section
            legal_group = QGroupBox("📜 Developer Agreement & License")
            legal_layout = QVBoxLayout(legal_group)
            
            legal_text = QTextEdit()
            legal_text.setReadOnly(True)
            legal_text.setMaximumHeight(180)
            legal_text.setStyleSheet("background-color: #1a1a1a; color: #ccc; font-size: 10px;")
            legal_text.setHtml("""
<p><b>IMAGE ANARCHY PLUGIN DEVELOPER AGREEMENT</b></p>
<p><i>Last Updated: January 2026</i></p>

<p>By submitting a plugin to the Image Anarchy Plugin Store ("Store"), you ("Developer") agree to the following terms and conditions:</p>

<p><b>1. GRANT OF LICENSE</b><br>
For all plugins submitted with a "free" or "donation" license type, Developer hereby grants to Image Anarchy ("IA"), its successors, and assigns, an irrevocable, perpetual, worldwide, royalty-free, non-exclusive license to use, reproduce, modify, distribute, publicly display, publicly perform, sublicense, and create derivative works from the submitted plugin. Upon submission, such plugins become the property of Image Anarchy.</p>

<p><b>2. DISCLAIMER OF LIABILITY</b><br>
THE PLUGIN STORE AND ALL PLUGINS ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. IMAGE ANARCHY DISCLAIMS ALL LIABILITY FOR ANY DAMAGES, INCLUDING BUT NOT LIMITED TO DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, ARISING OUT OF OR RELATED TO THE USE OR INABILITY TO USE ANY PLUGIN, REGARDLESS OF WHETHER SUCH DAMAGES WERE FORESEEABLE OR WHETHER IMAGE ANARCHY WAS ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.</p>

<p><b>3. INDEMNIFICATION</b><br>
Developer agrees to indemnify, defend, and hold harmless Image Anarchy, its officers, directors, employees, agents, and affiliates from and against any and all claims, damages, obligations, losses, liabilities, costs, and expenses arising from: (a) Developer's plugin; (b) Developer's violation of any third-party rights; (c) Developer's violation of any applicable law or regulation.</p>

<p><b>4. CONTENT RESPONSIBILITY</b><br>
Developer is solely responsible for ensuring that submitted plugins do not infringe upon any intellectual property rights, contain malicious code, or violate any applicable laws. Image Anarchy reserves the right to remove any plugin at its sole discretion without notice.</p>

<p><b>5. TAKEDOWN REQUESTS</b><br>
Developers may submit takedown requests to: <b>requests@imageanarchy.com</b><br>
Developer agrees to allow Image Anarchy a minimum of forty-eight (48) hours to process and act upon any takedown request. Paid plugins (when available) will include a self-service removal option.</p>

<p><b>6. LIMITATION OF LIABILITY</b><br>
IN NO EVENT SHALL IMAGE ANARCHY'S TOTAL LIABILITY TO DEVELOPER EXCEED ZERO DOLLARS ($0.00 USD). IMAGE ANARCHY SHALL NOT BE LIABLE FOR ANY LOST PROFITS, LOST DATA, OR ANY FORM OF CONSEQUENTIAL DAMAGES.</p>

<p><b>7. GOVERNING LAW</b><br>
This Agreement shall be governed by the laws applicable to software distribution platforms, without regard to conflict of law principles.</p>

<p><b>8. ENTIRE AGREEMENT</b><br>
This Agreement constitutes the entire agreement between Developer and Image Anarchy regarding plugin submissions and supersedes all prior agreements and understandings.</p>

<p style="color:#ff9800;"><b>BY SIGNING BELOW, YOU ACKNOWLEDGE THAT YOU HAVE READ, UNDERSTOOD, AND AGREE TO BE BOUND BY ALL TERMS OF THIS AGREEMENT.</b></p>
            """)
            legal_layout.addWidget(legal_text)
            
            # Signature canvas
            sig_label = QLabel("✍️ Sign below with your mouse or finger to agree:")
            sig_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
            legal_layout.addWidget(sig_label)
            
            # Signature widget (custom drawing canvas)
            from PyQt6.QtGui import QPainterPath, QPainter, QPen, QColor
            
            class SignatureCanvas(QWidget):
                def __init__(self, parent=None):
                    super().__init__(parent)
                    self.setMinimumSize(400, 80)
                    self.setMaximumHeight(80)
                    self.setStyleSheet("background-color: #f5f5f5; border: 2px solid #444; border-radius: 4px;")
                    self.path = QPainterPath()
                    self.last_point = None
                    self.has_signature = False
                
                def clear(self):
                    self.path = QPainterPath()
                    self.last_point = None
                    self.has_signature = False
                    self.update()
                
                def paintEvent(self, event):
                    painter = QPainter(self)
                    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
                    painter.fillRect(self.rect(), QColor("#f5f5f5"))
                    
                    if not self.has_signature:
                        painter.setPen(QColor("#aaa"))
                        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "Sign here...")
                    
                    painter.setPen(QPen(QColor("#1a1a1a"), 2))
                    painter.drawPath(self.path)
                
                def mousePressEvent(self, event):
                    if event.button() == Qt.MouseButton.LeftButton:
                        self.last_point = event.position()
                        self.path.moveTo(self.last_point)
                        self.has_signature = True
                
                def mouseMoveEvent(self, event):
                    if event.buttons() & Qt.MouseButton.LeftButton and self.last_point:
                        new_point = event.position()
                        self.path.lineTo(new_point)
                        self.last_point = new_point
                        self.update()
                
                def mouseReleaseEvent(self, event):
                    self.last_point = None
            
            self._signature_canvas = SignatureCanvas()
            legal_layout.addWidget(self._signature_canvas)
            
            # Clear signature button
            clear_sig_btn = QPushButton("🗑️ Clear Signature")
            clear_sig_btn.setMaximumWidth(150)
            clear_sig_btn.clicked.connect(self._signature_canvas.clear)
            legal_layout.addWidget(clear_sig_btn)
            
            layout.addWidget(legal_group)
            
            # Security notice
            security_notice = QLabel(
                "🔒 <b>Security Notice:</b> All plugins are scanned for malware before acceptance. "
                "Plugins containing executables (.exe, .dll) may take 1-2 minutes to upload while scanning completes."
            )
            security_notice.setWordWrap(True)
            security_notice.setStyleSheet("color: #888; font-size: 11px; padding: 8px; background-color: rgba(33, 150, 243, 0.1); border-radius: 4px;")
            layout.addWidget(security_notice)
            
            # Status
            self._upload_status = QLabel("")
            self._upload_status.setWordWrap(True)
            layout.addWidget(self._upload_status)
            
            layout.addStretch()
            
            scroll.setWidget(scroll_widget)
            
            dialog_layout = QVBoxLayout(dialog)
            dialog_layout.addWidget(scroll)
            
            # Buttons
            btn_layout = QHBoxLayout()
            btn_layout.addStretch()
            
            cancel_btn = QPushButton("Cancel")
            cancel_btn.clicked.connect(dialog.reject)
            btn_layout.addWidget(cancel_btn)
            
            upload_btn = QPushButton("📤 Upload Plugin")
            upload_btn.setObjectName("upload_btn")  # Set object name for finding later
            upload_btn.setStyleSheet("background-color: #4CAF50; padding: 8px 20px;")
            upload_btn.clicked.connect(lambda: self._do_upload(dialog))
            btn_layout.addWidget(upload_btn)
            
            dialog_layout.addLayout(btn_layout)
            
            # Initialize screenshot list
            self._screenshot_paths = []
            
            dialog.exec()
        
        def _add_external_dep(self):
            """Add an external dependency to the list."""
            name = self._dep_name.text().strip()
            url = self._dep_url.text().strip()
            target_path = self._dep_path.text().strip() or "./"
            
            if not name:
                self._deps_status.setText("⚠️ Please enter a dependency name")
                self._deps_status.setStyleSheet("color: #f44336;")
                return
            
            if not url:
                self._deps_status.setText("⚠️ Please enter a download URL")
                self._deps_status.setStyleSheet("color: #f44336;")
                return
            
            if not url.startswith(("http://", "https://")):
                self._deps_status.setText("⚠️ URL must start with http:// or https://")
                self._deps_status.setStyleSheet("color: #f44336;")
                return
            
            # Add to list
            dep = {"name": name, "url": url, "path": target_path, "validated": False}
            self._external_deps.append(dep)
            
            item_text = f"📦 {name} → {target_path} | {url[:60]}..."
            self._ext_deps_list.addItem(item_text)
            
            # Clear inputs
            self._dep_name.clear()
            self._dep_url.clear()
            self._dep_path.clear()
            
            self._deps_status.setText(f"✓ Added {name}")
            self._deps_status.setStyleSheet("color: #4CAF50;")
        
        def _remove_external_dep(self):
            """Remove selected external dependency."""
            current = self._ext_deps_list.currentRow()
            if current >= 0:
                self._ext_deps_list.takeItem(current)
                removed = self._external_deps.pop(current)
                self._deps_status.setText(f"Removed {removed['name']}")
                self._deps_status.setStyleSheet("color: #888;")
        
        def _validate_external_deps(self):
            """Validate all external dependency URLs."""
            if not self._external_deps:
                self._deps_status.setText("No dependencies to validate")
                self._deps_status.setStyleSheet("color: #888;")
                return
            
            self._deps_status.setText("🔄 Validating URLs...")
            self._deps_status.setStyleSheet("color: #4fc3f7;")
            QApplication.processEvents()
            
            import urllib.request
            import urllib.error
            
            valid_count = 0
            errors = []
            
            for i, dep in enumerate(self._external_deps):
                try:
                    # HEAD request to check if URL is valid and downloadable
                    req = urllib.request.Request(dep['url'], method='HEAD')
                    req.add_header('User-Agent', 'ImageAnarchy/1.1')
                    
                    with urllib.request.urlopen(req, timeout=10) as response:
                        status = response.getcode()
                        content_type = response.headers.get('Content-Type', '')
                        content_length = response.headers.get('Content-Length', 'unknown')
                        
                        if status == 200:
                            dep['validated'] = True
                            dep['size'] = content_length
                            valid_count += 1
                            
                            # Update list item with checkmark
                            item = self._ext_deps_list.item(i)
                            if item:
                                size_str = f" ({int(content_length) // 1024 // 1024}MB)" if content_length != 'unknown' else ""
                                item.setText(f"✅ {dep['name']} → {dep['path']}{size_str}")
                        else:
                            dep['validated'] = False
                            errors.append(f"{dep['name']}: HTTP {status}")
                            
                            item = self._ext_deps_list.item(i)
                            if item:
                                item.setText(f"❌ {dep['name']} - HTTP {status}")
                                
                except urllib.error.HTTPError as e:
                    dep['validated'] = False
                    errors.append(f"{dep['name']}: HTTP {e.code}")
                    item = self._ext_deps_list.item(i)
                    if item:
                        item.setText(f"❌ {dep['name']} - HTTP {e.code}")
                        
                except urllib.error.URLError as e:
                    dep['validated'] = False
                    errors.append(f"{dep['name']}: {str(e.reason)}")
                    item = self._ext_deps_list.item(i)
                    if item:
                        item.setText(f"❌ {dep['name']} - Connection failed")
                        
                except Exception as e:
                    dep['validated'] = False
                    errors.append(f"{dep['name']}: {str(e)}")
                    item = self._ext_deps_list.item(i)
                    if item:
                        item.setText(f"❌ {dep['name']} - Error")
                
                QApplication.processEvents()
            
            if valid_count == len(self._external_deps):
                self._deps_status.setText(f"✅ All {valid_count} URLs validated successfully!")
                self._deps_status.setStyleSheet("color: #4CAF50;")
            else:
                self._deps_status.setText(f"⚠️ {valid_count}/{len(self._external_deps)} valid. Errors: {'; '.join(errors)}")
                self._deps_status.setStyleSheet("color: #f44336;")
        
        def _add_screenshot(self, dialog):
            """Add a screenshot to the upload with image validation."""
            if len(self._screenshot_paths) >= 5:
                QMessageBox.warning(dialog, "Limit Reached", "Maximum 5 screenshots allowed.")
                return
            
            file_path, _ = QFileDialog.getOpenFileName(
                dialog,
                "Select Screenshot",
                "",
                "All Files (*.*)"
            )
            
            if file_path:
                # Validate that it's actually an image using magic bytes
                def is_valid_image(filepath):
                    """Check if file is a valid image using magic bytes, not extension."""
                    try:
                        with open(filepath, 'rb') as f:
                            header = f.read(32)
                        
                        # JPEG magic bytes
                        if header[:3] == b'\xff\xd8\xff':
                            return True, "JPEG"
                        # PNG magic bytes
                        if header[:8] == b'\x89PNG\r\n\x1a\n':
                            return True, "PNG"
                        # GIF magic bytes
                        if header[:6] in (b'GIF87a', b'GIF89a'):
                            return True, "GIF"
                        # WebP magic bytes (RIFF....WEBP)
                        if header[:4] == b'RIFF' and header[8:12] == b'WEBP':
                            return True, "WebP"
                        # BMP magic bytes
                        if header[:2] == b'BM':
                            return True, "BMP"
                        
                        return False, None
                    except Exception:
                        return False, None
                
                is_image, img_type = is_valid_image(file_path)
                
                if not is_image:
                    QMessageBox.warning(
                        dialog, 
                        "Invalid Image",
                        "The selected file is not a valid image.\n\n"
                        "Supported formats: JPEG, PNG, GIF, WebP, BMP\n\n"
                        "Note: Files are validated by their content, not extension."
                    )
                    return
                
                # Check file size (max 5MB)
                file_size = os.path.getsize(file_path)
                if file_size > 5 * 1024 * 1024:
                    QMessageBox.warning(
                        dialog,
                        "File Too Large",
                        f"Screenshot is too large ({file_size / 1024 / 1024:.1f}MB).\n\n"
                        "Maximum size: 5MB"
                    )
                    return
                
                self._screenshot_paths.append(file_path)
                self._screenshot_list.addItem(f"{os.path.basename(file_path)} ({img_type})")
        
        def _remove_screenshot(self):
            """Remove selected screenshot."""
            current = self._screenshot_list.currentRow()
            if current >= 0:
                self._screenshot_list.takeItem(current)
                self._screenshot_paths.pop(current)
        
        def _browse_upload_file(self, dialog):
            """Browse for plugin zip file."""
            file_path, _ = QFileDialog.getOpenFileName(
                dialog,
                "Select Plugin ZIP",
                "",
                "ZIP Files (*.zip)"
            )
            
            if file_path:
                self._upload_file_path.setText(file_path)
                
                # Try to read manifest from zip
                try:
                    import zipfile
                    with zipfile.ZipFile(file_path, 'r') as zf:
                        # Find manifest.json
                        for name in zf.namelist():
                            if name.endswith('manifest.json'):
                                with zf.open(name) as mf:
                                    manifest = json.load(mf)
                                    self._upload_name.setText(manifest.get('name', ''))
                                    self._upload_version.setText(manifest.get('version', '1.0'))
                                    self._upload_desc.setPlainText(manifest.get('description', ''))
                                    
                                    # Long description
                                    if manifest.get('long_description'):
                                        self._upload_long_desc.setPlainText(manifest.get('long_description', ''))
                                    
                                    # Set category
                                    cat = manifest.get('category', 'tools')
                                    idx = self._upload_category.findText(cat, Qt.MatchFlag.MatchFixedString)
                                    if idx >= 0:
                                        self._upload_category.setCurrentIndex(idx)
                                    
                                    # Set icon
                                    icon = manifest.get('icon', '🔧')
                                    self._upload_icon.setText(icon)
                                    
                                    # Set license
                                    lic = manifest.get('license_type', 'free')
                                    idx = self._upload_license.findText(lic, Qt.MatchFlag.MatchFixedString)
                                    if idx >= 0:
                                        self._upload_license.setCurrentIndex(idx)
                                    
                                    self._upload_price.setValue(manifest.get('price', 0))
                                    
                                    # Set git_clone if present
                                    git_clone = manifest.get('git_clone', {})
                                    if git_clone:
                                        self._git_repo_url.setText(git_clone.get('repo', ''))
                                        self._git_target_dir.setText(git_clone.get('target', ''))
                                    
                                    # Set setup_commands if present
                                    setup_commands = manifest.get('setup_commands', [])
                                    if setup_commands and isinstance(setup_commands, list):
                                        self._setup_commands.setPlainText('\n'.join(setup_commands))
                                    
                                    # Show requirements info in status
                                    reqs = manifest.get('requirements', [])
                                    status_parts = ["✓ Manifest loaded from ZIP"]
                                    if reqs:
                                        status_parts.append(f"📦 {len(reqs)} pip packages")
                                    if git_clone:
                                        status_parts.append(f"📥 Git clone: {git_clone.get('target', 'repo')}")
                                    if setup_commands:
                                        status_parts.append(f"⚡ {len(setup_commands)} setup command(s)")
                                    
                                    self._upload_status.setText(" | ".join(status_parts))
                                    self._upload_status.setStyleSheet("color: #4CAF50;")
                                break
                except Exception as e:
                    self._upload_status.setText(f"Could not read manifest: {str(e)}")
                    self._upload_status.setStyleSheet("color: #ff9800;")
        
        def _do_upload(self, dialog):
            """Perform the plugin upload."""
            # Check signature first
            if not hasattr(self, '_signature_canvas') or not self._signature_canvas.has_signature:
                self._upload_status.setText("⚠️ Please sign the Developer Agreement to continue")
                self._upload_status.setStyleSheet("color: #f44336;")
                return
            
            file_path = self._upload_file_path.text()
            
            if not file_path or not os.path.exists(file_path):
                self._upload_status.setText("Please select a plugin ZIP file")
                self._upload_status.setStyleSheet("color: #f44336;")
                return
            
            name = self._upload_name.text().strip()
            if not name:
                self._upload_status.setText("Please enter a plugin name")
                self._upload_status.setStyleSheet("color: #f44336;")
                return
            
            # Check if external deps are validated (if any exist)
            external_deps = getattr(self, '_external_deps', [])
            if external_deps:
                unvalidated = [d for d in external_deps if not d.get('validated', False)]
                if unvalidated:
                    self._upload_status.setText("⚠️ Please validate all external dependency URLs first")
                    self._upload_status.setStyleSheet("color: #f44336;")
                    return
            
            # Build manifest data
            manifest = {
                'name': name,
                'version': self._upload_version.text().strip() or '1.0.0',
                'description': self._upload_desc.toPlainText().strip(),
                'long_description': self._upload_long_desc.toPlainText().strip(),
                'category': self._upload_category.currentText(),
                'icon': self._upload_icon.text().strip() or '🔧',
                'license_type': self._upload_license.currentText(),
                'price': 0,  # Paid plugins coming soon
                'external_dependencies': external_deps  # Include validated dependencies
            }
            
            # Add git_clone if specified
            git_repo = self._git_repo_url.text().strip()
            if git_repo:
                git_clone_data = {
                    'repo': git_repo,
                    'target': self._git_target_dir.text().strip() or None
                }
                manifest['git_clone'] = git_clone_data
            
            # Show detailed upload progress message
            self._upload_status.setText("📤 Uploading plugin...\n🔒 Security scanning in progress (may take 1-2 minutes for plugins with binaries)")
            self._upload_status.setStyleSheet("color: #2196F3;")
            
            # Disable upload button during process
            upload_btn = dialog.findChild(QPushButton, "upload_btn")
            if upload_btn:
                upload_btn.setEnabled(False)
                upload_btn.setText("⏳ Scanning...")
            
            # Get screenshot paths
            screenshots = getattr(self, '_screenshot_paths', [])
            
            # Run upload in background thread to prevent UI freeze
            self._upload_thread = PluginUploadThread(plugin_store_api, manifest, file_path, screenshots)
            self._upload_dialog = dialog  # Store reference for callback
            self._upload_name_text = name  # Store for success message
            
            def on_upload_progress(msg):
                self._upload_status.setText(msg + "\n🔒 Security scanning in progress...")
            
            def on_upload_finished(result):
                # Re-enable upload button
                if upload_btn:
                    upload_btn.setEnabled(True)
                    upload_btn.setText("📤 Upload Plugin")
                
                if 'error' in result:
                    # Check for re-login needed
                    if result.get('code') == 'USER_NOT_FOUND':
                        self._upload_status.setText("❌ Session expired. Please log out and log in again.")
                    else:
                        self._upload_status.setText(f"❌ Upload failed: {result['error']}")
                    self._upload_status.setStyleSheet("color: #f44336;")
                else:
                    self._upload_dialog.accept()
                    ss_count = result.get('screenshots', 0)
                    deps_count = result.get('external_deps', 0)
                    
                    deps_msg = f"\nExternal Dependencies: {deps_count} (will be downloaded during review)\n" if deps_count else ""
                    
                    QMessageBox.information(
                        self,
                        "Plugin Submitted",
                        f"Your plugin '{self._upload_name_text}' has been submitted!\n\n"
                        f"Screenshots: {ss_count}{deps_msg}\n"
                        "It will be reviewed by an admin before appearing in the store.\n"
                        "External dependencies will be downloaded and validated during review.\n\n"
                        "You'll receive an email when it's approved.\n\n"
                        "📜 By signing, you agreed to the Developer Agreement.\n"
                        "Free plugins become property of Image Anarchy.\n"
                        "Takedown requests: requests@imageanarchy.com (48hr response)"
                    )
            
            self._upload_thread.progress.connect(on_upload_progress)
            self._upload_thread.finished.connect(on_upload_finished)
            self._upload_thread.start()

    return QApplication, ImageAnarchyGUI, QPalette, QColor, PluginsTab, PreReadyChecklistDialog


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def run_cli(args):
    """Run the command-line interface."""
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    partition_names = [n.strip() for n in args.images.split(',') if n.strip()] or None
    
    Path(args.out).mkdir(parents=True, exist_ok=True)
    
    with PayloadFile(args.payload_path) as payload_file:
        magic = payload_file.read(4)
        if magic != PAYLOAD_MAGIC:
            raise PayloadError(f"Invalid magic header: expected {PAYLOAD_MAGIC!r}, got {magic!r}")
        
        format_version = unpack_u64(payload_file.read(8))
        if format_version != SUPPORTED_FORMAT_VERSION:
            raise PayloadError(f"Unsupported format version: {format_version}")
        
        manifest_size = unpack_u64(payload_file.read(8))
        metadata_signature_size = unpack_u32(payload_file.read(4))
        
        manifest_data = payload_file.read(manifest_size)
        payload_file.read(metadata_signature_size)
        data_offset = payload_file.tell()
        
        manifest = DeltaArchiveManifest()
        manifest.ParseFromString(manifest_data)
        
        handler = OperationHandler(payload_file, data_offset, manifest.block_size)
        
        # Get partitions to extract
        if partition_names:
            available = {p.partition_name: p for p in manifest.partitions}
            partitions = []
            for name in partition_names:
                if name in available:
                    partitions.append(available[name])
                else:
                    logger.warning(f"Partition '{name}' not found in payload")
        else:
            partitions = list(manifest.partitions)
        
        # Extract each partition
        for partition in partitions:
            name = partition.partition_name
            logger.info(f"Processing {name} partition...")
            
            output_path = Path(args.out) / f"{name}.img"
            old_file = None
            
            if args.diff:
                old_path = Path(args.old) / f"{name}.img"
                if old_path.exists():
                    old_file = open(old_path, 'rb')
                else:
                    logger.warning(f"Original image not found: {old_path}")
            
            try:
                with open(output_path, 'wb') as out_file:
                    for op in partition.operations:
                        handler.process(op, out_file, old_file)
                        sys.stdout.write(".")
                        sys.stdout.flush()
                print(" Done")
            finally:
                if old_file:
                    old_file.close()
        
        # Extract super partition contents if requested
        if getattr(args, 'extract_super', False):
            super_path = Path(args.out) / "super.img"
            if super_path.exists():
                _extract_super_cli(str(super_path), args.out)
            else:
                logger.info("No super.img found, skipping super extraction")


def _extract_super_cli(super_path: str, output_dir: str):
    """Extract partitions from super.img in CLI mode."""
    logger.info("\n" + "="*50)
    logger.info("Extracting super partition contents...")
    logger.info("="*50)
    
    try:
        # Check if it's a valid super image
        img_type = detect_image_type(super_path)
        
        if img_type == 'sparse':
            # First convert sparse to raw
            logger.info("Super image is sparse, converting to raw first...")
            raw_path = super_path.replace('.img', '_raw.img')
            converter = SparseImageConverter()
            converter.convert(super_path, raw_path)
            logger.info(f"  Converted to: {raw_path}")
            super_path = raw_path
            img_type = detect_image_type(super_path)
        
        if img_type != 'super':
            logger.warning(f"super.img is not a dynamic partition image (type: {img_type})")
            logger.warning("Skipping super extraction")
            return
        
        # Create output directory for super contents
        super_output_dir = Path(output_dir) / "super_extracted"
        super_output_dir.mkdir(parents=True, exist_ok=True)
        
        # List partitions in super image
        extractor = SuperImageExtractor()
        partitions = extractor.list_partitions(super_path)
        
        if not partitions:
            logger.info("No partitions found in super image")
            return
        
        valid_partitions = [p for p in partitions if p.size > 0]
        logger.info(f"Found {len(valid_partitions)} partition(s) in super image:")
        
        for p in valid_partitions:
            logger.info(f"  - {p.name}: {p.size / (1024*1024):.2f} MB")
        
        # Extract all partitions
        logger.info("\nExtracting partitions from super image...")
        results = extractor.extract(super_path, str(super_output_dir))
        
        for name, path in results.items():
            logger.info(f"  Extracted: {name}")
            
            # Detect and report sub-partition types
            if Path(path).exists():
                sub_type = detect_image_type(path)
                if sub_type != 'raw':
                    logger.info(f"    (Type: {sub_type})")
        
        logger.info(f"\nSuper partition contents extracted to: {super_output_dir}")
        
    except Exception as e:
        logger.error(f"Error extracting super partition: {e}")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Image Anarchy - Android Image Swiss Army Knife | https://github.com/vehoelite/image-anarchy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    Launch GUI
  
  Extract (dump) payload:
  %(prog)s --extract payload.bin              Extract all partitions
  %(prog)s --extract ota.zip -i system        Extract only system partition
  %(prog)s --extract payload.bin --diff       Extract differential OTA
  %(prog)s --extract payload.bin -s           Extract payload + super partition contents
  
  Create (repack) payload:
  %(prog)s --create ./images -o payload.bin   Create payload from images
  %(prog)s --create ./images --compression xz Create with XZ compression
  
  Process Android images:
  %(prog)s --image super.img                  Extract partitions from super image
  %(prog)s --image boot.img                   Extract kernel/ramdisk from boot image
  %(prog)s --image system.img --analyze       Analyze image without extracting
  %(prog)s --image sparse.img --no-convert-sparse  Keep as sparse format
        """
    )
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '--extract', '--cli',
        dest='extract_path',
        metavar='PAYLOAD',
        help='Extract partitions from a payload file'
    )
    mode_group.add_argument(
        '--create',
        dest='input_dir',
        metavar='DIR',
        help='Create payload from partition images in directory'
    )
    
    # Common options
    parser.add_argument(
        '--out', '-o',
        default=None,
        help='Output directory (extract) or file (create)'
    )
    parser.add_argument(
        '--images', '-i',
        default='',
        help='Comma-separated list of partition names (default: all)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    # Extract-specific options
    parser.add_argument(
        '--diff', '-d',
        action='store_true',
        help='Extract differential OTA (requires --old directory)'
    )
    parser.add_argument(
        '--old',
        default='old',
        help='Directory with original images for differential OTA (default: old)'
    )
    parser.add_argument(
        '--extract-super', '-s',
        action='store_true',
        help='Extract super partition contents (system, vendor, etc.) after extraction'
    )
    
    # Create-specific options
    parser.add_argument(
        '--compression', '-c',
        choices=['zstd', 'xz', 'bz2', 'none'],
        default='zstd',
        help='Compression algorithm for payload creation (default: zstd)'
    )
    parser.add_argument(
        '--level', '-l',
        type=int,
        default=9,
        help='Compression level 1-22 (default: 9)'
    )
    
    # Image extraction mode
    mode_group.add_argument(
        '--image',
        dest='image_path',
        metavar='IMAGE',
        help='Extract/convert an Android image file (sparse, boot, super)'
    )
    parser.add_argument(
        '--analyze',
        action='store_true',
        help='Only analyze the image, don\'t extract (use with --image)'
    )
    parser.add_argument(
        '--no-convert-sparse',
        action='store_true',
        help='Don\'t convert sparse images to raw (use with --image)'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.extract_path:
        # Extract mode
        args.payload_path = args.extract_path
        args.out = args.out or 'output'
        try:
            run_cli(args)
        except PayloadError as e:
            logger.error(f"Error: {e}")
            sys.exit(1)
        except KeyboardInterrupt:
            logger.info("\nAborted by user")
            sys.exit(130)
    
    elif args.input_dir:
        # Create mode
        args.output = args.out or 'payload.bin'
        try:
            run_create(args)
        except PayloadError as e:
            logger.error(f"Error: {e}")
            sys.exit(1)
        except KeyboardInterrupt:
            logger.info("\nAborted by user")
            sys.exit(130)
    
    elif args.image_path:
        # Image extraction mode
        args.out = args.out or 'extracted_images'
        try:
            run_image_extract(args)
        except PayloadError as e:
            logger.error(f"Error: {e}")
            sys.exit(1)
        except KeyboardInterrupt:
            logger.info("\nAborted by user")
            sys.exit(130)
    
    else:
        # GUI mode
        try:
            QApplication, ImageAnarchyGUI, QPalette, QColor, PluginsTab, PreReadyChecklistDialog = create_gui_app()
        except ImportError:
            print("PyQt6 is required for GUI mode. Install with: pip install PyQt6")
            print("Or use CLI mode: python image_anarchy.py --cli payload.bin")
            sys.exit(1)
        
        app = QApplication(sys.argv)
        app.setApplicationName("Image Anarchy")
        app.setStyle("Fusion")
        
        # Dark palette
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(212, 212, 212))
        palette.setColor(QPalette.ColorRole.Base, QColor(45, 45, 45))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(37, 37, 37))
        palette.setColor(QPalette.ColorRole.Text, QColor(212, 212, 212))
        palette.setColor(QPalette.ColorRole.Button, QColor(45, 45, 45))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(212, 212, 212))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(38, 79, 120))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
        app.setPalette(palette)
        
        # Show Pre-Ready Checklist splash screen
        splash = PreReadyChecklistDialog()
        splash.exec()
        
        window = ImageAnarchyGUI()
        
        # Add Plugins tab
        plugins_tab = PluginsTab(window)
        window.tab_widget.addTab(plugins_tab, "🔌 Plugins")
        
        window.show()
        
        sys.exit(app.exec())


if __name__ == "__main__":
    main()
