# Dump Surgeon — Design Spec

**Date:** 2026-06-19
**Status:** Approved (design)
**Target:** `image_anarchy.py` (main app) — new top-level tab + one logic class

## Purpose

Add MTK/eMMC dump-repair tooling to Image Anarchy's built-in extractor. Born from a real MT6761 recovery session: every tool here corresponds to an operation we had to do by hand (build a preloader EMI for mtkclient, trim oversized partition dumps, and losslessly un-mangle CRLF-corrupted backups that nearly cost the user their data).

These are **offline file operations only** — no device or network I/O.

## Scope

A single new top-level tab **`🔪 Dump Surgeon`** containing an inner `QTabWidget` with four tools, backed by one pure-Python logic class `MtkDumpTools`. No new dependencies (stdlib only: `struct`, `hashlib`, `os`). Does not modify existing extractor logic.

## Component 1 — `MtkDumpTools` (logic, no Qt)

Placed alongside the other self-contained extractor classes (near `AndroidImageExtractor`). All methods are static/pure and operate on `bytes`/`bytearray`, returning data + a structured report. No GUI imports.

### `trim_partition(data: bytes, target_size: int | None = None) -> (bytes, dict)`
- If `target_size` given: return `data[:target_size]` (and warn if it would cut non-padding bytes).
- Else auto-detect: find the last byte that is not `0x00` and not `0xFF`; trim trailing padding, rounded **up** to the next 512-byte sector boundary. Never trims into real content.
- Report: original size, trimmed size, bytes removed, padding byte detected, whether a sector boundary was applied.

### `build_emi(data: bytes) -> (bytes | None, dict)`
- Find `MTK_BLOADER_INFO_v` (bloader string). Read the 2-char version that follows.
- Locate the EMI length field: the first offset `P` after the bloader where `uint32_le(data[P:P+4]) == P - bloader_offset`. EMI block = `data[bloader_offset:P]`.
- Validate it parses via mtkclient's `idx==0` path (block starts with the bloader string).
- Report: bloader version, block length, DRAM-config ID (eMMC CID near bloader if present), validation pass/fail. Returns `None` block on failure with a clear reason.

### `unmangle_crlf(data: bytes) -> (bytes, dict)`
- Detect: count `0x0a` and `\r\n` pairs in a sample; flag mangled when (nearly) every `0x0a` is preceded by `0x0d` AND/OR size is odd / not 512-aligned.
- Reverse losslessly: `data.replace(b"\x0d\x0a", b"\x0a")` (proven equivalent to "remove one CR before each LF").
- Report: detected mangled (bool + confidence), bytes removed, before/after size, before/after 512-alignment.

### `inspect_dump(data: bytes) -> dict`
- Size + 512/4K alignment; leading magic (`EMMC_BOOT`, GFH `MMM\x01\x38…`, `FILE_INFO`); `MTK_BLOADER_INFO_v` version; device ID + DRAM-config ID strings if present; EMI presence (via `build_emi`); trailing footer/padding; **all-zero (wiped) detection**; sha256.
- Verdict: one of `clean` / `oversized (has footer/padding)` / `crlf-mangled` / `wiped (all zeros)` / `unknown`, with a one-line human summary.

## Component 2 — UI (`create_dump_surgeon_tab`, in `ImageAnarchyGUI`)

- One top-level tab added via `self.tab_widget.addTab(dump_surgeon_tab, "🔪 Dump Surgeon")`, following the existing tab pattern.
- Inner `QTabWidget` with 4 sub-tabs (Trim, EMI Builder, Un-mangle, Inspector).
- Each sub-tab: input-file picker (`QFileDialog`, reuse `_browse_*` style), tool-specific options (e.g. optional target-size field for Trim), an output-file picker where applicable, a **Run** button, and a shared read-only report pane (`QTextEdit`) styled like the existing `log_output`.
- Reuses the app stylesheet; buttons registered as `self.dsurg_*_btn` and polished in `_apply_styles`.

## Component 3 — Threading

- **Inline** (instant): `build_emi`, `inspect_dump` — operate on file or a bounded read.
- **Worker `QThread`** (large files, e.g. multi-GB userdata): `unmangle_crlf`, `trim_partition`. Emit progress + result via `pyqtSignal` (never touch UI from the worker, per CLAUDE.md). Report pane updates on the `result` signal; a `QProgressBar` reflects progress.

## Error handling

- Validate file exists/readable before running; guard parse failures and show a clear themed message rather than raising.
- `build_emi` failure → explain why (no bloader string / no length field).
- Trim with explicit size larger than file or that would cut content → warn and require confirm.
- Never overwrite the input file silently; default output name suggests a suffix (`_trimmed`, `_emi`, `_recovered`).

## Testing

- `MtkDumpTools` is pure logic → unit tests with both synthetic fixtures and real ground-truth: the mangled preloader backup vs the clean live dump (un-mangle must reproduce it byte-for-byte), and a known preloader for `build_emi` (592-byte v38 block). Wiped/oversized/clean fixtures for `inspect_dump` verdicts.

## Out of scope

- Any device/USB interaction (that's the MTK Toolkit plugin's job).
- Repacking/writing partitions back. Dump Surgeon only reads/repairs/extracts to new files.
