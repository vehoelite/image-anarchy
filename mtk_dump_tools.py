"""Dump Surgeon — offline MTK/eMMC dump repair & inspection (pure stdlib, no Qt)."""
import hashlib


class MtkDumpTools:
    BLOADER = b"MTK_BLOADER_INFO_v"

    @staticmethod
    def unmangle_crlf(data):
        data = bytes(data)
        sample = data[: 1 << 20]
        lf = sample.count(b"\x0a")
        crlf = sample.count(b"\x0d\x0a")
        ratio = (crlf / lf) if lf else 0.0
        recovered = data.replace(b"\x0d\x0a", b"\x0a")
        report = {
            "mangled": lf > 0 and ratio >= 0.98,
            "crlf_ratio": round(ratio, 4),
            "bytes_removed": len(data) - len(recovered),
            "size_before": len(data),
            "size_after": len(recovered),
            "aligned_before": len(data) % 512 == 0,
            "aligned_after": len(recovered) % 512 == 0,
        }
        return recovered, report

    @staticmethod
    def trim_partition(data, target_size=None):
        data = bytes(data)
        if target_size is not None:
            trimmed = data[:target_size]
            cut = (target_size < len(data)
                   and any(b not in (0x00, 0xFF) for b in data[target_size:]))
            return trimmed, {
                "mode": "explicit", "size_before": len(data),
                "size_after": len(trimmed), "bytes_removed": len(data) - len(trimmed),
                "cut_real_content": cut,
            }
        last = len(data) - 1
        while last >= 0 and data[last] in (0x00, 0xFF):
            last -= 1
        content_end = last + 1
        sector = 512
        size = ((content_end + sector - 1) // sector) * sector
        size = min(size, len(data))
        trimmed = data[:size]
        pad = data[content_end] if content_end < len(data) else None
        return trimmed, {
            "mode": "auto", "size_before": len(data), "size_after": len(trimmed),
            "bytes_removed": len(data) - len(trimmed), "content_end": content_end,
            "padding_byte": (f"0x{pad:02x}" if pad is not None else None),
            "sector_aligned": len(trimmed) % 512 == 0,
        }
