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
