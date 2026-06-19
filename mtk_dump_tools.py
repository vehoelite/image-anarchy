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

    @staticmethod
    def build_emi(data):
        data = bytes(data)
        bld = MtkDumpTools.BLOADER
        b = data.find(bld)
        if b == -1:
            return None, {"ok": False, "reason": "no MTK_BLOADER_INFO_v marker found"}
        ver = data[b + len(bld): b + len(bld) + 2].rstrip(b"\x00").decode("latin1", "replace")
        found = None
        for p in range(b + 0x200, min(b + 0x4000, len(data) - 4)):
            if int.from_bytes(data[p:p + 4], "little") == (p - b):
                found = p
                break
        if found is None:
            return None, {"ok": False, "reason": "no EMI length field found after marker", "version": ver}
        block = data[b:found]
        return block, {
            "ok": True, "version": ver, "emi_offset": b, "emi_length": len(block),
            "length_field_offset": found, "parses": block.startswith(bld),
        }

    @staticmethod
    def inspect_dump(data):
        data = bytes(data)
        n = len(data)
        nz = n - data.count(0)
        rep = {
            "size": n, "aligned_512": n % 512 == 0, "aligned_4k": n % 4096 == 0,
            "all_zero": nz == 0, "nonzero_bytes": nz,
            "sha256": hashlib.sha256(data).hexdigest(),
            "head_magic": None, "bloader_version": None, "has_emi": False,
            "crlf_mangled": False,
        }
        if data[:9] == b"EMMC_BOOT":
            rep["head_magic"] = "EMMC_BOOT"
        elif data[:4] == b"\x4d\x4d\x4d\x01":
            rep["head_magic"] = "GFH(MMM)"
        elif data[:9] == b"FILE_INFO":
            rep["head_magic"] = "FILE_INFO"
        emi, emi_rep = MtkDumpTools.build_emi(data)
        if emi is not None:
            rep["has_emi"] = True
            rep["bloader_version"] = emi_rep.get("version")
            rep["emi_length"] = emi_rep.get("emi_length")
        _, cr = MtkDumpTools.unmangle_crlf(data)
        rep["crlf_mangled"] = cr["mangled"]
        if rep["all_zero"]:
            verdict = "wiped (all zeros)"
        elif rep["crlf_mangled"]:
            verdict = "crlf-mangled"
        elif not rep["aligned_512"]:
            verdict = "oversized/odd (footer or padding)"
        else:
            verdict = "clean"
        rep["verdict"] = verdict
        rep["summary"] = (
            f"{n} bytes, verdict={verdict}"
            + (f", bloader v{rep['bloader_version']}" if rep["bloader_version"] else "")
        )
        return rep
