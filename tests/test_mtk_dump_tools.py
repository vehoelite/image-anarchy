import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mtk_dump_tools import MtkDumpTools


class TestUnmangleCrlf(unittest.TestCase):
    def test_roundtrip_recovers_original(self):
        original = bytes(range(256)) * 400  # contains many 0x0a bytes
        mangled = original.replace(b"\x0a", b"\x0d\x0a")  # insert CR before each LF
        recovered, rep = MtkDumpTools.unmangle_crlf(mangled)
        self.assertEqual(recovered, original)
        self.assertTrue(rep["mangled"])
        self.assertEqual(rep["bytes_removed"], original.count(b"\x0a"))
        self.assertEqual(rep["size_after"], len(original))

    def test_clean_binary_not_flagged(self):
        clean = bytes([0xAB, 0xCD] * 5000)  # no 0x0a at all
        recovered, rep = MtkDumpTools.unmangle_crlf(clean)
        self.assertEqual(recovered, clean)
        self.assertFalse(rep["mangled"])
        self.assertEqual(rep["bytes_removed"], 0)


class TestTrimPartition(unittest.TestCase):
    def test_auto_strips_padding_to_sector(self):
        data = b"REALDATA" + b"\xff" * 2000  # 8 + 2000 = 2008 bytes
        trimmed, rep = MtkDumpTools.trim_partition(data)
        self.assertEqual(rep["mode"], "auto")
        self.assertEqual(rep["content_end"], 8)
        self.assertEqual(len(trimmed), 512)          # 8 rounded up to next 512
        self.assertTrue(rep["sector_aligned"])
        self.assertEqual(trimmed[:8], b"REALDATA")

    def test_explicit_size_flags_content_cut(self):
        data = b"ABCD" + b"\xff" * 4
        trimmed, rep = MtkDumpTools.trim_partition(data, target_size=4)
        self.assertEqual(trimmed, b"ABCD")
        self.assertFalse(rep["cut_real_content"])
        trimmed2, rep2 = MtkDumpTools.trim_partition(b"ABCDEF", target_size=3)
        self.assertEqual(trimmed2, b"ABC")
        self.assertTrue(rep2["cut_real_content"])


import struct

def _make_preloader(version=b"38", emi_len=600, pre=64):
    head = b"MTK_BLOADER_INFO_v" + version + b"\x00\x00"
    block = head + b"\xAA" * (emi_len - len(head))     # payload won't collide with length value
    assert len(block) == emi_len
    return b"\x00" * pre + block + struct.pack("<I", emi_len) + b"\x00" * 32

class TestBuildEmi(unittest.TestCase):
    def test_extracts_block_and_version(self):
        data = _make_preloader(emi_len=600, pre=64)
        emi, rep = MtkDumpTools.build_emi(data)
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["version"], "38")
        self.assertEqual(rep["emi_length"], 600)
        self.assertTrue(rep["parses"])
        self.assertTrue(emi.startswith(b"MTK_BLOADER_INFO_v38"))

    def test_no_marker_returns_none(self):
        emi, rep = MtkDumpTools.build_emi(b"\x00" * 4096)
        self.assertIsNone(emi)
        self.assertFalse(rep["ok"])


class TestInspectDump(unittest.TestCase):
    def test_wiped_detected(self):
        rep = MtkDumpTools.inspect_dump(b"\x00" * 4096)
        self.assertTrue(rep["all_zero"])
        self.assertEqual(rep["verdict"], "wiped (all zeros)")

    def test_mangled_detected(self):
        original = bytes(range(256)) * 400
        mangled = original.replace(b"\x0a", b"\x0d\x0a")
        rep = MtkDumpTools.inspect_dump(mangled)
        self.assertTrue(rep["crlf_mangled"])
        self.assertEqual(rep["verdict"], "crlf-mangled")

    def test_clean_preloader_reports_emi(self):
        data = _make_preloader(emi_len=600, pre=64)
        # pad to a 512 boundary so it isn't flagged oversized/odd
        data = data + b"\xff" * (512 - (len(data) % 512))
        rep = MtkDumpTools.inspect_dump(data)
        self.assertTrue(rep["has_emi"])
        self.assertEqual(rep["bloader_version"], "38")
        self.assertFalse(rep["crlf_mangled"])


if __name__ == "__main__":
    unittest.main()
