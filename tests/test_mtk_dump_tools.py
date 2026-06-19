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


if __name__ == "__main__":
    unittest.main()
