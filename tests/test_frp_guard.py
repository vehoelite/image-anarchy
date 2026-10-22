"""Every device toolkit must refuse to erase or overwrite Factory Reset Protection.

See ACCEPTABLE_USE_POLICY.md ("Hard Lines"). Reads/backups stay allowed.
"""
import ast, os, re, shutil, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD_NAMES = {"FRP_PARTITIONS", "FRP_BLOCKED_MSG", "_FRP_ADB_RE", "_is_frp_partition", "_frp_blocked"}


def load_guard(plugin_id: str) -> dict:
    """Pull just the guard constants/functions out of a plugin (no PyQt6 needed)."""
    src = (ROOT / "plugins" / plugin_id / "plugin.py").read_text(encoding="utf-8")
    body = []
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name in GUARD_NAMES:
            body.append(node)
        elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in GUARD_NAMES for t in node.targets):
            body.append(node)
    ns = {"os": os, "re": re}
    exec(compile(ast.Module(body=body, type_ignores=[]), plugin_id, "exec"), ns)
    return ns


class TestFastbootGuard(unittest.TestCase):
    def setUp(self):
        self.blocked = load_guard("fastboot_toolkit")["_frp_blocked"]

    def test_blocks_frp_writes(self):
        for args in (["erase", "frp"], ["flash", "frp_a", "x.img"], ["format", "persistent"],
                     ["--disable-verity", "flash", "config", "x.img"], ["flash:raw", "FRP", "x.img"]):
            with self.subTest(args=args):
                self.assertTrue(self.blocked(args))

    def test_allows_normal_use(self):
        for args in (["flash", "boot", "boot.img"], ["erase", "userdata"], ["getvar", "all"],
                     ["flash", "persist", "persist.img"], ["reboot"]):
            with self.subTest(args=args):
                self.assertFalse(self.blocked(args))


class TestCliGuards(unittest.TestCase):
    """mtkclient and edl.py share the same e/w/wl command shapes."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_mtk_and_edl(self):
        for plugin_id in ("mtk_toolkit", "qualcomm_edl_toolkit"):
            blocked = load_guard(plugin_id)["_frp_blocked"]
            with self.subTest(plugin=plugin_id):
                self.assertTrue(blocked(["e", "frp"]))
                self.assertTrue(blocked(["e", "userdata,frp"]))
                self.assertTrue(blocked(["w", "boot,frp", "boot.img,frp.img"]))
                self.assertTrue(blocked(["w", "persistent", "p.bin"]))
                self.assertFalse(blocked(["r", "frp", "frp.bin"]))  # backups are fine
                self.assertFalse(blocked(["w", "boot", "boot.img"]))
                self.assertFalse(blocked(["e", "cache"]))
                self.assertFalse(blocked(["printgpt"]))

                Path(self.dir, "boot.bin").write_bytes(b"")
                self.assertFalse(blocked(["wl", self.dir]))
                Path(self.dir, "frp.bin").write_bytes(b"")
                self.assertTrue(blocked(["wl", self.dir]))
                os.remove(Path(self.dir, "frp.bin"))


class TestAdbGuard(unittest.TestCase):
    def setUp(self):
        self.blocked = load_guard("adb_toolkit")["_frp_blocked"]

    def test_blocks_shell_bypasses(self):
        for cmd in ("dd if=/sdcard/zero of=/dev/block/by-name/frp",
                    "su -c 'dd if=/dev/zero of=/dev/block/platform/soc/by-name/persistent'",
                    "su -c 'cat x > /dev/block/bootdevice/by-name/config'",
                    "settings put secure user_setup_complete 1",
                    "content insert --uri content://settings/secure --bind name:s:user_setup_complete --bind value:s:1"):
            with self.subTest(cmd=cmd):
                self.assertTrue(self.blocked(["shell", cmd]))

    def test_allows_reads_and_normal_shell(self):
        for cmd in ("su -c 'dd if=/dev/block/by-name/frp of=/sdcard/frp.img'",
                    "getprop ro.frp.pst", "ls /dev/block/by-name", "pm list packages"):
            with self.subTest(cmd=cmd):
                self.assertFalse(self.blocked(["shell", cmd]))


class TestFeaturesRemoved(unittest.TestCase):
    def test_no_frp_erase_or_imei_write_in_mtk(self):
        src = (ROOT / "plugins" / "mtk_toolkit" / "plugin.py").read_text(encoding="utf-8")
        for name in ("def _erase_frp", "def write_imei", "def meta_write_imei_at", "def _write_imei",
                     "'erase_frp'", "'write_imei'", "'meta_write_imei'"):
            with self.subTest(name=name):
                self.assertNotIn(name, src)


if __name__ == "__main__":
    unittest.main()
