"""Linux/macOS must never resolve to Windows binaries left by Plugin Store zips.

Store zips are built on Windows and contain adb.exe, fastboot.exe, scrcpy.exe.
The plugin finders must skip them and use the native tools on PATH instead,
otherwise users get "Permission denied" trying to run a .exe.
"""
import ast, os, shutil, sys, tempfile, unittest
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parent.parent

# Finder functions (and the helpers they call) pulled out of each plugin, so
# the test doesn't need PyQt6 installed.
HELPERS = {"_is_runnable", "_exe_names", "get_plugin_dir", "get_base_path"}
FINDERS = {
    "adb_toolkit": ["find_adb"],
    "fastboot_toolkit": ["find_fastboot", "find_adb"],
    "iaabs": ["find_adb"],
    "root_patcher": ["find_adb", "find_fastboot"],
    "scrcpy_toolkit": ["find_adb_toolkit_path", "find_scrcpy_path"],
}

# What a Windows-built store zip leaves behind (no execute bit)
STORE_LEFTOVERS = [
    "adb_toolkit/adb.exe", "adb_toolkit/platform-tools/adb.exe",
    "fastboot_toolkit/fastboot.exe", "fastboot_toolkit/adb.exe",
    "root_patcher/adb.exe", "root_patcher/fastboot.exe",
    "scrcpy_toolkit/adb.exe", "scrcpy_toolkit/scrcpy.exe",
]


def load_finders(plugin_id: str, fake_root: Path) -> dict:
    src = (ROOT / "plugins" / plugin_id / "plugin.py").read_text(encoding="utf-8")
    wanted = HELPERS | set(FINDERS[plugin_id])
    body = [n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    ns = {"os": os, "sys": sys, "shutil": shutil, "Optional": Optional, "List": List, "Path": Path,
          "__file__": str(fake_root / "plugins" / plugin_id / "plugin.py")}
    exec(compile(ast.Module(body=body, type_ignores=[]), plugin_id, "exec"), ns)
    if "get_base_path" in ns:
        ns["get_base_path"] = lambda: fake_root
    return ns


@unittest.skipIf(os.name == "nt", "execute-bit semantics are POSIX-only")
class TestFindersSkipWindowsBinaries(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        for pid in FINDERS:
            (self.root / "plugins" / pid / "platform-tools").mkdir(parents=True)
        for rel in STORE_LEFTOVERS:
            (self.root / "plugins" / rel).write_bytes(b"MZ")
        self.bindir = self.root / "bin"
        self.bindir.mkdir()
        for tool in ("adb", "fastboot", "scrcpy"):
            p = self.bindir / tool
            p.write_text("#!/bin/sh\n")
            p.chmod(0o755)
        self._old_path = os.environ["PATH"]
        os.environ["PATH"] = f"{self.bindir}{os.pathsep}{self._old_path}"

    def tearDown(self):
        os.environ["PATH"] = self._old_path
        shutil.rmtree(self.root)

    def test_finders_return_native_tools(self):
        for pid, funcs in FINDERS.items():
            ns = load_finders(pid, self.root)
            for fn in funcs:
                with self.subTest(finder=f"{pid}.{fn}"):
                    found = ns[fn]()
                    self.assertIsNotNone(found)
                    self.assertEqual(Path(found).parent, self.bindir)

    def test_bundled_native_binary_still_preferred(self):
        native = self.root / "plugins" / "fastboot_toolkit" / "fastboot"
        native.write_text("#!/bin/sh\n")
        native.chmod(0o755)
        ns = load_finders("fastboot_toolkit", self.root)
        self.assertEqual(ns["find_fastboot"](), str(native))


if __name__ == "__main__":
    unittest.main()
