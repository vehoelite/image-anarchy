import os
from plugins.qualcomm_edl_toolkit import edl_paths


def test_plugin_dir_is_this_package():
    d = edl_paths.plugin_dir()
    assert os.path.isdir(d)
    assert d.endswith("qualcomm_edl_toolkit")


def test_get_edl_dir_prefers_plugin_edl(monkeypatch, tmp_path):
    fake_plugin = tmp_path / "qualcomm_edl_toolkit"
    (fake_plugin / "edl").mkdir(parents=True)
    (fake_plugin / "edl" / "edl.py").write_text("# edl")
    monkeypatch.setattr(edl_paths, "plugin_dir", lambda: str(fake_plugin))
    assert edl_paths.get_edl_dir() == str(fake_plugin / "edl")


def test_get_adb_prefers_bundled(monkeypatch, tmp_path):
    fake_plugin = tmp_path / "qualcomm_edl_toolkit"
    fake_plugin.mkdir(parents=True)
    (fake_plugin / edl_paths._ADB_NAME).write_text("x")
    monkeypatch.setattr(edl_paths, "plugin_dir", lambda: str(fake_plugin))
    assert edl_paths.get_adb() == str(fake_plugin / edl_paths._ADB_NAME)
