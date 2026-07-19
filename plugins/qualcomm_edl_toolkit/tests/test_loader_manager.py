from plugins.qualcomm_edl_toolkit import loader_manager as lm


def test_parse_loader_name_valid():
    r = lm.parse_loader_name("001b80e102e80000_8b2d1c830d9d8576_fhprg.bin")
    assert r["hwid"] == "001b80e102e80000"
    assert r["pkhash"] == "8b2d1c830d9d8576"


def test_parse_loader_name_invalid():
    assert lm.parse_loader_name("prog_firehose_ddr.elf") is None


def test_index_and_match(tmp_path):
    for n in ["001b80e102e80000_8b2d1c830d9d8576_fhprg.bin",
              "001b80e100000000_503b13f78c1e5374_fhprg.bin",
              "0009b0e100000000_deadbeef00000000_fhprg.bin"]:
        (tmp_path / n).write_text("ELF")
    loaders = lm.index_loaders([str(tmp_path)])
    assert len(loaders) == 3
    # exact hwid+pkhash beats hwid-only
    ranked = lm.match(loaders, "001b80e102e80000", "8b2d1c830d9d8576ffff")
    assert ranked[0]["pkhash"] == "8b2d1c830d9d8576"
    # hwid-only matches when pkhash differs
    ranked2 = lm.match(loaders, "001b80e102e80000", "ec15a2914a2b435a")
    assert all(x["hwid"] == "001b80e102e80000" for x in ranked2)
    assert len(ranked2) == 1


def test_import_byo(tmp_path):
    src = tmp_path / "myloader.elf"
    src.write_text("ELF")
    dest_dir = tmp_path / "loaders"
    out = lm.import_byo(str(src), str(dest_dir))
    assert out.endswith("myloader.elf")
    assert (dest_dir / "myloader.elf").read_text() == "ELF"
