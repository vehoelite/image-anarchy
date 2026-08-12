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


def test_match_pkhash_only_when_hwid_differs(tmp_path):
    # LG G7 One case: device HWID string (JTAG msm_id 0005e0e1) matches no loader's
    # HWID (named with HW_ID1 3002…/0005f0e1), but the signing key (pkhash) matches.
    for n in ["3002000000010000_2cf7619a278d2607_fhprg.bin",
              "0005f0e100310000_2cf7619a278d2607_fhprg.bin",
              "001b80e102e80000_8b2d1c830d9d8576_fhprg.bin"]:
        (tmp_path / n).write_text("ELF")
    loaders = lm.index_loaders([str(tmp_path)])
    ranked = lm.match(loaders, "0005e0e100310000", "2cf7619a278d2607aaaa")
    assert len(ranked) == 2  # both same-key loaders surface (previously: zero → "no loader")
    assert all(x["pkhash"] == "2cf7619a278d2607" for x in ranked)
    assert all("8b2d1c83" not in x["pkhash"] for x in ranked)  # different key excluded


def test_match_tier_order_exact_before_pkhash(tmp_path):
    for n in ["0005e0e100310000_2cf7619a278d2607_fhprg.bin",   # exact hwid+pk
              "3002000000010000_2cf7619a278d2607_fhprg.bin"]:   # pkhash only
        (tmp_path / n).write_text("ELF")
    loaders = lm.index_loaders([str(tmp_path)])
    ranked = lm.match(loaders, "0005e0e100310000", "2cf7619a278d2607")
    assert ranked[0]["hwid"] == "0005e0e100310000"  # exact ranked first
    assert len(ranked) == 2


def test_match_none_when_neither_hwid_nor_pkhash(tmp_path):
    (tmp_path / "3002000000010000_2cf7619a278d2607_fhprg.bin").write_text("ELF")
    loaders = lm.index_loaders([str(tmp_path)])
    assert lm.match(loaders, "999999999999", "deadbeefdeadbeef") == []


def test_import_byo(tmp_path):
    src = tmp_path / "myloader.elf"
    src.write_text("ELF")
    dest_dir = tmp_path / "loaders"
    out = lm.import_byo(str(src), str(dest_dir))
    assert out.endswith("myloader.elf")
    assert (dest_dir / "myloader.elf").read_text() == "ELF"
