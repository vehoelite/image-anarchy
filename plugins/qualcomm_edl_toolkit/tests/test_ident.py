from plugins.qualcomm_edl_toolkit import ident


def test_parse_ok():
    line = ('{"ok":true,"serial":"0x60b4df14","hwid":"001b80e102350305",'
            '"pkhash":"ec15a2914a2b435a","secureboot":true,"error":""}')
    r = ident.parse_ident_json("noise\n" + line + "\nmore")
    assert r["ok"] and r["serial"] == "0x60b4df14"
    assert r["hwid"] == "001b80e102350305"
    assert r["secureboot"] is True


def test_parse_zero_pkhash_not_secureboot():
    line = ('{"ok":true,"serial":"0x1","hwid":"0009b0e100000000",'
            '"pkhash":"0000000000000000","secureboot":false,"error":""}')
    assert ident.parse_ident_json(line)["secureboot"] is False


def test_parse_garbage():
    r = ident.parse_ident_json("no json here")
    assert r["ok"] is False and r["error"]
