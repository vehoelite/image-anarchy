from plugins.qualcomm_edl_toolkit import driver_manager as dm


def test_parse_present_winusb():
    lines = ["OK|WinUSB|USB\\VID_05C6&PID_9008\\9&abc&0&1"]
    st = dm.parse_9008_state(lines)
    assert st["present"] and st["winusb"]
    assert st["instance_id"].endswith("0&1")


def test_parse_present_not_winusb():
    lines = ["OK|usbser|USB\\VID_05C6&PID_9008\\9&abc&0&1"]
    st = dm.parse_9008_state(lines)
    assert st["present"] and not st["winusb"]


def test_parse_absent():
    st = dm.parse_9008_state(["OK|WinUSB|USB\\VID_1234&PID_5678\\x"])
    assert not st["present"] and st["instance_id"] is None
