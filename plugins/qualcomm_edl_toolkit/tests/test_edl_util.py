from plugins.qualcomm_edl_toolkit import edl_util


def test_is_drop_line_usberror():
    assert edl_util.is_drop_line("DeviceClass - USBError(5, 'Input/Output Error')")


def test_is_drop_line_no_such_device():
    assert edl_util.is_drop_line("No such device (it may have been disconnected)")


def test_is_drop_line_pipe():
    assert edl_util.is_drop_line("USBError(32, 'Pipe error')")


def test_is_drop_line_normal_is_false():
    assert not edl_util.is_drop_line("sahara - Uploading loader moto_g52.bin ...")
    assert not edl_util.is_drop_line("main - Device detected :)")
