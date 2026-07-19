"""Windows WinUSB detection + bind for the Qualcomm 9008 interface."""
import os
import subprocess

# Sibling import works both as a package (tests) and as a top-level module
# (Image Anarchy loads plugin.py via spec_from_file_location, not as a package).
try:
    from . import edl_paths
except ImportError:  # pragma: no cover - runtime top-level context
    import edl_paths

VID_PID = "VID_05C6&PID_9008"
_PS_QUERY = (
    "Get-PnpDevice -PresentOnly | "
    "Where-Object { $_.InstanceId -match 'VID_05C6&PID_9008' } | "
    "ForEach-Object { "
    "$svc = ($_ | Get-PnpDeviceProperty -KeyName 'DEVPKEY_Device_Service').Data; "
    "\"$($_.Status)|$svc|$($_.InstanceId)\" }"
)


def parse_9008_state(pnp_lines):
    for raw in pnp_lines:
        line = (raw or "").strip()
        if VID_PID not in line:
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        status, service, instance_id = parts[0], parts[1], parts[2]
        return {
            "present": True,
            "winusb": service.strip().lower() == "winusb",
            "instance_id": instance_id.strip(),
        }
    return {"present": False, "winusb": False, "instance_id": None}


def is_ready():
    if os.name != "nt":
        return {"present": False, "winusb": False, "instance_id": None}
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", _PS_QUERY],
            capture_output=True, text=True, timeout=20,
        )
        return parse_9008_state(out.stdout.splitlines())
    except Exception:
        return {"present": False, "winusb": False, "instance_id": None}


def bind_winusb(instance_id: str):
    """Bind WinUSB to the 9008 interface using the bundled inf via pnputil.
    Returns (ok, message). Windows only. Requires the bundled winusb inf in plugin_dir()."""
    if os.name != "nt":
        return (False, "WinUSB bind is Windows-only")
    st = is_ready()
    if st["present"] and st["winusb"]:
        return (True, "already bound to WinUSB")
    inf = os.path.join(edl_paths.plugin_dir(), "drivers", "winusb_9008.inf")
    if not os.path.isfile(inf):
        return (False, "Bundled WinUSB inf not found (drivers/winusb_9008.inf)")
    try:
        r = subprocess.run(
            ["pnputil", "/add-driver", inf, "/install"],
            capture_output=True, text=True, timeout=60,
        )
        out = (r.stdout + r.stderr)
        if "Added driver packages:  1" in out or "Driver package added" in out:
            return (True, "WinUSB installed — replug the device if it doesn't switch")
        if "digital signature" in out.lower() or "signature" in out.lower():
            return (False,
                    "Windows rejected the unsigned WinUSB inf. Use Zadig (or the bundled "
                    "libwdi installer) to set WinUSB on 'VID_05C6&PID_9008', or plug the "
                    "device into the USB port you previously bound.")
        return (False, out.strip() or "pnputil failed")
    except Exception as e:
        return (False, str(e))
