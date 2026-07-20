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


# INSTALLFLAG_FORCE — makes UpdateDriverForPlugAndPlayDevicesW replace an
# already-bound, higher-ranked (WHQL-signed) driver with our unsigned WinUSB inf.
# Plain `pnputil /add-driver /install` only STAGES the inf; the signed qcusbser
# (oem*.inf) driver still wins on rank, so the device never actually switches.
# This is the same force-install Zadig/libwdi perform, via newdev.dll directly.
_FORCE_BIND_PS = r"""
$ErrorActionPreference = 'Stop'
$src = @'
using System;
using System.Runtime.InteropServices;
public static class IAForceDrv {
    [DllImport("newdev.dll", CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
    public static extern bool UpdateDriverForPlugAndPlayDevicesW(
        IntPtr hwnd, string hwid, string inf, uint flags, out bool reboot);
    public static int Bind(string hwid, string inf) {
        bool rb;
        bool ok = UpdateDriverForPlugAndPlayDevicesW(IntPtr.Zero, hwid, inf, 0x1, out rb);
        if (!ok) return Marshal.GetLastWin32Error();
        return 0;
    }
}
'@
Add-Type -TypeDefinition $src -Language CSharp | Out-Null
exit ([IAForceDrv]::Bind('USB\VID_05C6&PID_9008', %INF%))
"""


def force_bind(inf_path: str):
    """Force our WinUSB inf onto the 9008 device via newdev.dll
    UpdateDriverForPlugAndPlayDevicesW (INSTALLFLAG_FORCE) — overrides the
    signed qcusbser driver that plain pnputil cannot. Returns (rc, output);
    rc 0 = success, 259 = no matching device present."""
    if os.name != "nt":
        return (1, "force bind is Windows-only")
    script = _FORCE_BIND_PS.replace("%INF%", "'" + inf_path.replace("'", "''") + "'")
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=90,
        )
        return (r.returncode, (r.stdout + r.stderr).strip())
    except Exception as e:
        return (1, str(e))


def bind_winusb(instance_id: str):
    """Bind WinUSB to the 9008 interface using the bundled inf.
    Returns (ok, message). Windows only. Requires the bundled winusb inf in plugin_dir()."""
    if os.name != "nt":
        return (False, "WinUSB bind is Windows-only")
    st = is_ready()
    if st["present"] and st["winusb"]:
        return (True, "already bound to WinUSB")
    inf = os.path.join(edl_paths.plugin_dir(), "drivers", "winusb_9008.inf")
    if not os.path.isfile(inf):
        return (False, "Bundled WinUSB inf not found (drivers/winusb_9008.inf)")
    # Stage the inf in the driver store first (trusts the cert once enforcement is
    # off), then FORCE it onto the device to beat the signed qcusbser driver on rank.
    try:
        subprocess.run(
            ["pnputil", "/add-driver", inf, "/install"],
            capture_output=True, text=True, timeout=60,
        )
    except Exception:
        pass  # staging is best-effort; the force bind below does the real work
    rc, out = force_bind(inf)
    st2 = is_ready()
    if st2["present"] and st2["winusb"]:
        return (True, "WinUSB force-bound ✅")
    if rc == 259:  # ERROR_NO_MORE_ITEMS — no matching device on the bus
        return (False, "No 9008 device on the bus to bind (enter EDL first)")
    low = (out or "").lower()
    if "digital signature" in low or "publisher" in low or "signature" in low:
        return (False,
                "Windows blocked the unsigned WinUSB driver. Disable driver-signature "
                "enforcement (Image Anarchy's startup dialog explains how) and try again.")
    return (False, out or f"force bind failed (rc={rc})")
