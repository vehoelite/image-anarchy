"""Small pure helpers for the EDL engine (no PyQt6 — unit-testable)."""

_DROP_MARKERS = (
    "USBError",
    "No such device",
    "Pipe error",
    "Input/Output Error",
    "Timed out",
)


def is_drop_line(line: str) -> bool:
    """True if a line signals the device dropped off the bus / the transfer died.
    Used to stop reading edl.py's otherwise-infinite error stream after a rejected
    (unsigned/wrong-key) loader upload."""
    l = line or ""
    return any(m in l for m in _DROP_MARKERS)
