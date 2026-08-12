"""Put the repo root on sys.path so `plugins.qualcomm_edl_toolkit` imports as a
namespace package during tests."""
import os
import sys

_REPO_ROOT = os.path.dirname(  # image-anarchy/
    os.path.dirname(           # plugins/
        os.path.dirname(       # qualcomm_edl_toolkit/
            os.path.dirname(os.path.abspath(__file__))  # tests/
        )
    )
)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
