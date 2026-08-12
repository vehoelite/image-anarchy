"""Parse the JSON emitted by qedl_ident.py."""
import json
import re

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def _is_zero_hash(pk: str) -> bool:
    pk = (pk or "").replace("0x", "").strip().lower()
    return pk == "" or set(pk) <= {"0"}


def parse_ident_json(text: str) -> dict:
    default = {"ok": False, "serial": "", "hwid": "", "pkhash": "",
               "secureboot": False, "error": ""}
    m = _JSON_RE.search(text or "")
    if not m:
        default["error"] = "no ident JSON in output"
        return default
    try:
        data = json.loads(m.group(0))
    except Exception as e:
        default["error"] = f"bad ident JSON: {e}"
        return default
    out = dict(default)
    out.update({k: data.get(k, default[k]) for k in default})
    if "secureboot" not in data:
        out["secureboot"] = not _is_zero_hash(out["pkhash"])
    return out
