"""PowerShell の静的情報。構文解析自体はホストの Parser API に委ね、ここでは #requires のみ読む。"""

from __future__ import annotations

import re

_REQ = re.compile(r"^\s*#requires\s+(?P<rest>.+)$", re.IGNORECASE | re.MULTILINE)


def scan_requires(text: str) -> dict:
    """#requires 行から版・エディション・モジュールを読む（実行しない）。"""
    out: dict = {"version": None, "editions": [], "modules": [], "admin": False}
    for m in _REQ.finditer(text):
        rest = m.group("rest").strip()
        low = rest.lower()
        if low.startswith("-version"):
            out["version"] = rest.split(None, 1)[1].strip() if " " in rest else None
        elif low.startswith("-psedition"):
            out["editions"] += [x.strip() for x in rest.split(None, 1)[1].split(",")]
        elif low.startswith("-modules"):
            out["modules"] += [x.strip().strip("'\"") for x in rest.split(None, 1)[1].split(",")]
        elif low.startswith("-runasadministrator"):
            out["admin"] = True
    return out


def version_tuple(v: str | None) -> tuple[int, ...] | None:
    if not v:
        return None
    m = re.match(r"(\d+(?:\.\d+){0,3})", v.strip())
    return tuple(int(x) for x in m.group(1).split(".")) if m else None
