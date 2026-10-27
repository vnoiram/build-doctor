"""PowerShell ホストの検出と、補助スクリプト経由の情報取得・構文解析。"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from importlib import resources

from .. import runner
from . import is_windows
from .tools import dedupe, known_powershell_locations, path_candidates

HELPER_RESOURCE = (
    "helpers",
    "inspect_ps.ps1",
)  # zipapp 内でも読めるよう resources 経由
MAX_ENCODED_COMMAND = 30000  # Windows のコマンドライン上限を考慮


def discover(explicit: str | None) -> list[dict]:
    if explicit:
        return [{"path": os.path.abspath(explicit), "source": "explicit"}]
    names = ["pwsh.exe", "powershell.exe"] if is_windows() else ["pwsh"]
    on_path, _ = path_candidates(names)
    return dedupe(
        [(p, "path") for p in on_path]
        + [(p, "known") for p in known_powershell_locations()]
    )


def helper_source() -> str:
    return resources.files("build_doctor").joinpath(*HELPER_RESOURCE).read_text("utf-8")


def _encoded_helper() -> str:
    src = helper_source()
    enc = base64.b64encode(src.encode("utf-16-le")).decode("ascii")
    if len(enc) > MAX_ENCODED_COMMAND:
        raise RuntimeError("補助スクリプトが大きすぎる")
    return enc


def invoke(
    host: str, request: dict, timeout: float, max_bytes: int
) -> tuple[dict | None, dict]:
    """固定の補助スクリプトを起動する。対象パスは stdin の JSON(base64) で渡し、コード文字列に混ぜない。"""
    payload = base64.b64encode(json.dumps(request).encode("utf-8"))
    argv = [host, "-NoProfile", "-NonInteractive", "-EncodedCommand", _encoded_helper()]
    res = runner.run(
        argv,
        timeout=timeout,
        max_output_bytes=max_bytes,
        cwd=tempfile.gettempdir(),
        stdin_data=payload,
    )
    meta = {"reason_code": res.reason_code, "exit_code": res.exit_code}
    if res.reason_code:
        return None, meta
    for line in reversed(res.text().splitlines()):
        line = line.strip().lstrip("﻿")
        if line.startswith("{"):
            try:
                return json.loads(line), meta
            except json.JSONDecodeError:
                break
    meta["reason_code"] = "HELPER_FAILED"
    return None, meta
