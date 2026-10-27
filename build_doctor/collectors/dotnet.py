"""dotnet / SDK / runtime / .NET Framework の収集。ツールの絶対パスごとに別管理する。"""

from __future__ import annotations

import os
import re
import tempfile

from .. import runner
from . import is_windows, normalize_arch
from .tools import dedupe, known_dotnet_locations, path_candidates

DOTNET_ENV = {
    "DOTNET_NOLOGO": "1",
    "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
    "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
    "DOTNET_CLI_UI_LANGUAGE": "en",
    "MSBUILDDISABLENODEREUSE": "1",
}


def dotnet_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update(DOTNET_ENV)
    return env


def discover(explicit: str | None) -> tuple[list[dict], dict]:
    exe = "dotnet.exe" if is_windows() else "dotnet"
    if explicit:
        return [{"path": os.path.abspath(explicit), "source": "explicit"}], {
            "explicit": True
        }
    on_path, skipped = path_candidates([exe])
    cands = dedupe(
        [(p, "path") for p in on_path]
        + [(p, "known") for p in known_dotnet_locations()]
    )
    for rank, c in enumerate(cands):
        c["path_rank"] = rank
    return cands, {
        "explicit": False,
        "path_entries_ignored": skipped,
        "searched": ["PATH", "DOTNET_ROOT*", "known install locations"],
    }


def parse_sdks(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\S+)\s+\[(.+)\]\s*$", line)
        if m:
            out.append({"version": m.group(1), "path": m.group(2)})
    return out


def parse_runtimes(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\S+)\s+(\S+)\s+\[(.+)\]\s*$", line)
        if m:
            out.append({"name": m.group(1), "version": m.group(2), "path": m.group(3)})
    return out


def query(path: str, timeout: float, max_bytes: int) -> dict:
    """1 つの dotnet について SDK / runtime / アーキテクチャを問い合わせる。"""
    cwd = tempfile.gettempdir()
    info: dict = {"path": path, "errors": []}
    for key, args in (
        ("sdks", ["--list-sdks"]),
        ("runtimes", ["--list-runtimes"]),
        ("info", ["--info"]),
    ):
        res = runner.run(
            [path, *args],
            timeout=timeout,
            max_output_bytes=max_bytes,
            cwd=cwd,
            env=dotnet_env(),
        )
        if res.reason_code or res.exit_code != 0:
            info["errors"].append(
                {
                    "query": key,
                    "reason_code": res.reason_code or "NONZERO_EXIT",
                    "exit_code": res.exit_code,
                }
            )
            continue
        text = res.text()
        if key == "sdks":
            info["sdks"] = parse_sdks(text)
            for sdk in info["sdks"]:
                sdk["has_csc"] = os.path.isfile(
                    os.path.join(
                        sdk["path"], sdk["version"], "Roslyn", "bincore", "csc.dll"
                    )
                )
        elif key == "runtimes":
            info["runtimes"] = parse_runtimes(text)
        else:
            arch = re.search(r"^\s*Architecture:\s*(\S+)", text, re.MULTILINE)
            rid = re.search(r"^\s*RID:\s*(\S+)", text, re.MULTILINE)
            info["architecture"] = normalize_arch(arch.group(1)) if arch else None
            info["rid"] = rid.group(1) if rid else None
    return info


def select_sdk(path: str, workdir: str, timeout: float, max_bytes: int) -> dict:
    """作業ディレクトリで実際に選択される SDK（global.json を反映）。"""
    res = runner.run(
        [path, "--version"],
        timeout=timeout,
        max_output_bytes=max_bytes,
        cwd=workdir,
        env=dotnet_env(),
    )
    if res.reason_code:
        return {"selected": None, "reason_code": res.reason_code}
    if res.exit_code != 0:
        return {
            "selected": None,
            "reason_code": "SDK_NOT_RESOLVED",
            "exit_code": res.exit_code,
        }
    return {
        "selected": res.text().strip().splitlines()[0] if res.text().strip() else None
    }


def tfm_major(tfm: str) -> int | None:
    """net8.0 → 8, netcoreapp3.1 → 3, net472 → None（SDK 世代とは無関係）。"""
    m = re.match(r"net(\d+)\.\d+", tfm.lower())
    if m:
        return int(m.group(1))
    m = re.match(r"netcoreapp(\d+)\.\d+", tfm.lower())
    return int(m.group(1)) if m else None


def sdk_major(version: str | None) -> int | None:
    m = re.match(r"(\d+)\.", version or "")
    return int(m.group(1)) if m else None


NETFX_RELEASES = (
    (533320, "4.8.1"),
    (528040, "4.8"),
    (461808, "4.7.2"),
    (461308, "4.7.1"),
    (460798, "4.7"),
    (394802, "4.6.2"),
    (394254, "4.6.1"),
    (393295, "4.6"),
    (379893, "4.5.2"),
    (378675, "4.5.1"),
    (378389, "4.5"),
)


def netfx_version(release: int | None) -> str | None:
    """Release レジストリ値 → 実行用 Framework のバージョン。"""
    if release is None:
        return None
    return next((v for r, v in NETFX_RELEASES if release >= r), None)


def framework_compilers() -> list[str]:
    """Framework ディレクトリ内の csc.exe。SDK 内のコンパイラーとは別物。"""
    win = os.environ.get("SystemRoot", r"C:\Windows")
    cands = [
        os.path.join(win, "Microsoft.NET", d, "v4.0.30319", "csc.exe")
        for d in ("Framework64", "Framework")
    ]
    return [c for c in cands if os.path.isfile(c)]


def netframework_installs() -> dict | None:
    """Windows のみ。32/64bit レジストリビューを別々に照会する。"""
    if not is_windows():
        return None
    import winreg  # type: ignore[import-not-found]

    out: dict = {"views": {}}
    for label, flag in (
        ("x64", winreg.KEY_WOW64_64KEY),
        ("x86", winreg.KEY_WOW64_32KEY),
    ):
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full",
                0,
                winreg.KEY_READ | flag,
            ) as k:
                release, _ = winreg.QueryValueEx(k, "Release")
                out["views"][label] = {
                    "release": int(release),
                    "version": netfx_version(int(release)),
                }
        except OSError as e:
            out["views"][label] = {
                "release": None,
                "reason_code": "ACCESS_DENIED"
                if isinstance(e, PermissionError)
                else "NOT_FOUND",
            }
    base = os.path.join(
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        "Reference Assemblies",
        "Microsoft",
        "Framework",
        ".NETFramework",
    )
    out["compilers"] = framework_compilers()
    out["reference_assemblies_dir"] = base
    out["targeting_packs"] = sorted(os.listdir(base)) if os.path.isdir(base) else []
    return out
