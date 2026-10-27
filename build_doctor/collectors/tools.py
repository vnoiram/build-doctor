"""実行ファイルの探索。候補は常に絶対パスで記録し、相対 PATH 要素は無視する。"""

from __future__ import annotations

import os

from . import is_windows


def path_candidates(names: list[str]) -> tuple[list[str], int]:
    """(見つかった絶対パス, 無視した相対/空の PATH 要素数)"""
    found: list[str] = []
    skipped = 0
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            skipped += 1
            continue
        for n in names:
            cand = os.path.join(entry, n)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                found.append(cand)
    return found, skipped


def dedupe(paths: list[tuple[str, str]]) -> list[dict]:
    seen: set[str] = set()
    out = []
    for path, source in paths:
        key = os.path.normcase(os.path.realpath(path))
        if key in seen:
            continue
        seen.add(key)
        out.append({"path": path, "source": source})
    return out


def existing(paths: list[str]) -> list[str]:
    return [p for p in paths if p and os.path.isfile(p) and os.access(p, os.X_OK)]


def known_dotnet_locations() -> list[str]:
    exe = "dotnet.exe" if is_windows() else "dotnet"
    roots = [
        os.environ.get(k) for k in ("DOTNET_ROOT", "DOTNET_ROOT_X64", "DOTNET_ROOT_X86")
    ]
    if is_windows():
        roots += [
            os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "dotnet"),
            os.path.join(
                os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "dotnet"
            ),
        ]
    else:
        roots += [
            "/usr/share/dotnet",
            "/usr/lib/dotnet",
            "/usr/local/share/dotnet",
            os.path.expanduser("~/.dotnet"),
        ]
    return existing([os.path.join(r, exe) for r in roots if r and os.path.isabs(r)])


def known_powershell_locations() -> list[str]:
    if is_windows():
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        win = os.environ.get("SystemRoot", r"C:\Windows")
        cands = [
            os.path.join(pf, "PowerShell", "7", "pwsh.exe"),
            os.path.join(pf86, "PowerShell", "7", "pwsh.exe"),
            os.path.join(
                win, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
            ),
            os.path.join(
                win, "SysWOW64", "WindowsPowerShell", "v1.0", "powershell.exe"
            ),
        ]
    else:
        cands = [
            "/opt/microsoft/powershell/7/pwsh",
            "/usr/bin/pwsh",
            "/usr/local/bin/pwsh",
            os.path.expanduser("~/.dotnet/tools/pwsh"),
        ]
    return existing(cands)
