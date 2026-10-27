"""MSBuild / コンパイラーの所在検出。実行はせず、存在と由来だけを記録する。"""

from __future__ import annotations

import glob
import os

from . import is_windows
from .tools import dedupe, existing, path_candidates


def known_msbuild_locations() -> list[str]:
    """Visual Studio / Build Tools の標準位置（Windows のみ）。"""
    if not is_windows():
        return []
    roots = [os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
             os.environ.get("ProgramFiles", r"C:\Program Files")]
    cands: list[str] = []
    for root in roots:
        for pattern in (("Microsoft Visual Studio", "*", "*", "MSBuild", "Current", "Bin", "MSBuild.exe"),
                        ("Microsoft Visual Studio", "*", "*", "MSBuild", "Current", "Bin", "amd64",
                         "MSBuild.exe"),
                        ("MSBuild", "*", "Bin", "MSBuild.exe")):
            cands += sorted(glob.glob(os.path.join(root, *pattern)))
    return existing(cands)


def discover(explicit: str | None) -> list[dict]:
    if explicit:
        return [{"path": os.path.abspath(explicit), "source": "explicit",
                 "exists": os.path.isfile(explicit)}]
    names = ["MSBuild.exe", "msbuild.exe"] if is_windows() else ["msbuild"]
    on_path, _ = path_candidates(names)
    cands = dedupe([(p, "path") for p in on_path] + [(p, "known") for p in known_msbuild_locations()])
    for c in cands:
        c["exists"] = True
    return cands
