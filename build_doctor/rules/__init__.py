"""Rule は Fact を判定して Finding にするだけで、OS コマンドは実行しない。"""

import os
import shlex
import subprocess
import sys


def format_command(argv: list[str]) -> str:
    """表示専用。実行中の OS に合わせて引用する。"""
    if sys.platform == "win32":
        return subprocess.list2cmdline(argv)
    return " ".join(shlex.quote(a) for a in argv)


def path_arg(path: str | None, placeholder: str = "<PROJECT>") -> str:
    return path if path else placeholder


def short(path: str) -> str:
    return os.path.basename(path)
