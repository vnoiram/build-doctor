#!/usr/bin/env python3
"""build_doctor を単一ファイル(.pyz)にまとめる。実行には Python 3.11 以降が必要。

使い方: python3 scripts/build_zipapp.py [出力先(既定 dist/build-doctor.pyz)]
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str]) -> int:
    out = Path(argv[0]) if argv else ROOT / "dist" / "build-doctor.pyz"
    if out.exists():
        sys.stderr.write(f"エラー: 出力先が既に存在する(上書きしない): {out}\n")
        return 2
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp) / "app"
        shutil.copytree(
            ROOT / "build_doctor",
            stage / "build_doctor",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        zipapp.create_archive(
            stage,
            out,
            interpreter="/usr/bin/env python3",
            main="build_doctor.cli:main",
            compressed=True,
        )
    sys.stdout.write(f"{out}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
