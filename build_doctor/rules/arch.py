"""32/64bit・CPU 不一致の Rule。OS / プロセス / 成果物 / ネイティブ依存を独立して比較する。"""

from __future__ import annotations

import sys

from ..models import Report

CPU_ARCHES = {"x86", "x64", "arm64", "arm"}


def describe(info: dict) -> str:
    arch = info["arch"]
    if info.get("kind") == "managed":
        extra = "mixed-mode" if info.get("mixed_mode") else "IL"
        return f"{arch} ({info['pe_format']}, 管理アセンブリ/{extra})"
    return f"{arch} ({info['format']}, ネイティブ)"


def evaluate_binary(
    report: Report,
    fact_id: str,
    name: str,
    info: dict,
    host_arch: str | None,
    native_deps: list[tuple[str, str, dict]],
) -> None:
    """native_deps: (fact_id, 名前, 解析結果)"""
    arch = info["arch"]
    if host_arch:
        if arch in CPU_ARCHES and arch != host_arch:
            kind = (
                "プロセス内ロード"
                if info.get("is_dll", True) or info["format"] == "ELF"
                else "起動"
            )
            report.add_finding(
                "ARCH001",
                "CONFIRMED",
                "error",
                f"指定された {host_arch} ホストと {arch} 専用の {name} が不一致",
                evidence=[fact_id],
                meaning=f"{kind}する場合に CPU 要件が合わない。{describe(info)} は {host_arch} プロセスでは扱えない。",
                limit="実際のロードは実行していない。ホストは利用者の指定条件(--host-arch)。",
                next_steps=[
                    f"{arch} ホスト(プロセス)から利用できるか確認する",
                    f"または {host_arch} 向けに再ビルド/入手した成果物に差し替える",
                ],
            )
        elif arch == "anycpu-prefer32" and info.get("is_dll") is False:
            report.add_finding(
                "ARCH001",
                "CANDIDATE",
                "info",
                f"{name} は Prefer32Bit のため {host_arch} OS でも 32bit プロセスで起動し得る",
                evidence=[fact_id],
                meaning="AnyCPU(32BITPREF)の EXE は、対応 runtime では 32bit で起動する場合がある。",
                limit="実際の起動ホストと runtime により結果が変わる。",
                next_steps=[
                    "64bit ネイティブ依存を読み込むなら Prefer32Bit の設定を確認する"
                ],
            )
    for dep_id, dep_name, dep in native_deps:
        want = host_arch or (arch if arch in CPU_ARCHES else None)
        if want and dep["arch"] in CPU_ARCHES and dep["arch"] != want:
            report.add_finding(
                "ARCH002",
                "CONFIRMED",
                "error",
                f"ネイティブ依存 {dep_name}({dep['arch']}) が {want} 側と不一致",
                evidence=[fact_id, dep_id],
                meaning=(
                    "AnyCPU 自体の問題ではなく、ネイティブ境界の CPU 不一致。"
                    if arch.startswith("anycpu")
                    else "同一プロセスにロードできない組み合わせ。"
                ),
                limit="依存関係は利用者が明示したものだけを照合している。ローダーの探索パスは未評価。",
                next_steps=[
                    f"{want} 向けのネイティブ依存に揃える、または実行プロセスを {dep['arch']} に揃える"
                ],
            )


def evaluate_os(report: Report, fact_id: str, name: str, info: dict) -> None:
    """ファイル形式と、この OS 上での実行可否は別項目。"""
    on_windows = sys.platform == "win32"
    if info["format"] == "PE" and not info.get("managed") and not on_windows:
        report.add_finding(
            "OS001",
            "CONFIRMED",
            "info",
            f"{name} は Windows 用のネイティブ PE",
            evidence=[fact_id],
            meaning="この OS では直接ロード・実行できない形式。ファイル情報のみ報告する。",
            limit="Wine 等の互換層は評価していない。",
            next_steps=[],
        )
    elif info["format"] == "ELF" and on_windows:
        report.add_finding(
            "OS001",
            "CONFIRMED",
            "info",
            f"{name} は Linux 用の ELF",
            evidence=[fact_id],
            meaning="この OS では直接ロード・実行できない形式。ファイル情報のみ報告する。",
            limit="WSL 等は評価していない。",
            next_steps=[],
        )
