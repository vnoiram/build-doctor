"""プロジェクトの設定間・参照先・runtime の整合性 Rule。実効値を証明できないものは候補に留める。"""

from __future__ import annotations

import os
import re

from ..collectors.dotnet import sdk_major, tfm_major
from ..models import Report
from ..parsers.project import effective, resolve_reference
from . import format_command

MAX_CSHARP_BY_SDK = {6: 10.0, 7: 11.0, 8: 12.0, 9: 13.0, 10: 14.0}
CPU = {"x86", "x64", "arm64", "arm"}


def _true(v: str | None) -> bool:
    return (v or "").strip().lower() == "true"


def _rid_arch(rid: str) -> str | None:
    last = rid.rsplit("-", 1)[-1].lower()
    return last if last in CPU else None


def evaluate_platform(report: Report, proj: dict, fid: str, host_arch: str | None,
                      runtime: str | None) -> None:
    """PlatformTarget / RID / Prefer32Bit と、想定ホスト・RID の突き合わせ。"""
    props = proj["properties"]
    pt, st = effective(props, "PlatformTarget")
    target = (pt or "").lower()
    rid_value = runtime or effective(props, "RuntimeIdentifier")[0]
    rid_arch = _rid_arch(rid_value) if rid_value else None
    if st == "CONFIGURED" and target in CPU:
        if host_arch and target != host_arch:
            report.add_finding(
                "ARCH003", "CANDIDATE", "warning",
                f"PlatformTarget={pt} は指定ホスト {host_arch} と一致しない",
                evidence=[fid],
                meaning=f"出力は {target} 専用になる設定。{host_arch} プロセスからロードする用途とは合わない候補。",
                limit="条件付き/式を含む実効値は評価していない。ホストは利用者の指定条件。",
                next_steps=["PlatformTarget を AnyCPU にするか、ホストを揃えるか検討する"])
        if rid_arch and rid_arch != target:
            report.add_finding(
                "ARCH003", "CANDIDATE", "warning",
                f"PlatformTarget={pt} と RuntimeIdentifier={rid_value} の CPU が不一致",
                evidence=[fid], meaning="設定同士が矛盾しており、ビルドまたは実行時に不整合となる候補。",
                limit="実効値(条件・Import)は評価していない。",
                next_steps=["PlatformTarget と RuntimeIdentifier のどちらかを揃える"])
    elif rid_arch and host_arch and rid_arch != host_arch:
        report.add_finding(
            "ARCH003", "CANDIDATE", "info",
            f"RuntimeIdentifier={rid_value} は指定ホスト {host_arch} と CPU が異なる",
            evidence=[fid], meaning="クロスビルドの可能性はあるが、成果物はそのホストでは動作しない。",
            limit="ビルド可能性と実行互換性は別。", next_steps=[])
    p32, _ = effective(props, "Prefer32Bit")
    out, _ = effective(props, "OutputType")
    if _true(p32) and host_arch in ("x64", "arm64") and (out or "").lower() in ("exe", "winexe"):
        report.add_finding(
            "ARCH003", "CANDIDATE", "info", "Prefer32Bit=true の EXE は 64bit OS でも 32bit で起動し得る",
            evidence=[fid], meaning="64bit のネイティブ依存を読み込む場合に不一致となる候補。",
            limit="実際の起動ホストと runtime により変わる。", next_steps=["Prefer32Bit の設定を確認する"])


def evaluate_langversion(report: Report, proj: dict, fid: str, selected_sdk: str | None) -> None:
    lang, st = effective(proj["properties"], "LangVersion")
    major = sdk_major(selected_sdk)
    limit_ver = MAX_CSHARP_BY_SDK.get(major) if major else None
    if st != "CONFIGURED" or not lang or limit_ver is None or not re.fullmatch(r"\d+(\.\d+)?", lang):
        return
    if float(lang) > limit_ver:
        report.add_finding(
            "CS003", "CANDIDATE", "warning",
            f"LangVersion={lang} は選択 SDK {selected_sdk} が対応する C# {limit_ver:g} を超える",
            evidence=[fid], meaning="コンパイラーが言語バージョンに対応しない場合、CS1617 などで失敗する候補。",
            limit="SDK 同梱コンパイラーの対応表に基づく目安。他のコンパイラー(analyzer 等)は未評価。",
            next_steps=["LangVersion を下げる、または対応する SDK を使う"])


def evaluate_runtime(report: Report, proj: dict, fid: str, dotnet: dict | None) -> None:
    """EXE を実行するための runtime(ビルド用 SDK とは別資源)。"""
    props = proj["properties"]
    out, _ = effective(props, "OutputType")
    sc, _ = effective(props, "SelfContained")
    if dotnet is None or "runtimes" not in dotnet or (out or "").lower() not in ("exe", "winexe") \
            or _true(sc):
        return
    have = {int(m.group(1)) for r in dotnet["runtimes"] if r["name"] == "Microsoft.NETCore.App"
            and (m := re.match(r"(\d+)\.", r["version"]))}
    for t in proj["tfms"]:
        major = tfm_major(t)
        if major is not None and have and major not in have:
            report.add_finding(
                "RT001", "CANDIDATE", "warning", f"{t} の EXE を実行する runtime が見つからない",
                evidence=[fid, dotnet["fact"]] if dotnet.get("fact") else [fid],
                meaning=f"Microsoft.NETCore.App {major}.x が導入されていない。SDK があってもビルドのみで、実行には runtime が必要。",
                limit="rollForward 設定や別の dotnet の導入は評価していない。",
                next_steps=[f"`dotnet --list-runtimes` で {major}.x の有無を確認する"])


def evaluate_runtimeconfigs(report: Report, arts: dict, fid: str, dotnet: dict | None) -> None:
    if dotnet is None or not dotnet.get("runtimes"):
        return
    names = {(r["name"], int(r["version"].split(".")[0])) for r in dotnet["runtimes"]
             if r["version"].split(".")[0].isdigit()}
    for rc in arts["runtimeconfigs"]:
        for fw in rc.get("frameworks") or []:
            ver = (fw.get("version") or "").split(".")[0]
            if fw.get("name") and ver.isdigit() and (fw["name"], int(ver)) not in names:
                report.add_finding(
                    "RT001", "CANDIDATE", "warning",
                    f"{os.path.basename(rc['path'])} が要求する {fw['name']} {fw['version']} がこの dotnet にない",
                    evidence=[fid], meaning="既存のビルド出力が要求する共有 runtime が導入されていない候補。",
                    limit="rollForward と複数の dotnet の組み合わせは評価していない(既存出力に基づく)。",
                    next_steps=["必要な runtime の導入、または対象 TFM の見直しを検討する"])


def evaluate_references(report: Report, proj: dict, fid: str, project_dir: str) -> int:
    """ProjectReference / HintPath の参照先ファイル。式を含むものは未評価として数だけ返す。"""
    unresolved = 0
    missing: list[str] = []
    items = [("ProjectReference", v) for v in proj["references"]["project"]] + \
            [("HintPath", r["hint_path"]) for r in proj["references"]["reference"] if r["hint_path"]]
    for kind, value in items:
        path = resolve_reference(project_dir, value)
        if path is None:
            unresolved += 1
        elif not os.path.exists(path):
            missing.append(f"{kind}: {value}")
    if missing:
        report.add_finding(
            "DEP004", "CANDIDATE", "warning", f"参照先が見つからない {len(missing)} 件",
            evidence=[fid], meaning="; ".join(missing[:5]) + " — CS0006 や MSB3202 の原因候補。",
            limit="Condition や Import による実効値は評価していない。ビルドで生成される参照先は存在しない場合がある。",
            next_steps=["参照先の配置、先行プロジェクトのビルド、パスの誤記を確認する"])
    return unresolved


def evaluate_restore_state(report: Report, proj: dict, fid: str, project_path: str,
                           assets_path: str | None, arts: dict, arts_fact: str) -> None:
    """assets / lock の新しさと対象 TFM との整合。存在は restore 成功の証明ではない。"""
    restore = format_command(["dotnet", "restore", project_path])
    if assets_path and os.path.isfile(assets_path):
        try:
            stale = os.path.getmtime(assets_path) < os.path.getmtime(project_path)
        except OSError:
            stale = False
        if stale:
            report.add_finding(
                "DEP003", "CANDIDATE", "warning", "project.assets.json がプロジェクトファイルより古い",
                evidence=[fid, arts_fact], meaning="プロジェクト変更後に restore されていない候補(既存キャッシュに基づく)。",
                limit="更新時刻のみの比較。Directory.Build.props 等の変更や内容の差は未評価。",
                next_steps=[f"restore を実行する: {restore}"])
    lock = arts.get("packages_lock")
    if lock and not lock.get("error") and proj["tfms"]:
        have = {t.split("/")[0].lower() for t in lock.get("targets") or []}
        missing = [t for t in proj["tfms"] if t.lower() not in have]
        if have and missing:
            report.add_finding(
                "DEP003", "CANDIDATE", "warning",
                f"packages.lock.json に対象 {', '.join(missing)} の節がない",
                evidence=[fid, arts_fact], meaning="TargetFramework の変更後にロックファイルが更新されていない候補。",
                limit="ロックファイルの依存内容と実際の参照の整合は未評価。",
                next_steps=[f"restore を実行して lock を更新するか検討する: {restore}"])
