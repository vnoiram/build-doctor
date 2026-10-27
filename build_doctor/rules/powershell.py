"""PowerShell の Rule。ホストごとの結果を混同しない。"""

from __future__ import annotations

from ..models import Report
from ..parsers.powershell import version_tuple


def evaluate_parse(report: Report, name: str, host_label: str, host_fact: str, result: dict) -> None:
    errors = result.get("parse_errors") or []
    if errors:
        first = errors[0]
        report.add_finding(
            "PS001", "CONFIRMED", "error",
            f"{host_label} で {name} に構文エラー {len(errors)} 件 (先頭: {first.get('line')}行{first.get('column')}列)",
            evidence=[host_fact],
            meaning=f"{first.get('message')} — このホストの Parser API による結果。他のエディション/版では結果が異なる可能性がある。",
            limit="構文解析のみ。実行・モジュール読込・C# コンパイルの成否は評価していない。",
            next_steps=["該当の行と列、および構文互換性(5.1 と 7 の差)を確認する"])


def evaluate_manifest(report: Report, name: str, host_label: str, host_fact: str, host: dict,
                      manifest: dict) -> None:
    """モジュールマニフェストの要求とホストの照合。インポート成功は保証しない。"""
    ed = manifest.get("CompatiblePSEditions")
    ed = [ed] if isinstance(ed, str) else [e for e in (ed or []) if isinstance(e, str)]
    evaluate_requires(report, name, host_label, host_fact, host, {
        "version": manifest.get("PowerShellVersion") if isinstance(manifest.get("PowerShellVersion"), str) else None,
        "editions": ed})
    pa = manifest.get("ProcessorArchitecture")
    want = {"amd64": "x64", "x86": "x86", "arm": "arm"}.get(pa.lower()) if isinstance(pa, str) else None
    if want and host.get("process_arch") and host["process_arch"] != want:
        report.add_finding(
            "ARCH001", "CONFIRMED", "error",
            f"{name} の ProcessorArchitecture={pa} と {host_label} のプロセス({host['process_arch']})が不一致",
            evidence=[host_fact], meaning="このマニフェストはホストのプロセス アーキテクチャと一致しない。",
            limit="マニフェストの宣言のみ。実際のインポートは実行していない。",
            next_steps=[f"{want} のホストで実行するか、マニフェストの宣言を確認する"])


def evaluate_requires(report: Report, name: str, host_label: str, host_fact: str, host: dict,
                      req: dict) -> None:
    need = version_tuple(req.get("version"))
    have = version_tuple(host.get("ps_version"))
    if need and have and have < need:
        report.add_finding(
            "PS002", "CONFIRMED", "error",
            f"{name} は PowerShell {req['version']} 以上を要求するが {host_label} は {host['ps_version']}",
            evidence=[host_fact], meaning="#requires -Version の要求をこのホストは満たさない。",
            limit="指定/検出したホストのみの判定。",
            next_steps=["要求を満たすホストを `--powershell-path` で指定する"])
    editions = [e.lower() for e in req.get("editions") or []]
    if editions and (host.get("edition") or "").lower() not in set(editions):
        report.add_finding(
            "PS002", "CONFIRMED", "error",
            f"{name} は PSEdition {','.join(req['editions'])} を要求するが {host_label} は {host.get('edition')}",
            evidence=[host_fact], meaning="#requires -PSEdition の要求をこのホストは満たさない。",
            limit="指定/検出したホストのみの判定。",
            next_steps=["要求を満たすエディションのホストを `--powershell-path` で指定する"])


def evaluate_files(report: Report, name: str, fid: str, base_dir: str, data: dict) -> None:
    """マニフェストと Add-Type -Path が指す静的なファイルの存在確認(読み込みはしない)。"""
    import os
    wanted: list[tuple[str, str]] = []
    manifest = data.get("manifest") or {}
    for key in ("RootModule", "NestedModules", "RequiredAssemblies"):
        v = manifest.get(key)
        for item in ([v] if isinstance(v, str) else v if isinstance(v, list) else []):
            if isinstance(item, str):
                wanted.append((key, item))
    for ref in data.get("references") or []:
        if ref.get("command") == "Add-Type" and ref.get("param") in ("path", "literalpath") \
                and ref.get("kind") == "literal" and ref.get("value"):
            wanted.append(("Add-Type -Path", ref["value"]))
    missing = []
    for key, item in wanted:
        if "$" in item or "*" in item:
            continue
        if key in ("RootModule", "NestedModules") and "." not in os.path.basename(item):
            continue  # 拡張子なしはモジュール名であり、ファイルパスではない
        cand = item if os.path.isabs(item) else os.path.join(base_dir, item.replace("\\", os.sep))
        if not os.path.exists(cand):
            missing.append(f"{key}: {item}")
    if missing:
        report.add_finding(
            "PS003", "CANDIDATE", "warning", f"{name} が参照する静的パスが見つからない {len(missing)} 件",
            evidence=[fid], meaning="; ".join(missing[:5]) + " — 読み込み失敗の原因候補。",
            limit="スクリプトの実行時カレントや $PSScriptRoot 展開後の解決は評価していない。拡張子なしのモジュール名は対象外。",
            next_steps=["ファイルの配置と相対パスの基準ディレクトリを確認する"])
