"""SDK / フレームワーク / restore の Rule。確定できない設定は UNKNOWN として残す。"""

from __future__ import annotations

import sys

from ..collectors.dotnet import sdk_major, tfm_major
from ..models import Report
from ..parsers.project import assets_matches, effective
from . import format_command


def _is_true(value: str | None) -> bool:
    return (value or "").strip().lower() == "true"


def evaluate_project(report: Report, proj: dict, fact_id: str, *, dotnet: dict | None,
                     selection: dict | None, global_json: dict | None, gj_fact: str | None,
                     assets: dict | None, assets_fact: str | None, framework: str | None,
                     runtime: str | None, netfx: dict | None, name: str) -> None:
    props = proj["properties"]
    tfms = [framework] if framework else proj["tfms"]

    # --- SDK001: 選択結果 ---
    if selection is not None:
        if selection.get("selected") is None and selection.get("reason_code") == "SDK_NOT_RESOLVED":
            gj = (f" global.json: version={global_json.get('version')}, "
                  f"rollForward={global_json.get('rollForward')}") if global_json else ""
            report.add_finding(
                "SDK001", "CONFIRMED", "error", "作業ディレクトリで利用可能な .NET SDK を選択できない",
                evidence=[e for e in (fact_id, gj_fact) if e],
                meaning="`dotnet --version` が失敗した。global.json に適合する SDK がないか SDK が未導入。" + gj,
                limit="選択に使った dotnet は 1 つのみ。別の dotnet では結果が異なる可能性がある。",
                next_steps=["`dotnet --list-sdks` の結果と global.json の sdk.version / rollForward を比較する"])
    elif dotnet is not None and not dotnet.get("sdks") and not dotnet.get("errors"):
        report.add_finding(
            "SDK001", "CONFIRMED", "error", "指定/検出された dotnet に SDK がない",
            evidence=[fact_id], meaning="runtime だけでは SDK 形式プロジェクトをビルドできない。",
            limit="この dotnet の結果のみ。他の場所の SDK は評価していない。",
            next_steps=["SDK(runtime ではなく)の導入有無を確認する"])

    # --- FX001: SDK の世代 < TFM ---
    sel = (selection or {}).get("selected")
    sel_major = sdk_major(sel)
    if sel_major is not None and proj["sdk_style"]:
        too_new = [t for t in tfms if (m := tfm_major(t)) is not None and m > sel_major]
        if too_new:
            report.add_finding(
                "FX001", "CONFIRMED", "error",
                f"選択される SDK {sel} は対象 {', '.join(too_new)} より古い",
                evidence=[fact_id], meaning="ビルドすると NETSDK1045 になる組み合わせ。SDK の世代は TFM 以上が必要。",
                limit="PATH 先頭または明示した dotnet の選択結果。Preview SDK や追加 workload は未評価。",
                next_steps=["対応する SDK の導入、global.json、または TargetFramework の見直しを検討する"])

    # --- WIN001: Windows 固有要件 ---
    if proj["sdk_style"] and sys.platform != "win32":
        for key in ("UseWPF", "UseWindowsForms"):
            val, status = effective(props, key)
            if _is_true(val):
                ewt, _ = effective(props, "EnableWindowsTargeting")
                if not _is_true(ewt):
                    report.add_finding(
                        "WIN001", "CANDIDATE", "warning",
                        f"{key}=true は Windows 固有。Linux では EnableWindowsTargeting が必要な候補",
                        evidence=[fact_id], meaning="ビルドのみ可能にするには EnableWindowsTargeting=true が必要。実行は Windows 専用。",
                        limit="実効値の評価はしていない。実行互換性は別問題。",
                        next_steps=["Windows 上でビルドする、または EnableWindowsTargeting の設定を検討する"])

    # --- FX002: 旧形式 .NET Framework の参照アセンブリ ---
    if not proj["sdk_style"] and netfx is not None:
        for t in tfms:
            installed = {d.lower() for d in netfx.get("targeting_packs", [])}
            ver = _tfm_to_dir(t)
            if ver and ver.lower() not in installed:
                report.add_finding(
                    "FX002", "CANDIDATE", "warning", f"{t} の参照アセンブリが標準位置に見つからない",
                    evidence=[fact_id], meaning="Developer Pack / Targeting Pack の不足候補。実行用 Framework の有無とは別。",
                    limit="標準の Reference Assemblies 位置のみ確認。Visual Studio 内の別配置は未評価。",
                    next_steps=[f"{ver} の Developer Pack(参照アセンブリ)の導入有無を確認する"])

    # --- DEP003: restore 結果 ---
    if proj["sdk_style"]:
        restore = format_command(["dotnet", "restore", proj["path"]])
        rids = [r for r in ([runtime] if runtime else _split(effective(props, "RuntimeIdentifier")[0]) +
                            _split(effective(props, "RuntimeIdentifiers")[0])) if r]
        if assets is None:
            report.add_finding(
                "DEP003", "CANDIDATE", "warning", "obj/project.assets.json が見つからない",
                evidence=[fact_id],
                meaning="restore が未実施の候補。assets の有無は restore 成功の証明ではない。",
                limit="既定の obj ディレクトリのみ確認(BaseIntermediateOutputPath の変更は未評価)。",
                next_steps=[f"restore を実行する: {restore}"])
        elif tfms:
            missing_tfm, missing_rid = assets_matches(assets, tfms, rids)
            if missing_tfm or missing_rid:
                what = ", ".join(missing_tfm + missing_rid)
                report.add_finding(
                    "DEP003", "CANDIDATE", "warning", f"既存の assets に対象 {what} の節がない",
                    evidence=[e for e in (fact_id, assets_fact) if e],
                    meaning="設定変更後に restore されていない、古い assets の候補(既存キャッシュに基づく)。",
                    limit="assets の新しさと実効設定は確定できない。",
                    next_steps=[f"restore を実行する: {restore}"])


def _split(v: str | None) -> list[str]:
    return [x.strip() for x in (v or "").split(";") if x.strip()]


def _tfm_to_dir(tfm: str) -> str | None:
    t = tfm.lower()
    if not t.startswith("net") or "." in t or not t[3:].isdigit() or len(t) < 5:
        return None
    digits = t[3:]
    return "v" + ".".join(digits)
