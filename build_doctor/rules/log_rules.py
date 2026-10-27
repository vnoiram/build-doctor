"""ログ診断の Rule。エラーコード → 原因候補。ログ上のエラーは観測、原因は候補として分ける。"""

from __future__ import annotations

from ..models import Report
from ..parsers.logs import Diagnostic
from . import format_command, path_arg

# code -> (rule_id, title, meaning, next)
CATALOG: dict[str, tuple[str, str, str, list[str]]] = {}


def _add(
    codes: list[str], rule_id: str, title: str, meaning: str, nxt: list[str]
) -> None:
    for c in codes:
        CATALOG[c] = (rule_id, title, meaning, nxt)


_add(
    ["NETSDK1045"],
    "FX001",
    "選択された SDK が対象フレームワークに対応していない",
    "ビルドに使われた .NET SDK が TargetFramework より古い可能性がある。PATH 先頭の dotnet や global.json の選択結果が候補。",
    [
        "対象ディレクトリで `dotnet --version` を実行し、実際に選択される SDK を確認する",
        "`dotnet --list-sdks` で導入済み SDK を比較し、SDK の導入、global.json、または対象フレームワークの見直しを検討する",
    ],
)
_add(
    ["MSB3644"],
    "FX002",
    "対象フレームワークの参照アセンブリが見つからない",
    "実行用 runtime の有無とは別に、targeting pack / Developer Pack / reference assemblies が不足している候補。",
    [
        "対象フレームワークの Developer Pack または参照アセンブリ(NuGet の Microsoft.NETFramework.ReferenceAssemblies 等)の導入有無を確認する"
    ],
)
_add(
    ["NETSDK1141", "MSB4236"],
    "SDK001",
    "要求された SDK を解決できない",
    "global.json の sdk.version / rollForward に適合する SDK が見つからない、または SDK が未導入の候補。",
    [
        "`dotnet --list-sdks` の結果と global.json の sdk.version / rollForward を比較する"
    ],
)
_add(
    ["NETSDK1004", "NETSDK1005", "NETSDK1047"],
    "DEP003",
    "restore 結果(assets)が欠落、または対象と不整合",
    "obj/project.assets.json が無い、または対象 TFM / RID の節が含まれていない候補。restore が未実施か、設定変更後に古いまま。",
    [
        "restore を実行する(例: {restore}) 。ネットワークやパッケージソースが必要になる場合がある"
    ],
)
_add(
    ["CS0006", "CS0012"],
    "DEP001",
    "参照メタデータ/型の定義が見つからない",
    "参照アセンブリの欠落、必要な追加参照、または先行プロジェクトのビルド失敗が原因の候補。",
    [
        "エラー位置の参照先ファイルの存在を確認する",
        "同じログ中の先行プロジェクトの失敗を確認する",
    ],
)
_add(
    ["NU1101"],
    "DEP002",
    "パッケージが見つからない(NU1101)",
    "パッケージ名の誤り、またはパッケージソースに存在しない候補。",
    ["パッケージ名と構成済みのパッケージソースを確認する"],
)
_add(
    ["NU1301"],
    "DEP002",
    "パッケージソースに到達できない(NU1301)",
    "ネットワーク、認証、ソース URL のいずれかの問題の候補。",
    ["NuGet のソース設定と接続性・認証を確認する"],
)
_add(
    ["NU1605"],
    "DEP002",
    "パッケージのダウングレードを検出(NU1605)",
    "依存関係の推移で、直接参照より低いバージョンが要求されている候補。",
    ["競合するパッケージのバージョン指定を確認する"],
)
_add(
    ["CS0246", "CS0234"],
    "CS001",
    "型/名前空間が見つからない",
    "using の不足、参照・パッケージの不足、名前の誤記、TFM の差異による API 不在の候補。",
    [
        "エラー位置周辺の using と参照を確認する",
        "対象 TFM でその型が提供されるか確認する",
    ],
)
_add(
    ["CS0103", "CS1002", "CS1513", "CS1514"],
    "CS002",
    "名前解決・構文エラー",
    "識別子の誤記、スコープ外参照、括弧・セミコロンの不足などの候補。",
    ["エラー位置と直前の行を確認する"],
)
_add(
    ["CS0227", "CS8026", "CS8107", "CS8302", "CS8370", "CS8400", "CS8652", "CS8773"],
    "CS003",
    "unsafe 設定または C# 言語バージョンの不足",
    "AllowUnsafeBlocks、または LangVersion / コンパイラーのバージョンが使用機能に足りない候補。",
    [
        "プロジェクトの AllowUnsafeBlocks / LangVersion と、使用中のコンパイラーのバージョンを確認する"
    ],
)
_add(
    ["PS:ParseException"],
    "PS001",
    "PowerShell の構文エラー",
    "構文互換性の問題、またはスクリプトの記述ミスの候補。",
    ["`inspect` で対象ホストを指定して行・列を確認する"],
)


def _load_next(code: str) -> tuple[str, str, str, list[str]]:
    kind = code.split(":", 1)[1]
    meanings = {
        "BadImageFormatException": "ビット数の不一致、ファイル破損、非管理 DLL の管理ロードなど複数の候補がある。例外名だけでは断定できない。",
        "FileNotFoundException": "ファイルまたは推移的依存が見つからない候補。探索パスと配置を確認。",
        "FileLoadException": "バージョン不一致や署名の問題など複数の候補がある。",
        "DllNotFoundException": "ネイティブ DLL の欠落、またはビット数・依存先 DLL の不一致の候補。",
    }
    return (
        "LOAD001",
        f"アセンブリ/ライブラリの読み込み失敗 ({kind})",
        meanings.get(kind, "読み込み失敗の原因は複数候補がある。"),
        [
            "`inspect` で DLL の CPU / 管理・非管理を確認し、`--host-arch` でロード先と照合する",
            "推移的依存と探索パスを確認する",
        ],
    )


def lookup(code: str | None) -> tuple[str, str, str, list[str]] | None:
    if not code:
        return None
    if code in CATALOG:
        return CATALOG[code]
    if code.startswith("LOAD:"):
        return _load_next(code)
    return None


def evaluate_log(
    report: Report,
    diags: list[Diagnostic],
    *,
    truncated: bool = False,
    restore_target: str | None = None,
) -> list[tuple[str, str, set[str]]]:
    """(finding_id, rule_id, ログ上のプロジェクト) の一覧を返す。"""
    groups: dict[tuple[str, str], list[tuple[Diagnostic, str]]] = {}
    for d in diags:
        fid = report.add_fact(
            "log",
            {
                "severity": d.severity,
                "code": d.code,
                "file": d.file,
                "line": d.line,
                "column": d.column,
                "project": d.project,
                "count": d.count,
                "message": d.message[:300],
            },
            location=f"{d.file}:{d.line}" if d.line else d.file,
        )
        entry = lookup(d.code)
        key = (entry[0] if entry else "LOG000", d.class_code)
        groups.setdefault(key, []).append((d, fid))

    created: list[tuple[str, str, set[str]]] = []
    for (rule_id, code), items in groups.items():
        severity = (
            "error" if any(d.severity == "error" for d, _ in items) else "warning"
        )
        total = sum(d.count for d, _ in items)
        entry = lookup(code if code != "UNCLASSIFIED" else None)
        evidence = [fid for _, fid in items][:10]
        if entry:
            _, title, meaning, nxt = entry
            projects = sorted({d.project for d, _ in items if d.project})
            proj = projects[0] if len(projects) == 1 else restore_target
            restore = format_command(["dotnet", "restore", path_arg(proj)])
            nxt = [n.replace("{restore}", restore) for n in nxt]
            status = "CANDIDATE"
        else:
            title = (
                f"未分類の診断 {code}" if code != "UNCLASSIFIED" else "コードなしの診断"
            )
            meaning = "既知の規則に当てはまらない。ログ上の位置と文言を直接確認する必要がある。"
            nxt = ["ログ中の該当行とその前後を確認する"]
            status = "UNKNOWN"
        report.add_finding(
            rule_id,
            status,
            severity,
            f"{title} ×{total}" if total > 1 else title,
            evidence=evidence,
            meaning=meaning,
            limit="ログ上の観測とエラーコードのみに基づく。環境・プロジェクトの実態は未確認。"
            "根本原因は候補であり、並列ビルドの最初の行を原因とは限らない。",
            next_steps=nxt,
        )
        created.append(
            (
                report.records[-1]["id"],
                rule_id,
                {d.project for d, _ in items if d.project},
            )
        )
    if truncated:
        report.add_check(
            "log-complete",
            "unknown",
            reason_code="INPUT_LIMIT",
            detail="入力が上限で打ち切られた。後続のエラーは解析していない",
        )
    return created
