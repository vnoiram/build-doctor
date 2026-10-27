"""Rule ID の登録簿。ID は安定させ、必要な Fact と適用条件を明示する。"""

from __future__ import annotations

# rule_id -> (必要な Fact の種類, 適用条件)
RULES: dict[str, tuple[tuple[str, ...], str]] = {
    "ARCH001": (("binary-header",), "--host-arch 指定時、DLL/EXE の CPU 要件がホストと不一致"),
    "ARCH002": (("binary-header",), "--native-dep 指定時、依存先の CPU が不一致"),
    "ARCH003": (("project",), "PlatformTarget / RID / ホストの不整合"),
    "OS001": (("binary-header", "os"), "この OS では扱えない形式(例: Linux 上の PE)"),
    "WIN001": (("project",), "Windows 固有要件(WPF / WinForms 等)を非 Windows で評価"),
    "SDK001": (("dotnet", "sdk-selection"), "SDK 形式プロジェクトで SDK を選択できない/未導入"),
    "FX001": (("dotnet", "sdk-selection"), "選択 SDK の世代が対象 TFM より古い、または NETSDK1045"),
    "FX002": (("netframework", "log"), "参照アセンブリ不足(旧形式)または MSB3644"),
    "RT001": (("dotnet",), "実行用 runtime の不足"),
    "DEP001": (("log",), "CS0006 / CS0012"),
    "DEP002": (("log",), "NU1101 / NU1301 / NU1605"),
    "DEP003": (("project", "log"), "assets / lock の欠落・不整合・古さ、NETSDK1004/1005"),
    "DEP004": (("project",), "ProjectReference / HintPath の参照先なし"),
    "CS001": (("log",), "CS0246 / CS0234"),
    "CS002": (("log",), "CS0103 / CS1002 / CS1513"),
    "CS003": (("log", "project"), "unsafe / LangVersion 関連"),
    "PS001": (("ps-parse", "log"), "PowerShell Parser エラー"),
    "PS002": (("ps-requires", "powershell"), "#requires / マニフェスト要求がホストと不一致"),
    "PS003": (("ps-parse",), "静的に特定できるパスの欠落"),
    "LOAD001": (("log",), "BadImageFormat / FileNotFound / DllNotFound"),
    "LOG000": (("log",), "未分類の診断"),
    "BUILD000": (("build-plan",), "診断なしのビルド失敗"),
}
