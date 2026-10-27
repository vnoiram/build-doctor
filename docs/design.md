# PowerShell / C# Build Doctor 設計書

状態: 第1〜3段階を実装済み。第4段階は PE/ELF の依存名抽出、CLR メタデータ(AssemblyRef/P/Invoke)、ReadyToRun・apphost の識別、単体配布まで対応。ARM64・Windows x86 の実機検証は未実施。

## 1. 目的と提供価値

PowerShell スクリプト、C# プロジェクト、コンパイル済み DLL/EXE、ビルドログを入力に、ビルドや読み込みに失敗する原因を診断する。Windows / Linux 共通の CLI と JSON 形式を提供する。

利用者に返すものは「何が合わないか」「その根拠」「まだ不明なこと」「次に試す具体的な操作」。単なる環境情報一覧で終わらせず、以下を関連付ける。

- OS、実行ホスト、成果物、ネイティブ依存 DLL のアーキテクチャ。
- .NET SDK、実行用ランタイム、.NET Framework、参照アセンブリ。
- プロジェクトの対象フレームワーク・RID・ビルド構成と、実際に選択されるツール。
- PowerShell エディション、構文、モジュール、`Add-Type` の参照。
- エラーコード、発生箇所、依存関係、原因候補。

自動インストール、プロジェクト自動修正、実行ポリシー変更、検査対象アプリの実行は対象外。MVP は診断と修正案の提示までとする。

## 2. 技術構成の決定

**Python の共通コアと、任意の PowerShell 補助プロセスを採用する。**

| 案 | 利点 | 問題 | 決定 |
| --- | --- | --- | --- |
| PowerShell 単体 | Windows で導入しやすく AST を利用可能 | Linux に PowerShell が必要。診断対象ホストに依存 | 補助機能に使用 |
| C# / .NET 単体 | PE メタデータや MSBuild API を利用しやすい | .NET 不足時の起動には OS/CPU ごとの自己完結配布が必要 | 将来の高度解析用候補 |
| Python 共通コア | .NET / PowerShell がなくても不足を診断できる | Windows では Python または単体配布が必要 | 採用 |

Python 3.11 以降を初期実装の基準とし、`argparse`、`subprocess`、`json`、`struct`、XML パーサーなど標準ライブラリを基本とする。既存診断スクリプトの依存最小化方針を引き継ぐ。PowerShell の構文解析は、自作パーサーではなく検出したホストの Parser API に委ねる。

初期配布はソース一式。次段階で Windows x64 / Linux x64 用の Python 同梱配布を用意する。配布物自身の起動互換性も CI で確認する。x86 成果物の静的検査には、Doctor 自身を x86 で動かす必要はない。

## 3. 対応範囲

| 機能 | Windows | Linux |
| --- | --- | --- |
| C# 設定・ログ・PE の静的解析 | 対応 | 対応 |
| ネイティブファイルの識別 | PE | ELF と PE |
| .NET SDK / runtime 検出 | 対応、x86/x64 を別管理 | 対応、アーキテクチャごとに管理 |
| Windows PowerShell 5.1 の環境・構文解析 | ホストが存在すれば対応 | 対応ホストなし。ログ・静的情報のみ |
| PowerShell 7 の環境・構文解析 | ホストが存在すれば対応 | ホストが存在すれば対応 |
| .NET Framework のインストール情報 | レジストリと参照アセンブリを検査 | ローカル実行互換性は対象外 |
| SDK 形式プロジェクトの実ビルド | SDK と必要な依存があれば対応 | SDK と必要な依存があれば対応 |
| 旧形式 .NET Framework プロジェクト | MSBuild / Build Tools を指定して検証 | 原則として静的診断。Mono は初期対象外 |
| WPF / WinForms / COM の実行互換性 | 必要条件を診断、実行試験はしない | Windows 固有要件として報告 |

主な検証環境は Windows x64 と Linux x64。Windows の x86 ホストは独立した試験を設ける。ARM64 は識別・報告を先行し、実行検証の対応を別管理する。WSL は Linux 環境として扱い、Windows 側ツールの自動実行はしない。

PowerShell 5.1 と PowerShell 7 では基盤 .NET と利用可能な機能が異なるため、エディション間の互換性を同一視しない。[Microsoft: PowerShell の相違点](https://learn.microsoft.com/en-us/powershell/scripting/whats-new/differences-from-windows-powershell)

## 4. CLI

以下の例は実装予定のインターフェース。Windows は `python`、Linux は `python3` で起動する。

```powershell
# 環境のみ。検査対象のコードを実行しない
python build_doctor.py env

# プロジェクトと関連ファイルの静的診断
python build_doctor.py inspect ./src/App.csproj --configuration Release

# DLL と、利用予定のホストを照合
python build_doctor.py inspect ./lib/Example.dll --host-arch x64

# 実際に利用する PowerShell ホストを明示して構文解析
python build_doctor.py inspect ./scripts/example.ps1 --powershell-path 'C:\Program Files\PowerShell\7\pwsh.exe'

# 保存済みログだけを診断。ツールチェーン不要
python build_doctor.py explain ./build.log --format json
```

```bash
python3 build_doctor.py inspect ./src/App.csproj --framework net8.0 --runtime linux-x64
python3 build_doctor.py explain - < build.log

# 実行するコマンド、作業ディレクトリ、書き込み先の想定を表示
python3 build_doctor.py build ./src/App.csproj --dry-run

# ユーザーが明示的に要求する実ビルド。既定で --no-restore
python3 build_doctor.py build ./src/App.csproj

# restore を明示的に許可する場合
python3 build_doctor.py build ./src/App.csproj --restore
```

`net8.0` は引数形式の例であり、新規開発用バージョンの推奨を意味しない。

| コマンド | 入力 | 処理 |
| --- | --- | --- |
| `env` | 任意のツールパス | OS、CPU、ホスト、SDK、runtime、コンパイラーの検出 |
| `inspect` | `.ps1/.psm1/.psd1/.cs/.csproj/.sln/.dll/.exe/.so`、ディレクトリ | 静的解析と必要な環境照会 |
| `explain` | テキストログのパス、または `-` | ログ解析のみ。環境との関連付けは `--project PATH` 指定時 |
| `build` | 単一の `.csproj` または `.sln` | 明示的なビルドとログ診断。対象が曖昧なら選択を要求するエラー |

共通オプションは各サブコマンドの後に指定する。

- `--format text|json`、`--output FILE`、`--quiet`、`--verbose`、`--no-color`。
- `--timeout SECONDS`（照会単位、既定 10 秒）、`--max-output-bytes`（子プロセス単位、既定 4 MiB）。
- `--dotnet-path`、`--powershell-path`、`--msbuild-path` で使用するツールを固定可能。
- `--configuration`、`--framework`、`--runtime`、`--platform` でビルド条件を明示。
- `--host-arch x86|x64|arm64` はロード先プロセスの想定。`--runtime` や `--platform` と混同しない。
- `--static-only` は `env` / `inspect` の外部ツール起動を禁止。取得不能部分を残す。
- `--fail-on warning|error` は既定 `error`。不完全診断の終了コードは別に判定する。
- `build` 固有: `--restore`、`--dry-run`、`--build-timeout`（既定 300 秒）。

引数なしは短い使用例を表示。非対話環境でも待たない。`--help` と `--version` は外部照会せず終了する。

stdout は結果のみ、stderr は進捗・操作エラーのみ。JSON には色や子プロセスの生ログを混ぜない。`--output` は同じレポートを新規保存し、既存ファイルは上書きしない。日本語表示、UTF-8 JSON、`NO_COLOR` をサポートする。

## 5. 処理の構造

```text
CLI / 入力検証
    ↓
対象識別 + 診断計画
    ↓
環境 Collector / 静的 Parser / 明示的 Build Runner
    ↓
正規化された Fact と取得状態
    ↓
Rule Engine + 根拠の関連付け
    ↓
Finding + 修正候補 + 検証手順
    ↓
Text / JSON Reporter + 終了コード
```

予定構成:

```text
build_doctor.py
build_doctor/
  cli.py                    # 引数・終了コード
  models.py                 # Fact / Finding / Report
  runner.py                 # 時間・出力制限、プロセス終了
  collectors/               # windows / linux / dotnet / powershell
  parsers/                  # project / pe / elf / powershell / logs
  rules/                    # architecture / framework / dependency / compile
  reporters/                # text / json
  helpers/inspect_ps.ps1     # ホスト情報と Parser API 呼び出し
schemas/build-doctor-v1.schema.json
tests/build_doctor/
```

Collector は事実収集、Rule は判定に限定する。Rule に OS コマンドを直接書かない。Rule ごとに安定した ID、必要な Fact、適用条件、根拠、提案テンプレート、回帰テストを持つ。

## 6. 32/64bit 診断

次の値を独立して保持する。

1. OS のアーキテクチャ。
2. Doctor 自身のプロセスのアーキテクチャ。
3. 対象 PowerShell / dotnet / MSBuild ホストのアーキテクチャ。
4. プロジェクトの `PlatformTarget`、`Prefer32Bit`、RID。
5. PE Machine、PE32/PE32+、CLR ヘッダー、ILONLY、32BITREQ、32BITPREF。
6. ネイティブ依存先のアーキテクチャ。

PE32 という理由だけで x86 専用としない。管理対象アセンブリでは CLR フラグも必要。純粋な IL の AnyCPU と、ネイティブ部分を含む mixed-mode、ReadyToRun、apphost を分ける。未対応形式は推測で確定しない。

- 明示された x64 プロセスに x86 専用 DLL を読み込む計画: 不一致を確定可能。
- AnyCPU DLL と x86 ネイティブ依存: AnyCPU 自体の問題とせず、ネイティブ境界の不一致を示す。
- `Prefer32Bit` の影響: EXE/DLL、対象 runtime、実際の起動ホストを合わせて評価する。
- `BadImageFormatException`: ビット数、破損、非管理 DLL の管理ロードなど複数候補を提示。例外名だけでは断定しない。
- Linux 上の Windows PE: ファイル情報は報告するが、OS 上の実行可否は別項目にする。

CLR フラグの意味は [Microsoft: CorFlags](https://learn.microsoft.com/en-us/dotnet/framework/tools/corflags-exe-corflags-conversion-tool) を基準にする。Doctor はファイルのフラグを書き換えない。

## 7. .NET とビルドツール診断

`dotnet --info`、`--list-sdks`、`--list-runtimes` をツールの絶対パスごとに収集する。PATH の先頭候補と追加候補を区別し、1 つの dotnet の結果を全アーキテクチャの一覧としない。明示パス、PATH、既知のインストール場所を探索し、探索範囲も記録する。[Microsoft: dotnet CLI](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet)

SDK と runtime は別資源として診断する。runtime だけではビルド可としない。SDK の存在だけで必要な runtime、Framework Developer Pack、workload の存在を保証しない。

`global.json` は実際にビルドする作業ディレクトリから親へ探索する。`sdk.version`、`rollForward`、`allowPrerelease` を記録し、`dotnet --version` を同じ作業ディレクトリで実行して選択結果を得る。SDK 選択と TFM を別々に評価する。未対応の新しい設定は無視せず未評価とする。[Microsoft: global.json](https://learn.microsoft.com/en-us/dotnet/core/tools/global-json)

Windows は .NET Framework のレジストリを 32/64bit ビュー別に照会し、実行用 Framework と reference assemblies / targeting pack を区別する。Framework ディレクトリ内の `csc.exe`、SDK 内のコンパイラー、Visual Studio Build Tools を混同しない。古いコンパイラーによる言語機能不足は、コンパイラーバージョンとエラーの組み合わせで示す。

SDK 形式では `TargetFramework(s)`、`RuntimeIdentifier(s)`、`PlatformTarget`、`LangVersion`、`Nullable`、`AllowUnsafeBlocks`、`UseWPF`、`UseWindowsForms`、`EnableWindowsTargeting` を収集する。クロスビルド可能性と実行互換性を分離する。[Microsoft: SDK プロジェクトのプロパティ](https://learn.microsoft.com/en-us/dotnet/core/project-sdk/msbuild-props)

## 8. 依存関係と静的評価の限界

入力プロジェクトとその親ディレクトリの関連設定を上限付きで読む。

- `ProjectReference`、`PackageReference`、`Reference` / `HintPath`。
- `Directory.Build.props/targets`、`Directory.Packages.props`、`packages.config`。
- `packages.lock.json`、`obj/project.assets.json`、`.deps.json`、`.runtimeconfig.json`。
- NuGet 設定のソース識別情報、`RestoreSources`。認証情報の値は収集しない。
- PowerShell の `#requires`、モジュールマニフェスト、静的な `Import-Module` と `Add-Type` 参照。

条件、プロパティ展開、Import の効果を独自実装で完全再現しない。設定の文字列が読めた場合は `CONFIGURED`、実効値を証明できなければ未評価として残す。外部 Import や複数 TFM を一つの確定値に潰さない。ソリューション内のプロジェクトごと、TFM / RID / configuration ごとに結果を区別する。

assets / lock ファイルの存在を restore 成功の証明にしない。対象フレームワーク・RID の節、参照ファイルの存在、設定変更との整合性を調べる。新しさや実効設定を確定できなければ「既存キャッシュに基づく候補」とする。

MVP のネイティブ検査は PE/ELF の種類とアーキテクチャ、および明示された依存先の照合まで。AssemblyRef、P/Invoke、PE import、ELF DT_NEEDED の網羅的グラフ解析は次段階。動的なライブラリ名、ローダーの実効探索パス、COM 登録の実効利用まで静的検査で保証しない。検査対象への `Assembly.Load` や `ldd` は使用しない。

## 9. PowerShell の解析

選択した各ホストを `-NoProfile -NonInteractive` で起動し、固定の補助スクリプトから `$PSVersionTable`、プロセスアーキテクチャ、LanguageMode、Parser API の結果を JSON で返す。対象パスをコード文字列へ埋め込まず、引数として渡す。

`Parser.ParseFile` による構文解析だけを行い、対象の実行、dot-source、`Import-Module`、`Add-Type` は行わない。`.psd1` も AST の定数だけを読み、式を実行して値を得ない。

検出対象は構文エラー、`#requires`、`PowerShellVersion`、`CompatiblePSEditions`、`ProcessorArchitecture`、`RequiredModules`、静的に特定できる DLL / C# コード参照。モジュールはマニフェストとファイル位置を照合し、インポート成功を保証しない。

`Add-Type` 内の C# は静的なリテラルだけ抽出する。補間・外部入力・動的生成を伴う場合は未解析とする。PowerShell の構文成功を C# コンパイル成功としない。ホストがない場合は構文解析を省略し `UNKNOWN`。PowerShell 7 での成功を 5.1 での成功として報告しない。

## 10. エラー分類と提案

コードと構造情報を優先し、日本語・英語メッセージの文言一致だけに依存しない。コードなしのエラーも未分類として保持する。パス、行、列、プロジェクト、フェーズを取り出し、同一エラーの再掲を集約する。

| Rule ID | エラー・状況例 | 診断と次の確認 |
| --- | --- | --- |
| `ARCH001` | 実行ホストと DLL の CPU が不一致 | 対象ホスト切り替え、または依存先と揃えた再ビルドを候補化 |
| `SDK001` | SDK なし / `global.json` に適合しない | 選択対象 SDK とインストール済み SDK を比較 |
| `FX001` | `NETSDK1045` | 選択 SDK と対象 TFM、PATH、global.json を確認 |
| `FX002` | `MSB3644` | Framework の参照アセンブリ不足候補。runtime の有無とは区別 |
| `DEP001` | `CS0006` / `CS0012` | 欠落メタデータ、必要な参照、先行プロジェクトの失敗を確認 |
| `DEP002` | `NU1101` / `NU1301` / `NU1605` | パッケージ解決、ソース到達、ダウングレードを別原因に分類 |
| `DEP003` | `NETSDK1004` / `NETSDK1005` | assets 欠落、対象 TFM 不整合を確認。restore を提案 |
| `CS001` | `CS0246` / `CS0234` | using、参照、名前の誤記、TFM 差異を候補化 |
| `CS002` | `CS0103` / `CS1002` / `CS1513` | 名前解決・構文エラーの位置と周辺の確認箇所を提示 |
| `CS003` | `CS0227` / 言語バージョン関連エラー | unsafe / LangVersion の設定を説明し、変更案を提示 |
| `PS001` | Parser エラー | 対象ホスト、行・列、構文互換性を提示 |
| `LOAD001` | BadImageFormat / FileNotFound / DllNotFound | CPU、管理/非管理、推移依存、探索パスの候補を分離 |

ログに出たエラー自体は観測事実、根本原因は別 Finding とする。例えば `CS0246` だけで NuGet 不足を確定しない。並列ビルドの最初の行を根本原因とせず、依存関係が確認できる場合に先行失敗を関連付ける。

提案には対象、理由、実行する場合のコマンド、期待結果を含める。修正コマンドは表示専用。OS に合わせた引用形式を使い、未確定のパッケージ名やバージョンを勝手に埋めない。

## 11. 実ビルドの契約

`build` の呼び出しを対象プロジェクトのコード実行に対する明示的な操作とする。追加の対話確認は不要。`--dry-run` で事前確認可能。

SDK 形式は固定した dotnet パスで `dotnet build <target> --no-restore` を基本とする。`--restore` 指定時にのみ暗黙 restore を許す。旧形式は明示した Windows MSBuild を利用する。作業ディレクトリは対象ファイルの親で固定し、レポートに記録する。任意のシェル文字列を実行するオプションは作らない。

`dotnet build` は通常 restore を伴うため、診断モードとの境界を明示する。[Microsoft: dotnet build](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-build)

MSBuild targets、analyzers、source generators、カスタムタスクはコードを実行できる。`--no-restore` はネットワーク遮断でもサンドボックスでもない。ビルドは `bin/obj` やツールキャッシュを書き換え得る。Doctor は既存出力を自動削除しない。ネットワーク隔離が必要なビルドは利用者のコンテナ/VM 内で行う。

子プロセスは引数配列で起動し、stdout/stderr を並行して上限付きで取得する。タイムアウト・出力超過時は POSIX プロセスグループ / Windows Job Object 等で配下も停止し、部分ログと理由を残す。終了管理を保証できない環境では実ビルドを開始しない。単なる `subprocess.run(timeout=...)` だけで孫プロセスまで停止できたとは扱わない。

## 12. レポートと判定モデル

既存ツールと同じ確度語彙を維持し、重大度とは別軸にする。

| フィールド | 値・意味 |
| --- | --- |
| `status` | `CONFIRMED` 観測、`CONFIGURED` 設定、`CANDIDATE` 仮説、`UNKNOWN` 不明 |
| `severity` | `info` / `warning` / `error` |
| `checks[].outcome` | `completed` / `unknown` / `skipped` / `not_applicable` |
| `coverage` | 要求された適用可能検査の完了・不明・省略の件数 |

非該当は UNKNOWN としない。必要なホストがなく実施できない検査は UNKNOWN。`--static-only` は最初から静的検査を要求範囲とするため、ビルド未実行だけで不完全扱いにしない。静的検査内で解釈できない設定は不完全として残す。

JSON の主要形状:

```json
{
  "schema_version": 1,
  "tool": "build-doctor",
  "tool_version": "0.1.0",
  "time_utc": "2026-01-01T00:00:00Z",
  "mode": "inspect",
  "target": "<PROJECT>/lib/Example.dll",
  "parameters": {"host_arch": "x64"},
  "coverage": {"completed": 2, "unknown": 0, "skipped": 0},
  "checks": [{"id": "pe-header", "outcome": "completed"}, {"id": "host-constraint", "outcome": "completed"}],
  "facts": [{"id": "fact-1", "source": "pe-header", "value": {"requires_32bit": true}}],
  "summary": {"info": 0, "warning": 0, "error": 1},
  "records": [{
    "id": "finding-1",
    "rule_id": "ARCH001",
    "status": "CONFIRMED",
    "severity": "error",
    "title": "指定された x64 ホストと x86 専用 DLL が不一致",
    "evidence_refs": ["fact-1"],
    "meaning": "指定条件でプロセス内ロードする場合に CPU 要件が合わない",
    "limit": "実際のロードは実行していない。ホストは利用者の指定条件",
    "next": ["x86 ホストの利用可否、または DLL の再ビルド条件を確認する"],
    "related_findings": []
  }],
  "execution": {"build_started": false, "child_exit_code": null},
  "exit_code": 1
}
```

取得エラーは `reason_code`（`TOOL_MISSING`、`ACCESS_DENIED`、`TIMEOUT`、`OUTPUT_LIMIT`、`UNSUPPORTED_FORMAT` 等）で機械判定可能にする。Fact は取得元、位置、取得時刻、完全性を保持する。JSON の破壊的変更では schema_version を上げる。

### 終了コード

| コード | 意味 |
| --- | --- |
| 0 | 要求範囲が完了し、閾値以上の所見なし |
| 1 | 閾値以上の所見あり、またはビルドが失敗 |
| 2 | 引数不正、入力不能、保存失敗、内部エラー |
| 3 | 確定した失敗はないが、要求範囲に UNKNOWN / 実施不能がある |
| 130 | 利用者による中断 |

優先順位は 130 → 2 → 1 → 3 → 0。失敗と未完了が併存するときも JSON に両方を残す。任意の未知ビルド終了コードも 1 に対応させ、元コードを保持する。既存診断ツールの終了コード仕様は変更しない。

## 13. 入力・資源・情報管理

- 検査対象ファイルをロード・実行せず、解析用データとして読む。DTD / 外部エンティティは拒否する。
- PE/ELF のオフセット・サイズ・算術境界を検証する。破損データは未知形式と区別して報告する。
- ディレクトリ探索は既定深さ 8、ファイル数 10,000。リンクを自動追跡せず、外部参照は未検査として残す。
- テキスト入力は既定 16 MiB、バイナリ入力は 256 MiB まで。超過や切り詰めを成功扱いしない。ログはストリーム解析する。
- Windows の BOM 付き UTF-8 / UTF-16 を識別する。BOM なしは UTF-8 を基本とし、必要時 `--input-encoding` を指定。復号失敗を黙って置換しない。
- ツール候補は絶対パスで記録し、空の PATH 要素によるカレントディレクトリ探索はしない。環境照会もローカル実行ファイルを信頼する操作であり、完全な無実行が必要なら `--static-only` を使う。
- 環境変数は診断用の許可リストのみ収集。ホームとプロジェクトの絶対パスは既定でプレースホルダー化する。ソースの全文やログの全文はレポートへ転記しない。
- URL の認証情報・クエリ、既知のシークレット形式は伏せる。任意ログの完全な秘匿化は保証できない。レポートは自動アップロードしない。
- バイナリログ `.binlog` の読込・生成は初期対象外。将来追加時は別の明示オプションとする。

## 14. 検証計画と受け入れ条件

テストはネットワークに依存しない fixture を基本とし、実環境試験を別レイヤーにする。

| 分類 | 必須ケース | 期待結果 |
| --- | --- | --- |
| ツール欠落 | dotnet / PowerShell / MSBuild がない | Doctor は起動し、不足または未検査を明示 |
| CPU | x86 / x64 / AnyCPU、32BITREQ/PREF、x86 ネイティブ依存 | PE32 を一律 x86 と判定しない |
| バイナリ | PE/ELF、切断、巨大オフセット、未対応形式 | クラッシュせず理由を報告 |
| SDK | runtime のみ、複数 SDK、global.json 不適合 | SDK 選択と runtime を分離 |
| Framework | runtime あり・targeting pack なし | ビルド要件不足を検出 |
| プロジェクト | 条件付き属性、Import、複数 TFM、古い assets | 静的文字列を実効設定と誤認しない |
| PowerShell | 5.1/7 の構文差、動的 Add-Type、欠落モジュール | ホスト別結果、動的部分は未解析 |
| ログ | 日英、複数プロジェクト、重複、未知コード、UTF-16 | 原因候補と観測を分離 |
| CLI | 空白・Unicode パス、非 TTY、JSON、保存失敗 | 引数破損・stdout 混入・対話待ちがない |
| 実行制御 | 遅延、大量出力、孫プロセス、中断 | 上限内で停止し部分結果を保持 |
| 実行境界 | 対象にファイル生成処理を含める | inspect では生成されず、build のときだけ実行 |

受け入れ条件:

1. Windows / Linux の双方で同じ fixture から同じ Rule ID を返す。
2. .NET / PowerShell 未導入でも `env`、PE 静的解析、ログ解析が起動する。
3. 各 error / warning に根拠、限界、次の確認がある。
4. 権限不足・未対応・探索上限を「問題なし」に変換しない。
5. JSON Schema と終了コードを CI で固定する。
6. Windows x86 PowerShell と x64 PowerShell の差を実機または VM で検証する。
7. 実ビルド成功を対象アプリの実行成功として表示しない。

## 15. 実装順序

**第1段階: 共通基盤とオフライン診断。** CLI、Fact/Finding、JSON、PE/ELF 識別、環境照会、SDK と Framework の区別、基本的な設定解析、ログ分類。`env` / `inspect` / `explain` を提供する。

**第2段階: PowerShell と依存関係。** ホスト別 AST 解析、マニフェスト、静的 Add-Type、NuGet / assets / reference 照合、複数 TFM、根拠の関連付け。ここまでを最初の利用可能版とする。

**第3段階: 明示的ビルド。** `build` / `--dry-run`、Windows MSBuild、子プロセスツリー停止、restore の制御、CI 連携。実行制御テストが通るまで公開しない。

**第4段階: 高度な解析と配布。** 管理・ネイティブ依存グラフ、対応形式の拡張、単体配布、ARM64 実環境検証。自動修正はこの設計の範囲に含めない。
