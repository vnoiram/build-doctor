# Build Doctor

PowerShell スクリプト、C# プロジェクト、DLL/EXE、ビルドログから、ビルドや読み込みに失敗する原因を診断する CLI です。
返すのは「何が合わないか」「根拠」「まだ不明なこと」「次に試す操作」で、自動インストール・自動修正・検査対象の実行はしません。
設計は [docs/design.md](docs/design.md) を参照してください。

> 本ツールは自分が権限を持つコード・環境の診断を目的としています。

## 必要環境

Python 3.11 以降（標準ライブラリのみ）。.NET SDK / PowerShell は任意で、無くても `env` / `explain` / PE・ELF の静的解析は動きます。

## 使い方

```bash
python3 build_doctor.py env
python3 build_doctor.py inspect ./src/App.csproj --configuration Release
python3 build_doctor.py inspect ./lib/Example.dll --host-arch x64 [--native-dep ./native.dll]
python3 build_doctor.py inspect ./scripts/example.ps1 --powershell-path /path/to/pwsh
python3 build_doctor.py explain ./build.log --format json     # '-' で標準入力
python3 build_doctor.py build ./src/App.csproj --dry-run       # 実行内容の確認のみ
python3 build_doctor.py build ./src/App.csproj [--restore]     # 明示的な実ビルド
```

主な共通オプション: `--format text|json`、`--output FILE`（既存ファイルは上書きしない）、`--static-only`（外部ツールを起動しない）、
`--fail-on warning|error`、`--timeout`、`--max-output-bytes`、`--dotnet-path` / `--powershell-path` / `--msbuild-path`、`--show-paths`。

## 終了コード

| コード | 意味 |
| --- | --- |
| 0 | 要求範囲が完了し、閾値以上の所見なし |
| 1 | 閾値以上の所見あり、またはビルドが失敗 |
| 2 | 引数不正・入力不能・保存失敗・内部エラー |
| 3 | 確定した失敗はないが、UNKNOWN / 実施不能の検査がある |
| 130 | 中断 |

## 注意

- `build` は対象プロジェクトの MSBuild ターゲット等を実行し得ます。`--no-restore`（既定）はサンドボックスではありません。
- `inspect` は対象を実行しません。ただし `dotnet` / PowerShell ホストの照会はローカルの実行ファイルを起動します（避けるなら `--static-only`）。
- JSON の形式は `schemas/build-doctor-v1.schema.json`。
- ホームとプロジェクトの絶対パスは既定でプレースホルダーに置換されます。ログ全体の秘匿化は保証できません。

## テスト

```bash
python3 -m pip install pytest && python3 -m pytest
```
