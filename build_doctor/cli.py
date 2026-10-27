"""引数解析・終了コード。stdout は結果のみ、stderr は進捗と操作エラーのみ。"""

from __future__ import annotations

import argparse
import os
import sys
import traceback

from . import __version__, analysis
from .analysis import Session, UsageError
from .models import EXIT_INTERRUPTED, EXIT_USAGE, Report
from .redact import Redactor
from .reporters import json_reporter, text_reporter

USAGE_EXAMPLES = """\
使用例:
  build_doctor.py env
  build_doctor.py inspect ./src/App.csproj --configuration Release
  build_doctor.py inspect ./lib/Example.dll --host-arch x64
  build_doctor.py inspect ./scripts/example.ps1 --powershell-path /path/to/pwsh
  build_doctor.py explain ./build.log --format json
  build_doctor.py build ./src/App.csproj --dry-run
詳細: build_doctor.py --help
"""


def positive_float(value: str) -> float:
    v = float(value)
    if v <= 0:
        raise argparse.ArgumentTypeError("正の数を指定してください")
    return v


def positive_int(value: str) -> int:
    v = int(value)
    if v <= 0:
        raise argparse.ArgumentTypeError("正の整数を指定してください")
    return v


def common_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group("共通オプション")
    g.add_argument(
        "--format", choices=["text", "json"], default="text", help="出力形式"
    )
    g.add_argument(
        "--output",
        metavar="FILE",
        help="同じレポートを新規ファイルに保存(既存は上書きしない)",
    )
    g.add_argument("--quiet", action="store_true", help="stderr の進捗を出さない")
    g.add_argument("--verbose", action="store_true", help="詳細な進捗/事実を出す")
    g.add_argument("--no-color", action="store_true", help="色を付けない")
    g.add_argument(
        "--timeout",
        type=positive_float,
        default=10,
        metavar="SECONDS",
        help="照会単位のタイムアウト(既定 10)",
    )
    g.add_argument(
        "--max-output-bytes",
        type=positive_int,
        default=4 * 1024 * 1024,
        metavar="N",
        help="子プロセス単位の出力上限(既定 4 MiB)",
    )
    g.add_argument("--dotnet-path", metavar="PATH", help="使用する dotnet を固定")
    g.add_argument(
        "--powershell-path", metavar="PATH", help="使用する PowerShell ホストを固定"
    )
    g.add_argument("--msbuild-path", metavar="PATH", help="使用する MSBuild を固定")
    g.add_argument("--configuration", help="ビルド構成")
    g.add_argument("--framework", help="対象フレームワーク(TFM)")
    g.add_argument("--runtime", help="RuntimeIdentifier")
    g.add_argument("--platform", help="Platform")
    g.add_argument(
        "--host-arch",
        choices=["x86", "x64", "arm64"],
        help="ロード先プロセスの想定(--runtime/--platform とは別)",
    )
    g.add_argument("--static-only", action="store_true", help="外部ツールを起動しない")
    g.add_argument(
        "--fail-on",
        choices=["warning", "error"],
        default="error",
        help="終了コード 1 にする最低重大度(既定 error)",
    )
    g.add_argument(
        "--input-encoding", metavar="ENC", help="BOM なしテキスト入力のエンコーディング"
    )
    g.add_argument(
        "--show-paths",
        action="store_true",
        help="ホーム/プロジェクトの絶対パスを伏せない",
    )
    return p


def build_parser() -> argparse.ArgumentParser:
    common = common_parser()
    p = argparse.ArgumentParser(
        prog="build_doctor",
        description="PowerShell / C# のビルド・読み込み失敗を診断する",
        epilog="診断と修正案の提示のみを行う。自動インストール・自動修正・検査対象の実行はしない。",
    )
    p.add_argument("--version", action="version", version=f"build-doctor {__version__}")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser(
        "env",
        parents=[common],
        help="OS・ホスト・SDK・runtime の検出",
        description="環境のみを検出する。検査対象のコードは実行しない。",
    )
    s = sub.add_parser(
        "inspect", parents=[common], help="成果物・プロジェクト・スクリプトの静的診断"
    )
    s.add_argument(
        "target",
        help=".ps1/.psm1/.psd1/.cs/.csproj/.sln/.dll/.exe/.so またはディレクトリ",
    )
    s.add_argument(
        "--native-dep",
        action="append",
        metavar="PATH",
        help="ネイティブ依存ファイル(CPU を照合)。複数指定可",
    )
    s = sub.add_parser("explain", parents=[common], help="保存済みログの診断")
    s.add_argument("log", help="ログのパス、または - (標準入力)")
    s.add_argument(
        "--project", metavar="PATH", help="環境との関連付けに使うプロジェクト"
    )
    s = sub.add_parser("build", parents=[common], help="明示的な実ビルドとログ診断")
    s.add_argument(
        "target", help="単一の .csproj または .sln(ディレクトリなら 1 つだけ含むこと)"
    )
    s.add_argument(
        "--restore", action="store_true", help="暗黙 restore を許可(既定 --no-restore)"
    )
    s.add_argument(
        "--dry-run",
        action="store_true",
        help="実行するコマンドと書き込み先を表示するだけ",
    )
    s.add_argument(
        "--build-timeout",
        type=positive_float,
        default=300,
        metavar="SECONDS",
        help="ビルドのタイムアウト(既定 300)",
    )
    return p


def _defaults(args: argparse.Namespace) -> None:
    for k, v in (
        ("native_dep", None),
        ("project", None),
        ("restore", False),
        ("dry_run", False),
        ("build_timeout", 300),
    ):
        if not hasattr(args, k):
            setattr(args, k, v)


def _param_dict(args: argparse.Namespace) -> dict:
    keys = (
        "configuration",
        "framework",
        "runtime",
        "platform",
        "host_arch",
        "static_only",
        "fail_on",
        "restore",
        "dry_run",
    )
    return {
        k: getattr(args, k) for k in keys if getattr(args, k, None) not in (None, False)
    }


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        sys.stderr.write(USAGE_EXAMPLES)
        return EXIT_USAGE
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else EXIT_USAGE
    if not args.command:
        sys.stderr.write(USAGE_EXAMPLES)
        return EXIT_USAGE
    _defaults(args)
    if args.output and os.path.exists(args.output):
        sys.stderr.write(
            f"エラー: --output の保存先が既に存在する(上書きしない): {args.output}\n"
        )
        return EXIT_USAGE

    def progress(msg: str) -> None:
        if not args.quiet:
            sys.stderr.write(msg + "\n")

    args._progress = progress
    target = {
        "env": None,
        "inspect": getattr(args, "target", None),
        "explain": getattr(args, "log", None),
        "build": getattr(args, "target", None),
    }[args.command]
    report = Report(
        args.command,
        None if target == "-" else (os.path.abspath(target) if target else None),
        _param_dict(args),
    )
    root_hint = args.project if args.command == "explain" and args.project else target
    redactor = Redactor(
        analysis.find_project_root(root_hint)
        if root_hint and root_hint != "-" and os.path.exists(root_hint)
        else None,
        show_paths=args.show_paths,
    )
    session = Session(report, args)

    try:
        if args.command == "env":
            analysis.run_env(session)
        elif args.command == "inspect":
            analysis.run_inspect(session, args.target)
        elif args.command == "explain":
            analysis.run_explain(session, args.log)
        else:
            analysis.run_build(session, args.target)
    except UsageError as e:
        sys.stderr.write(f"エラー: {e}\n")
        return EXIT_USAGE
    except KeyboardInterrupt:
        sys.stderr.write("中断されました\n")
        return EXIT_INTERRUPTED
    except Exception as e:  # 内部エラーは診断結果として扱わない  # noqa: BLE001
        sys.stderr.write(f"内部エラー: {type(e).__name__}: {e}\n")
        if args.verbose:
            traceback.print_exc()
        return EXIT_USAGE

    data = redactor.apply(report.to_dict(args.fail_on))
    if args.format == "json":
        text = json_reporter.render(data)
    else:
        use_color = (
            sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        )
        text = text_reporter.render(data, use_color=use_color, verbose=args.verbose)
    code = data["exit_code"]
    try:
        sys.stdout.reconfigure(
            encoding="utf-8" if args.format == "json" else None, errors="replace"
        )
    except (AttributeError, ValueError):
        pass
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except BrokenPipeError:
        pass
    if args.output:
        try:
            with open(args.output, "x", encoding="utf-8", newline="\n") as f:
                f.write(
                    text
                    if args.format == "json"
                    else text_reporter.render(
                        data, use_color=False, verbose=args.verbose
                    )
                )
        except OSError as e:
            sys.stderr.write(f"エラー: レポートを保存できない: {e}\n")
            return EXIT_USAGE
    return code
