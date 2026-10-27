"""サブコマンドの実処理。Collector / Parser を呼び、Fact と Check を積み、Rule に渡す。"""

from __future__ import annotations

import io
import os
import platform
import sys
import time

from . import runner
from .collectors import dotnet as dn
from .collectors import normalize_arch, process_arch
from .collectors import powershell as psc
from .models import Report
from .parsers import FormatError
from .parsers import binary as binparse
from .parsers import logs as logparse
from .parsers import project as proj
from .parsers.powershell import scan_requires
from .rules import arch as arch_rules
from .rules import framework as fx_rules
from .rules import log_rules
from .rules import powershell as ps_rules
from .rules import format_command

MAX_TEXT = 16 * 1024 * 1024
MAX_BINARY = 256 * 1024 * 1024
MAX_DEPTH = 8
MAX_FILES = 10000
MAX_PROJECTS_IN_SLN = 200
BINARY_EXT = {".dll", ".exe", ".so"}
PS_EXT = {".ps1", ".psm1", ".psd1"}
ENV_ALLOWLIST = ("DOTNET_ROOT", "DOTNET_ROOT_X64", "DOTNET_ROOT_X86", "DOTNET_CLI_HOME",
                 "NUGET_PACKAGES", "PROCESSOR_ARCHITECTURE", "PROCESSOR_ARCHITEW6432")


class UsageError(Exception):
    """引数不正・入力不能（終了コード 2）。"""


def os_arch() -> str:
    if sys.platform == "win32":
        return normalize_arch(os.environ.get("PROCESSOR_ARCHITEW6432")
                              or os.environ.get("PROCESSOR_ARCHITECTURE"))
    return normalize_arch(platform.machine())


def is_wsl() -> bool:
    try:
        with open("/proc/version", encoding="utf-8", errors="replace") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def find_project_root(target: str) -> str:
    start = os.path.abspath(target)
    cur = start if os.path.isdir(start) else os.path.dirname(start)
    fallback = cur
    for _ in range(8):
        try:
            names = os.listdir(cur)
        except OSError:
            break
        if ".git" in names or "global.json" in names or any(n.endswith(".sln") for n in names):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return fallback


class Session:
    """1 回の実行内で環境照会の結果を共有する。"""

    def __init__(self, report: Report, args):
        self.report, self.args = report, args
        self.static_only = bool(getattr(args, "static_only", False))
        self._dotnets: list[dict] | None = None
        self._dotnet_scope: dict = {}
        self._ps: list[dict] | None = None
        self._netfx: tuple[bool, dict | None] | None = None

    def progress(self, msg: str) -> None:
        cb = getattr(self.args, "_progress", None)
        if cb:
            cb(msg)

    # ---- dotnet ----
    def dotnets(self) -> list[dict]:
        if self._dotnets is not None:
            return self._dotnets
        a, r = self.args, self.report
        cands, scope = dn.discover(a.dotnet_path)
        self._dotnet_scope = scope
        r.add_fact("dotnet-discovery", {"candidates": cands, **scope})
        r.add_check("dotnet-discovery", "completed")
        infos = []
        for c in cands:
            self.progress(f"dotnet を照会: {c['path']}")
            info = dn.query(c["path"], a.timeout, a.max_output_bytes)
            info.update(source=c["source"], path_rank=c.get("path_rank"))
            info["fact"] = r.add_fact("dotnet", {k: v for k, v in info.items() if k != "fact"},
                                      location=c["path"], complete=not info["errors"])
            err = info["errors"][0] if info["errors"] else None
            r.add_check(f"dotnet-query:{c['path']}", "unknown" if err else "completed",
                        reason_code=err["reason_code"] if err else None,
                        detail=f"{err['query']} に失敗" if err else None)
            infos.append(info)
        self._dotnets = infos
        return infos

    def primary_dotnet(self) -> dict | None:
        d = self.dotnets()
        return d[0] if d else None

    # ---- PowerShell ----
    def ps_hosts(self) -> list[dict]:
        if self._ps is not None:
            return self._ps
        a, r = self.args, self.report
        cands = psc.discover(a.powershell_path)
        r.add_fact("powershell-discovery", {"candidates": cands})
        r.add_check("powershell-discovery", "completed")
        hosts = []
        for c in cands:
            self.progress(f"PowerShell を照会: {c['path']}")
            data, meta = psc.invoke(c["path"], {"mode": "info"}, a.timeout, a.max_output_bytes)
            if data is None:
                r.add_check(f"ps-host:{c['path']}", "unknown",
                            reason_code=meta["reason_code"] or "HELPER_FAILED")
                continue
            data.update(path=c["path"], source=c["source"])
            data["fact"] = r.add_fact("powershell", {k: v for k, v in data.items() if k != "fact"},
                                      location=c["path"])
            r.add_check(f"ps-host:{c['path']}", "completed")
            hosts.append(data)
        self._ps = hosts
        return hosts

    # ---- .NET Framework ----
    def netfx(self) -> dict | None:
        if self._netfx is None:
            if sys.platform != "win32":
                self.report.add_check("netframework", "not_applicable")
                self._netfx = (True, None)
            else:
                info = dn.netframework_installs()
                self.report.add_fact("netframework", info)
                self.report.add_check("netframework", "completed")
                self._netfx = (True, info)
        return self._netfx[1]


# ------------------------------------------------------------------ env
def run_env(session: Session) -> None:
    r, a = session.report, session.args
    r.add_fact("os", {
        "system": platform.system(), "release": platform.release(), "os_arch": os_arch(),
        "doctor_process_arch": process_arch(), "python": platform.python_version(),
        "wsl": is_wsl(),
        "env": {k: os.environ[k] for k in ENV_ALLOWLIST if k in os.environ}})
    r.add_check("os-info", "completed")
    if session.static_only:
        for cid in ("dotnet-discovery", "powershell-discovery"):
            r.add_check(cid, "skipped", reason_code="STATIC_ONLY")
    else:
        session.dotnets()
        session.ps_hosts()
    session.netfx()


# ------------------------------------------------------------------ inspect
def _open_checked(path: str, limit: int):
    size = os.path.getsize(path)
    if size > limit:
        raise FormatError("INPUT_LIMIT", f"入力が上限 {limit} bytes を超えている ({size} bytes)")
    return open(path, "rb"), size


def inspect_binary(session: Session, path: str, rel: str) -> None:
    r, a = session.report, session.args
    cid = f"binary-header:{rel}"
    try:
        f, size = _open_checked(path, MAX_BINARY)
        with f:
            info = binparse.parse_binary(f, size)
    except FormatError as e:
        r.add_check(cid, "unknown", reason_code=e.reason_code, detail=e.detail)
        return
    except OSError as e:
        r.add_check(cid, "unknown", reason_code="ACCESS_DENIED", detail=str(e))
        return
    fid = r.add_fact("binary-header", info, location=rel)
    r.add_check(cid, "completed")
    deps = []
    for dep in a.native_dep or []:
        try:
            f, size = _open_checked(dep, MAX_BINARY)
            with f:
                dinfo = binparse.parse_binary(f, size)
        except (FormatError, OSError) as e:
            r.add_check(f"native-dep:{os.path.basename(dep)}", "unknown",
                        reason_code=getattr(e, "reason_code", "ACCESS_DENIED"),
                        detail=str(e))
            continue
        did = r.add_fact("binary-header", dinfo, location=os.path.basename(dep))
        r.add_check(f"native-dep:{os.path.basename(dep)}", "completed")
        deps.append((did, os.path.basename(dep), dinfo))
    arch_rules.evaluate_os(r, fid, os.path.basename(path), info)
    arch_rules.evaluate_binary(r, fid, os.path.basename(path), info, a.host_arch, deps)
    r.add_check(f"host-constraint:{rel}", "completed" if a.host_arch else "not_applicable")


def inspect_project(session: Session, path: str, rel: str) -> None:
    r, a = session.report, session.args
    cid = f"project:{rel}"
    try:
        p = proj.parse_project(path, MAX_TEXT)
    except FormatError as e:
        r.add_check(cid, "unknown", reason_code=e.reason_code, detail=e.detail)
        return
    except OSError as e:
        r.add_check(cid, "unknown", reason_code="ACCESS_DENIED", detail=str(e))
        return
    summary = {name: list(defs) for name, defs in p["properties"].items()}
    fid = r.add_fact("project", {
        "sdk_style": p["sdk_style"], "sdk": p["sdk"], "tfms": p["tfms"],
        "tfm_status": p["tfm_status"], "properties": summary, "imports": p["imports"],
        "references": {"project": p["references"]["project"],
                       "package_count": len(p["references"]["package"]),
                       "assembly_references": p["references"]["reference"]},
        "directory_build_props": p["directory_build_props"],
        "directory_packages_props": p["directory_packages_props"],
        "packages_config": p["uses_packages_config"]}, location=rel)
    unevaluated = [n for n, defs in p["properties"].items() if any(not d["evaluated"] for d in defs)]
    if unevaluated:
        r.add_check(f"project-effective-config:{rel}", "unknown", reason_code="UNEVALUATED_PROPERTY",
                    detail="条件付き/式を含む属性は実効値を確定していない: " + ", ".join(sorted(unevaluated)))
    else:
        r.add_check(f"project-effective-config:{rel}", "completed")
    r.add_check(cid, "completed")

    project_dir = os.path.dirname(os.path.abspath(path))
    nuget = proj.parse_nuget_sources(project_dir)
    if nuget:
        r.add_fact("nuget-sources", nuget, location=nuget["path"])

    # global.json
    gj, gj_fact = None, None
    gj_path = proj.find_upward(project_dir, ("global.json",))
    if gj_path:
        try:
            gj = proj.parse_global_json(gj_path)
            gj_fact = r.add_fact("global.json", gj, location=gj_path)
            if gj["unsupported_keys"]:
                r.add_check("global-json-settings", "unknown", reason_code="UNSUPPORTED_SETTING",
                            detail="未対応の設定を評価していない: " + ", ".join(gj["unsupported_keys"]))
            else:
                r.add_check("global-json-settings", "completed")
        except FormatError as e:
            r.add_check("global-json-settings", "unknown", reason_code=e.reason_code, detail=e.detail)

    # 環境照会
    dotnet_info, selection = None, None
    if p["sdk_style"]:
        if session.static_only:
            r.add_check(f"sdk-selection:{rel}", "skipped", reason_code="STATIC_ONLY")
        else:
            dotnet_info = session.primary_dotnet()
            if dotnet_info is None:
                r.add_check(f"sdk-selection:{rel}", "unknown", reason_code="TOOL_MISSING",
                            detail="dotnet が見つからない(探索範囲: " +
                                   ", ".join(session._dotnet_scope.get("searched", ["--dotnet-path"])) + ")")
            else:
                selection = dn.select_sdk(dotnet_info["path"], project_dir, a.timeout, a.max_output_bytes)
                r.add_fact("sdk-selection", selection, location=project_dir)
                if selection.get("reason_code") in ("TIMEOUT", "TOOL_MISSING", "ACCESS_DENIED", "OUTPUT_LIMIT"):
                    r.add_check(f"sdk-selection:{rel}", "unknown", reason_code=selection["reason_code"])
                else:
                    r.add_check(f"sdk-selection:{rel}", "completed")
    netfx = None
    if not p["sdk_style"] and not session.static_only:
        netfx = session.netfx()

    assets, assets_fact = None, None
    assets_path = os.path.join(project_dir, "obj", "project.assets.json")
    if p["sdk_style"] and os.path.isfile(assets_path):
        try:
            assets = proj.read_assets(assets_path)
            assets_fact = r.add_fact("project.assets.json", {"targets": assets["targets"]},
                                     location=os.path.relpath(assets_path, project_dir))
        except FormatError as e:
            r.add_check(f"assets:{rel}", "unknown", reason_code=e.reason_code, detail=e.detail)

    fx_rules.evaluate_project(
        r, p, fid, dotnet=dotnet_info, selection=selection, global_json=gj, gj_fact=gj_fact,
        assets=assets, assets_fact=assets_fact, framework=a.framework, runtime=a.runtime,
        netfx=netfx, name=os.path.basename(path))
    if p["uses_packages_config"]:
        r.add_check(f"packages-config:{rel}", "unknown", reason_code="UNSUPPORTED_FORMAT",
                    detail="packages.config の解決状態は未評価")


def inspect_solution(session: Session, path: str, rel: str) -> None:
    r = session.report
    try:
        projects = proj.parse_solution(path, MAX_TEXT)
    except (FormatError, OSError) as e:
        r.add_check(f"solution:{rel}", "unknown", reason_code=getattr(e, "reason_code", "ACCESS_DENIED"),
                    detail=str(e))
        return
    r.add_fact("solution", {"projects": [os.path.basename(p) for p in projects]}, location=rel)
    r.add_check(f"solution:{rel}", "completed")
    for p in projects[:MAX_PROJECTS_IN_SLN]:
        if os.path.isfile(p):
            inspect_project(session, p, os.path.relpath(p, os.path.dirname(path)))
        else:
            r.add_check(f"project:{os.path.basename(p)}", "unknown", reason_code="NOT_FOUND",
                        detail="ソリューションが参照するプロジェクトが存在しない")
    if len(projects) > MAX_PROJECTS_IN_SLN:
        r.add_check(f"solution-limit:{rel}", "unknown", reason_code="LIMIT",
                    detail=f"プロジェクト数が上限 {MAX_PROJECTS_IN_SLN} を超えた")


def _decode_script(path: str) -> str | None:
    try:
        f, _ = _open_checked(path, MAX_TEXT)
    except (FormatError, OSError):
        return None
    with f:
        data = f.read()
    for bom, enc in logparse.LOG_ENCODING_BOMS:
        if data.startswith(bom):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def inspect_powershell(session: Session, path: str, rel: str) -> None:
    r, a = session.report, session.args
    name = os.path.basename(path)
    req = None
    if os.path.splitext(path)[1].lower() != ".psd1":
        text = _decode_script(path)
        if text is None:
            r.add_check(f"ps-requires:{rel}", "unknown", reason_code="DECODE_ERROR",
                        detail="#requires を UTF-8/BOM 付きとして読めない")
        else:
            req = scan_requires(text)
            r.add_fact("ps-requires", req, location=rel)
            r.add_check(f"ps-requires:{rel}", "completed")
    if session.static_only:
        r.add_check(f"ps-parse:{rel}", "skipped", reason_code="STATIC_ONLY")
        return
    hosts = session.ps_hosts()
    if not hosts:
        r.add_check(f"ps-parse:{rel}", "unknown", reason_code="TOOL_MISSING",
                    detail="構文解析に使える PowerShell ホストがない")
        return
    for h in hosts:
        label = f"{h.get('edition')} {h.get('ps_version')} ({h.get('process_arch')})"
        cid = f"ps-parse:{rel}@{h['path']}"
        data, meta = psc.invoke(h["path"], {"mode": "parse", "path": os.path.abspath(path)},
                                a.timeout, a.max_output_bytes)
        if data is None:
            r.add_check(cid, "unknown", reason_code=meta["reason_code"] or "HELPER_FAILED")
            continue
        fid = r.add_fact("ps-parse", {k: v for k, v in data.items() if k not in ("references",)},
                         location=rel)
        r.add_check(cid, "completed")
        ps_rules.evaluate_parse(r, name, label, fid, data)
        merged = req or {}
        if data.get("requires"):
            merged = {**merged, **{k: v for k, v in data["requires"].items() if v}}
        ps_rules.evaluate_requires(r, name, label, fid, h, merged)
        if data.get("manifest"):
            ps_rules.evaluate_manifest(r, name, label, fid, h, data["manifest"])
        dyn = 0
        for ref in data.get("references") or []:
            r.add_fact("ps-reference", ref, location=f"{rel}:{ref.get('line')}")
            dyn += ref.get("kind") == "dynamic"
        if dyn:
            r.add_check(f"ps-static-references:{rel}@{h['path']}", "unknown", reason_code="DYNAMIC_CODE",
                        detail=f"動的な引数 {dyn} 件は静的に解析できない")


def _walk(root: str):
    """深さ・件数上限付き。シンボリックリンクは追跡しない。"""
    count, truncated = 0, False
    base_depth = root.rstrip(os.sep).count(os.sep)
    out = []
    for cur, dirs, files in os.walk(root, followlinks=False):
        depth = cur.rstrip(os.sep).count(os.sep) - base_depth
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(cur, d)))
        if depth >= MAX_DEPTH:
            if dirs:
                truncated = True
            dirs[:] = []
        for fn in sorted(files):
            p = os.path.join(cur, fn)
            if os.path.islink(p):
                continue
            count += 1
            if count > MAX_FILES:
                return out, True
            out.append(p)
    return out, truncated


def inspect_file(session: Session, path: str, rel: str) -> None:
    ext = os.path.splitext(path)[1].lower()
    r = session.report
    if ext in BINARY_EXT:
        inspect_binary(session, path, rel)
    elif ext == ".csproj":
        inspect_project(session, path, rel)
    elif ext == ".sln":
        inspect_solution(session, path, rel)
    elif ext in PS_EXT:
        inspect_powershell(session, path, rel)
    elif ext == ".cs":
        cur = os.path.dirname(os.path.abspath(path))
        for _ in range(MAX_DEPTH):
            found = sorted(f for f in os.listdir(cur) if f.endswith(".csproj"))
            if found:
                if len(found) > 1:
                    r.add_check(f"cs-project:{rel}", "unknown", reason_code="AMBIGUOUS_PROJECT",
                                detail="同じ場所に複数の .csproj がある")
                else:
                    inspect_project(session, os.path.join(cur, found[0]), found[0])
                    r.add_check(f"cs-project:{rel}", "completed")
                return
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
        r.add_check(f"cs-project:{rel}", "unknown", reason_code="NOT_FOUND",
                    detail="所属する .csproj が見つからない")
    else:
        r.add_check(f"file:{rel}", "unknown", reason_code="UNSUPPORTED_FORMAT",
                    detail=f"未対応の拡張子: {ext or '(なし)'}")


def run_inspect(session: Session, target: str) -> None:
    r = session.report
    if not os.path.exists(target):
        raise UsageError(f"対象が存在しない: {target}")
    if os.path.isdir(target):
        files, truncated = _walk(target)
        targets = [f for f in files if os.path.splitext(f)[1].lower()
                   in BINARY_EXT | PS_EXT | {".csproj", ".sln"}]
        # .sln があれば、その配下の .csproj は sln 経由で評価されるため重複を避ける
        slns = [f for f in targets if f.endswith(".sln")]
        covered = set()
        for s in slns:
            try:
                covered.update(os.path.normcase(p) for p in proj.parse_solution(s, MAX_TEXT))
            except (FormatError, OSError):
                pass
        for f in targets:
            if f.endswith(".csproj") and os.path.normcase(f) in covered:
                continue
            inspect_file(session, f, os.path.relpath(f, target))
        if truncated:
            r.add_check("directory-walk", "unknown", reason_code="LIMIT",
                        detail=f"深さ {MAX_DEPTH} / {MAX_FILES} ファイルの上限で探索を打ち切った")
        else:
            r.add_check("directory-walk", "completed")
        if not targets:
            r.add_check("directory-targets", "unknown", reason_code="UNSUPPORTED_FORMAT",
                        detail="対応する形式のファイルが見つからない")
    else:
        inspect_file(session, target, os.path.basename(target))


# ------------------------------------------------------------------ explain
def run_explain(session: Session, source: str) -> None:
    r, a = session.report, session.args
    project_findings_start = len(r.records)
    if a.project:
        if not os.path.isfile(a.project):
            raise UsageError(f"--project が存在しない: {a.project}")
        inspect_file(session, a.project, os.path.basename(a.project))
    env_records = {rec["id"]: rec["rule_id"] for rec in r.records[project_findings_start:]}

    try:
        if source == "-":
            stream = sys.stdin.buffer
            diags, truncated = logparse.parse_log(stream, MAX_TEXT, a.input_encoding)
        else:
            with open(source, "rb") as f:
                diags, truncated = logparse.parse_log(f, MAX_TEXT, a.input_encoding)
    except FormatError as e:
        raise UsageError(f"ログを読めない: {e.detail}")
    except OSError as e:
        raise UsageError(f"ログを開けない: {e}")
    r.add_check("log-parse", "completed")
    created = log_rules.evaluate_log(r, diags, truncated=truncated, restore_target=a.project)
    for fid, rule_id, _ in created:
        for eid, erule in env_records.items():
            if erule == rule_id:
                r.link(fid, eid)
    _link_prerequisite_failures(r, created, a.project)


def _link_prerequisite_failures(r: Report, created, project_path: str | None) -> None:
    """参照先プロジェクトの失敗と、参照元の DEP001 を関連付ける。"""
    by_name: dict[str, list[str]] = {}
    for fid, rule_id, projects in created:
        for p in projects:
            by_name.setdefault(os.path.basename(p).lower(), []).append(fid)
    for fid, rule_id, projects in created:
        if rule_id != "DEP001":
            continue
        for p in projects:
            path = p if os.path.isfile(p) else (project_path if project_path and
                                                os.path.basename(project_path) == os.path.basename(p) else None)
            if not path:
                continue
            try:
                refs = proj.parse_project(path, MAX_TEXT)["references"]["project"]
            except (FormatError, OSError):
                continue
            for ref in refs:
                for other in by_name.get(os.path.basename(ref.replace("\\", "/")).lower(), []):
                    if other != fid:
                        r.link(fid, other)


# ------------------------------------------------------------------ build
def resolve_build_target(target: str) -> str:
    if os.path.isdir(target):
        found = sorted(f for f in os.listdir(target) if f.endswith((".sln", ".csproj")))
        if len(found) != 1:
            raise UsageError("ビルド対象が曖昧(または見つからない)。1 つ選択して指定してください: "
                             + (", ".join(found) if found else "候補なし"))
        return os.path.join(target, found[0])
    if not os.path.isfile(target) or not target.lower().endswith((".sln", ".csproj")):
        raise UsageError("build の対象は単一の .csproj または .sln")
    return target


def plan_build(session: Session, target: str) -> dict:
    a = session.args
    target = os.path.abspath(target)
    project_dir = os.path.dirname(target)
    sdk_style = True
    if target.lower().endswith(".csproj"):
        try:
            sdk_style = proj.parse_project(target, MAX_TEXT)["sdk_style"]
        except (FormatError, OSError) as e:
            raise UsageError(f"プロジェクトを読めない: {e}")
    use_msbuild = bool(a.msbuild_path) and (not sdk_style or target.lower().endswith(".sln"))
    if not sdk_style and not a.msbuild_path:
        raise UsageError("旧形式プロジェクトのビルドには --msbuild-path が必要")
    if not sdk_style and sys.platform != "win32":
        raise UsageError("旧形式プロジェクトの実ビルドは Windows のみ(Linux では静的診断を使用)")
    if use_msbuild:
        argv = [os.path.abspath(a.msbuild_path), target, "-nologo", "-v:minimal"]
        if a.restore:
            argv.append("-restore")
        if a.configuration:
            argv.append(f"-p:Configuration={a.configuration}")
        if a.platform:
            argv.append(f"-p:Platform={a.platform}")
        if a.framework:
            argv.append(f"-p:TargetFramework={a.framework}")
        if a.runtime:
            argv.append(f"-p:RuntimeIdentifier={a.runtime}")
    else:
        dotnet_path = a.dotnet_path
        if not dotnet_path:
            if session.static_only:
                raise UsageError("--static-only では build できない")
            primary = session.primary_dotnet()
            if primary is None:
                raise UsageError("dotnet が見つからない。--dotnet-path で指定してください")
            dotnet_path = primary["path"]
        argv = [os.path.abspath(dotnet_path), "build", target, "-nologo", "-v:minimal"]
        if not a.restore:
            argv.append("--no-restore")
        if a.configuration:
            argv += ["-c", a.configuration]
        if a.framework:
            argv += ["-f", a.framework]
        if a.runtime:
            argv += ["-r", a.runtime]
        if a.platform:
            argv.append(f"-p:Platform={a.platform}")
    return {"argv": argv, "command": format_command(argv), "cwd": project_dir, "target": target,
            "restore_allowed": bool(a.restore),
            "may_write": [os.path.join(project_dir, "bin"), os.path.join(project_dir, "obj")],
            "timeout_seconds": a.build_timeout,
            "notice": "ビルドは対象プロジェクトの MSBuild ターゲット/アナライザー等のコードを実行し得る。"
                      "--no-restore はネットワーク遮断やサンドボックスではない。"}


def run_build(session: Session, target: str) -> None:
    r, a = session.report, session.args
    target = resolve_build_target(target)
    r.target = target
    plan = plan_build(session, target)
    r.add_fact("build-plan", {k: v for k, v in plan.items() if k != "argv"}, location=plan["cwd"])
    r.execution["planned_command"] = plan["command"]
    r.execution["cwd"] = plan["cwd"]
    if a.dry_run:
        r.add_check("build-plan", "completed")
        return
    if not runner.can_manage_process_tree():
        raise UsageError("子プロセスのツリー停止を保証できない環境では実ビルドを開始しない")
    session.progress(f"ビルド開始: {plan['command']}")
    start = time.monotonic()
    res = runner.run(plan["argv"], timeout=a.build_timeout, max_output_bytes=a.max_output_bytes,
                     cwd=plan["cwd"], env=dn.dotnet_env())
    r.execution.update(build_started=res.reason_code not in ("TOOL_MISSING", "ACCESS_DENIED", "EXEC_FAILED"),
                       child_exit_code=res.exit_code, duration_seconds=round(time.monotonic() - start, 1))
    if res.reason_code in ("TOOL_MISSING", "ACCESS_DENIED", "EXEC_FAILED"):
        raise UsageError(f"ビルドツールを起動できない: {res.reason_code}: {res.detail}")
    r.execution["notice"] = "ビルドの成否であり、対象アプリの実行成功ではない。"
    text = (res.text("stdout") + "\n" + res.text("stderr")).encode("utf-8")
    diags, truncated = logparse.parse_log(io.BytesIO(text), MAX_TEXT + 1, "utf-8")
    if res.killed:
        r.add_check("build-run", "unknown", reason_code=res.reason_code,
                    detail="上限に達したため子プロセスツリーを停止した。部分ログのみ解析")
    else:
        r.add_check("build-run", "completed")
        r.build_failed = res.exit_code != 0
    created = log_rules.evaluate_log(r, diags, truncated=truncated)
    if target.lower().endswith(".csproj"):
        start_idx = len(r.records)
        inspect_project(session, target, os.path.basename(target))
        for fid, rule_id, _ in created:
            for rec in r.records[start_idx:]:
                if rec["rule_id"] == rule_id:
                    r.link(fid, rec["id"])
    if res.exit_code not in (0, None) and not diags and not res.killed:
        r.add_finding("BUILD000", "UNKNOWN", "error", f"ビルドが終了コード {res.exit_code} で失敗",
                      meaning="既知の診断を含むログが得られなかった。", limit="出力に診断行がない。",
                      next_steps=["ビルドを単独で再実行して出力を確認する"])
