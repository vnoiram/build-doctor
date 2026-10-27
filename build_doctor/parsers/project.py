"""csproj / sln / global.json / assets 等の静的解析。MSBuild の評価は再現しない。"""

from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET

from ..redact import sanitize_url
from . import FormatError

WATCHED = ("TargetFramework", "TargetFrameworks", "TargetFrameworkVersion", "RuntimeIdentifier",
           "RuntimeIdentifiers", "PlatformTarget", "Prefer32Bit", "LangVersion", "Nullable",
           "AllowUnsafeBlocks", "UseWPF", "UseWindowsForms", "EnableWindowsTargeting",
           "OutputType", "SelfContained")
MAX_UPWARD = 16
KNOWN_GLOBAL_TOP = {"sdk", "tools", "msbuild-sdks", "test"}
KNOWN_GLOBAL_SDK = {"version", "rollForward", "allowPrerelease", "paths", "errorMessage"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def read_bytes_limited(path: str, max_bytes: int) -> bytes:
    size = os.path.getsize(path)
    if size > max_bytes:
        raise FormatError("INPUT_LIMIT", f"入力が上限 {max_bytes} bytes を超えている ({size})")
    with open(path, "rb") as f:
        return f.read()


def parse_xml(data: bytes) -> ET.Element:
    if re.search(rb"<!(DOCTYPE|ENTITY)", data, re.IGNORECASE):
        raise FormatError("UNSUPPORTED_FORMAT", "DTD / 外部エンティティを含む XML は拒否する")
    try:
        return ET.fromstring(data)
    except ET.ParseError as e:
        raise FormatError("CORRUPT", f"XML として解析できない: {e}")


def _cond_ok(*conds: str | None) -> bool:
    return not any(conds)


def _collect_properties(root: ET.Element, source: str) -> dict[str, list[dict]]:
    props: dict[str, list[dict]] = {}
    for group in root:
        if _local(group.tag) != "PropertyGroup":
            continue
        for el in group:
            name = _local(el.tag)
            if name not in WATCHED:
                continue
            value = (el.text or "").strip()
            cond = el.get("Condition") or group.get("Condition")
            props.setdefault(name, []).append({
                "value": value, "condition": cond, "source": source,
                "evaluated": _cond_ok(cond) and "$(" not in value,
            })
    return props


def effective(props: dict[str, list[dict]], name: str) -> tuple[str | None, str]:
    """(値, 状態)。状態は CONFIGURED / UNEVALUATED / UNSET。"""
    defs = props.get(name)
    if not defs:
        return None, "UNSET"
    if all(d["evaluated"] for d in defs):
        return defs[-1]["value"], "CONFIGURED"
    return None, "UNEVALUATED"


def netfx_tfm(version: str) -> str | None:
    m = re.fullmatch(r"v(\d)\.(\d)(?:\.(\d))?", version.strip())
    return f"net{m.group(1)}{m.group(2)}{m.group(3) or ''}" if m else None


def find_upward(start: str, names: tuple[str, ...]) -> str | None:
    cur = os.path.abspath(start)
    for _ in range(MAX_UPWARD):
        for n in names:
            cand = os.path.join(cur, n)
            if os.path.isfile(cand):
                return cand
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent
    return None


def parse_project(path: str, max_bytes: int = 16 * 1024 * 1024) -> dict:
    root = parse_xml(read_bytes_limited(path, max_bytes))
    if _local(root.tag) != "Project":
        raise FormatError("UNSUPPORTED_FORMAT", "Project 要素で始まっていない")
    sdk = root.get("Sdk")
    imports = []
    refs: dict[str, list] = {"project": [], "package": [], "reference": []}
    for el in root.iter():
        t = _local(el.tag)
        if t == "Sdk" and el.get("Name"):
            sdk = sdk or el.get("Name")
        elif t == "Import":
            imports.append({"project": el.get("Project"), "sdk": el.get("Sdk"),
                            "condition": el.get("Condition")})
        elif t == "ProjectReference" and el.get("Include") and len(refs["project"]) < 500:
            refs["project"].append(el.get("Include"))
        elif t == "PackageReference" and el.get("Include") and len(refs["package"]) < 500:
            ver = el.get("Version") or el.get("VersionOverride")
            if ver is None:
                for ch in el:
                    if _local(ch.tag) == "Version":
                        ver = (ch.text or "").strip()
            refs["package"].append({"name": el.get("Include"), "version": ver})
        elif t == "Reference" and el.get("Include") and len(refs["reference"]) < 500:
            hint = next(((ch.text or "").strip() for ch in el if _local(ch.tag) == "HintPath"), None)
            refs["reference"].append({"name": el.get("Include"), "hint_path": hint})
    props = _collect_properties(root, "project")
    sdk_style = sdk is not None or any(i["sdk"] for i in imports)

    # 最寄りの Directory.Build.props が同じ属性を定義していれば併記する
    dbp = find_upward(os.path.dirname(os.path.abspath(path)), ("Directory.Build.props",))
    dbp_info = None
    if dbp:
        try:
            for name, defs in _collect_properties(
                    parse_xml(read_bytes_limited(dbp, max_bytes)), "Directory.Build.props").items():
                props.setdefault(name, [])[:0] = defs
            dbp_info = dbp
        except FormatError:
            dbp_info = dbp

    tfms: list[str] = []
    tfm_status = "UNSET"
    for name in ("TargetFrameworks", "TargetFramework"):
        value, status = effective(props, name)
        if status != "UNSET":
            tfm_status = status
            if value:
                tfms = [x.strip() for x in value.split(";") if x.strip()]
            break
    if tfm_status == "UNSET":
        value, status = effective(props, "TargetFrameworkVersion")
        if status != "UNSET":
            tfm_status = status
            if value and (t := netfx_tfm(value)):
                tfms = [t]
    return {
        "path": path, "sdk_style": sdk_style, "sdk": sdk, "properties": props, "imports": imports,
        "references": refs, "tfms": tfms, "tfm_status": tfm_status,
        "directory_build_props": dbp_info,
        "directory_packages_props": find_upward(os.path.dirname(os.path.abspath(path)),
                                                ("Directory.Packages.props",)),
        "uses_packages_config": os.path.isfile(os.path.join(os.path.dirname(path), "packages.config")),
    }


def parse_solution(path: str, max_bytes: int = 16 * 1024 * 1024) -> list[str]:
    text = read_bytes_limited(path, max_bytes).decode("utf-8-sig", errors="replace")
    base = os.path.dirname(os.path.abspath(path))
    found = []
    for m in re.finditer(r'^Project\("[^"]*"\)\s*=\s*"[^"]*",\s*"([^"]+\.(?:cs|vb|fs)proj)"', text,
                         re.MULTILINE | re.IGNORECASE):
        found.append(os.path.normpath(os.path.join(base, m.group(1).replace("\\", os.sep))))
    return found


def strip_json_comments(text: str) -> str:
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 1
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def parse_global_json(path: str) -> dict:
    data = read_bytes_limited(path, 1024 * 1024).decode("utf-8-sig")
    try:
        obj = json.loads(strip_json_comments(data))
    except json.JSONDecodeError as e:
        raise FormatError("CORRUPT", f"global.json を解析できない: {e}")
    if not isinstance(obj, dict):
        raise FormatError("CORRUPT", "global.json の最上位がオブジェクトではない")
    sdk = obj.get("sdk") if isinstance(obj.get("sdk"), dict) else {}
    unknown = sorted(set(obj) - KNOWN_GLOBAL_TOP) + sorted(f"sdk.{k}" for k in set(sdk) - KNOWN_GLOBAL_SDK)
    return {"path": path, "version": sdk.get("version"), "rollForward": sdk.get("rollForward"),
            "allowPrerelease": sdk.get("allowPrerelease"), "unsupported_keys": unknown}


def parse_nuget_sources(start: str) -> dict | None:
    """ソースの識別情報のみ。認証情報（packageSourceCredentials）は読まない。"""
    cfg = find_upward(start, ("NuGet.Config", "nuget.config", "NuGet.config"))
    if not cfg:
        return None
    try:
        root = parse_xml(read_bytes_limited(cfg, 1024 * 1024))
    except FormatError:
        return {"path": cfg, "sources": [], "error": True}
    sources = []
    for ps in root.iter():
        if _local(ps.tag) == "packageSources":
            for add in ps:
                if _local(add.tag) == "add" and add.get("value"):
                    sources.append({"key": add.get("key"), "url": sanitize_url(add.get("value"))})
    return {"path": cfg, "sources": sources[:50]}


def _norm_tfm_key(key: str) -> str:
    key = key.split("/")[0]
    m = re.fullmatch(r"\.NETFramework,Version=v(\d)\.(\d)(?:\.(\d))?", key)
    if m:
        return f"net{m.group(1)}{m.group(2)}{m.group(3) or ''}"
    m = re.fullmatch(r"\.NETCoreApp,Version=v(\d+\.\d+)(?:,Profile=.*)?", key)
    if m:
        return f"net{m.group(1)}" if int(m.group(1).split(".")[0]) >= 5 else f"netcoreapp{m.group(1)}"
    m = re.fullmatch(r"\.NETStandard,Version=v(\d+\.\d+)", key)
    if m:
        return f"netstandard{m.group(1)}"
    return key.lower()


def _tfm_base(tfm: str) -> str:
    return tfm.lower().split("-")[0]


def read_assets(path: str) -> dict:
    data = read_bytes_limited(path, 64 * 1024 * 1024)
    try:
        obj = json.loads(data.decode("utf-8-sig"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise FormatError("CORRUPT", f"project.assets.json を解析できない: {e}")
    targets = list(obj.get("targets", {}))
    return {"path": path, "targets": targets,
            "tfms": sorted({_norm_tfm_key(t) for t in targets}),
            "rids": sorted({t.split("/")[1] for t in targets if "/" in t})}


def assets_matches(assets: dict, tfms: list[str], rids: list[str]) -> tuple[list[str], list[str]]:
    """欠けている TFM と RID を返す。"""
    have = {_tfm_base(t) for t in assets["tfms"]}
    missing_tfm = [t for t in tfms if _tfm_base(t) not in have]
    missing_rid = [r for r in rids if r not in assets["rids"]]
    return missing_tfm, missing_rid


def resolve_reference(project_dir: str, value: str) -> str | None:
    """相対参照を絶対パスにする。式を含む値は静的に解決できないので None。"""
    if not value or "$(" in value or "@(" in value or "%" in value:
        return None
    return os.path.normpath(os.path.join(project_dir, value.replace("\\", os.sep)))


def find_build_artifacts(project_dir: str, max_files: int = 20) -> dict:
    """Directory.Build.targets、packages.lock.json、bin 配下の runtimeconfig / deps.json。"""
    out: dict = {"directory_build_targets": find_upward(project_dir, ("Directory.Build.targets",)),
                 "packages_lock": None, "runtimeconfigs": [], "deps_json_count": 0}
    lock = os.path.join(project_dir, "packages.lock.json")
    if os.path.isfile(lock):
        try:
            obj = json.loads(read_bytes_limited(lock, 64 * 1024 * 1024).decode("utf-8-sig"))
            out["packages_lock"] = {"path": lock, "version": obj.get("version"),
                                    "targets": sorted((obj.get("dependencies") or {}).keys())}
        except (FormatError, ValueError, OSError):
            out["packages_lock"] = {"path": lock, "error": True}
    bin_dir = os.path.join(project_dir, "bin")
    base_depth = bin_dir.rstrip(os.sep).count(os.sep)
    for cur, dirs, files in os.walk(bin_dir, followlinks=False):
        if cur.count(os.sep) - base_depth >= 4:
            dirs[:] = []
        for fn in sorted(files):
            full = os.path.join(cur, fn)
            if os.path.islink(full):
                continue
            if fn.endswith(".deps.json"):
                out["deps_json_count"] += 1
            elif fn.endswith(".runtimeconfig.json") and len(out["runtimeconfigs"]) < max_files:
                try:
                    opts = json.loads(read_bytes_limited(full, 1024 * 1024).decode("utf-8-sig")
                                      ).get("runtimeOptions", {})
                except (FormatError, ValueError, OSError):
                    out["runtimeconfigs"].append({"path": full, "error": True})
                    continue
                fws = opts.get("frameworks") or ([opts["framework"]] if "framework" in opts else [])
                out["runtimeconfigs"].append({
                    "path": full, "tfm": opts.get("tfm"),
                    "frameworks": [{"name": f.get("name"), "version": f.get("version")} for f in fws
                                   if isinstance(f, dict)]})
    return out
