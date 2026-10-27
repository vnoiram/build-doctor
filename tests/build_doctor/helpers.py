"""テスト用の fixture 生成と最小スキーマ検証。バイナリ fixture はコミットせず都度生成する。"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads(
    (ROOT / "schemas" / "build-doctor-v1.schema.json").read_text(encoding="utf-8")
)


def make_pe(
    machine: int = 0x14C,
    pe32plus: bool = False,
    clr_flags: int | None = None,
    dll: bool = True,
    truncate: int | None = None,
    bad_rva: bool = False,
    imports: str | None = None,
    metadata: bytes | None = None,
    r2r: bool = False,
    trailer: bytes = b"",
) -> bytes:
    """最小の PE。clr_flags が None ならネイティブ。"""
    opt_size = 240 if pe32plus else 224
    dd_off = 112 if pe32plus else 96
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B if pe32plus else 0x10B)
    struct.pack_into("<H", opt, 68, 3)
    struct.pack_into("<I", opt, 108 if pe32plus else 92, 16)
    if clr_flags is not None:
        struct.pack_into(
            "<II", opt, dd_off + 14 * 8, 0xDEAD000 if bad_rva else 0x1000, 72
        )
    if imports is not None:
        struct.pack_into("<II", opt, dd_off + 8, 0x1100, 40)
    chars = 0x2000 if dll else 0x0002
    coff = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, opt_size, chars)
    body_size = 0x200 + (len(metadata) if metadata else 0)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text",
        body_size,
        0x1000,
        body_size,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    header = bytearray(0x200)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\0\0"
    blob = coff + bytes(opt) + section
    header[0x44 : 0x44 + len(blob)] = blob
    body = bytearray(body_size)
    if clr_flags is not None:
        struct.pack_into("<IHH", body, 0, 72, 2, 5)
        struct.pack_into("<I", body, 16, clr_flags)
        if r2r:
            struct.pack_into("<II", body, 64, 0x1300, 16)
        if metadata:
            struct.pack_into("<II", body, 8, 0x1200, len(metadata))
            body[0x200 : 0x200 + len(metadata)] = metadata
    if imports is not None:
        struct.pack_into("<I", body, 0x100 + 12, 0x1180)
        body[0x180 : 0x180 + len(imports) + 1] = imports.encode() + b"\0"
    data = bytes(header) + bytes(body) + trailer
    return data[:truncate] if truncate is not None else data


def make_metadata(assembly_refs: list[str], modules: list[str]) -> bytes:
    """AssemblyRef / ModuleRef / ImplMap(各モジュール 1 件)のみを持つ最小メタデータ。"""
    strings = bytearray(b"\0")

    def s(text: str) -> int:
        off = len(strings)
        strings.extend(text.encode() + b"\0")
        return off

    asm = b"".join(
        struct.pack("<HHHHIHHHH", 1, 2, 3, 4, 0, 0, s(n), 0, 0) for n in assembly_refs
    )
    mod = b"".join(struct.pack("<H", s(n)) for n in modules)
    impl = b"".join(
        struct.pack("<HHHH", 0, 0, s("Fn"), i + 1) for i in range(len(modules))
    )
    valid = (1 << 0x1A) | (1 << 0x1C) | (1 << 0x23)
    tab = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid, 0)
    tab += struct.pack("<III", len(modules), len(modules), len(assembly_refs))
    tab += mod + impl + asm
    while len(tab) % 4:
        tab += b"\0"
    while len(strings) % 4:
        strings += b"\0"
    version = b"v4.0.30319\0\0"
    head_len = 16 + len(version) + 4 + (8 + 4) + (8 + 12)
    streams = struct.pack("<II4s", head_len, len(tab), b"#~\0\0")
    streams += struct.pack(
        "<II12s", head_len + len(tab), len(strings), b"#Strings\0\0\0\0"
    )
    root = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)) + version
    root += struct.pack("<HH", 0, 2) + streams
    assert len(root) == head_len
    return root + tab + bytes(strings)


def make_elf(machine: int = 62, cls: int = 2) -> bytes:
    h = bytearray(64)
    h[0:4] = b"\x7fELF"
    h[4], h[5], h[6] = cls, 1, 1
    struct.pack_into("<HH", h, 16, 3, machine)
    return bytes(h)


def write(path: Path, data: bytes | str, mode: int | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)
    if mode is not None:
        path.chmod(mode)
    return path


def fake_tool(path: Path, script: str) -> Path:
    """POSIX シェルスクリプトによる擬似ツール。"""
    write(path, "#!/bin/sh\n" + script, 0o755)
    return path


def run_cli(
    *args: str,
    cwd: Path | None = None,
    stdin: bytes | None = None,
    env: dict | None = None,
) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    full_env.pop("NO_COLOR", None)
    full_env["PYTHONIOENCODING"] = "utf-8"
    if env:
        full_env.update(env)
    return subprocess.run(  # noqa: PLW1510
        [sys.executable, str(ROOT / "build_doctor.py"), *args],
        cwd=cwd,
        input=stdin,
        capture_output=True,
        env=full_env,
        timeout=120,
    )


def validate(instance, schema=SCHEMA, path="$") -> list[str]:
    """テストに必要な範囲の JSON Schema 検証(type/enum/const/required/properties/items)。"""
    errs: list[str] = []
    if "const" in schema and instance != schema["const"]:
        errs.append(f"{path}: const {schema['const']!r} != {instance!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errs.append(f"{path}: {instance!r} not in {schema['enum']}")
    types = schema.get("type")
    if types:
        names = types if isinstance(types, list) else [types]
        py = {
            "string": str,
            "integer": int,
            "boolean": bool,
            "object": dict,
            "array": list,
            "null": type(None),
        }
        if not any(
            isinstance(instance, py[n])
            and not (n == "integer" and isinstance(instance, bool))
            for n in names
        ):
            errs.append(f"{path}: type {names} != {type(instance).__name__}")
            return errs
    if isinstance(instance, dict):
        for k in schema.get("required", []):
            if k not in instance:
                errs.append(f"{path}: missing {k}")
        for k, sub in schema.get("properties", {}).items():
            if k in instance:
                errs += validate(instance[k], sub, f"{path}.{k}")
    if isinstance(instance, list) and "items" in schema:
        for i, item in enumerate(instance):
            errs += validate(item, schema["items"], f"{path}[{i}]")
    return errs


SDK_CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>{tfm}</TargetFramework>
    {extra}
  </PropertyGroup>
</Project>
"""
