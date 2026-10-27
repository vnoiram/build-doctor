"""PE / ELF のヘッダー解析。対象をロード・実行せず、境界を検証しながら読む。"""

from __future__ import annotations

import struct
from typing import BinaryIO

from . import FormatError

PE_MACHINES = {
    0x14C: "x86",
    0x8664: "x64",
    0xAA64: "arm64",
    0x1C0: "arm",
    0x1C4: "arm",
    0x200: "ia64",
}
ELF_MACHINES = {3: "x86", 62: "x64", 183: "arm64", 40: "arm", 243: "riscv"}
ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared", 4: "core"}

COMIMAGE_ILONLY = 0x1
COMIMAGE_32BITREQUIRED = 0x2
COMIMAGE_STRONGNAMESIGNED = 0x8
COMIMAGE_NATIVE_ENTRYPOINT = 0x10
COMIMAGE_32BITPREFERRED = 0x20000

MAX_SECTIONS = 96


class _Reader:
    def __init__(self, f: BinaryIO, size: int):
        self.f, self.size = f, size

    def read(self, off: int, n: int) -> bytes:
        if off < 0 or n < 0 or off + n > self.size:
            raise FormatError(
                "CORRUPT",
                f"範囲外の読み取り (offset={off}, size={n}, file={self.size})",
            )
        self.f.seek(off)
        data = self.f.read(n)
        if len(data) != n:
            raise FormatError("CORRUPT", "ファイルが途中で終了している")
        return data

    def u16(self, off: int) -> int:
        return struct.unpack("<H", self.read(off, 2))[0]

    def u32(self, off: int) -> int:
        return struct.unpack("<I", self.read(off, 4))[0]


def detect_format(f: BinaryIO, size: int) -> str:
    head = _Reader(f, size).read(0, min(4, size)) if size else b""
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head[:2] == b"MZ":
        return "PE"
    raise FormatError("UNSUPPORTED_FORMAT", "PE / ELF ではない、または識別できない形式")


def parse_pe(f: BinaryIO, size: int) -> dict:
    r = _Reader(f, size)
    if size < 0x40 or r.read(0, 2) != b"MZ":
        raise FormatError("UNSUPPORTED_FORMAT", "MZ ヘッダーがない")
    pe_off = r.u32(0x3C)
    sig = r.read(pe_off, 4) if pe_off + 4 <= size else b""
    if sig[:2] in (b"NE", b"LE", b"LX"):
        raise FormatError("UNSUPPORTED_FORMAT", "16bit / DOS 系の実行形式は未対応")
    if sig != b"PE\0\0":
        raise FormatError("CORRUPT", "PE シグネチャが見つからない")

    coff = pe_off + 4
    machine_raw = r.u16(coff)
    n_sections = r.u16(coff + 2)
    opt_size = r.u16(coff + 16)
    characteristics = r.u16(coff + 18)
    if n_sections > MAX_SECTIONS:
        raise FormatError("CORRUPT", f"セクション数が異常 ({n_sections})")
    opt = coff + 20
    if opt_size < 70:
        raise FormatError("CORRUPT", "オプションヘッダーが小さすぎる")
    magic = r.u16(opt)
    if magic == 0x10B:
        pe_format, dd_off, count_off = "PE32", 96, 92
    elif magic == 0x20B:
        pe_format, dd_off, count_off = "PE32+", 112, 108
    else:
        raise FormatError(
            "UNSUPPORTED_FORMAT", f"未対応のオプションヘッダー magic=0x{magic:x}"
        )
    subsystem = r.u16(opt + 68)

    sections = []
    sec_off = opt + opt_size
    for i in range(n_sections):
        base = sec_off + 40 * i
        r.read(base, 40)
        vsize, va, raw_size, raw_ptr = struct.unpack("<IIII", r.read(base + 8, 16))
        sections.append((va, max(vsize, raw_size), raw_ptr, raw_size))

    def rva_to_off(rva: int) -> int:
        for va, span, ptr, raw in sections:
            if va <= rva < va + span:
                delta = rva - va
                if delta >= raw:
                    break
                return ptr + delta
        raise FormatError("CORRUPT", f"RVA 0x{rva:x} がセクションに含まれない")

    clr = None
    n_dirs = r.u32(opt + count_off) if count_off + 4 <= opt_size else 0
    if n_dirs > 14 and dd_off + 15 * 8 <= opt_size:
        com_rva, com_size = struct.unpack("<II", r.read(opt + dd_off + 14 * 8, 8))
        if com_rva and com_size:
            if com_size < 72:
                raise FormatError("CORRUPT", "CLR ヘッダーのサイズが小さすぎる")
            cor = rva_to_off(com_rva)
            cb = r.u32(cor)
            if cb < 72:
                raise FormatError("CORRUPT", "CLR ヘッダーの cb が不正")
            flags = r.u32(cor + 16)
            clr = {
                "runtime_version": f"{r.u16(cor + 4)}.{r.u16(cor + 6)}",
                "flags": flags,
                "ilonly": bool(flags & COMIMAGE_ILONLY),
                "requires_32bit": bool(flags & COMIMAGE_32BITREQUIRED),
                "prefers_32bit": bool(flags & COMIMAGE_32BITPREFERRED),
                "strong_name_signed": bool(flags & COMIMAGE_STRONGNAMESIGNED),
                "native_entrypoint": bool(flags & COMIMAGE_NATIVE_ENTRYPOINT),
            }

    machine = PE_MACHINES.get(machine_raw, f"other(0x{machine_raw:x})")
    result = {
        "format": "PE",
        "pe_format": pe_format,
        "machine": machine,
        "machine_raw": f"0x{machine_raw:x}",
        "is_dll": bool(characteristics & 0x2000),
        "subsystem": subsystem,
        "managed": clr is not None,
        "clr": clr,
    }
    result.update(_classify_pe(machine, clr))
    return result


def _classify_pe(machine: str, clr: dict | None) -> dict:
    """arch: 実行に必要な CPU。PE32 であるだけで x86 専用とはしない。"""
    if clr is None:
        return {"arch": machine, "kind": "native", "mixed_mode": False}
    if machine == "x86":
        if clr["requires_32bit"] or not clr["ilonly"]:
            arch = "x86"
        elif clr["prefers_32bit"]:
            arch = "anycpu-prefer32"
        else:
            arch = "anycpu"
    else:
        arch = machine
    return {"arch": arch, "kind": "managed", "mixed_mode": not clr["ilonly"]}


def parse_elf(f: BinaryIO, size: int) -> dict:
    r = _Reader(f, size)
    if size < 20 or r.read(0, 4) != b"\x7fELF":
        raise FormatError("UNSUPPORTED_FORMAT", "ELF ヘッダーがない")
    ei_class, ei_data = r.read(4, 2)
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise FormatError("CORRUPT", "ELF の class / data が不正")
    endian = "<" if ei_data == 1 else ">"
    e_type, e_machine = struct.unpack(endian + "HH", r.read(16, 4))
    machine = ELF_MACHINES.get(e_machine, f"other({e_machine})")
    return {
        "format": "ELF",
        "elf_class": 32 if ei_class == 1 else 64,
        "endian": "little" if ei_data == 1 else "big",
        "type": ELF_TYPES.get(e_type, f"other({e_type})"),
        "machine": machine,
        "arch": machine,
        "kind": "native",
        "managed": False,
        "mixed_mode": False,
    }


def parse_binary(f: BinaryIO, size: int) -> dict:
    kind = detect_format(f, size)
    return parse_pe(f, size) if kind == "PE" else parse_elf(f, size)
