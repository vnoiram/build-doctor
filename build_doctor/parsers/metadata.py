"""CLR メタデータ(ECMA-335)の静的読み取り。AssemblyRef と P/Invoke(ImplMap)のモジュール名のみ。

対象をロードせず、テーブル行サイズを計算して必要な行だけを境界検証付きで読む。
"""

from __future__ import annotations

import struct

from . import FormatError

MAX_METADATA = 64 * 1024 * 1024
MAX_ROWS = 20000
MAX_STREAMS = 16

# 符号付き索引: (タグのビット数, 参照先テーブル)
CODED = {
    "TypeDefOrRef": (2, [0x02, 0x01, 0x1B]),
    "ResolutionScope": (2, [0x00, 0x1A, 0x23, 0x01]),
    "HasConstant": (2, [0x04, 0x08, 0x17]),
    "HasCustomAttribute": (
        5,
        [
            0x06,
            0x04,
            0x01,
            0x02,
            0x08,
            0x09,
            0x0A,
            0x00,
            0x0E,
            0x17,
            0x14,
            0x11,
            0x1A,
            0x1B,
            0x20,
            0x23,
            0x26,
            0x27,
            0x28,
            0x2A,
            0x2C,
            0x2B,
        ],
    ),
    "HasFieldMarshal": (1, [0x04, 0x08]),
    "HasDeclSecurity": (2, [0x02, 0x06, 0x20]),
    "MemberRefParent": (3, [0x02, 0x01, 0x1A, 0x06, 0x1B]),
    "HasSemantics": (1, [0x14, 0x17]),
    "MethodDefOrRef": (1, [0x06, 0x0A]),
    "MemberForwarded": (1, [0x04, 0x06]),
    "Implementation": (2, [0x26, 0x23, 0x27]),
    "CustomAttributeType": (3, [0x06, 0x0A]),
    "TypeOrMethodDef": (1, [0x02, 0x06]),
}

# 列: 整数=固定バイト数, "S"/"G"/"B"=ヒープ索引, "T:n"=単純テーブル索引, 他=符号付き索引名
TABLES: dict[int, list] = {
    0x00: [2, "S", "G", "G", "G"],
    0x01: ["ResolutionScope", "S", "S"],
    0x02: [4, "S", "S", "TypeDefOrRef", "T:4", "T:6"],
    0x03: ["T:4"],
    0x04: [2, "S", "B"],
    0x05: ["T:6"],
    0x06: [4, 2, 2, "S", "B", "T:8"],
    0x07: ["T:8"],
    0x08: [2, 2, "S"],
    0x09: ["T:2", "TypeDefOrRef"],
    0x0A: ["MemberRefParent", "S", "B"],
    0x0B: [2, "HasConstant", "B"],
    0x0C: ["HasCustomAttribute", "CustomAttributeType", "B"],
    0x0D: ["HasFieldMarshal", "B"],
    0x0E: [2, "HasDeclSecurity", "B"],
    0x0F: [2, 4, "T:2"],
    0x10: [4, "T:4"],
    0x11: ["B"],
    0x12: ["T:2", "T:20"],
    0x13: ["T:20"],
    0x14: [2, "S", "TypeDefOrRef"],
    0x15: ["T:2", "T:23"],
    0x16: ["T:23"],
    0x17: [2, "S", "B"],
    0x18: [2, "T:6", "HasSemantics"],
    0x19: ["T:2", "MethodDefOrRef", "MethodDefOrRef"],
    0x1A: ["S"],
    0x1B: ["B"],
    0x1C: [2, "MemberForwarded", "S", "T:26"],
    0x1D: [4, "T:4"],
    0x1E: [4, 4],
    0x1F: [4],
    0x20: [4, 2, 2, 2, 2, 4, "B", "S", "S"],
    0x21: [4],
    0x22: [4, 4, 4],
    0x23: [2, 2, 2, 2, 4, "B", "S", "S", "B"],
    0x24: [4, "T:35"],
    0x25: [4, 4, 4, "T:35"],
    0x26: [4, "S", "B"],
    0x27: [4, 4, "S", "S", "Implementation"],
    0x28: [4, 4, "S", "Implementation"],
    0x29: ["T:2", "T:2"],
    0x2A: [2, 2, "TypeOrMethodDef", "S"],
    0x2B: ["MethodDefOrRef", "B"],
    0x2C: ["T:42", "TypeDefOrRef"],
}
# "T:n" の n は 10 進のテーブル番号(例: T:20 = 0x14)。


def _index_size(rows: dict[int, int], col, heap_sizes: int) -> int:
    if isinstance(col, int):
        return col
    if col == "S":
        return 4 if heap_sizes & 1 else 2
    if col == "G":
        return 4 if heap_sizes & 2 else 2
    if col == "B":
        return 4 if heap_sizes & 4 else 2
    if col.startswith("T:"):
        return 4 if rows.get(int(col[2:]), 0) >= 0x10000 else 2
    bits, targets = CODED[col]
    biggest = max(rows.get(t, 0) for t in targets)
    return 4 if biggest >= (1 << (16 - bits)) else 2


def parse_metadata(read, base: int, size: int) -> dict:
    """read(off, n) -> bytes は境界検証付き。base はファイル内オフセット。"""
    if size < 32 or size > MAX_METADATA:
        raise FormatError("CORRUPT", "メタデータのサイズが不正")
    if struct.unpack("<I", read(base, 4))[0] != 0x424A5342:
        raise FormatError("CORRUPT", "メタデータのシグネチャが不正")
    vlen = struct.unpack("<I", read(base + 12, 4))[0]
    if vlen > 255 or 16 + vlen + 4 > size:
        raise FormatError("CORRUPT", "メタデータのバージョン長が不正")
    pos = 16 + vlen
    n_streams = struct.unpack("<H", read(base + pos + 2, 2))[0]
    if n_streams > MAX_STREAMS:
        raise FormatError("CORRUPT", "メタデータのストリーム数が異常")
    pos += 4
    streams: dict[str, tuple[int, int]] = {}
    for _ in range(n_streams):
        off, ssize = struct.unpack("<II", read(base + pos, 8))
        name_raw = read(base + pos + 8, min(32, size - pos - 8))
        end = name_raw.find(b"\0")
        if end < 0:
            raise FormatError("CORRUPT", "ストリーム名が終端しない")
        streams[name_raw[:end].decode("ascii", errors="replace")] = (off, ssize)
        pos += 8 + ((end + 1 + 3) & ~3)
    for name, (off, ssize) in streams.items():
        if off + ssize > size:
            raise FormatError("CORRUPT", f"ストリーム {name} がメタデータ範囲外")
    tab = streams.get("#~") or streams.get("#-")
    strings = streams.get("#Strings")
    if not tab or not strings:
        raise FormatError("CORRUPT", "テーブル/文字列ストリームがない")

    t0 = base + tab[0]
    heap_sizes = read(t0 + 6, 1)[0]
    valid = struct.unpack("<Q", read(t0 + 8, 8))[0]
    p = t0 + 24
    rows: dict[int, int] = {}
    for t in range(64):
        if valid >> t & 1:
            if t not in TABLES:
                raise FormatError(
                    "UNSUPPORTED_FORMAT", f"未対応のメタデータテーブル 0x{t:x}"
                )
            rows[t] = struct.unpack("<I", read(p, 4))[0]
            p += 4

    offsets: dict[int, tuple[int, int]] = {}
    for t in sorted(rows):
        row_size = sum(_index_size(rows, c, heap_sizes) for c in TABLES[t])
        offsets[t] = (p, row_size)
        p += row_size * rows[t]
    if p > t0 + tab[1]:
        raise FormatError("CORRUPT", "テーブルがストリームの範囲を超える")

    s_base = base + strings[0]

    def string(idx: int) -> str:
        if idx >= strings[1]:
            raise FormatError("CORRUPT", "文字列ヒープの索引が範囲外")
        n = min(260, strings[1] - idx)
        raw = read(s_base + idx, n)
        end = raw.find(b"\0")
        if end < 0:
            raise FormatError("CORRUPT", "終端のない文字列")
        return raw[:end].decode("utf-8", errors="replace")

    def column(table: int, row: int, col: int) -> int:
        start, rsize = offsets[table]
        off = start + rsize * row
        for c in TABLES[table][:col]:
            off += _index_size(rows, c, heap_sizes)
        width = _index_size(rows, TABLES[table][col], heap_sizes)
        return int.from_bytes(read(off, width), "little")

    def bounded(table: int) -> int:
        n = rows.get(table, 0)
        if n > MAX_ROWS:
            raise FormatError("CORRUPT", f"テーブル 0x{table:x} の行数が異常 ({n})")
        return n

    assembly_refs = []
    for i in range(bounded(0x23)):
        start, rsize = offsets[0x23]
        major, minor, build, rev = struct.unpack("<HHHH", read(start + rsize * i, 8))
        assembly_refs.append(
            {
                "name": string(column(0x23, i, 6)),
                "version": f"{major}.{minor}.{build}.{rev}",
            }
        )

    modules = [string(column(0x1A, i, 0)) for i in range(bounded(0x1A))]
    pinvoke: dict[str, int] = {}
    for i in range(bounded(0x1C)):
        ref = column(0x1C, i, 3)
        if not 1 <= ref <= len(modules):
            raise FormatError("CORRUPT", "ImplMap の ModuleRef 索引が不正")
        pinvoke[modules[ref - 1]] = pinvoke.get(modules[ref - 1], 0) + 1
    return {
        "assembly_refs": assembly_refs[:512],
        "pinvoke_modules": [
            {"name": n, "imports": c} for n, c in sorted(pinvoke.items())
        ][:512],
        "module_refs": sorted(set(modules))[:512],
    }
