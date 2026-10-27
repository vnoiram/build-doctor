"""ビルドログの解析。エラーコードと構造情報を優先し、文言には依存しない。"""

from __future__ import annotations

import codecs
import re
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from . import FormatError

_PROJ = re.compile(r"\s*\[(?P<proj>[^\[\]]+\.(?:csproj|vbproj|fsproj|sln|proj|props|targets))\]\s*$",
                   re.IGNORECASE)
_LOC = re.compile(
    r"^\s*(?P<file>.+?)\((?P<line>\d+)(?:,(?P<col>\d+))?(?:,\d+,\d+)?\)\s*:\s*"
    r"(?:[\w ]+? )?(?P<sev>error|warning)\s+(?P<code>[A-Za-z][A-Za-z0-9]*\d)?\s*:\s*(?P<msg>.*)$")
_TOOL = re.compile(
    r"^\s*(?P<file>(?:[A-Za-z]:)?[^:]*?)\s*:\s*(?:[\w ]+? )?(?P<sev>error|warning)\s+"
    r"(?P<code>[A-Za-z][A-Za-z0-9]*\d)?\s*:\s*(?P<msg>.*)$")
_EXC = re.compile(r"\b(?P<exc>(?:System\.(?:IO\.)?)?(?:BadImageFormatException|FileNotFoundException|"
                  r"FileLoadException|DllNotFoundException))\b")
_PSERR = re.compile(r"\b(ParseException|ParserError)\b")

LOG_ENCODING_BOMS = ((codecs.BOM_UTF8, "utf-8-sig"), (codecs.BOM_UTF16_LE, "utf-16"),
                     (codecs.BOM_UTF16_BE, "utf-16"))


@dataclass
class Diagnostic:
    severity: str  # error / warning
    code: str | None
    message: str
    file: str | None = None
    line: int | None = None
    column: int | None = None
    project: str | None = None
    count: int = 1

    def key(self) -> tuple:
        return (self.severity, self.code, self.file, self.line, self.column, self.project,
                self.message)

    @property
    def class_code(self) -> str:
        return self.code or "UNCLASSIFIED"


def classify_line(line: str) -> Diagnostic | None:
    text = line.rstrip("\r\n")
    project = None
    m = _PROJ.search(text)
    if m:
        project = m.group("proj")
        text = text[:m.start()]
    for pat in (_LOC, _TOOL):
        m = pat.match(text)
        if m:
            d = Diagnostic(severity=m.group("sev"), code=m.group("code"),
                           message=m.group("msg").strip(), project=project)
            file = m.group("file").strip()
            d.file = file or None
            if pat is _LOC:
                d.line = int(m.group("line"))
                d.column = int(m.group("col")) if m.group("col") else None
            return d
    m = _EXC.search(text)
    if m:
        return Diagnostic("error", "LOAD:" + m.group("exc").split(".")[-1], text.strip()[:300],
                          project=project)
    m = _PSERR.search(text)
    if m:
        return Diagnostic("error", "PS:ParseException", text.strip()[:300], project=project)
    return None


def detect_encoding(head: bytes, override: str | None) -> str:
    if override:
        try:
            codecs.lookup(override)
        except LookupError:
            raise FormatError("UNSUPPORTED_FORMAT", f"未知のエンコーディング: {override}")
        return override
    for bom, enc in LOG_ENCODING_BOMS:
        if head.startswith(bom):
            return enc
    return "utf-8"


def iter_lines(stream: BinaryIO, max_bytes: int, encoding: str | None = None
               ) -> Iterator[tuple[str, bool]]:
    """(行, 打ち切りか) を返す。復号失敗は黙って置換せず FormatError にする。"""
    first = stream.read(65536)
    enc = detect_encoding(first, encoding)
    decoder = codecs.getincrementaldecoder(enc)(errors="strict")
    consumed, pending, chunk = 0, "", first
    while True:
        truncated = False
        if consumed + len(chunk) > max_bytes:
            chunk = chunk[:max(max_bytes - consumed, 0)]
            truncated = True
        consumed += len(chunk)
        try:
            pending += decoder.decode(chunk, final=not chunk)
        except UnicodeDecodeError as e:
            raise FormatError("DECODE_ERROR",
                              f"{enc} として復号できない (byte {consumed - len(chunk) + e.start})。"
                              "--input-encoding を指定してください")
        *lines, pending = pending.split("\n")
        for ln in lines:
            yield ln, False
        if truncated or not chunk:
            break
        chunk = stream.read(65536)
    if pending:
        yield pending, False
    if truncated:
        yield "", True


def parse_log(stream: BinaryIO, max_bytes: int, encoding: str | None = None
              ) -> tuple[list[Diagnostic], bool]:
    """重複を集約した診断一覧と、入力が上限で打ち切られたかを返す。"""
    seen: dict[tuple, Diagnostic] = {}
    truncated = False
    for line, cut in iter_lines(stream, max_bytes, encoding):
        if cut:
            truncated = True
            continue
        d = classify_line(line)
        if d is None:
            continue
        existing = seen.get(d.key())
        if existing:
            existing.count += 1
        else:
            seen[d.key()] = d
    return list(seen.values()), truncated
