import io

import pytest
from helpers import make_elf, make_pe

from build_doctor.parsers import FormatError
from build_doctor.parsers.binary import parse_binary


def parse(data: bytes) -> dict:
    return parse_binary(io.BytesIO(data), len(data))


def test_pe32_is_not_automatically_x86_only():
    # PE32 + ILONLY のみ = AnyCPU
    info = parse(make_pe(0x14C, clr_flags=0x1))
    assert info["pe_format"] == "PE32" and info["arch"] == "anycpu" and info["managed"]


def test_32bitreq_is_x86():
    assert parse(make_pe(0x14C, clr_flags=0x1 | 0x2))["arch"] == "x86"


def test_prefer32_is_anycpu_prefer32():
    assert parse(make_pe(0x14C, clr_flags=0x1 | 0x20000))["arch"] == "anycpu-prefer32"


def test_mixed_mode_x86():
    info = parse(make_pe(0x14C, clr_flags=0x0))
    assert info["arch"] == "x86" and info["mixed_mode"]


def test_x64_managed_and_native():
    assert parse(make_pe(0x8664, pe32plus=True, clr_flags=0x1))["arch"] == "x64"
    native = parse(make_pe(0x8664, pe32plus=True))
    assert native["arch"] == "x64" and native["kind"] == "native" and not native["managed"]


def test_arm64_native():
    assert parse(make_pe(0xAA64, pe32plus=True))["arch"] == "arm64"


def test_elf():
    info = parse(make_elf(62))
    assert info["format"] == "ELF" and info["arch"] == "x64" and info["elf_class"] == 64
    assert parse(make_elf(183))["arch"] == "arm64"


@pytest.mark.parametrize("data,code", [
    (b"", "UNSUPPORTED_FORMAT"),
    (b"hello world, not a binary", "UNSUPPORTED_FORMAT"),
    (b"MZ" + b"\0" * 10, "UNSUPPORTED_FORMAT"),
    (make_pe(clr_flags=1)[:100], "CORRUPT"),
    (make_pe(clr_flags=1, bad_rva=True), "CORRUPT"),
])
def test_broken_inputs_do_not_crash(data, code):
    with pytest.raises(FormatError) as e:
        parse(data)
    assert e.value.reason_code == code


def test_huge_pe_offset():
    data = bytearray(make_pe())
    data[0x3C:0x40] = (0x7FFFFFF0).to_bytes(4, "little")
    with pytest.raises(FormatError):
        parse(bytes(data))
