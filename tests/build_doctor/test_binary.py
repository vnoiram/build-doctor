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
    assert (
        native["arch"] == "x64" and native["kind"] == "native" and not native["managed"]
    )


def test_arm64_native():
    assert parse(make_pe(0xAA64, pe32plus=True))["arch"] == "arm64"


def test_elf():
    info = parse(make_elf(62))
    assert info["format"] == "ELF" and info["arch"] == "x64" and info["elf_class"] == 64
    assert parse(make_elf(183))["arch"] == "arm64"


@pytest.mark.parametrize(
    "data,code",
    [
        (b"", "UNSUPPORTED_FORMAT"),
        (b"hello world, not a binary", "UNSUPPORTED_FORMAT"),
        (b"MZ" + b"\0" * 10, "UNSUPPORTED_FORMAT"),
        (make_pe(clr_flags=1)[:100], "CORRUPT"),
        (make_pe(clr_flags=1, bad_rva=True), "CORRUPT"),
    ],
)
def test_broken_inputs_do_not_crash(data, code):
    with pytest.raises(FormatError) as e:
        parse(data)
    assert e.value.reason_code == code


def test_huge_pe_offset():
    data = bytearray(make_pe())
    data[0x3C:0x40] = (0x7FFFFFF0).to_bytes(4, "little")
    with pytest.raises(FormatError):
        parse(bytes(data))


def test_pe_import_names_are_listed():
    info = parse(make_pe(0x8664, pe32plus=True, imports="native.dll"))
    assert info["imports"] == ["native.dll"] and info["imports_error"] is None


def test_pe_without_imports_has_empty_list():
    assert parse(make_pe(0x8664, pe32plus=True))["imports"] == []


def test_elf_without_section_headers_has_no_needed():
    info = parse(make_elf())
    assert info["needed"] == [] and info["needed_error"] is None


def test_elf_needed_from_real_binary():
    import os

    path = "/bin/ls"
    if not os.path.isfile(path):
        pytest.skip("no sample ELF")
    with open(path, "rb") as f:
        info = parse_binary(f, os.path.getsize(path))
    assert any(n.startswith("libc.") for n in info["needed"])


def test_managed_metadata_assembly_refs_and_pinvoke_modules():
    from helpers import make_metadata

    md = make_metadata(["System.Runtime", "Other.Lib"], ["native.dll", "kernel32.dll"])
    info = parse(make_pe(0x14C, clr_flags=0x1, metadata=md))
    meta = info["clr"]["metadata"]
    assert [a["name"] for a in meta["assembly_refs"]] == ["System.Runtime", "Other.Lib"]
    assert meta["assembly_refs"][0]["version"] == "1.2.3.4"
    assert {m["name"] for m in meta["pinvoke_modules"]} == {
        "native.dll",
        "kernel32.dll",
    }
    assert info["clr"]["metadata_error"] is None


def test_corrupt_metadata_is_reported_not_raised():
    from helpers import make_metadata

    md = bytearray(make_metadata(["A"], ["m.dll"]))
    md[0:4] = b"XXXX"
    info = parse(make_pe(0x14C, clr_flags=0x1, metadata=bytes(md)))
    assert info["clr"]["metadata"] is None
    assert info["clr"]["metadata_error"]["reason_code"] == "CORRUPT"
