import io

import pytest

from build_doctor.parsers import FormatError
from build_doctor.parsers.logs import classify_line, parse_log

LINE = r"/src/App/Program.cs(12,5): error CS0246: The type or namespace name 'Foo' could not be found [/src/App/App.csproj]"


def test_msbuild_line_structure():
    d = classify_line(LINE)
    assert (d.severity, d.code, d.line, d.column) == ("error", "CS0246", 12, 5)
    assert d.file == "/src/App/Program.cs" and d.project == "/src/App/App.csproj"


def test_windows_path_without_line():
    d = classify_line(r"C:\src\App.csproj : error NU1101: Unable to find package")
    assert d.code == "NU1101" and d.file == r"C:\src\App.csproj"


def test_tool_prefix_and_no_code():
    assert classify_line("CSC : error CS2001: Source file missing").code == "CS2001"
    d = classify_line("MSBUILD : error : something odd")
    assert d is not None and d.code is None


def test_japanese_message_is_classified_by_code():
    d = classify_line(
        "Program.cs(3,1): error CS0246: 型または名前空間の名前 'Foo' が見つかりませんでした"
    )
    assert d.code == "CS0246"


def test_exception_names_are_language_independent():
    d = classify_line(
        "System.BadImageFormatException: 形式が正しくないプログラムを読み込もうとしました。"
    )
    assert d.code == "LOAD:BadImageFormatException"


def test_duplicates_are_aggregated():
    log = (LINE + "\n") * 3 + LINE.replace("CS0246", "CS0103") + "\n"
    diags, truncated = parse_log(io.BytesIO(log.encode()), 1 << 20)
    assert not truncated and len(diags) == 2
    assert {d.code: d.count for d in diags} == {"CS0246": 3, "CS0103": 1}


@pytest.mark.parametrize("enc,bom", [("utf-16", b""), ("utf-8-sig", b"")])
def test_bom_encodings(enc, bom):
    data = LINE.encode(enc)
    diags, _ = parse_log(io.BytesIO(data), 1 << 20)
    assert diags and diags[0].code == "CS0246"


def test_invalid_utf8_is_an_error_not_replacement():
    with pytest.raises(FormatError) as e:
        parse_log(io.BytesIO(b"abc \xff\xfe\xfa error"), 1 << 20)
    assert e.value.reason_code == "DECODE_ERROR"


def test_explicit_encoding_override():
    data = "Program.cs(1,1): error CS0103: 名前".encode("cp932")
    diags, _ = parse_log(io.BytesIO(data), 1 << 20, "cp932")
    assert diags[0].code == "CS0103"


def test_truncation_is_reported():
    log = (LINE + "\n") * 1000
    _, truncated = parse_log(io.BytesIO(log.encode()), 500)
    assert truncated
