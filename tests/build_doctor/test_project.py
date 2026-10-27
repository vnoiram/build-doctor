import json

import pytest
from helpers import SDK_CSPROJ, write

from build_doctor.parsers import FormatError
from build_doctor.parsers.project import (
    assets_matches,
    effective,
    parse_global_json,
    parse_nuget_sources,
    parse_project,
    parse_solution,
    read_assets,
)


def test_sdk_style_basics(tmp_path):
    p = write(
        tmp_path / "App.csproj",
        SDK_CSPROJ.format(tfm="net8.0", extra="<UseWPF>true</UseWPF>"),
    )
    info = parse_project(str(p))
    assert (
        info["sdk_style"]
        and info["tfms"] == ["net8.0"]
        and info["tfm_status"] == "CONFIGURED"
    )
    assert effective(info["properties"], "UseWPF") == ("true", "CONFIGURED")


def test_multiple_tfms_stay_separate(tmp_path):
    p = write(
        tmp_path / "App.csproj",
        SDK_CSPROJ.format(tfm="net8.0", extra="").replace(
            "<TargetFramework>net8.0</TargetFramework>",
            "<TargetFrameworks>net8.0;net472</TargetFrameworks>",
        ),
    )
    assert parse_project(str(p))["tfms"] == ["net8.0", "net472"]


def test_conditional_and_expanded_values_are_unevaluated(tmp_path):
    p = write(
        tmp_path / "App.csproj",
        """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)'=='Debug'"><PlatformTarget>x86</PlatformTarget></PropertyGroup>
  <PropertyGroup><RuntimeIdentifier>$(MyRid)</RuntimeIdentifier></PropertyGroup>
</Project>""",
    )
    props = parse_project(str(p))["properties"]
    assert effective(props, "PlatformTarget") == (None, "UNEVALUATED")
    assert effective(props, "RuntimeIdentifier") == (None, "UNEVALUATED")
    assert effective(props, "TargetFramework")[1] == "CONFIGURED"


def test_legacy_project(tmp_path):
    ns = 'xmlns="http://schemas.microsoft.com/developer/msbuild/2003"'
    p = write(
        tmp_path / "Old.csproj",
        f"""<Project ToolsVersion="15.0" {ns}>
  <PropertyGroup><TargetFrameworkVersion>v4.7.2</TargetFrameworkVersion><PlatformTarget>x86</PlatformTarget></PropertyGroup>
  <ItemGroup><Reference Include="Foo"><HintPath>..\\lib\\Foo.dll</HintPath></Reference></ItemGroup>
</Project>""",
    )
    info = parse_project(str(p))
    assert not info["sdk_style"] and info["tfms"] == ["net472"]
    assert info["references"]["reference"][0]["hint_path"] == "..\\lib\\Foo.dll"


def test_dtd_is_rejected(tmp_path):
    p = write(
        tmp_path / "Evil.csproj",
        '<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><Project>&a;</Project>',
    )
    with pytest.raises(FormatError) as e:
        parse_project(str(p))
    assert e.value.reason_code == "UNSUPPORTED_FORMAT"


def test_directory_build_props_is_recorded(tmp_path):
    write(
        tmp_path / "Directory.Build.props",
        "<Project><PropertyGroup><LangVersion>latest</LangVersion></PropertyGroup></Project>",
    )
    p = write(
        tmp_path / "src" / "App.csproj", SDK_CSPROJ.format(tfm="net8.0", extra="")
    )
    info = parse_project(str(p))
    assert (
        info["directory_build_props"]
        and info["properties"]["LangVersion"][0]["source"] == "Directory.Build.props"
    )


def test_global_json_with_comments_and_unknown_keys(tmp_path):
    p = write(
        tmp_path / "global.json",
        """{
  // comment
  "sdk": {"version": "8.0.100", "rollForward": "latestFeature", "future": 1},
  "newTop": {}
}""",
    )
    gj = parse_global_json(str(p))
    assert gj["version"] == "8.0.100" and gj["rollForward"] == "latestFeature"
    assert gj["unsupported_keys"] == ["newTop", "sdk.future"]


def test_nuget_sources_hide_credentials(tmp_path):
    p = write(
        tmp_path / "NuGet.Config",
        """<configuration><packageSources>
<add key="priv" value="https://user:pw@example.com/feed?token=abc" /></packageSources>
<packageSourceCredentials><priv><add key="Password" value="secret"/></priv></packageSourceCredentials>
</configuration>""",
    )
    out = parse_nuget_sources(str(tmp_path))
    assert out["sources"] == [
        {"key": "priv", "url": "https://***@example.com/feed?***"}
    ]
    assert "secret" not in json.dumps(out) and p.exists()


def test_solution_projects(tmp_path):
    write(tmp_path / "a" / "A.csproj", "<Project/>")
    sln = write(
        tmp_path / "S.sln",
        'Project("{FAE04EC0}") = "A", "a\\A.csproj", "{1}"\nEndProject\n',
    )
    assert parse_solution(str(sln)) == [str(tmp_path / "a" / "A.csproj")]


def test_assets_match(tmp_path):
    p = write(
        tmp_path / "project.assets.json",
        json.dumps({"targets": {"net6.0": {}, "net6.0/linux-x64": {}}}),
    )
    a = read_assets(str(p))
    assert assets_matches(a, ["net6.0"], ["linux-x64"]) == ([], [])
    assert assets_matches(a, ["net8.0"], ["win-x64"]) == (["net8.0"], ["win-x64"])
    a2 = read_assets(
        str(
            write(
                tmp_path / "f.json",
                json.dumps({"targets": {".NETFramework,Version=v4.7.2": {}}}),
            )
        )
    )
    assert assets_matches(a2, ["net472"], []) == ([], [])
