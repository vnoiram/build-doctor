import json
import os

import pytest
from helpers import SDK_CSPROJ, fake_tool, make_pe, run_cli, validate, write

from build_doctor.collectors.dotnet import netfx_version
from build_doctor.parsers.project import find_build_artifacts, resolve_reference

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX シェルによる擬似ツール")


def jrun(*args, **kw):
    res = run_cli(*args, "--format", "json", **kw)
    return res, json.loads(res.stdout)


def rules(data):
    return [r["rule_id"] for r in data["records"]]


def csproj(tmp_path, body, name="App.csproj", tfm="net8.0"):
    return write(tmp_path / name, f"""<Project Sdk="Microsoft.NET.Sdk">
<PropertyGroup><TargetFramework>{tfm}</TargetFramework>{body}</PropertyGroup></Project>""")


def test_platform_target_vs_host_arch(tmp_path):
    p = csproj(tmp_path, "<PlatformTarget>x86</PlatformTarget>")
    _, data = jrun("inspect", str(p), "--static-only", "--host-arch", "x64")
    rec = next(r for r in data["records"] if r["rule_id"] == "ARCH003")
    assert rec["status"] == "CANDIDATE" and "x86" in rec["title"]


def test_platform_target_vs_rid(tmp_path):
    p = csproj(tmp_path, "<PlatformTarget>x86</PlatformTarget><RuntimeIdentifier>win-x64</RuntimeIdentifier>")
    _, data = jrun("inspect", str(p), "--static-only")
    assert any(r["rule_id"] == "ARCH003" and "RuntimeIdentifier" in r["title"] for r in data["records"])


def test_matching_platform_has_no_arch_finding(tmp_path):
    p = csproj(tmp_path, "<PlatformTarget>x64</PlatformTarget>")
    _, data = jrun("inspect", str(p), "--static-only", "--host-arch", "x64")
    assert "ARCH003" not in rules(data)


def test_conditional_platform_is_not_judged(tmp_path):
    p = write(tmp_path / "App.csproj", """<Project Sdk="Microsoft.NET.Sdk">
<PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
<PropertyGroup Condition="'$(X)'=='1'"><PlatformTarget>x86</PlatformTarget></PropertyGroup></Project>""")
    _, data = jrun("inspect", str(p), "--static-only", "--host-arch", "x64")
    assert "ARCH003" not in rules(data)


def test_missing_project_reference_and_hintpath(tmp_path):
    p = write(tmp_path / "App.csproj", """<Project Sdk="Microsoft.NET.Sdk">
<PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
<ItemGroup><ProjectReference Include="..\\Lib\\Lib.csproj"/>
<Reference Include="X"><HintPath>libs\\X.dll</HintPath></Reference>
<Reference Include="Y"><HintPath>$(Dir)\\Y.dll</HintPath></Reference></ItemGroup></Project>""")
    _, data = jrun("inspect", str(p), "--static-only")
    rec = next(r for r in data["records"] if r["rule_id"] == "DEP004")
    assert "Lib.csproj" in rec["meaning"] and "X.dll" in rec["meaning"] and "Y.dll" not in rec["meaning"]
    assert any(c.get("reason_code") == "UNEVALUATED_PROPERTY" and c["id"].startswith("references:")
               for c in data["checks"])


def test_existing_references_are_clean(tmp_path):
    write(tmp_path / "Lib" / "Lib.csproj", SDK_CSPROJ.format(tfm="net8.0", extra=""))
    p = write(tmp_path / "App" / "App.csproj", """<Project Sdk="Microsoft.NET.Sdk">
<PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
<ItemGroup><ProjectReference Include="..\\Lib\\Lib.csproj"/></ItemGroup></Project>""")
    _, data = jrun("inspect", str(p), "--static-only")
    assert "DEP004" not in rules(data)


FAKE = """\
case "$1" in
  --list-sdks) echo "{sdk} [{root}/sdk]";;
  --list-runtimes) echo "Microsoft.NETCore.App {rt} [{root}/shared]";;
  --info) printf '  Architecture: x64\\n  RID: linux-x64\\n';;
  --version) echo {sdk};;
esac
"""


def fake_dotnet(tmp_path, sdk="8.0.100", rt="6.0.0"):
    root = tmp_path / "dn"
    csc = root / "sdk" / sdk / "Roslyn" / "bincore" / "csc.dll"
    write(csc, "x")
    return fake_tool(tmp_path / "bin" / "dotnet", FAKE.format(sdk=sdk, rt=rt, root=root))


@posix_only
def test_exe_without_matching_runtime(tmp_path):
    dn = fake_dotnet(tmp_path, sdk="8.0.100", rt="6.0.0")
    p = csproj(tmp_path / "a", "<OutputType>Exe</OutputType>")
    res, data = jrun("inspect", str(p), "--dotnet-path", str(dn))
    assert "RT001" in rules(data) and "FX001" not in rules(data)
    sdk = next(f for f in data["facts"] if f["source"] == "dotnet")["value"]["sdks"][0]
    assert sdk["has_csc"] is True


@posix_only
def test_library_and_selfcontained_skip_runtime_rule(tmp_path):
    dn = fake_dotnet(tmp_path)
    lib = csproj(tmp_path / "lib", "")
    sc = csproj(tmp_path / "sc", "<OutputType>Exe</OutputType><SelfContained>true</SelfContained>")
    for p in (lib, sc):
        _, data = jrun("inspect", str(p), "--dotnet-path", str(dn))
        assert "RT001" not in rules(data)


@posix_only
def test_langversion_beyond_sdk(tmp_path):
    dn = fake_dotnet(tmp_path, sdk="8.0.100", rt="8.0.0")
    p = csproj(tmp_path / "a", "<LangVersion>14.0</LangVersion>")
    _, data = jrun("inspect", str(p), "--dotnet-path", str(dn))
    assert "CS003" in rules(data)
    ok = csproj(tmp_path / "b", "<LangVersion>latest</LangVersion>")
    _, data = jrun("inspect", str(ok), "--dotnet-path", str(dn))
    assert "CS003" not in rules(data)


@posix_only
def test_runtimeconfig_requires_missing_runtime(tmp_path):
    dn = fake_dotnet(tmp_path, rt="6.0.0")
    p = csproj(tmp_path / "a", "")
    write(tmp_path / "a" / "bin" / "Debug" / "net8.0" / "App.runtimeconfig.json", json.dumps(
        {"runtimeOptions": {"tfm": "net8.0", "framework": {"name": "Microsoft.NETCore.App", "version": "8.0.0"}}}))
    write(tmp_path / "a" / "bin" / "Debug" / "net8.0" / "App.deps.json", "{}")
    _, data = jrun("inspect", str(p), "--dotnet-path", str(dn))
    assert any(r["rule_id"] == "RT001" and "runtimeconfig" in r["title"] for r in data["records"])
    arts = next(f for f in data["facts"] if f["source"] == "build-artifacts")["value"]
    assert arts["deps_json_count"] == 1


def test_build_artifacts_and_lock(tmp_path):
    write(tmp_path / "Directory.Build.targets", "<Project/>")
    write(tmp_path / "p" / "packages.lock.json", json.dumps({"version": 1, "dependencies": {"net8.0": {}}}))
    arts = find_build_artifacts(str(tmp_path / "p"))
    assert arts["directory_build_targets"] and arts["packages_lock"]["targets"] == ["net8.0"]


def test_resolve_reference_skips_expressions(tmp_path):
    assert resolve_reference(str(tmp_path), "$(X)\\a.dll") is None
    assert resolve_reference(str(tmp_path), "a\\b.dll") == str(tmp_path / "a" / "b.dll")


def test_netfx_release_mapping():
    assert netfx_version(528040) == "4.8" and netfx_version(461808) == "4.7.2"
    assert netfx_version(378389) == "4.5" and netfx_version(100) is None


FAKE_PWSH = """\
cat >/dev/null
echo '{"ps_version":"7.4.0","edition":"Core","process_arch":"x64","language_mode":"FullLanguage",\
"parse_errors":[],"manifest":{"RootModule":"Mod.psm1","RequiredAssemblies":["lib/X.dll"],"NestedModules":["Name"]},\
"references":[{"command":"Add-Type","param":"path","line":1,"kind":"literal","value":"gone.dll"}]}'
"""


@posix_only
def test_powershell_missing_static_files(tmp_path):
    host = fake_tool(tmp_path / "bin" / "pwsh", FAKE_PWSH)
    psd1 = write(tmp_path / "m" / "Mod.psd1", "@{ RootModule='Mod.psm1' }")
    write(tmp_path / "m" / "Mod.psm1", "")
    res, data = jrun("inspect", str(psd1), "--powershell-path", str(host))
    assert not validate(data)
    rec = next(r for r in data["records"] if r["rule_id"] == "PS003")
    assert "X.dll" in rec["meaning"] and "gone.dll" in rec["meaning"]
    assert "Mod.psm1" not in rec["meaning"] and "Name" not in rec["meaning"]
