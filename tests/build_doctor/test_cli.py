import json
import os

import pytest
from helpers import SDK_CSPROJ, fake_tool, make_elf, make_pe, run_cli, validate, write

posix_only = pytest.mark.skipif(
    os.name != "posix", reason="POSIX シェルによる擬似ツール"
)

FAKE_DOTNET = """\
case "$1" in
  --list-sdks) echo "7.0.100 [/fake/sdk]";;
  --list-runtimes) echo "Microsoft.NETCore.App 7.0.0 [/fake/shared]";;
  --info) printf '  Architecture: x64\\n  RID: linux-x64\\n';;
  --version) echo 7.0.100;;
  build)
    touch generated.marker
    echo "Program.cs(1,1): error CS0246: missing [$2]"
    exit ${FAKE_BUILD_EXIT:-1};;
esac
"""


def jrun(*args, **kw):
    res = run_cli(*args, "--format", "json", **kw)
    return res, (json.loads(res.stdout) if res.stdout.strip() else None)


def rule_ids(data):
    return [r["rule_id"] for r in data["records"]]


@pytest.fixture
def dotnet(tmp_path):
    return fake_tool(tmp_path / "bin" / "dotnet", FAKE_DOTNET)


# ---------------------------------------------------------------- CLI の基本
def test_no_args_prints_usage_and_does_not_wait():
    res = run_cli()
    assert (
        res.returncode == 2 and b"build_doctor.py" in res.stderr and res.stdout == b""
    )


def test_version_and_help_do_not_query_tools():
    assert run_cli("--version").returncode == 0
    assert run_cli("inspect", "--help").returncode == 0


def test_missing_target_is_usage_error(tmp_path):
    res = run_cli("inspect", str(tmp_path / "nope.dll"))
    assert res.returncode == 2 and res.stdout == b""


def test_env_without_tools_still_runs(tmp_path):
    res, data = jrun(
        "env",
        "--dotnet-path",
        "/nonexistent/dotnet",
        "--powershell-path",
        "/nonexistent/pwsh",
    )
    assert not validate(data), validate(data)
    reasons = {c.get("reason_code") for c in data["checks"]}
    assert "TOOL_MISSING" in reasons and res.returncode == 3


def test_env_static_only_skips_tools(tmp_path, dotnet):
    res, data = jrun("env", "--static-only", "--dotnet-path", str(dotnet))
    assert res.returncode == 0
    assert [c["outcome"] for c in data["checks"] if c["id"].endswith("discovery")] == [
        "skipped"
    ] * 3


# ---------------------------------------------------------------- 32/64bit
def test_x86_dll_on_x64_host_is_confirmed_mismatch(tmp_path):
    dll = write(tmp_path / "lib" / "Example.dll", make_pe(0x14C, clr_flags=0x3))
    res, data = jrun("inspect", str(dll), "--host-arch", "x64")
    assert not validate(data), validate(data)
    assert res.returncode == 1 and rule_ids(data) == ["ARCH001"]
    rec = data["records"][0]
    assert (
        rec["status"] == "CONFIRMED"
        and rec["evidence_refs"]
        and rec["limit"]
        and rec["next"]
    )
    assert res.stderr == b"" or b"\xe3" not in res.stdout[:0]


def test_anycpu_dll_on_x64_host_is_fine(tmp_path):
    dll = write(tmp_path / "Any.dll", make_pe(0x14C, clr_flags=0x1))
    res, data = jrun("inspect", str(dll), "--host-arch", "x64")
    assert res.returncode == 0 and data["records"] == []


def test_anycpu_with_x86_native_dependency_blames_the_boundary(tmp_path):
    dll = write(tmp_path / "Any.dll", make_pe(0x14C, clr_flags=0x1))
    native = write(tmp_path / "native.dll", make_pe(0x14C))
    _res, data = jrun(
        "inspect", str(dll), "--host-arch", "x64", "--native-dep", str(native)
    )
    assert (
        rule_ids(data) == ["ARCH002"]
        and "ネイティブ境界" in data["records"][0]["meaning"]
    )


def test_broken_binary_is_reported_not_crashed(tmp_path):
    bad = write(tmp_path / "bad.dll", make_pe(clr_flags=1)[:100])
    res, data = jrun("inspect", str(bad))
    assert res.returncode == 3
    assert any(c.get("reason_code") == "CORRUPT" for c in data["checks"])


def test_elf_is_identified(tmp_path):
    so = write(tmp_path / "libx.so", make_elf(62))
    _res, data = jrun("inspect", str(so), "--host-arch", "x86")
    assert rule_ids(data) == ["ARCH001"] or os.name == "nt"


def test_unicode_and_space_paths(tmp_path):
    dll = write(
        tmp_path / "テスト 用" / "例 .dll", make_pe(0x8664, pe32plus=True, clr_flags=1)
    )
    res, data = jrun("inspect", str(dll), "--host-arch", "x64")
    assert res.returncode == 0 and data["facts"][0]["value"]["arch"] == "x64"


# ---------------------------------------------------------------- プロジェクト
@posix_only
def test_old_sdk_for_net8_is_confirmed(tmp_path, dotnet):
    p = write(
        tmp_path / "App" / "App.csproj", SDK_CSPROJ.format(tfm="net8.0", extra="")
    )
    res, data = jrun("inspect", str(p), "--dotnet-path", str(dotnet))
    assert "FX001" in rule_ids(data) and res.returncode == 1
    fx = next(r for r in data["records"] if r["rule_id"] == "FX001")
    assert fx["status"] == "CONFIRMED" and "7.0.100" in fx["title"]


@posix_only
def test_static_only_never_starts_tools(tmp_path):
    marker = tmp_path / "started"
    tool = fake_tool(tmp_path / "bin" / "dotnet", f"touch {marker}\n")
    p = write(tmp_path / "App.csproj", SDK_CSPROJ.format(tfm="net8.0", extra=""))
    res, data = jrun("inspect", str(p), "--static-only", "--dotnet-path", str(tool))
    assert not marker.exists() and res.returncode in (0, 1)
    assert any(c["outcome"] == "skipped" for c in data["checks"])
    assert "FX001" not in rule_ids(data)


def test_conditional_property_is_left_unevaluated(tmp_path):
    p = write(
        tmp_path / "App.csproj",
        """<Project Sdk="Microsoft.NET.Sdk">
<PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
<PropertyGroup Condition="'$(X)'=='1'"><PlatformTarget>x86</PlatformTarget></PropertyGroup></Project>""",
    )
    res, data = jrun("inspect", str(p), "--static-only")
    assert res.returncode == 3
    assert any(c.get("reason_code") == "UNEVALUATED_PROPERTY" for c in data["checks"])


def test_missing_assets_is_candidate_not_proof(tmp_path):
    p = write(tmp_path / "App.csproj", SDK_CSPROJ.format(tfm="net8.0", extra=""))
    _, data = jrun("inspect", str(p), "--static-only")
    rec = next(r for r in data["records"] if r["rule_id"] == "DEP003")
    assert rec["status"] == "CANDIDATE"


def test_stale_assets_for_other_tfm(tmp_path):
    p = write(tmp_path / "App.csproj", SDK_CSPROJ.format(tfm="net8.0", extra=""))
    write(
        tmp_path / "obj" / "project.assets.json",
        json.dumps({"targets": {"net6.0": {}}}),
    )
    _, data = jrun("inspect", str(p), "--static-only")
    assert any(
        r["rule_id"] == "DEP003" and "net8.0" in r["title"] for r in data["records"]
    )


def test_directory_inspect_and_symlinks_not_followed(tmp_path):
    write(tmp_path / "a" / "A.dll", make_pe(0x14C, clr_flags=0x3))
    outside = tmp_path.parent / (tmp_path.name + "_out")
    write(outside / "B.dll", make_pe(0x14C, clr_flags=0x3))
    try:
        os.symlink(outside, tmp_path / "link")
    except (OSError, NotImplementedError):
        pytest.skip("symlink 不可")
    _res, data = jrun("inspect", str(tmp_path), "--host-arch", "x64")
    assert len([r for r in data["records"] if r["rule_id"] == "ARCH001"]) == 1


# ---------------------------------------------------------------- explain
LOG = """\
Program.cs(3,1): error CS0246: The type or namespace name 'X' could not be found [/p/App.csproj]
/p/App.csproj : error NETSDK1045: The current .NET SDK does not support targeting .NET 8.0.
/p/App.csproj : error NU1101: Unable to find package Foo
"""


def test_explain_from_stdin_separates_observation_and_cause():
    res, data = jrun("explain", "-", stdin=LOG.encode())
    assert not validate(data), validate(data)
    assert {"CS001", "FX001", "DEP002"} <= set(rule_ids(data)) and res.returncode == 1
    assert all(r["status"] == "CANDIDATE" for r in data["records"])
    assert any(f["source"] == "log" for f in data["facts"])


def test_explain_unknown_code_is_kept_as_unclassified(tmp_path):
    log = write(tmp_path / "b.log", "Foo.cs(1,1): error XYZ9999: weird\n")
    _, data = jrun("explain", str(log))
    assert (
        data["records"][0]["rule_id"] == "LOG000"
        and data["records"][0]["status"] == "UNKNOWN"
    )


def test_explain_utf16_log(tmp_path):
    log = tmp_path / "u16.log"
    log.write_bytes(LOG.encode("utf-16"))
    _, data = jrun("explain", str(log))
    assert "CS001" in rule_ids(data)


def test_explain_undecodable_input_is_usage_error(tmp_path):
    log = tmp_path / "bad.log"
    log.write_bytes(b"abc \x80\x81\x82 error CS0001: x\n")
    assert run_cli("explain", str(log)).returncode == 2


@posix_only
def test_explain_with_project_links_environment(tmp_path, dotnet):
    p = write(
        tmp_path / "App" / "App.csproj", SDK_CSPROJ.format(tfm="net8.0", extra="")
    )
    log = write(
        tmp_path / "b.log",
        "/p/App.csproj : error NETSDK1045: The current SDK does not support\n",
    )
    _, data = jrun(
        "explain", str(log), "--project", str(p), "--dotnet-path", str(dotnet)
    )
    fx = [r for r in data["records"] if r["rule_id"] == "FX001"]
    assert len(fx) == 2 and fx[0]["related_findings"] == [fx[1]["id"]]


def test_prerequisite_failure_is_linked(tmp_path):
    a = write(
        tmp_path / "A" / "A.csproj",
        """<Project Sdk="Microsoft.NET.Sdk">
<ItemGroup><ProjectReference Include="..\\B\\B.csproj"/></ItemGroup></Project>""",
    )
    b = write(tmp_path / "B" / "B.csproj", SDK_CSPROJ.format(tfm="net8.0", extra=""))
    log = write(
        tmp_path / "b.log",
        f"{a} : error CS0006: metadata not found [{a}]\n"
        f"X.cs(1,1): error CS0103: nope [{b}]\n",
    )
    _, data = jrun("explain", str(log))
    dep = next(r for r in data["records"] if r["rule_id"] == "DEP001")
    cs = next(r for r in data["records"] if r["rule_id"] == "CS002")
    assert cs["id"] in dep["related_findings"]


# ---------------------------------------------------------------- 出力
def test_output_file_is_never_overwritten(tmp_path):
    out = tmp_path / "report.json"
    assert (
        run_cli(
            "explain", "-", "--format", "json", "--output", str(out), stdin=LOG.encode()
        ).returncode
        == 1
    )
    first = out.read_text(encoding="utf-8")
    assert json.loads(first)["mode"] == "explain"
    res = run_cli("explain", "-", "--format", "json", "--output", str(out), stdin=b"")
    assert res.returncode == 2 and out.read_text(encoding="utf-8") == first


def test_home_and_project_paths_are_placeholders(tmp_path):
    p = write(
        tmp_path / "proj" / "App.csproj", SDK_CSPROJ.format(tfm="net8.0", extra="")
    )
    write(tmp_path / "proj" / "global.json", "{}")
    res = run_cli(
        "inspect",
        str(p),
        "--static-only",
        "--format",
        "json",
        env={"HOME": str(tmp_path)},
    )
    assert str(tmp_path).encode() not in res.stdout and b"<PROJECT>" in res.stdout
    shown = run_cli(
        "inspect", str(p), "--static-only", "--format", "json", "--show-paths"
    )
    assert str(tmp_path).encode() in shown.stdout


def test_text_output_has_no_ansi_when_piped(tmp_path):
    res = run_cli("explain", "-", stdin=LOG.encode())
    assert b"\x1b[" not in res.stdout and "次の確認" in res.stdout.decode("utf-8")


# ---------------------------------------------------------------- PowerShell
FAKE_PWSH = """\
req=$(cat | base64 -d)
case "$req" in
  *'"mode": "parse"'*)
    echo '{"ps_version":"5.1.0","edition":"Desktop","process_arch":"x64","language_mode":"FullLanguage",'\
'"parse_errors":[{"message":"Unexpected token","id":"UnexpectedToken","line":3,"column":7}],'\
'"requires":{"version":"7.0","editions":["Core"],"modules":[],"admin":false},'\
'"references":[{"command":"Add-Type","param":"typedefinition","line":2,"kind":"dynamic"}]}';;
  *) echo '{"ps_version":"5.1.0","edition":"Desktop","process_arch":"x64","language_mode":"FullLanguage"}';;
esac
"""


@posix_only
def test_powershell_parse_with_host(tmp_path):
    host = fake_tool(tmp_path / "bin" / "pwsh", FAKE_PWSH)
    ps1 = write(tmp_path / "x.ps1", "#requires -Version 7.0\nwrite-host (\n")
    res, data = jrun("inspect", str(ps1), "--powershell-path", str(host))
    assert not validate(data), validate(data)
    ids = rule_ids(data)
    assert "PS001" in ids and "PS002" in ids and res.returncode == 1
    assert any(c.get("reason_code") == "DYNAMIC_CODE" for c in data["checks"])


def test_powershell_without_host_is_unknown_but_requires_is_read(tmp_path):
    ps1 = write(tmp_path / "x.ps1", "#requires -Version 5.1\n")
    res, data = jrun("inspect", str(ps1), "--powershell-path", "/nonexistent/pwsh")
    assert res.returncode == 3
    assert any(c.get("reason_code") == "TOOL_MISSING" for c in data["checks"])
    assert any(f["source"] == "ps-requires" for f in data["facts"])


def test_powershell_helper_never_embeds_target_in_command():
    from build_doctor.collectors import powershell as psc

    src = psc.HELPER.read_text(encoding="utf-8")
    assert "Invoke-Expression" not in src and "Add-Type -" not in src
    assert "ParseFile" in src and "Import-Module -" not in src


# ---------------------------------------------------------------- build
@posix_only
def test_dry_run_creates_nothing_and_shows_plan(tmp_path, dotnet):
    p = write(
        tmp_path / "App" / "App.csproj", SDK_CSPROJ.format(tfm="net8.0", extra="")
    )
    res, data = jrun("build", str(p), "--dry-run", "--dotnet-path", str(dotnet))
    assert (
        res.returncode == 0 and "--no-restore" in data["execution"]["planned_command"]
    )
    assert not data["execution"]["build_started"]
    assert not (tmp_path / "App" / "generated.marker").exists()


@posix_only
def test_restore_is_opt_in(tmp_path, dotnet):
    p = write(tmp_path / "App.csproj", SDK_CSPROJ.format(tfm="net8.0", extra=""))
    _, data = jrun(
        "build", str(p), "--dry-run", "--restore", "--dotnet-path", str(dotnet)
    )
    assert "--no-restore" not in data["execution"]["planned_command"]


@posix_only
def test_inspect_does_not_run_build_but_build_does(tmp_path, dotnet):
    p = write(
        tmp_path / "App" / "App.csproj", SDK_CSPROJ.format(tfm="net7.0", extra="")
    )
    marker = tmp_path / "App" / "generated.marker"
    jrun("inspect", str(p), "--dotnet-path", str(dotnet))
    assert not marker.exists()
    res, data = jrun("build", str(p), "--dotnet-path", str(dotnet))
    assert marker.exists() and res.returncode == 1
    assert (
        data["execution"]["build_started"] and data["execution"]["child_exit_code"] == 1
    )
    assert "CS001" in rule_ids(data)


@posix_only
def test_unknown_build_exit_code_is_preserved(tmp_path):
    tool = fake_tool(tmp_path / "bin" / "dotnet", "echo oops >&2\nexit 42\n")
    p = write(tmp_path / "App.csproj", SDK_CSPROJ.format(tfm="net8.0", extra=""))
    res, data = jrun("build", str(p), "--dotnet-path", str(tool), "--quiet")
    assert res.returncode == 1 and data["execution"]["child_exit_code"] == 42


@posix_only
def test_successful_build_is_not_app_success(tmp_path):
    tool = fake_tool(tmp_path / "bin" / "dotnet", "exit 0\n")
    p = write(tmp_path / "App.csproj", SDK_CSPROJ.format(tfm="net8.0", extra=""))
    _res, data = jrun("build", str(p), "--dotnet-path", str(tool), "--static-only")
    assert (
        data["execution"]["child_exit_code"] == 0
        and "実行成功ではない" in data["execution"]["notice"]
    )


@posix_only
def test_build_timeout_stops_children_and_is_incomplete(tmp_path):
    marker = tmp_path / "grandchild"
    tool = fake_tool(
        tmp_path / "bin" / "dotnet",
        f'[ "$1" = build ] || exit 0\n(sleep 3; touch {marker}) &\nsleep 60\n',
    )
    p = write(tmp_path / "App.csproj", SDK_CSPROJ.format(tfm="net8.0", extra=""))
    res, data = jrun(
        "build", str(p), "--dotnet-path", str(tool), "--build-timeout", "1"
    )
    assert res.returncode == 3
    assert any(c.get("reason_code") == "TIMEOUT" for c in data["checks"])
    import time

    time.sleep(4)
    assert not marker.exists()


def test_ambiguous_build_target_is_error(tmp_path):
    write(tmp_path / "A.csproj", SDK_CSPROJ.format(tfm="net8.0", extra=""))
    write(tmp_path / "B.csproj", SDK_CSPROJ.format(tfm="net8.0", extra=""))
    res = run_cli("build", str(tmp_path), "--dry-run", "--dotnet-path", "/x/dotnet")
    assert res.returncode == 2 and "曖昧" in res.stderr.decode("utf-8")
