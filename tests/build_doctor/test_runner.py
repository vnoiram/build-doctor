import os
import sys
import time

import pytest

from build_doctor import runner

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX 前提のシェル")


def test_missing_tool():
    res = runner.run(["/nonexistent/tool"], timeout=5, max_output_bytes=1000)
    assert res.reason_code == "TOOL_MISSING" and res.exit_code is None


def test_captures_output_and_exit_code():
    res = runner.run(
        [sys.executable, "-c", "import sys;print('hi');sys.exit(3)"],
        timeout=20,
        max_output_bytes=1000,
    )
    assert res.exit_code == 3 and res.text().strip() == "hi" and not res.killed


def test_timeout_keeps_partial_output():
    code = "import time,sys;print('start',flush=True);time.sleep(30)"
    t0 = time.monotonic()
    res = runner.run([sys.executable, "-c", code], timeout=1, max_output_bytes=1000)
    assert res.reason_code == "TIMEOUT" and res.killed and "start" in res.text()
    assert time.monotonic() - t0 < 15


def test_output_limit_stops_the_process():
    code = "import sys\nwhile True: sys.stdout.write('x'*1000); sys.stdout.flush()"
    res = runner.run([sys.executable, "-c", code], timeout=20, max_output_bytes=10000)
    assert res.reason_code == "OUTPUT_LIMIT" and res.killed and len(res.stdout) <= 10000


@posix_only
def test_grandchild_is_killed(tmp_path):
    marker = tmp_path / "alive"
    script = f"(sleep 3; touch {marker}) &\nsleep 30\n"
    res = runner.run(["/bin/sh", "-c", script], timeout=1, max_output_bytes=1000)
    assert res.timed_out
    time.sleep(4)
    assert not marker.exists(), "孫プロセスが停止されていない"


@posix_only
def test_no_orphan_after_normal_exit(tmp_path):
    marker = tmp_path / "alive"
    runner.run(
        ["/bin/sh", "-c", f"(sleep 2; touch {marker}) >/dev/null 2>&1 &\nexit 0"],
        timeout=10,
        max_output_bytes=1000,
    )
    time.sleep(3)
    assert not marker.exists()


def test_stdin_data():
    res = runner.run(
        [sys.executable, "-c", "import sys;print(sys.stdin.read().upper())"],
        timeout=20,
        max_output_bytes=1000,
        stdin_data=b"abc",
    )
    assert res.text().strip() == "ABC"


def test_zipapp_builds_and_starts(tmp_path):
    import subprocess
    import sys

    from helpers import ROOT

    out = tmp_path / "bd.pyz"
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_zipapp.py"), str(out)],
        check=True,
        capture_output=True,
    )
    res = subprocess.run(
        [sys.executable, str(out), "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0 and "build-doctor" in res.stdout
