"""子プロセスの実行。時間・出力量を制限し、配下のプロセスまで停止する。"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field


@dataclass
class RunResult:
    argv: list[str]
    exit_code: int | None = None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    output_exceeded: bool = False
    reason_code: str | None = None  # TOOL_MISSING / ACCESS_DENIED / TIMEOUT / OUTPUT_LIMIT / EXEC_FAILED
    detail: str | None = None
    killed: bool = False

    @property
    def ok(self) -> bool:
        return self.reason_code is None and self.exit_code == 0

    def text(self, stream: str = "stdout") -> str:
        return getattr(self, stream).decode("utf-8", errors="replace")


def can_manage_process_tree() -> bool:
    """配下のプロセスまで確実に止められる環境かどうか。"""
    if os.name == "posix":
        return hasattr(os, "killpg")
    return shutil.which("taskkill") is not None


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    except (ProcessLookupError, PermissionError, OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def run(argv: list[str], *, timeout: float, max_output_bytes: int, cwd: str | None = None,
        stdin_data: bytes | None = None, env: dict[str, str] | None = None) -> RunResult:
    """argv 配列で起動する（シェルは使わない）。"""
    result = RunResult(argv=list(argv))
    kwargs: dict = dict(stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env,
                        shell=False)
    if os.name == "posix":
        kwargs["start_new_session"] = True
    else:
        kwargs["creationflags"] = (getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                                   | getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        proc = subprocess.Popen(argv, **kwargs)
    except FileNotFoundError as e:
        result.reason_code, result.detail = "TOOL_MISSING", str(e)
        return result
    except PermissionError as e:
        result.reason_code, result.detail = "ACCESS_DENIED", str(e)
        return result
    except OSError as e:
        result.reason_code, result.detail = "EXEC_FAILED", str(e)
        return result

    exceeded = threading.Event()
    bufs = {"stdout": bytearray(), "stderr": bytearray()}

    def reader(name: str, stream) -> None:
        buf = bufs[name]
        try:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    return
                room = max_output_bytes - len(buf)
                if len(chunk) > room:
                    buf += chunk[:max(room, 0)]
                    exceeded.set()
                    return
                buf += chunk
        except (OSError, ValueError):
            return

    def writer() -> None:
        try:
            proc.stdin.write(stdin_data)
            proc.stdin.close()
        except (OSError, ValueError):
            pass

    threads = [threading.Thread(target=reader, args=("stdout", proc.stdout), daemon=True),
               threading.Thread(target=reader, args=("stderr", proc.stderr), daemon=True)]
    if stdin_data is not None:
        threads.append(threading.Thread(target=writer, daemon=True))
    for t in threads:
        t.start()

    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                proc.wait(timeout=0.05)
                break
            except subprocess.TimeoutExpired:
                pass
            if exceeded.is_set():
                result.output_exceeded, result.killed = True, True
                _kill_tree(proc)
                break
            if time.monotonic() >= deadline:
                result.timed_out, result.killed = True, True
                _kill_tree(proc)
                break
    except BaseException:
        _kill_tree(proc)
        raise
    finally:
        # 親が終了しても孫が残っている場合に備え、プロセスグループ全体を片付ける
        _kill_tree(proc)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    for t in threads:
        t.join(timeout=2)
    if exceeded.is_set():
        result.output_exceeded = True
    result.stdout, result.stderr = bytes(bufs["stdout"]), bytes(bufs["stderr"])
    result.exit_code = proc.returncode
    if result.timed_out:
        result.reason_code = "TIMEOUT"
    elif result.output_exceeded:
        result.reason_code = "OUTPUT_LIMIT"
    return result
