import platform
import struct
import sys
import sysconfig

ARCH_ALIASES = {
    "x86_64": "x64", "amd64": "x64", "x64": "x64",
    "i386": "x86", "i486": "x86", "i586": "x86", "i686": "x86", "x86": "x86",
    "aarch64": "arm64", "arm64": "arm64",
    "armv7l": "arm", "armv8l": "arm", "arm": "arm",
}


def normalize_arch(value: str | None) -> str:
    if not value:
        return "unknown"
    return ARCH_ALIASES.get(value.strip().lower(), value.strip().lower())


def is_windows() -> bool:
    return sys.platform == "win32"


def process_arch() -> str:
    """Doctor 自身のプロセスのアーキテクチャ（OS のものとは別）。"""
    plat = sysconfig.get_platform().lower()
    if plat == "win32":
        return "x86"
    if "arm64" in plat or "aarch64" in plat:
        return "arm64"
    if "amd64" in plat or "x86_64" in plat:
        return "x64"
    return "x86" if struct.calcsize("P") == 4 else normalize_arch(platform.machine())
