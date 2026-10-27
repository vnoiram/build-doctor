"""レポート出力時のパス置換とシークレット伏せ字。"""

from __future__ import annotations

import os
import re
from typing import Any

_URL_CRED = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)[^/\s@]+@")
_URL_QUERY = re.compile(
    r"(?P<url>[A-Za-z][A-Za-z0-9+.-]*://[^\s?#\"'<>]+)\?[^\s\"'<>]*"
)
_SECRETS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(
        r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey)(\s*[=:]\s*)\S+"
    ),
]


def sanitize_url(value: str) -> str:
    value = _URL_CRED.sub(r"\g<scheme>***@", value)
    return _URL_QUERY.sub(r"\g<url>?***", value)


def scrub_secrets(text: str) -> str:
    text = sanitize_url(text)
    text = _SECRETS[3].sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)
    for pat in _SECRETS[:3]:
        text = pat.sub("***", text)
    return text


class Redactor:
    def __init__(self, project_root: str | None = None, show_paths: bool = False):
        self.show_paths = show_paths
        self.roots: list[tuple[str, str]] = []
        if show_paths:
            return
        if project_root:
            self.roots.append((project_root, "<PROJECT>"))
        home = os.path.expanduser("~")
        if home and home != "~":
            self.roots.append((home, "<HOME>"))
        # 長いパスを先に置換する
        self.roots.sort(key=lambda r: len(r[0]), reverse=True)
        extra = []
        for root, ph in self.roots:
            alt = root.replace("\\", "/")
            if alt != root:
                extra.append((alt, ph))
        self.roots += extra

    def text(self, s: str) -> str:
        s = scrub_secrets(s)
        for root, ph in self.roots:
            s = self._replace_root(s, root, ph)
        return s

    @staticmethod
    def _replace_root(s: str, root: str, ph: str) -> str:
        root = root.rstrip("/\\")
        if not root:
            return s
        pattern = re.compile(
            re.escape(root) + r"(?=$|[\\/\s\"'\]\),;:])",
            re.IGNORECASE if os.name == "nt" else 0,
        )
        return pattern.sub(ph, s)

    def apply(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, list):
            return [self.apply(x) for x in obj]
        if isinstance(obj, dict):
            return {k: self.apply(v) for k, v in obj.items()}
        return obj
