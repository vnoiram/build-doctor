"""Fact / Finding / Report と判定モデル。"""

from __future__ import annotations

import datetime
from typing import Any

from . import SCHEMA_VERSION, __version__
from .rules.registry import RULES

STATUSES = ("CONFIRMED", "CONFIGURED", "CANDIDATE", "UNKNOWN")
SEVERITIES = ("info", "warning", "error")
OUTCOMES = ("completed", "unknown", "skipped", "not_applicable")
SEV_RANK = {"info": 0, "warning": 1, "error": 2}

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3
EXIT_INTERRUPTED = 130


def now_utc() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Report:
    def __init__(self, mode: str, target: str | None, parameters: dict[str, Any]):
        self.mode = mode
        self.target = target
        self.parameters = parameters
        self.checks: list[dict] = []
        self.facts: list[dict] = []
        self.records: list[dict] = []
        self.execution: dict[str, Any] = {
            "build_started": False,
            "child_exit_code": None,
        }
        self.build_failed = False

    def add_fact(
        self,
        source: str,
        value: Any,
        *,
        location: str | None = None,
        complete: bool = True,
    ) -> str:
        fid = f"fact-{len(self.facts) + 1}"
        self.facts.append(
            {
                "id": fid,
                "source": source,
                "value": value,
                "location": location,
                "time_utc": now_utc(),
                "complete": complete,
            }
        )
        return fid

    def add_check(
        self,
        check_id: str,
        outcome: str,
        *,
        reason_code: str | None = None,
        detail: str | None = None,
    ) -> None:
        assert outcome in OUTCOMES, outcome
        entry: dict[str, Any] = {"id": check_id, "outcome": outcome}
        if reason_code:
            entry["reason_code"] = reason_code
        if detail:
            entry["detail"] = detail
        self.checks.append(entry)

    def add_finding(
        self,
        rule_id: str,
        status: str,
        severity: str,
        title: str,
        *,
        evidence: list[str] | tuple = (),
        meaning: str,
        limit: str,
        next_steps: list[str] | tuple = (),
        related: list[str] | tuple = (),
    ) -> str:
        assert status in STATUSES and severity in SEVERITIES
        assert rule_id in RULES, f"未登録の Rule ID: {rule_id}"
        fid = f"finding-{len(self.records) + 1}"
        self.records.append(
            {
                "id": fid,
                "rule_id": rule_id,
                "status": status,
                "severity": severity,
                "title": title,
                "evidence_refs": list(evidence),
                "meaning": meaning,
                "limit": limit,
                "next": list(next_steps),
                "related_findings": list(related),
            }
        )
        return fid

    def link(self, a: str, b: str) -> None:
        by_id = {r["id"]: r for r in self.records}
        if b not in by_id[a]["related_findings"]:
            by_id[a]["related_findings"].append(b)
        if a not in by_id[b]["related_findings"]:
            by_id[b]["related_findings"].append(a)

    def coverage(self) -> dict[str, int]:
        cov = {"completed": 0, "unknown": 0, "skipped": 0}
        for c in self.checks:
            if c["outcome"] in cov:
                cov[c["outcome"]] += 1
        return cov

    def summary(self) -> dict[str, int]:
        s = {"info": 0, "warning": 0, "error": 0}
        for r in self.records:
            s[r["severity"]] += 1
        return s

    def exit_code(self, fail_on: str = "error") -> int:
        threshold = SEV_RANK[fail_on]
        hit = any(SEV_RANK[r["severity"]] >= threshold for r in self.records)
        if hit or self.build_failed:
            return EXIT_FINDINGS
        if self.coverage()["unknown"] > 0:
            return EXIT_INCOMPLETE
        return EXIT_OK

    def to_dict(self, fail_on: str = "error") -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": "build-doctor",
            "tool_version": __version__,
            "time_utc": now_utc(),
            "mode": self.mode,
            "target": self.target,
            "parameters": self.parameters,
            "coverage": self.coverage(),
            "checks": self.checks,
            "facts": self.facts,
            "summary": self.summary(),
            "records": self.records,
            "execution": self.execution,
            "exit_code": self.exit_code(fail_on),
        }
