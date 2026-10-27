"""人が読むためのテキスト出力。レポート辞書（伏せ字処理済み）から生成する。"""

from __future__ import annotations

import json

COLORS = {"error": "31", "warning": "33", "info": "36"}
OUTCOME_JA = {"unknown": "不明", "skipped": "省略"}


def _c(text: str, code: str, use_color: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if use_color else text


def render(data: dict, *, use_color: bool = False, verbose: bool = False) -> str:
    out: list[str] = []
    add = out.append
    add(f"Build Doctor {data['tool_version']} — {data['mode']}")
    if data.get("target"):
        add(f"対象: {data['target']}")
    cov = data["coverage"]
    add(f"検査: 完了 {cov['completed']} / 不明 {cov['unknown']} / 省略 {cov['skipped']}")
    s = data["summary"]
    add(f"所見: error {s['error']} / warning {s['warning']} / info {s['info']}")
    ex = data["execution"]
    if ex.get("planned_command"):
        add(f"ビルドコマンド: {ex['planned_command']}")
        add(f"作業ディレクトリ: {ex.get('cwd')}")
    if ex.get("build_started"):
        add(f"ビルド終了コード: {ex.get('child_exit_code')}")
        if ex.get("notice"):
            add(f"注意: {ex['notice']}")
    add("")

    facts = {f["id"]: f for f in data["facts"]}
    for r in data["records"]:
        tag = _c(f"[{r['severity'].upper()}]", COLORS[r["severity"]], use_color)
        add(f"{tag}[{r['status']}] {r['rule_id']}: {r['title']}")
        add(f"  意味: {r['meaning']}")
        for ref in r["evidence_refs"][:5]:
            f = facts.get(ref)
            if f:
                loc = f" @ {f['location']}" if f.get("location") else ""
                add(f"  根拠: {ref} ({f['source']}{loc})")
        add(f"  限界: {r['limit']}")
        if r["next"]:
            add("  次の確認:")
            for n in r["next"]:
                add(f"    - {n}")
        if r["related_findings"]:
            add(f"  関連: {', '.join(r['related_findings'])}")
        add("")

    incomplete = [c for c in data["checks"] if c["outcome"] in ("unknown", "skipped")]
    if incomplete:
        add("未完了/省略の検査:")
        for c in incomplete:
            reason = f" [{c['reason_code']}]" if c.get("reason_code") else ""
            detail = f" {c['detail']}" if c.get("detail") else ""
            add(f"  - {c['id']}: {OUTCOME_JA[c['outcome']]}{reason}{detail}")
        add("")

    if verbose or data["mode"] == "env":
        add("取得した事実:")
        for f in data["facts"]:
            loc = f" @ {f['location']}" if f.get("location") else ""
            add(f"  - {f['id']} [{f['source']}]{loc} "
                f"{json.dumps(f['value'], ensure_ascii=False, separators=(',', ':'))[:400]}")
        add("")

    if not data["records"] and not incomplete:
        add("所見はありません。")
    add(f"終了コード: {data['exit_code']}")
    return "\n".join(out) + "\n"
