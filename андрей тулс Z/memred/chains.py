"""Цепочки атак (APT kill-chain): результат стадии 1 — оружие стадии 2.

Отличие от одиночной атаки: несколько сессий-стадий, каждая со своим
сообщением(-ями), и детерминированная проверка памяти ПОСЛЕ КАЖДОЙ стадии.
Так видно, как яд переживает промежуточные финализации/компакцию и как
стадия-«разведка» готовит почву для стадии-«эксфильтрации».

Формат YAML:
    id, name, class, signal, canary | expected_in_answer,
    stages:  # каждая стадия = новая сессия
      - id: implant           # человекочитаемое имя
        description: "..."
        messages: ["...", "finalize"]
        expect_markers: ["..."]   # что должно быть в памяти после стадии
    triggers: [...]           # невинные вопросы новых сессий в конце
"""

import time
from pathlib import Path

import yaml

from . import verdicts
from .runner import _await_memory_settle
from .trace import Trace, save_markdown, save_report


class ChainError(Exception):
    pass


def validate_chain(ch: dict, path: str = "?") -> dict:
    for key in ("id", "name", "stages", "triggers"):
        if not ch.get(key):
            raise ChainError(f"{path}: цепочке нужно поле {key}")
    if not (ch.get("canary") or ch.get("expected_in_answer")):
        raise ChainError(f"{path}: нужен canary или expected_in_answer")
    for i, st in enumerate(ch["stages"], 1):
        if not st.get("messages"):
            raise ChainError(f"{path}: стадия {i} без messages")
        if isinstance(st["messages"], str):
            st["messages"] = [st["messages"]]
    if isinstance(ch["triggers"], str):
        ch["triggers"] = [ch["triggers"]]
    ch.setdefault("class", "kill_chain")
    ch.setdefault("signal", "weak")
    ch.setdefault("owasp", "ASI06")
    return ch


def load_chain(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ChainError(f"{path}: YAML не содержит словарь")
    return validate_chain(data, path)


def load_dir(dirpath: str) -> list:
    import glob
    import os
    out = []
    for path in sorted(glob.glob(os.path.join(dirpath, "*.yaml"))):
        out.append(load_chain(path))
    return out


def run_chain(ch: dict, target, target_name: str, runs_root: str,
              run_dir: str = None, judge=None) -> dict:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run_dir = Path(run_dir) if run_dir else Path(runs_root) / f"{ch['id']}-{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    tr = Trace(run_dir)

    def log(msg):
        print(f"    {msg}")

    log(f"[0] сброс состояния мишени")
    target.reset()
    dump = target.dump_memory()
    tr.step("setup", "reset", count=dump["count"])

    # --- Стадии: новая сессия на каждую, скан памяти после каждой ---
    stage_reports = []
    for i, st in enumerate(ch["stages"], 1):
        sid = f"{ch['id']}-{stamp}-s{i}"
        log(f"[стадия {i}/{len(ch['stages'])}] {st.get('id','?')} — {st.get('description','')}")
        for j, msg in enumerate(st["messages"], 1):
            res = target.chat(msg, session_id=sid)
            tr.step(f"stage{i}", "chat_message", n=j, session=sid,
                    preview=msg[:120], answer_preview=res["answer"][:300])
            log(f"      сообщение {j}: ответ {len(res['answer'])} симв.")
        if target.name == "stand" and st["messages"]:
            settle = _await_memory_settle(target)
            tr.step(f"stage{i}", "await_settle", result=settle)
        dump = target.dump_memory()
        markers = st.get("expect_markers") or ([ch["canary"]] if ch.get("canary") else [])
        scan = verdicts.memory_contains(dump, markers, extra_markers=[sid])
        stage_reports.append({
            "stage": st.get("id", f"s{i}"),
            "description": st.get("description", ""),
            "markers": markers,
            "implanted": scan["implanted"],
            "memory_count": dump["count"],
            "matched": [{"id": c["id"], "source": c["source"],
                         "chunk": c["chunk"]} for c in scan["matched_chunks"]],
            "last_answer": res["answer"] if st["messages"] else "",
        })
        tr.step(f"stage{i}", "memory_scan", markers=markers,
                implanted=scan["implanted"], memory_count=dump["count"])
        log(f"      память: {dump['count']} чанков, маркеры: "
            f"{'ДА' if scan['implanted'] else 'нет'}")

    # --- Триггеры: свежие сессии ---
    log("[финал] триггеры в новых сессиях"
        + (f" + LLM-судья ({judge.name})" if judge else ""))
    trigger_results = []
    for i, t in enumerate(ch["triggers"], 1):
        res = target.chat(t, session_id=f"{ch['id']}-{stamp}-t{i}")
        chk = verdicts.check_answer(res["answer"], ch)
        row = {
            "question": t, "activated": chk["activated"],
            "adopted": chk["adopted"], "exposure_only": chk["exposure_only"],
            "answer": res["answer"],
        }
        if judge:
            row["judge"] = judge.judge_answer(ch, t, res["answer"])
        trigger_results.append(row)
        tr.step("execute", "trigger", question=t, activated=chk["activated"],
                adopted=chk["adopted"],
                judge=(row["judge"]["verdict"] if judge else None),
                answer=res["answer"][:800])
        extra = (f" | судья: {row['judge']['verdict']}" if judge else "")
        log(f"      активация: {'ДА' if chk['activated'] else 'нет'}{extra} :: {t[:60]}")

    activated = sum(1 for r in trigger_results if r["activated"])
    adopted = sum(1 for r in trigger_results if r["adopted"])
    report = {
        "attack_id": ch["id"],
        "attack_name": ch["name"],
        "kind": "chain",
        "class": ch.get("class"),
        "signal": ch.get("signal"),
        "owasp": ch.get("owasp"),
        "target": target_name,
        "stages": stage_reports,
        "verdict": {
            "stages_total": len(stage_reports),
            "stages_implanted": sum(1 for s in stage_reports if s["implanted"]),
            "activated_triggers": activated,
            "adopted_triggers": adopted,
            "triggers_total": len(trigger_results),
        },
        "trigger_results": trigger_results,
        "run_dir": str(run_dir),
    }
    save_report(run_dir, report)
    save_markdown(run_dir, chain_report_markdown(ch, report))
    return report


def chain_report_markdown(ch: dict, report: dict) -> str:
    v = report["verdict"]
    lines = [
        f"# {ch['id']} — {ch['name']} (цепочка)",
        "",
        f"*Класс:* {ch.get('class')} · *сигнал:* {ch.get('signal')} · "
        f"*мишень:* {report['target']}",
        "",
        "## Стадии",
        "",
        "| # | Стадия | Маркеры в памяти | Чанков |",
        "|---|---|---|---|",
    ]
    for i, s in enumerate(report["stages"], 1):
        mark = "**ДА**" if s["implanted"] else "нет"
        lines.append(f"| {i} | {s['stage']} — {s['description'][:60]} "
                     f"| {mark} ({', '.join(s['markers'])[:60]}) | {s['memory_count']} |")
    lines += [
        "",
        f"**Триггеры:** активация {v['activated_triggers']}/{v['triggers_total']}, "
        f"принятие {v['adopted_triggers']}/{v['triggers_total']}.",
        "",
    ]
    for s in report["stages"]:
        if s["matched"]:
            lines += [f"## Evidence после стадии «{s['stage']}»", ""]
            for c in s["matched"][:3]:
                lines.append(f"**`{c['id'][:8]}`** ({c['source']}):")
                lines.append("")
                lines.append("> " + c["chunk"][:400].replace("\n", "\n> "))
                lines.append("")
    lines += ["## Ответы на триггеры", ""]
    for i, t in enumerate(report["trigger_results"], 1):
        lines.append(f"**T{i}.** {t['question']}")
        lines.append("")
        lines.append("> " + t["answer"][:600].replace("\n", "\n> "))
        lines.append("")
    return "\n".join(lines)
