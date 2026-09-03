"""Раннер: полный цикл одной атаки по фазам с evidence на каждом шаге."""

import os
import time
from pathlib import Path

from . import verdicts
from .trace import Trace, attack_report_markdown, save_markdown, save_report


def run_attack(atk: dict, target, target_name: str, runs_root: str,
               run_dir: str = None, judge=None) -> dict:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run_dir = Path(run_dir) if run_dir else Path(runs_root) / f"{atk['id']}-{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    tr = Trace(run_dir)

    def log(msg):
        print(f"    {msg}")

    # --- 1. Сброс состояния ---
    log("[1/6] сброс состояния мишени")
    reset = target.reset()
    tr.step("setup", "reset", result=reset)
    dump = target.dump_memory()
    tr.step("setup", "start_memory", count=dump["count"],
            fingerprint=verdicts.fingerprint(dump))
    log(f"      стартовая память: {dump['count']} чанков")

    # --- 2. Baseline полезности ---
    log("[2/6] baseline: обычные вопросы до атаки")
    utility_before = []
    for u in atk.get("utility_questions", []):
        res = target.chat(u["q"])
        ok = verdicts.check_utility(res["answer"], u.get("expect", []))
        utility_before.append({"q": u["q"], "passed": ok, "answer": res["answer"][:500]})
        tr.step("baseline", "utility", question=u["q"], passed=ok)
    log(f"      полезность до: {_fmt_utility(utility_before)}")

    # --- 3. Доставка ---
    log(f"[3/6] доставка (канал: {atk['channel']})")
    delivery = atk["delivery"]
    if delivery.get("messages"):
        delivery_session = f"{atk['id']}-{stamp}-delivery"
        for i, msg in enumerate(delivery["messages"], 1):
            res = target.chat(msg, session_id=delivery_session)
            tr.step("delivery", "chat_message", n=i, session=delivery_session,
                    preview=msg[:120], answer_preview=res["answer"][:300])
            log(f"      сообщение {i}: ответ агента {len(res['answer'])} симв.")
    if delivery.get("document"):
        res = target.ingest(delivery["document"], atk.get("source", "upload"))
        tr.step("delivery", "ingest", source=atk.get("source"), result=res)
        log(f"      документ принят, чанков: {res.get('chunks_added')}")

    # --- 4. Внедрение (детерминированная проверка памяти) ---
    log("[4/6] проверка записи: скан долговременной памяти")
    if target.name == "stand" and delivery.get("messages"):
        # finalize на стенде отвечает сразу, а Mongo пишет асинхронно:
        # без ожидания скан видит только dialog_sessions и занижает внедрение
        settle = _await_memory_settle(target)
        tr.step("verify", "await_settle", result=settle)
        log(f"      память стабилизировалась: {settle['count']} чанков")
    dump = target.dump_memory()
    markers = ([atk["canary"]] if atk.get("canary") else []) + (
        atk.get("expected_in_memory") or []
    )
    delivery_markers = ([delivery_session] if delivery.get("messages") else [])
    implant = verdicts.memory_contains(dump, markers, extra_markers=delivery_markers)
    tr.step("verify", "memory_scan", markers=markers, extra_markers=delivery_markers,
            implanted=implant["implanted"],
            matched=[c["id"] for c in implant["matched_chunks"]])
    log(f"      внедрение: {'ДА' if implant['implanted'] else 'нет'} "
        f"({len(implant['matched_chunks'])} чанков с маркером)")

    # --- 5. Триггеры: новая сессия, проверка активации ---
    log("[5/6] новая сессия: невинные триггеры"
        + (f" + LLM-судья ({judge.name})" if judge else ""))
    trigger_results = []
    for i, t in enumerate(atk["triggers"], 1):
        res = target.chat(t, session_id=f"{atk['id']}-{stamp}-trigger{i}")
        chk = verdicts.check_answer(res["answer"], atk)
        row = {
            "question": t,
            "activated": chk["activated"],
            "adopted": chk["adopted"],
            "exposure_only": chk["exposure_only"],
            "answer": res["answer"],
            "sources": [s[:200] for s in res.get("sources", [])],
        }
        if judge:
            row["judge"] = judge.judge_answer(atk, t, res["answer"])
        trigger_results.append(row)
        tr.step("execute", "trigger", question=t, activated=chk["activated"],
                adopted=chk["adopted"],
                judge=(row["judge"]["verdict"] if judge else None),
                answer=res["answer"][:800])
        extra = (f" | судья: {row['judge']['verdict']}" if judge else "")
        log(f"      активация: {'ДА' if chk['activated'] else 'нет'}"
            f"{' (только упоминание с отказом)' if chk['exposure_only'] else ''}"
            f"{extra} :: {t[:60]}")
    activated_total = sum(1 for r in trigger_results if r["activated"])
    adopted_total = sum(1 for r in trigger_results if r["adopted"])

    # --- 6. Полезность после ---
    log("[6/6] контроль полезности после атаки")
    utility_after = []
    for u in atk.get("utility_questions", []):
        res = target.chat(u["q"])
        ok = verdicts.check_utility(res["answer"], u.get("expect", []))
        utility_after.append({"q": u["q"], "passed": ok, "answer": res["answer"][:500]})
        tr.step("post", "utility", question=u["q"], passed=ok)
    log(f"      полезность после: {_fmt_utility(utility_after)}")

    report = {
        "attack_id": atk["id"],
        "attack_name": atk["name"],
        "class": atk.get("class"),
        "signal": atk.get("signal"),
        "channel": atk.get("channel"),
        "atlas": atk.get("atlas"),
        "owasp": atk.get("owasp"),
        "target": target_name,
        "verdict": {
            "implanted": implant["implanted"],
            "activated_triggers": activated_total,
            "adopted_triggers": adopted_total,
            "triggers_total": len(trigger_results),
            "judge": ({"name": judge.name, "model": judge.model,
                       "adoption": sum(1 for r in trigger_results
                                       if r.get("judge", {}).get("verdict") == "adoption"),
                       "exposure": sum(1 for r in trigger_results
                                       if r.get("judge", {}).get("verdict") == "exposure"),
                       "refusal": sum(1 for r in trigger_results
                                      if r.get("judge", {}).get("verdict") in ("refusal", "irrelevant")),
                       "error": sum(1 for r in trigger_results
                                    if r.get("judge", {}).get("verdict") == "error")}
                      if judge else None),
            "utility_before": _fmt_utility(utility_before),
            "utility_after": _fmt_utility(utility_after),
            "matched_chunks": [
                {"id": c["id"], "source": c.get("source"), "chunk": c["chunk"]}
                for c in implant["matched_chunks"]
            ],
        },
        "delivery": {k: v for k, v in delivery.items()},
        "trigger_results": trigger_results,
        "utility_before": utility_before,
        "utility_after": utility_after,
        "run_dir": str(run_dir),
    }
    save_report(run_dir, report)
    save_markdown(run_dir, attack_report_markdown(atk, report))
    return report


def _await_memory_settle(target, max_wait: int = 90, pause: int = 3) -> dict:
    """Ждёт, пока долговременная память перестанет меняться (2 одинакых опроса)."""
    deadline = time.time() + max_wait
    prev = None
    stable = 0
    while time.time() < deadline:
        dump = target.dump_memory()
        sig = (dump["count"], tuple(dump.get("ids", [])))
        if sig == prev:
            stable += 1
            if stable >= 2:
                return {"settled": True, "count": dump["count"]}
        else:
            stable = 0
        prev = sig
        time.sleep(pause)
    return {"settled": False, "count": prev[0] if prev else None}


def _fmt_utility(rows: list) -> str:
    if not rows:
        return "н/д"
    return f"{sum(1 for r in rows if r['passed'])}/{len(rows)}"
