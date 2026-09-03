"""memred CLI — точка входа для теста.

Команды:
  python cli.py doctor                     — проверка окружения
  python cli.py target start|stop|status   — управление локальной мишенью
  python cli.py attacks [папка]            — список атак (валидация YAML)
  python cli.py run --id ID [--id ...]     — прогон атак по id
  python cli.py run --all [папка]          — вся батарея + сводный отчёт
  python cli.py mutate --text ... --canary ... — цель → 8 мутаций-формулировок
  python cli.py chain --list               — цепочки атак (APT kill chain)
  python cli.py chain --id CH-1-audit-exfil — прогон цепочки
  python cli.py judge-test [--judge qwen]  — проверка LLM-судьи (ключ/модель)
  python cli.py ui [--port 8080]           — веб-UI: редактор атак + живой запуск
"""

import argparse
import json
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from memred import attacks as atkmod  # noqa: E402
from memred import config as cfgmod  # noqa: E402
from memred import verdicts  # noqa: E402
from memred.adapters import build_target  # noqa: E402
from memred.runner import run_attack  # noqa: E402
from memred.trace import battery_markdown, save_markdown  # noqa: E402

ATTACKS_DIR = ROOT / "attacks"
RUNS_DIR = ROOT / "runs"
TARGET_LOG = RUNS_DIR / "target.log"


def ok(msg):
    print(f"  [OK]   {msg}")


def bad(msg):
    print(f"  [FAIL] {msg}")


def info(msg):
    print(f"  [..]   {msg}")


# ----------------------------------------------------------------- target

def target_process():
    """Запускает target/app.py отдельным процессом, возвращает Popen."""
    cfg = cfgmod.load_config(str(ROOT))
    env = dict(os.environ)
    env["OLLAMA_URL"] = cfg["ollama_url"]
    env["CHAT_MODEL"] = cfg["local"]["chat_model"]
    env["EMBED_MODEL"] = cfg["local"]["embed_model"]
    env["PORT"] = str(cfg["local"]["base_url"].rsplit(":", 1)[-1])
    env["PYTHONUTF8"] = "1"
    RUNS_DIR.mkdir(exist_ok=True)
    log = open(TARGET_LOG, "ab")
    return subprocess.Popen(
        [sys.executable, str(ROOT / "target" / "app.py")],
        env=env, stdout=log, stderr=log,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )


def _write_pid(pid):
    (RUNS_DIR / "target.pid").write_text(str(pid))


def _read_pid():
    p = RUNS_DIR / "target.pid"
    return p.read_text().strip() if p.exists() else None


def cmd_target(args):
    cfg = cfgmod.load_config(str(ROOT))
    adapter = build_target(cfg)
    if args.action == "status":
        print("работает" if adapter.is_up() else "не работает")
        return 0
    if args.action == "start":
        if adapter.is_up():
            print("мишень уже работает")
            return 0
        proc = target_process()
        _write_pid(proc.pid)
        for _ in range(90):
            if adapter.is_up():
                print(f"мишень поднята (pid {proc.pid})")
                return 0
            time.sleep(1)
        bad("не поднялась за 90 c, см. runs/target.log")
        return 1
    if args.action == "stop":
        pid = _read_pid()
        if pid:
            subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
            (RUNS_DIR / "target.pid").unlink(missing_ok=True)
        # добиваем всех python из target/app.py
        ps = (
            "Get-CimInstance Win32_Process -Filter \"Name like 'python%'\" | "
            "Where-Object {$_.CommandLine -like '*target*app.py*'} | "
            "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
        )
        subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True)
        print("остановлена")
        return 0


# ----------------------------------------------------------------- doctor

def cmd_doctor(args):
    cfg = cfgmod.load_config(str(ROOT))
    print("Проверка окружения memred-lab\n")

    print("1. Python и зависимости")
    ok(f"python {sys.version.split()[0]}")
    for mod in ("requests", "yaml", "fastapi", "uvicorn", "chromadb"):
        try:
            __import__(mod)
            ok(f"модуль {mod}")
        except ImportError:
            bad(f"модуль {mod} — pip install -r requirements.txt")

    print("\n2. Ollama")
    ollama = cfg["ollama_url"]
    try:
        models = requests.get(f"{ollama}/api/tags", timeout=5).json()
        names = {m["name"] for m in models.get("models", [])}
        ok(f"Ollama отвечает, моделей: {len(names)}")
        for m in (cfg["local"]["chat_model"], cfg["local"]["embed_model"]):
            base = m.split(":")[0]
            if m in names or base in {n.split(":")[0] for n in names}:
                ok(f"модель {m}")
            else:
                bad(f"модель {m} отсутствует — ollama pull {m}")
        try:
            r = requests.post(f"{ollama}/api/embed",
                              json={"model": cfg["local"]["embed_model"],
                                    "input": ["тест"]}, timeout=120)
            r.raise_for_status()
            ok(f"эмбеддинги работают ({len(r.json()['embeddings'][0])} dim)")
        except Exception as e:
            bad(f"эмбеддинги не работают: {e}")
    except Exception as e:
        bad(f"Ollama недоступна ({ollama}): {e}")

    print("\n3. Атаки")
    try:
        atks = atkmod.load_dir(str(ATTACKS_DIR))
        ok(f"валидны {len(atks)} YAML-атак в attacks/")
        for a in atks:
            info(f"{a['id']} — {a['name']} [{a['signal']}]")
    except Exception as e:
        bad(f"атаки: {e}")

    print("\n4. Мишень")
    adapter = build_target(cfg)
    if adapter.is_up():
        ok(f"мишень '{adapter.name}' работает на {cfg['local']['base_url']}")
    else:
        info("мишень не запущена — это нормально, 'run' поднимет сам")

    print("\nГотово. Если выше нет [FAIL] — можно тестировать: python cli.py run --all")
    return 0


# ----------------------------------------------------------------- attacks

def cmd_attacks(args):
    atks = atkmod.load_dir(args.dir or str(ATTACKS_DIR))
    print(f"Атак: {len(atks)}\n")
    for a in atks:
        n_trig = len(a["triggers"])
        has_canary = "канарейка" if a.get("canary") else "ожидаемые фрагменты"
        print(f"{a['id']:<28} {a.get('signal','?'):<6} {a.get('channel','?'):<10} "
              f"триггеров: {n_trig} ({has_canary})")
        print(f"{'':<28} {a['name']}")
    return 0


# ----------------------------------------------------------------- mutate

def cmd_mutate(args):
    from memred import mutations
    from memred import attacker as attackermod
    from memred.attacks import validate
    if args.llm:
        att = attackermod.load_attacker(cfgmod.load_config(str(ROOT)),
                                        profile=args.llm)
        if att is None:
            raise SystemExit(
                f"нет ключа атакующего (профиль '{args.llm}'). "
                "Вставь API-ключ в файл judge_key_qwen.txt — он общий для "
                "судьи и атакующего этого профиля")
        print(f"Атакующий-LLM: {att.describe()}")
        items = attackermod.generate_mutations(att, args.text, args.canary)
        atks = mutations.generate_llm(items, args.canary,
                                      triggers=args.trigger, prefix=args.prefix)
    else:
        atks = mutations.generate(args.text, args.canary,
                                  triggers=args.trigger, prefix=args.prefix)
    for a in atks:
        validate(a, a["id"])  # сгенерированное обязано быть валидным
    paths = mutations.write_dir(atks, args.out)
    print(f"Сгенерировано {len(paths)} мутаций одной цели в {args.out}:\n")
    for p, a in zip(paths, atks):
        print(f"  {a['id']:<14} {a['name']}")
    print(f"\nПрогон матрицей:\n  python cli.py run --all --dir {args.out}")
    return 0


# ----------------------------------------------------------------- judge

def _build_judge(profile=None):
    """Судья или None (нет ключа). Ошибку профиля не глотаем."""
    from memred import judge as judgemod
    return judgemod.load_judge(cfgmod.load_config(str(ROOT)), profile=profile)


def cmd_judge_test(args):
    from memred import judge as judgemod
    try:
        j = _build_judge(args.judge)
    except judgemod.JudgeUnavailable as e:
        return bad(str(e))
    if j is None:
        prof = args.judge or "deepseek (active)"
        bad("нет API-ключа судьи. Вставь ключ в файл judge_key_<имя>.txt "
            "в корне C:\\memred-lab (или env MEMRED_JUDGE_KEY) и повтори")
        info(f"профиль: {prof}; файлы ключей: judge_key_deepseek.txt, judge_key_qwen.txt")
        return 1
    ok(j.describe())
    info("отправляю тестовый запрос...")
    try:
        reply = j.chat("Ты калькулятор. Отвечай числом.", "2+2?")
    except Exception as e:
        return bad(f"судья недоступен: {e}")
    ok(f"ответ судьи: {reply.strip()[:120]}")
    print("\nСудья подключён: прогоны run/chain/UI автоматически получают "
          "вердикт судьи (adoption/exposure/refusal) рядом с детерминированным.")
    return 0


# ----------------------------------------------------------------- chain

def cmd_chain(args):
    from memred import chains as chmod
    dirpath = args.dir or str(ROOT / "attacks" / "chains")
    try:
        chs = chmod.load_dir(dirpath)
    except chmod.ChainError as e:
        raise SystemExit(str(e))
    if args.list or not chs:
        print(f"Цепочек: {len(chs)} ({dirpath})\n")
        for c in chs:
            print(f"{c['id']:<22} стадий: {len(c['stages'])}  {c['name']}")
        return 0
    if args.id:
        wanted = set(args.id)
        chs = [c for c in chs if c["id"] in wanted]
        missing = wanted - {c["id"] for c in chs}
        if missing:
            raise SystemExit(f"не найдены цепочки: {', '.join(sorted(missing))}")
    adapter = _ensure_target(cfgmod.load_config(
        str(ROOT),
        overrides={"stand": {"auth_mode": args.auth_mode}} if args.auth_mode else None))
    judge = None
    try:
        judge = _build_judge(args.judge)
        if judge:
            print(f"LLM-судья: {judge.describe()}")
    except Exception as e:
        print(f"  судья пропущен: {e}")
    RUNS_DIR.mkdir(exist_ok=True)
    for ch in chs:
        print(f"=== {ch['id']}: {ch['name']} ===")
        try:
            rep = chmod.run_chain(ch, adapter, adapter.name, str(RUNS_DIR),
                                  judge=judge)
        except Exception as e:
            bad(f"прогон упал: {e}")
            continue
        v = rep["verdict"]
        print(f"  → стадии: {v['stages_implanted']}/{v['stages_total']} с маркерами | "
              f"триггеры: {v['activated_triggers']}/{v['triggers_total']} "
              f"({v['adopted_triggers']} принято)")
        print(f"  → отчёт: {rep['run_dir']}\n")
    return 0


# ----------------------------------------------------------------- run

def _ensure_target(cfg):
    adapter = build_target(cfg)
    if adapter.is_up():
        return adapter
    if cfg["target"] != "local":
        raise SystemExit(f"мишень '{adapter.name}' недоступна: {cfg['stand']['base_url']}")
    print("поднимаю локальную мишень...")
    proc = target_process()
    _write_pid(proc.pid)
    for _ in range(90):
        if adapter.is_up():
            print(f"мишень поднята (pid {proc.pid}), первый запрос прогреет индекс")
            return adapter
        time.sleep(1)
    raise SystemExit("мишень не поднялась, см. runs/target.log")


def cmd_run(args):
    overrides = {"local": {"chat_model": args.model} if args.model else None}
    if args.auth_mode:
        overrides["stand"] = {"auth_mode": args.auth_mode}
    cfg = cfgmod.load_config(str(ROOT), overrides=overrides)
    dirpath = args.dir or str(ATTACKS_DIR)
    all_atks = atkmod.load_dir(dirpath)
    if args.id:
        wanted = set(args.id)
        atks = [a for a in all_atks if a["id"] in wanted]
        missing = wanted - {a["id"] for a in atks}
        if missing:
            raise SystemExit(f"не найдены атаки: {', '.join(sorted(missing))}")
    else:
        atks = all_atks
    if not atks:
        raise SystemExit("нет атак для прогона")

    adapter = _ensure_target(cfg)
    judge = None
    try:
        judge = _build_judge(args.judge)
        if judge:
            print(f"LLM-судья: {judge.describe()}")
    except Exception as e:
        print(f"  судья пропущен: {e}")
    RUNS_DIR.mkdir(exist_ok=True)
    reports = []
    print(f"\nПрогон: {len(atks)} атак(и), мишень '{adapter.name}'\n")
    for atk in atks:
        print(f"=== {atk['id']}: {atk['name']} ===")
        try:
            report = run_attack(atk, adapter, adapter.name, str(RUNS_DIR),
                                judge=judge)
        except Exception as e:
            bad(f"прогон упал: {e}")
            continue
        v = report["verdict"]
        reports.append(report)
        print(f"  → внедрение: {'ДА' if v['implanted'] else 'нет'} | "
              f"активация: {v['activated_triggers']}/{v['triggers_total']} | "
              f"полезность: {v['utility_before']} → {v['utility_after']}")
        print(f"  → отчёт: {report['run_dir']}\n")

    if reports:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        battery_path = RUNS_DIR / f"battery-{stamp}.md"
        # строки таблицы должны соответствовать отчётам по id
        rows = [next(a for a in atks if a["id"] == r["attack_id"]) for r in reports]
        battery_md = battery_markdown(rows, reports)
        battery_path.write_text(battery_md, encoding="utf-8")
        print("Сводка батареи:")
        print(battery_md)
        print(f"Сводный отчёт: {battery_path}")
        last = RUNS_DIR / "last-battery.json"
        last.write_text(json.dumps(
            {"battery_report": str(battery_path),
             "runs": [r["run_dir"] for r in reports]}, ensure_ascii=False, indent=2),
            encoding="utf-8")
    return 0


# ----------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(prog="memred", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="проверка окружения")

    p = sub.add_parser("target", help="управление локальной мишенью")
    p.add_argument("action", choices=["start", "stop", "status"])

    p = sub.add_parser("attacks", help="список атак")
    p.add_argument("dir", nargs="?", default=None)

    p = sub.add_parser("run", help="прогон атак")
    p.add_argument("--id", action="append", help="id атаки (можно несколько)")
    p.add_argument("--all", action="store_true", help="вся батарея")
    p.add_argument("--dir", default=None, help="папка с YAML-атаками")
    p.add_argument("--model", default=None, help="модель-мишень (Ollama)")
    p.add_argument("--judge", default=None, help="профиль LLM-судьи: deepseek | qwen")
    p.add_argument("--auth-mode", default=None, choices=["vulnerable", "protected"],
                   help="режим BAC стенда (только target: stand)")

    p = sub.add_parser("judge-test", help="проверка LLM-судьи (ключ, модель, запрос)")
    p.add_argument("--judge", default=None, help="профиль: deepseek | qwen")

    p = sub.add_parser("chain", help="прогон цепочек атак (APT kill chain)")
    p.add_argument("--id", action="append", help="id цепочки (можно несколько)")
    p.add_argument("--list", action="store_true", help="список цепочек")
    p.add_argument("--dir", default=None, help="папка с YAML-цепочками")
    p.add_argument("--auth-mode", default=None, choices=["vulnerable", "protected"],
                   help="режим BAC стенда")
    p.add_argument("--judge", default=None, help="профиль LLM-судьи: deepseek | qwen")

    p = sub.add_parser("mutate", help="цель атаки → 8 мутаций-формулировок")
    p.add_argument("--text", required=True, help="цель атаки (что должен делать агент)")
    p.add_argument("--canary", required=True, help="канарейка-маркер")
    p.add_argument("--trigger", action="append", default=None,
                   help="свой триггер (можно несколько)")
    p.add_argument("--out", default=None, help="куда писать YAML (по умолч. attacks/mutated)")
    p.add_argument("--prefix", default="MUT", help="префикс id атак")
    p.add_argument("--llm", default=None, metavar="ПРОФИЛЬ",
                   help="атакующий-LLM (напр. qwen): генерирует формулировки "
                        "вместо шаблонов; ключ из judge_key_<профиль>.txt")

    p = sub.add_parser("ui", help="веб-UI: онлайн-кастомизация и запуск атак")
    p.add_argument("--port", type=int, default=8080)

    args = ap.parse_args()
    if args.cmd == "doctor":
        return cmd_doctor(args)
    if args.cmd == "target":
        return cmd_target(args)
    if args.cmd == "attacks":
        return cmd_attacks(args)
    if args.cmd == "judge-test":
        return cmd_judge_test(args)
    if args.cmd == "chain":
        if not args.dir:
            args.dir = str(ROOT / "attacks" / "chains")
        return cmd_chain(args)
    if args.cmd == "mutate":
        if not args.out:
            args.out = str(ROOT / "attacks" / "mutated")
        return cmd_mutate(args)
    if args.cmd == "ui":
        import uvicorn
        from ui.server import app
        print(f"веб-UI memred: http://localhost:{args.port}  (Ctrl+C — выход)")
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
        return 0
    if args.cmd == "run":
        if not (args.all or args.id):
            ap.error("укажите --id ID или --all")
        return cmd_run(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
