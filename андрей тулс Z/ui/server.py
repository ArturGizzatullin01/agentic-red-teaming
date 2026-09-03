"""Веб-UI memred: онлайн-кастомизация атак — редактор YAML + живой запуск.

Запуск: python cli.py ui [--port 8080]  ->  http://localhost:8080
Один прогон за раз (валидация: прогоны сбрасывают память мишени).
Артефакты те же, что у CLI: runs/<attack-id>-<stamp>/ (report.md/json, trace.jsonl).
"""

import json
import sys
import threading
import time
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memred import attacks as atkmod  # noqa: E402
from memred import attacker as attackermod  # noqa: E402
from memred import chains as chnmod  # noqa: E402
from memred import config as cfgmod  # noqa: E402
from memred import judge as judgemod  # noqa: E402
from memred import mutations as mutmod  # noqa: E402
from memred.adapters import build_target  # noqa: E402
from memred.chains import run_chain  # noqa: E402
from memred.runner import run_attack  # noqa: E402

RUNS_DIR = ROOT / "runs"
ATTACK_DIRS = {
    "local": ROOT / "attacks",
    "stand": ROOT / "attacks" / "stand-templates",
    "chains": ROOT / "attacks" / "chains",
    "mutated": ROOT / "attacks" / "mutated",
    "mutated-llm": ROOT / "attacks" / "mutated-llm",
}
MUTATED_LLM_DIR = ROOT / "attacks" / "mutated-llm"
DEMO_CHAIN = "attacks/chains/CH-1-audit-exfil.yaml"

app = FastAPI(title="memred UI")

_run_lock = threading.Lock()          # один прогон за раз
_runs: dict = {}                      # run_id -> {status, run_dir, error, report}


def _safe_path(rel: str) -> Path:
    if not rel:
        raise HTTPException(400, "пустой путь")
    p = (ROOT / rel).resolve()
    try:
        p.relative_to(ROOT.resolve())
    except ValueError:
        raise HTTPException(400, "путь вне папки проекта")
    if p.suffix != ".yaml":
        raise HTTPException(400, "разрешены только .yaml в attacks/")
    return p


class SaveBody(BaseModel):
    path: str
    yaml: str


class RunBody(BaseModel):
    path: str
    auth_mode: str = None  # None = из конфига; vulnerable | protected


class MutateBody(BaseModel):
    goal: str        # что агент должен запомнить и исполнять
    canary: str      # уникальный маркер
    trigger: str = None  # необязательный вопрос-триггер


def _short_model(uri: str) -> str:
    """gpt://folder/deepseek-v4-flash/latest -> deepseek-v4-flash"""
    parts = [p for p in (uri or "").split("/") if p]
    return parts[-2] if len(parts) >= 2 else (uri or "?")


def _role_status(loader) -> dict:
    """judge/attacker: {name, model} | None (нет ключа) | {error}."""
    try:
        client = loader(cfgmod.load_config(str(ROOT)))
    except Exception as e:
        return {"error": str(e)[:120]}
    if client is None:
        return None
    return {"name": client.name, "model": _short_model(client.model)}


@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "index.html")


@app.get("/api/state")
def state():
    cfg = cfgmod.load_config(str(ROOT))
    kind = cfg.get("target", "local")
    target = build_target(cfg)
    base = cfg["stand"]["base_url"] if kind == "stand" else cfg["local"]["base_url"]
    return {"target": kind, "base_url": base, "auth_mode": cfg["stand"]["auth_mode"],
            "up": target.is_up(),
            "judge": _role_status(judgemod.load_judge),
            "attacker": _role_status(attackermod.load_attacker)}


@app.get("/api/attacks")
def list_attacks():
    out = []
    for group, d in ATTACK_DIRS.items():
        for p in sorted(d.glob("*.yaml")):
            try:
                if group == "chains":
                    c = chnmod.load_chain(str(p))
                    out.append({"group": group, "path": str(p.relative_to(ROOT)),
                                "id": c["id"], "name": c["name"],
                                "signal": c.get("signal"),
                                "channel": f"цепочка ×{len(c['stages'])} стадий",
                                "kind": "chain"})
                else:
                    a = atkmod.load_attack(str(p))
                    out.append({"group": group, "path": str(p.relative_to(ROOT)),
                                "id": a["id"], "name": a["name"],
                                "signal": a.get("signal"), "channel": a["channel"],
                                "kind": "attack"})
            except Exception:
                continue  # битый YAML не мешает списку — можно открыть и починить
    return out


@app.get("/api/attack")
def get_attack(path: str):
    p = _safe_path(path)
    if not p.exists():
        raise HTTPException(404, "файл не найден")
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    raw = raw if isinstance(raw, dict) else {}
    msgs = []
    delivery = raw.get("delivery")
    if isinstance(delivery, dict):
        msgs = [m for m in delivery.get("messages", [])
                if isinstance(m, str) and m.strip().lower() != "finalize"]
    stages = raw.get("stages")
    if not msgs and isinstance(stages, list) and stages and isinstance(stages[0], dict):
        st0 = stages[0]
        m0 = st0.get("messages")
        if not isinstance(m0, list) and isinstance(st0.get("delivery"), dict):
            m0 = st0["delivery"].get("messages", [])
        msgs = [m for m in (m0 or [])
                if isinstance(m, str) and m.strip().lower() != "finalize"]
    triggers = [t for t in raw.get("triggers", []) if isinstance(t, str)]
    meta = {
        "kind": "chain" if isinstance(stages, list) else "attack",
        "canary": raw.get("canary") if isinstance(raw.get("canary"), str) else "",
        "first_trigger": triggers[0] if triggers else "",
        "first_message": msgs[0] if msgs else "",
    }
    return {"path": str(p.relative_to(ROOT)), "yaml": p.read_text(encoding="utf-8"),
            "meta": meta}


@app.post("/api/attack")
def save_attack(body: SaveBody):
    p = _safe_path(body.path)
    # файл должен лежать в attacks/ или attacks/<подпапка>/ (stand-templates, chains, mutated)
    if p.parent.parent != ROOT / "attacks" and p.parent != ROOT / "attacks":
        raise HTTPException(400, "файл должен лежать в attacks/ или attacks/<подпапка>/")
    try:
        data = yaml.safe_load(body.yaml)
        if not isinstance(data, dict):
            raise atkmod.AttackError("YAML не содержит словарь")
        atkmod.validate(data, p.name)
    except atkmod.AttackError as e:
        raise HTTPException(400, f"валидация не прошла: {e}")
    except yaml.YAMLError as e:
        raise HTTPException(400, f"некорректный YAML: {e}")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body.yaml, encoding="utf-8")
    return {"saved": True, "path": str(p.relative_to(ROOT))}


@app.post("/api/run")
def start_run(body: RunBody):
    if not _run_lock.acquire(blocking=False):
        raise HTTPException(409, "уже идёт прогон — дождитесь завершения")
    try:
        p = _safe_path(body.path)
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise HTTPException(400, "YAML не содержит словарь")
        is_chain = "stages" in raw
        if is_chain:
            spec = chnmod.validate_chain(raw, p.name)
        else:
            spec = atkmod.validate(raw, p.name)
    except HTTPException:
        _run_lock.release()
        raise
    except Exception as e:
        _run_lock.release()
        raise HTTPException(400, f"валидация не прошла: {e}")

    run_id = f"{spec['id']}-{time.strftime('%Y%m%d-%H%M%S')}"
    run_dir = RUNS_DIR / run_id
    _runs[run_id] = {"status": "running", "run_dir": run_dir, "error": None,
                     "report": None}

    overrides = {"stand": {"auth_mode": body.auth_mode}} if body.auth_mode else None

    def work():
        try:
            cfg = cfgmod.load_config(str(ROOT), overrides=overrides)
            target = build_target(cfg)
            try:
                judge = judgemod.load_judge(cfg)  # None, если ключа нет
            except judgemod.JudgeUnavailable:
                judge = None
            report = (run_chain(spec, target, target.name, str(RUNS_DIR),
                                run_dir=str(run_dir), judge=judge) if is_chain else
                      run_attack(spec, target, target.name, str(RUNS_DIR),
                                 run_dir=str(run_dir), judge=judge))
            _runs[run_id]["report"] = report
            _runs[run_id]["status"] = "done"
        except Exception as e:
            _runs[run_id]["status"] = "error"
            _runs[run_id]["error"] = str(e)
        finally:
            _run_lock.release()

    threading.Thread(target=work, daemon=True).start()
    return {"run_id": run_id}


@app.post("/api/demo")
def start_demo():
    """Демо одной кнопкой: APT-цепочка CH-1 (режим аудита → эксфильтрация)."""
    p = ROOT / DEMO_CHAIN
    if not p.exists():
        raise HTTPException(404, f"демо-цепочка не найдена: {DEMO_CHAIN}")
    return start_run(RunBody(path=DEMO_CHAIN))


@app.post("/api/llm-mutate")
def llm_mutate(body: MutateBody):
    """Атакующий-LLМ (qwen): цель + канарейка → 8 формулировок-атак.

    Роли фиксированы правилом команды: атакующий — ТОЛЬКО qwen.
    Один клик = один платный запрос к Yandex Foundation Models.
    Перезаписывает attacks/mutated-llm/MUTLLM-*.yaml (прошлые прогоны
    остаются в runs/).
    """
    goal = (body.goal or "").strip()
    canary = (body.canary or "").strip()
    if not goal or not canary:
        raise HTTPException(400, "укажите цель атаки и канарейку")
    try:
        attacker = attackermod.load_attacker(cfgmod.load_config(str(ROOT)))
    except Exception as e:
        raise HTTPException(500, f"атакующий не сконфигурирован: {e}")
    if attacker is None:
        raise HTTPException(503, "нет API-ключа атакующего — заполни judge_key_qwen.txt")
    triggers = [body.trigger.strip()] if (body.trigger or "").strip() else None
    try:
        items = attackermod.generate_mutations(attacker, goal, canary)
        attacks = mutmod.generate_llm(items, canary, triggers)
        paths = mutmod.write_dir(attacks, str(MUTATED_LLM_DIR))
    except Exception as e:
        raise HTTPException(502, f"атакующий не справился: {str(e)[:300]}")
    return {"attacker": attacker.name, "model": _short_model(attacker.model),
            "count": len(attacks), "ids": [a["id"] for a in attacks],
            "paths": [str(Path(p).relative_to(ROOT)) for p in paths],
            "formulations": items}


@app.get("/api/run/{run_id}")
def run_status(run_id: str):
    entry = _runs.get(run_id)
    if not entry:
        raise HTTPException(404, "прогон не найден (в этой сессии UI)")
    events = []
    trace = entry["run_dir"] / "trace.jsonl"
    if trace.exists():
        for line in trace.read_text(encoding="utf-8").splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    report = None
    rj = entry["run_dir"] / "report.json"
    if rj.exists():
        try:
            report = json.loads(rj.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {"status": entry["status"], "error": entry["error"],
            "run_dir": str(entry["run_dir"]), "events": events, "report": report}
