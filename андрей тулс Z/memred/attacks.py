"""Загрузка и валидация YAML-атак. Киллер-фича: своя атака = положить файл."""

import glob
import os

import yaml

REQUIRED = ("id", "name", "channel", "delivery", "triggers")
KNOWN_CHANNELS = ("chat", "document", "web", "tool_output")


class AttackError(Exception):
    pass


def validate(atk: dict, path: str = "?") -> dict:
    missing = [k for k in REQUIRED if not atk.get(k)]
    if missing:
        raise AttackError(f"{path}: отсутствуют обязательные поля: {', '.join(missing)}")
    if atk["channel"] not in KNOWN_CHANNELS:
        raise AttackError(
            f"{path}: channel='{atk['channel']}' — допустимо: {', '.join(KNOWN_CHANNELS)}"
        )
    delivery = atk["delivery"]
    if atk["channel"] in ("chat", "web", "tool_output") and not delivery.get("messages"):
        raise AttackError(f"{path}: для channel='{atk['channel']}' нужен delivery.messages")
    if atk["channel"] == "document" and not delivery.get("document"):
        raise AttackError(f"{path}: для channel='document' нужен delivery.document")
    if not atk.get("canary") and not atk.get("expected_in_answer"):
        raise AttackError(
            f"{path}: нужен canary или expected_in_answer — иначе проверка успеха невозможна"
        )
    # нормализация
    atk.setdefault("class", "uncategorized")
    atk.setdefault("signal", "strong")
    atk.setdefault("atlas", "")
    atk.setdefault("owasp", "ASI06")
    atk.setdefault("source", atk.get("id", "attack") + ".txt")
    atk.setdefault("utility_questions", [])
    if isinstance(atk["triggers"], str):
        atk["triggers"] = [atk["triggers"]]
    if isinstance(atk["delivery"].get("messages"), str):
        atk["delivery"]["messages"] = [atk["delivery"]["messages"]]
    return atk


def load_attack(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise AttackError(f"{path}: YAML не содержит словарь")
    return validate(data, path)


def load_dir(dirpath: str) -> list:
    out, errors = [], []
    for path in sorted(glob.glob(os.path.join(dirpath, "*.yaml"))):
        try:
            out.append(load_attack(path))
        except AttackError as e:
            errors.append(str(e))
        except yaml.YAMLError as e:
            errors.append(f"{path}: некорректный YAML: {e}")
    if errors:
        raise AttackError("Ошибки в файлах атак:\n" + "\n".join(errors))
    return out
