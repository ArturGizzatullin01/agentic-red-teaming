"""Конфигурация: config.yaml в корне пакета, значения по умолчанию — здесь."""

import os

import yaml

DEFAULTS = {
    "target": "local",
    "local": {
        "base_url": "http://localhost:8101",
        "chat_model": "ornith-1.5:9b",
        "embed_model": "qwen3-embedding:0.6b",
    },
    # Дефолт — stack2 (изолированная копия, порты +1000): прогон делает
    # reset() Mongo-памяти, и указывать на общий стенд по умолчанию нельзя.
    "stand": {
        "base_url": "http://localhost:9600",
        "token": "",
        "cus": "1001",
        "auth_mode": "vulnerable",
        "finalize_word": "finalize",
        "mongo_uri": "mongodb://localhost:28017",
        "key_store": "stand_key_stack2.json",
    },
    "ollama_url": "http://localhost:11434",
    "judge_model": "qwen2.5:3b",
}


def load_config(root: str, overrides: dict = None) -> dict:
    cfg = dict(DEFAULTS)
    path = os.path.join(root, "config.yaml")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            for k, v in yaml.safe_load(f).items():
                if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
    if overrides:
        for k, v in overrides.items():
            if v is None:
                continue
            if isinstance(v, dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    return cfg
