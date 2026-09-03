# Как запушить memred-lab в общий GitHub — что нужно и как

> **Статус: уже запушено 04.09** в командный репозиторий
> `ArturGizzatullin01/agentic-red-teaming`, папка **«андрей тулс Z»**
> (62 файла, только трекнутое git'ом — ключи и runs/ исключены).
> Ниже — состав и инструкция на случай отдельного репо/обновления.

Репозиторий **готов к пушу**: секретов в файлах и истории нет, всё
чувствительное закрыто `.gitignore`. Ниже — что уедет на GitHub, чего
там не будет, и точные команды.

## 1. Что пушится (61 файл)

| Что | Путь | Комментарий |
|---|---|---|
| Движок | `memred/` (runner, chains, mutations, judge, attacker, adapters…) | ядро: прогоны, вердикты, LLM-судья/атакующий |
| CLI | `cli.py` | run / chain / mutate / judge-test / ui / attacks / doctor |
| Веб-UI | `ui/` | онлайн-кастомизация, демо-кнопка APT, панель атакующего-LLМ |
| Атаки | `attacks/` — 22 шаблона стенда + 3 цепочки + 5 локальных | YAML, каждая с классом и канарейкой |
| Докси | `README.md`, `QUICKSTART.md`, `docs/findings-stand.md`, `docs/coverage-matrix.md`, `docs/demo-script.md` | находки, матрица покрытия, сценарий демо |
| Отчёты | `tools/coverage_report.py` | авто-матрица по `runs/` |
| Окружение | `requirements.txt`, `config.yaml`, `.gitignore` | ключи в конфиге — только пути к файлам, не значения |

## 2. Чего на GitHub НЕ будет (и это правильно)

- `judge_key_*.txt`, `stand_key_*.json` — **ключи** (Yandex LLM, стенд).
  Каждый участник кладёт свои в корень после клона (инструкция в QUICKSTART).
- `runs/` — артефакты прогонов (34+ папок, отчёты/трейсы). Доказательства
  живут локально; при желании выложить — zip отдельно, не в git.
- `.venv/`, `attacks/mutated*/` — генерируются на месте.

## 3. Безопасность (уже проверено 04.09)

- `stand_key.json` был закоммичен в 2 ранних коммитах — **история
  переписана** (`git filter-branch` + gc): `git log --all -- stand_key.json`
  → пусто, blob'ов в объектах — 0. Коммиты (17) сохранены, хеши сменились.
- Значения облачных ключей (`AQVN…`, `AIza…`, `sk-…`) в истории и файлах —
  не встречались (проверка `git grep` по всем ревизиям).
- Перед пушем контрольная строка (должна быть пустой):
  `git grep -nE "AQVN[A-Za-z0-9_-]{10,}|sk-genai-|AIza[A-Za-z0-9_-]{20,}" $(git rev-list --all)`

## 4. Команды пуша (новый репо команды)

```bash
cd C:/memred-lab
# 1) создать ПУСТОЙ репо на github.com (без README/.gitignore), например:
#    alfa-agentic-redteam
git remote add origin https://github.com/<команда>/alfa-agentic-redteam.git
git push -u origin main
# 2) проверить в веб-интерфейсе: нет judge_key_*.txt / stand_key_*.json / runs/
```

Если общий репо команды уже существует — вместо создания пушим веткой:

```bash
git remote add team https://github.com/<команда>/<общий-репо>.git
git push -u team main            # или: git checkout -b memred && git push -u team memred
```

## 5. Что сделать участникам после клона

```bash
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
# ключи (НЕ коммитить!):
#   judge_key_deepseek.txt, judge_key_qwen.txt  — Yandex FM (судья/атакующий)
#   stand_key_stack2.json                        — ключ стенда :9600
python cli.py doctor     # проверка окружения
python cli.py ui         # веб-UI на :8080
```

## 6. Замечания

- Роли LLM фиксированы правилом команды: **deepseek — судья, qwen —
  атакующий** (`config.yaml`, не менять).
- Код оригинальный; LLAMATOR (CC BY-NC-SA) в поставку не входит.
- Тестовые данные стенда синтетические — пушить можно.
