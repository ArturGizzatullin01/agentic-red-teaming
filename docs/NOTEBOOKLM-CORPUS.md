# Что класть в NotebookLM для memnotsafe

Один ноутбук: `memnotsafe-canon`.
ID записать в волте: `Sources/.notebook-id`.

## Класть

- `description_interim.md`
- `PROJECT_OVERVIEW.md`
- `README.md`
- `.specify/memory/constitution.md`
- `docs/integration-handoff/{spec,plan,tasks,contracts,audit,acceptance}.md`
- `attack_classes/README.md`, `profiles/README.md`, `corpora/README.md`
- внешние бумаги/методички по memory poisoning, MPBench, MITRE ATLAS, OWASP ASI — как PDF в Inbox

## Не класть

- `runs/**` и live-трейсы (шум + возможные секреты стенда)
- `pytest.log`, гигантские JSON отчётов
- исходники целиком (`src/` дублирует то, что агент и так читает с диска)
- ключи, `.env`, дампы Mongo

Код агент читает из файлов проекта. NotebookLM — для постановки, таксономии атак и «как задумано», не для навигации по `cli.py`.
