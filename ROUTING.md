# Маршрут задач по memnotsafe

| Сигнал | Куда | Почему |
|---|---|---|
| MPBench, ATLAS, ASI06, постановка от Яны, бумага | NotebookLM → `Research/` | корпус, не код |
| «почему Attack нельзя судить внутри Adapter» | волт + constitution | уже зафиксировано |
| красный `test_e2e_cross_user` / один oracle | Codex App | узкий цикл |
| новый attack family + YAML + тест | Claude Code Desktop | много ролей, легко смешать |
| judge prompt / калибровка / budget | Claude Code, потом офлайн-тесты `tests/test_judge_*` | семантика + регресс |
| live Mongo adapter | только по явной задаче, Claude Code | секреты и стенд |
| HTML/SARIF вёрстка отчёта | Codex | локальный фикс |
| кампания 26 / метрики в `runs/` | не код; читай как артефакт | не коммитить в канон без нужды |

Параллелить Claude и Codex можно на разных файлах.
Нельзя: оба правят `core/` или один и тот же attack-файл.
