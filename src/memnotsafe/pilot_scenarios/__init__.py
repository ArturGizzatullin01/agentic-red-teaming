"""src/memnotsafe/pilot_scenarios/ — P19 (часть 2): стартовый набор сценариев
пилота, упакованный в wheel как package data.

Единственная УПАКОВАННАЯ копия сценариев стартового пака (`pilot_pack.STARTER_PACK`):
из голого `pip install` каталог репозитория `scenarios/` недоступен, поэтому
`memnotsafe pilot` разрешает сценарии через `importlib.resources` этого пакета
(fallback на repo-путь — поведение разработчика). Файлы БАЙТ-В-БАЙТ совпадают с
каноническими `scenarios/<name>.yaml` — расхождение ловит тест
`test_packaged_pilot_scenarios_match_repo_originals` (единый источник истины,
дрейфа быть не должно). Сами сценарии здесь не редактируются.
"""
