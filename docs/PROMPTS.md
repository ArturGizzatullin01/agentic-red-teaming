\# Промпты memnotsafe



Пин (оба приложения, раз за сессию):

Канон — team-publish. Соседние деревья не трогай.

Сначала MAP.md и хвост LOG.md.

Пока не ясна роль Attack/Adapter/Runner/Oracle/Reporter — код не пиши.

Живой стенд и Mongo не трогай. Mock не лечи.

Атака не пробилась = exit 0 + NOT\_EXPLOITABLE.

Проверка: python3 -m pytest tests/test\_e2e\_cross\_user.py tests/test\_all\_attacks.py -q

После: LOG.md + команда которую прогнал.



Codex, красный тест:

objective: только падающий тест

не трогать: core/, cli.py, live, соседние копии

Тест: <имя>

Трейс: <целиком>

Проверка: python3 -m pytest <файл> -q



Claude, новая семья — сначала без кода:

спека family + payload/delivery/trigger/expected\_effect + YAML + тесты

не выдумывать постановку

потом «ок, пиши»: только attacks/<name>.py + YAML + тест, не core/

