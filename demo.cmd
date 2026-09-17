@echo off
rem Лаунчер демо: офлайн-пара vulnerable/protected на моке, сравнение воронок и ASR.
rem Скрипт живёт в отслеживаемом scripts/ (раньше ссылался в gitignored .agent-work и
rem был сломан на любом свежем клоне). Параметры: -Python <путь>, -Open (открыть отчёты).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\demo-run.ps1" %*
exit /b %ERRORLEVEL%
