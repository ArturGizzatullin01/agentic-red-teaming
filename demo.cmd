@echo off
rem Лаунчер демо: из любой папки — .\demo (мок) или .\demo -Live (живой стенд)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0.agent-work\demo\demo-run.ps1" %*
