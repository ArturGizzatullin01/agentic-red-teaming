@echo off
chcp 65001 >nul
set PYTHONUTF8=1
cd /d %~dp0

echo === memred-lab: полная батарея атак ===
call .venv\Scripts\activate.bat
python cli.py run --all
echo.
echo Артефакты прогона: папка runs\ (сводный отчёт battery-*.md)
pause
