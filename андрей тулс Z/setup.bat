@echo off
chcp 65001 >nul
set PYTHONUTF8=1
cd /d %~dp0

echo === memred-lab: установка окружения ===
if not exist .venv (
    python -m venv .venv
    echo venv создан
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip -q
pip install -r requirements.txt -q
if errorlevel 1 (
    echo [FAIL] установка зависимостей не удалась
    pause
    exit /b 1
)
echo Зависимости установлены.
echo.
echo Проверка окружения:
python cli.py doctor
echo.
echo Готово. Дальше: run-battery.bat — полный прогон батареи атак.
pause
