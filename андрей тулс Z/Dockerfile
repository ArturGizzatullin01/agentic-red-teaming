# memred — сканер безопасности памяти ИИ-агентов (black-box, только API мишени)
# Сборка:  docker build -t memred .
# Запуск:  docker run --rm -v $(pwd)/config.yaml:/app/config.yaml \
#              -v $(pwd)/runs:/app/runs memred run --all --dir attacks/stand-templates
# Никаких доработок на стороне тестируемого агента не требуется.

FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cli.py .
COPY memred/ memred/
COPY tools/ tools/
COPY attacks/ attacks/

# ключи не в образе: монтируются файлами (judge_key_*.txt, stand_key_*.json)
ENTRYPOINT ["python", "cli.py"]
CMD ["doctor"]
