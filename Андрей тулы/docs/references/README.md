# docs/references — внешние статьи (writeups)

## Как вкладывать статьи ЭФФЕКТИВНО (а не «скопом»)

Кидать сырые .html скопом в корень проекта — плохо. Почему:
- В HTML 80–95% — навигация, скрипты, стили: агент тратит на это токены и «замыливается».
- Без индекса агент не знает, какую статью открыть под конкретную атаку.
- Если положить их туда, куда смотрит авто-загрузка (корень/CLAUDE.md), они раздуют КАЖДУЮ сессию.

### Правильный шаблон (focused-lens + on-demand)
1. **Место:** всё сюда, в `docs/references/`. НЕ в корень и НЕ упоминать из CLAUDE.md для авто-загрузки.
   Агент читает их только когда попросили — по одной, по нужной.
2. **Формат:** конвертируй .html → чистый .md (лёгкий текст). См. скрипт `_convert.py` ниже.
   Имя файла = говорящее: `2026-01_hacking-claude-memory_rehberger.md`.
3. **Индекс — главное:** `docs/attack-references.md` уже карта: какая статья, зачем нам,
   на какой канал/класс/последствие ложится. Агент читает СНАЧАЛА индекс, потом открывает 1 нужную статью.
   (Техника Conditional/фокусная линза из справочника — не «прочитай всё», а «прочитай релевантное».)

### Рабочий цикл в промпте
    Опираясь на docs/attack-references.md, возьми источник <название> из docs/references/
    и реализуй attack-пак по /new-attack. Не читай остальные статьи.

## Конвертер HTML → Markdown (`_convert.py`)
Положи скачанные .html в эту папку и запусти локально:

```bash
pip install trafilatura        # чистое извлечение основного текста
python _convert.py             # сделает .md рядом с каждым .html
```

```python
# _convert.py
import pathlib, trafilatura
here = pathlib.Path(__file__).parent
for html in here.glob("*.html"):
    raw = html.read_text(encoding="utf-8", errors="ignore")
    md = trafilatura.extract(raw, output_format="markdown", include_links=True) or ""
    out = html.with_suffix(".md")
    out.write_text(f"# {html.stem}\n\n{md}\n", encoding="utf-8")
    print("ok:", out.name)
```

После конвертации сырые .html можно удалить или убрать в `_html_raw/` — в работу идут только .md.

## Итог одной строкой
Индекс (`attack-references.md`) + лёгкие .md по одной статье в `docs/references/`, читаются ПО ТРЕБОВАНИЮ.
Никогда не сваливай сырой HTML в корень и не тащи статьи в CLAUDE.md.
