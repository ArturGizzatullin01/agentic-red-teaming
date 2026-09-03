# demos/ — вне pluggable-системы, пока не обсуждено с командой

`poc_indirect_tool_injection.py` — офлайн-PoC indirect prompt injection через тул
(`web_search`) против той же логики, что в `genai-invest-agent-memory-stand`
(`app/agent/runner.py`), с фокусом на BAC-последствие (модель сама решает чужой `cus`),
а не на персистентность в памяти.

**Почему не в `attacks/` рядом с паками Андрея:** формат `AttackBase` (см.
`core/attack_base.py`) заточен под evidence-first через Mongo-диф долговременной
памяти — `success_check` в этом PoC устроен иначе (перехват `cus` в аргументе tool-call
внутри одной сессии, без finalize/Mongo). Обвязывать его в `AttackBase` формально
можно, но по-честному это другой канал: `MPBenchClass.INFERRED_WRITE_TOOL_OUTPUT`,
который `HANDOFF_2026-09-03.md` явно отметил как непокрытый — "нет attacker-controlled
канала на этом стенде" (mcp-invest отдаёт синтетические read-only данные, DuckDuckGo
требует реального SEO-отравления). Этот PoC поэтому — офлайн-репродукция уязвимой
ЛОГИКИ (system prompt + `CUS_SCOPED_TOOLS`-приоритет скопированы дословно из
`runner.py`), а не прогон живого агента: `web_search`/тул портфеля — локальные
заглушки, честно помечено в докстринге файла.

**Что дальше — на обсуждение с командой, не решено в одиночку:**
1. Оставить как есть — отдельный референс/демо-материал (BAC-последствие, не memory
   poisoning per se).
2. Или дотянуть до настоящего attack-пака: после того как отравленный `web_search`
   спровоцировал утечку чужого портфеля в чат, дожать `finalize()` и проверить по
   `MongoEvidenceSource`, осела ли эта PII в `semantic_memories`/`episodic_memories`
   витчнесс-сессии — это ровно закрыло бы пробел `inferred_write_tool_output` из
   HANDOFF и дало бы полноценный `AttackBase`-пак с реальным Mongo-evidence, а не
   локальной заглушкой.

См. подробный разбор в переписке с Артуром (объяснение PoC, наблюдённый hit-rate на
`qwen2.5:7b`).
