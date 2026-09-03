# Attack Reference Pack — отобранные writeups под кейс «атаки на память»

> Отобрано из `ai-agent-hacking-writeups` под проект Команды 7 (red teaming памяти инвест-агента).
> Критерий отбора — совпадение с **нашими** конструкциями, а не «просто про ИИ-безопасность»:
> каналы доставки (веб-поиск / вывод MCP-тула / память), классы MPBench (сила сигнала),
> и наши целевые последствия (кросс-юзер `scope=global`, BAC/чтение чужого `cus`, эксфильтрация).
>
> Для каждого источника: **зачем он нам** и **куда ложится** (канал / класс / последствие / evidence).
> Приоритет: 🟥 ядро — брать первым; 🟧 сильно релевантно; 🟨 техника/фон.

---

## Tier 1 — Память и персистентность (прямое попадание в кейс) 🟥

Немного таких, но это буквально «атаки на долговременную память агента» — ближе всего к нашему `finalize → extract_semantics → AgentPolicyMemory`.

- 🟥 **Breaking Opus 4.7 with ChatGPT (Hacking Claude's Memory)** — Johann Rehberger, 2026-01
  https://embracethered.com/blog/posts/2026/breaking-opus-4.7-with-chatgpt/
  Инъекция, которая **записывается в долговременную память** одного агента и активируется позже/из другого контекста. Прямой аналог нашего разрыва write↔activate. → класс *explicit command insertion*, канал *memory*, evidence — персистентность после сброса сессии.

- 🟥 **Never Trust the Output: Data Pollution in AI Agents and MCP** — Slonser, 2026-01
  https://blog.slonser.info/posts/smugglle-ai-ouputs/
  Загрязнение контекста/памяти агента через **вывод тула** (в т.ч. невидимые данные). Ровно наш канал «результаты MCP-тулов» → запись в семантику. → weak-signal, канал *tool output*, класс *inferred-write*.

- 🟧 **Agent Commander: Promptware-Powered Command and Control** — Johann Rehberger, 2026-03
  https://embracethered.com/blog/posts/2026/agent-commander-your-agent-works-for-me-now/
  «Промптварь» как персистентная управляющая инструкция, переживающая шаги. Модель того, как отравленная политика в `agent_policy_memories` даёт устойчивый контроль над агентом всех клиентов. → последствие *hijack*, класс *policy poisoning*.

---

## Tier 2 — Инъекция через НАШИ каналы доставки (веб-поиск / вывод тула / retrieval) 🟧

Это шаблоны фазы *injection*: как недоверенный контент попадает в агента именно теми путями, что открыты у стенда.

- 🟥 **Agentjacking: Hijacking AI Coding Agents via Fake Sentry Errors (IPI through MCP)** — Tenet Labs, 2026-06 · critical
  https://tenetsecurity.ai/blog/agentjacking-coding-agents-with-fake-sentry-errors/
  Инъекция прячется в **выводе MCP-тула**, агент исполняет её как инструкцию. Наш канал tool-output в чистом виде. → канал *tool output*, сильный сигнал.

- 🟥 **Indirect Prompt Injection via Supabase MCP Leaks Entire SQL Database** — General Analysis, 2026-04
  https://www.generalanalysis.com/blog/supabase-mcp-blog
  MCP-тул → чтение всей БД. Прямой аналог нашего BAC: инъекция заставляет тул вернуть данные вне прав. → последствие *BAC / cross-client read*, канал *tool output*.

- 🟧 **GeminiJack: Zero-Click IPI Data Exfiltration in Gemini Enterprise & Vertex AI Search** — Noma Labs, 2025-12 · critical
  https://noma.security/blog/geminijack-google-gemini-zero-click-vulnerability
  **Zero-click отравление retrieval/RAG**: payload лежит в корпусе и срабатывает при обычном запросе. Идейно = наш weak-signal retrieval-triggered (GhostWriter-style). → класс *salience/retrieval poisoning*, канал *web/retrieval*.

- 🟧 **Data Exfiltration from Slack AI via Indirect Prompt Injection** — PromptArmor, 2024-08
  https://www.promptarmor.com/resources/data-exfiltration-from-slack-ai-via-indirect-prompt-injection
  Инъекция в общий корпус → утечка данных **другого** пользователя. Классика кросс-юзер распространения — наш `scope=global`. → последствие *cross-user propagation*.

- 🟨 **Indirect Prompt Injection Turns Bing Chat into a Data Pirate** — Kai Greshake (foundational)
  https://greshake.github.io/
  Первооснова IPI-через-веб. Полезно для языка/маппинга и как «канонический» пример канала web-search.

---

## Tier 3 — Отравление MCP-тулов / подмена схем (канал «результаты MCP-тулов») 🟧

У стенда 14 read-тулов mcp-invest — это отдельная поверхность записи в память и исполнения.

- 🟧 **MCP List Caching and Tool Poisoning (Rug-Pull) Attacks** — silentrobots, 2026-07
  https://silentrobots.com/mcp-list-caching-and-tool-poisoning/
  Tool poisoning + rug-pull: описание тула меняется после доверия. → канал *tool metadata*, класс *conditional/deferred command*.

- 🟧 **Agent Hypnosis and Parameter Abuse: Redefining MCP Tool Schemas via Prompt Injection** — Ryan, 2026-01
  http://bountyplz.xyz/ai,/security/2026/01/05/Agent-Hypnosis-and-Parameter-Abuse
  Переопределение схемы тула инъекцией → скрытая эксфильтрация через параметры. → техника доставки/эксфильтрации через тулы.

- 🟨 **MCP Security Hot Potato: Tool Poisoning, Rug Pulls, Tool Shadowing** — Mateusz Olejarka, 2026-02
  https://www.securing.pl/en/mcp-security-hot-potato/
  Обзорная систематика MCP-угроз — хороший словарь для маппинга наших MCP-атак.

---

## Tier 4 — BAC / кросс-тенант чтение (наше самое критичное последствие) 🟥

Демонстрируют «отравленная память/инъекция → чтение чужих данных» — то, к чему должна приводить наша цепочка.

- 🟥 **Tricking an AI Ops Agent into Leaking Unauthorized Report Data via a Notification Reference** — Hacktus, 2026-02
  https://hackt.us/how-i-tricked-an-ai-into-thinking-i-owned-your-data
  Агент отдаёт данные вне прав, «поверив» подставной ссылке-контексту. Прямой аналог: инъекция навязывает чужой `cus`. → последствие *BAC*.

- 🟧 **MCP Server Integration Bypasses Tenant Permissions to Leak All Conversations and Contacts** — 1-day, 2025-11
  https://1-day.medium.com/how-i-discovered-a-rare-vulnerability-in-mcp-server-bug-bounty-28a0ef643902
  Обход тенант-разграничения через MCP. Аналог `auth_mode=vulnerable` + сервис-токен. → последствие *cross-tenant read*.

- 🟨 **How I Hacked an AI Chatbot to Expose Customer Records (IDOR + Prompt Injection)** — Sumit Shah, 2025-11 · critical
  https://medium.com/@sumitshahorg/how-i-hacked-an-ai-chatbot-to-expose-thousands-of-customer-records-idor-prompt-injection-760092ed99a4
  IDOR+PI → массовое чтение клиентских записей. Иллюстрация тяжести последствия для банковских данных.

---

## Tier 5 — Техника эксфильтрации и evidence (для success-check и защит-ориентиров) 🟨

Нужны, чтобы строить проверку успеха «данные реально ушли» и понимать митигации.

- 🟧 **OpenAI Explains URL-Based Data Exfiltration Mitigations (paper)** — Rehberger, 2026-01
  https://embracethered.com/blog/posts/2026/data-exfiltration-mitigation-paper-by-openai/
  Разбор митигаций URL-эксфильтрации — задаёт, какие сигналы ловить в trace/evidence.

- 🟨 **LLM Data Exfiltration via URL Previews (OpenClaw example)** — qual1a/PromptArmor, 2026-02
  https://www.promptarmor.com/resources/llm-data-exfiltration-via-url-previews-(with-openclaw-example-and-test)
  Канал утечки через URL-preview + готовый тест — шаблон для нашего deterministic success-check.

- 🟨 **Scary Agent Skills: Hidden Unicode Instructions** — Rehberger, 2026-02
  https://embracethered.com/blog/posts/2026/scary-agent-skills/
  Невидимые (unicode) инструкции = техника **weak/скрытого сигнала**. Прямо в тему strong vs weak из MPBench.

- 🟨 **AI Injections: Direct and Indirect Prompt Injection Basics** — Rehberger & Greshake, 2023-01
  https://embracethered.com/blog/posts/2023/ai-injections-direct-and-indirect-prompt-injection-basics/
  Базовая таксономия — для терминологии в отчёте и онбординга.

---

## Что сознательно НЕ берём
Классические web-баги AI-продуктов (XSS/SSRF/OAuth/RCE в LangFlow, Triton, HuggingFace-инфра, MCP-OAuth redirect_uri и т.п.), «AI как инструмент атакующего», и exfil-кейсы конкретных SaaS без переносимой на память техники — вне scope «атаки на память». При желании оставим одну строку в отчёте как «смежные поверхности», но в код/батарею не тянем.

## Быстрый маппинг на батарею
| Наш элемент | Источники |
|---|---|
| Канал: вывод MCP-тула | Agentjacking, Supabase MCP, Never Trust the Output, Agent Hypnosis |
| Канал: веб-поиск/retrieval | GeminiJack, Greshake/Bing, Slack AI |
| Класс: policy/persistent (scope=global) | Hacking Claude's Memory, Agent Commander |
| Weak/скрытый сигнал | GeminiJack, Never Trust the Output, Scary Agent Skills |
| Последствие: BAC/cross-client | Supabase MCP, Hacktus notification, MCP tenant bypass, IDOR+PI |
| Последствие: cross-user propagation | Slack AI |
| Evidence/success-check эксфильтрации | OpenAI URL-exfil paper, URL previews |
