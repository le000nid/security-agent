# Архитектура

## Границы системы

Проект разделяет управление workflow и данные LLM. Application code остаётся
авторитетным для целей, путей, tools, scanner arguments, состояний и отчётов.

```text
CLI ───────┐
Web API ───┼→ RunRequest → RunService → Agent loop → ToolRegistry
Chat ──────┘                    │              │
                               │              ├→ Semgrep
                               │              ├→ Nuclei
                               │              ├→ enrichment
                               │              ├→ AI Brief
                               │              └→ reports
                               ▼
                     RunRepository / runs/<id>
```

## RunService

`RunService` разрешает benchmark через registry, валидирует mode/source/target,
выполняет DAST preflight, создаёт изолированный run и выбирает deterministic или
agent orchestration. CLI, UI и Chat не обходят этот слой.

## AgentState и Validator

`AgentState` содержит только структурированное состояние этапов. `Validator`
вычисляет разрешённые действия. Planner возвращает enum-действие и короткую причину,
но не аргументы. Единственный допустимый шаг может выполняться детерминированно без
LLM-запроса. Лимиты шагов и Planner requests независимы.

## ToolRegistry

Registry tools используют аргументы только из проверенного state:

- `RUN_SAST` — curated Semgrep config;
- `RUN_DAST` — curated local HTTP Nuclei templates;
- `ENRICH_FINDINGS` — разрешённые поля существующих findings;
- `GENERATE_AI_BRIEF` — компактная сводка;
- `GENERATE_REPORT` — локальные артефакты;
- `FINISH` — завершение автомата.

LLM output не попадает в subprocess command line.

## Scanner и Finding

Raw output сохраняется только в run logs. Parser проверяет структуру, scanner errors,
пути/позиции и создаёт immutable `Finding`. SAST/DAST используют одну модель.
Identity-поля enrichment не меняет.

## LLM-компоненты

- Planner: выбирает только разрешённое действие.
- Enrichment: дополняет описание, рекомендацию, normalized severity/category и rationale.
- AI Brief: создаёт короткий validated документ; bounded retry/repair.
- Chat Intent Parser: классифицирует UI-запрос по закрытому enum.
- Chat Analyst: read-only анализ сохранённого run.

У компонентов отдельные usage counters. Ошибка optional-компонента не удаляет
scanner findings. Transport failure и content/schema failure различаются.

## Chat

Chat Controller сначала проверяет явный run/finding. Локальные intents не требуют
LLM. START_SCAN создаёт одноразовое server-side предложение, после чего нужен
отдельный CSRF-protected confirm. Analytical intents не вызывают scanners.

Analyst получает bounded projection без raw logs, исходного кода, evidence, путей,
environment и API keys. Partial truncation recovery извлекает только displayable
поля, не создаёт finding links и не сохраняется в run artifacts.

## Registry и Docker

Registry — reviewed YAML. UI строится динамически из него. DAST host должен быть
loopback или точным зарегистрированным Docker service name. Все опубликованные
порты привязаны к `127.0.0.1`. MongoDB находится во внутренней network.

UI не имеет Docker socket. Wrapper поднимает стенды до старта UI. После изменения
`.env` UI force-recreate получает новый environment, а bind-mounted runs сохраняются.

## Артефакты

Каждый run изолирован в `runs/<id>`. Writes отчётов выполняются атомарно там, где
это критично. `runs/latest.json` указывает на последний созданный run. History
сортируется по времени изменения, а не случайному suffix.

## Инварианты безопасности

1. Произвольные внешние DAST targets запрещены.
2. Source path проходит проверку и не может быть root/UNC/network path.
3. Nuclei ограничен HTTP, local templates, без redirects/Interactsh/update.
4. Docker socket и опасные network capabilities отсутствуют.
5. SSRF/DAN/spoofing/security-key contours используют только безопасные simulations.
6. LLM не исполняет инструменты и не создаёт новые findings.
7. Ошибки и логи не содержат secrets, raw provider response или reasoning.
