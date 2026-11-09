# VEGA adapter

`vega/` — отдельный self-contained экспорт ограниченного evidence-агента для
тестовой системы VEGA. Он не меняет SAST/DAST pipeline, benchmark или правила
основного приложения.

Архитектура сохраняет основной принцип проекта:

```text
Task / observations -> LLM Planner -> structured action -> Validator
                    -> fixed tool -> observation -> LLM
```

Модель только предлагает одно из фиксированных действий: `LIST_FILES`,
`READ_FILE`, `SEARCH_FILES`, `GIT_LOG`, `GIT_SHOW`, `HTTP_REQUEST`, `WRITE_FLAG`
или `FINISH`. Локальный validator проверяет envelope и аргументы до исполнения.
Произвольного shell-action нет; Git запускается только фиксированными списками
аргументов с `shell=False`.

## Сборка

```powershell
python scripts/build_vega.py
```

Результат: `dist/security-agent-vega.zip`. В корне архива находятся ровно:

```text
run.sh
agent.json
agent.py
strategy.md
```

Runtime читает только `OPENAI_BASE_URL`, `OPENAI_API_KEY`, `LOCAL_AGENT_MODEL` и
`VEGA_AGENT_SESSION_ID` для OpenAI-compatible `/chat/completions`, а также
`VEGA_TASK_DIR` и `VEGA_CTF_ARTIFACT_DIR` для границ задачи и артефакта. Основной
`.env` проекта не загружается.

## Границы безопасности

- файловые операции остаются внутри canonical `VEGA_TASK_DIR`; symlink escape
  отклоняется;
- Git repository и его metadata должны находиться внутри `materials`;
- HTTP допускает только origin `http://target:8000`; redirects отключены;
- необычные и encoded HTTP paths разрешены внутри этого origin;
- ответы и observations ограничены по размеру, цикл ограничен 25 шагами;
- malformed planner JSON получает один безопасный repair request и не исполняется;
- `WRITE_FLAG` записывает только непустое значение в
  `VEGA_CTF_ARTIFACT_DIR/flag.txt` без дополнительного текста.

Agent best-effort читает `instruction.md` внутри task root. Если файла нет, он
использует общую цель из `strategy.md`: исследовать доступные материалы и локальную
цель, подтвердить найденное значение и записать artifact.

Offline-проверки запускаются так:

```powershell
pytest -q tests/test_vega_adapter.py
```

> Official agent.json schema was not available in supplied materials; this file may require adjustment to the platform validator.

Поэтому минимальный `agent.json` следует подтвердить реальным VEGA validator до
публикации архива для конкретной инсталляции.
