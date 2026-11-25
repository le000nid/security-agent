# CTF-агенты

Все CTF-агенты вшиты в ядро приложения — пакет `app/agent/ctf/`. Один
движок реализует общую механику (LLM-шлюз, JSON-контракт действий, файловый
guard, HTTP-слой с захватом cookie и base64-флагов, валидацию finish,
graceful-fallback), а профили поставляют только специфику домена —
подсказки, матрицы обхода и порядок фолбэков. Ни один профиль не меняет
SAST/DAST pipeline, benchmark или правила основного приложения.

## Профили

| Профиль | Домен |
|---|---|
| `evidence` | bounded evidence: строгий контракт действий, HTTP только `http://target:8000`, редиректы отключены |
| `file_inspection` | точный выбор значения секрета из materials |
| `git_history_recovery` | секрет, удалённый из Git-истории проекта |
| `path_filter_bypass` | LFI через наивный фильтр имени файла |
| `path_assembly_bypass` | LFI через проверку пути ДО сборки (HPP, multi-param, suffix-concat, double-decode) |
| `remote_inclusion` | RFI: включение по URI-схеме (php://filter, data:, expect://, phar://, zip://, file://, http(s)://, ssh2, SMB UNC) + обходы схемных фильтров + SSRF по внутренним целям |
| `sqli_login_bypass` | SQLi-обход формы входа |
| `sqli_admin_bypass` | SQLi-вход именно администратором + UNION-извлечение |
| `sqli_auth_inversion` | инверсия запрещающей проверки, мульти-формы, SSTI, cookie-подделка |

## Запуск внутри приложения

```powershell
python -m app.main ctf --list-profiles
python -m app.main ctf --profile git_history_recovery
```

Runtime читает только `OPENAI_BASE_URL`, `OPENAI_API_KEY`,
`LOCAL_AGENT_MODEL` и `CTF_AGENT_SESSION_ID` для OpenAI-compatible
`/chat/completions`, а также `CTF_TASK_DIR` и `CTF_ARTIFACT_DIR` для границ
задачи и артефакта. Основной `.env` проекта не загружается. Профили
`sqli_*` дополнительно читают `CTF_TARGET_URL` и умеют разрешать реальный
endpoint из `instruction.md` (prob-проверка каждого URL).

Git-форензика профиля `git_history_recovery` доступна и как отдельная
утилита аудита:

```powershell
python -m app.git_history_audit D:\repo --recover-secret
```

## Standalone-сборки

```powershell
python scripts/build_ctf.py                    # dist/ — все профили
python -m app.main ctf --profile path_filter_bypass --package dist/agent.zip
```

Результат: `dist/security-agent-<профиль>.zip`. В корне каждого архива
ровно `run.sh`, `agent.json`, `agent.py`, `strategy.md`; `agent.py`
рендерится из интегрированного ядра (runtime + profiles + точка входа
профиля), стандартная библиотека только.

## Границы безопасности

- файловые операции остаются внутри canonical `CTF_TASK_DIR`; realpath-guard
  отклоняет symlink/sibling escape;
- Git запускается только фиксированными списками аргументов с `shell=False`;
- HTTP-профили работают только с разрешённым origin (redirect guard);
  evidence-профиль — только с точным `http://target:8000`, редиректы
  отключены;
- необычные и encoded HTTP paths разрешены внутри origin;
- ответы и observations ограничены по размеру, цикл ограничен по шагам
  (`CTF_AGENT_MAX_STEPS`) и дедлайну профиля;
- `finish` валидируется по профилю: живые ответы сервиса (HTTP-профили),
  отсутствие значения в текущих непустых файлах (git-форензика), decoy-guard
  по admin-контексту (sqli_admin/inversion), заземление в файлах
  (file_inspection);
- malformed planner JSON получает один безопасный repair request и не
  исполняется;
- `write_artifact` — атомарная запись (tmp + `os.replace`), устаревший
  flag.txt сбрасывается перед запуском.

## Архитектура

```text
instruction.md + materials (+ live HTTP)
    -> LLM loop (профильные лимиты шагов/окна/дедлайна)
    -> одно JSON-действие -> фиксированный инструмент -> наблюдение -> LLM
    -> finish (валидация по профилю) -> CTF_ARTIFACT_DIR/flag.txt
    -> graceful fallback (профильный порядок кандидатов) + report.txt
```

Модули ядра:

- `app/agent/ctf/runtime.py` — Session (env, evidence, cookie, route),
  HTTP-слой, LLM-шлюз, action-контракт, главный цикл, фолбэки;
- `app/agent/ctf/profiles.py` — реестр профилей, доменные инструменты
  (LFI-матрицы, SQLi-пробер с фазами, Git-форензика, unpack/decode),
  валидаторы finish, фолбэки;
- `app/agent/ctf/evidence.py` — bounded evidence профиль со строгим
  контрактом (LIST_FILES…FINISH);
- `app/agent/ctf/package.py` — рендер standalone `agent.py` из ядра и
  сборка четырёхфайловых ZIP.

## SAST-срез file-exposure

Офлайн-SAST handoff для семейства file-disclosure задач —
`app/file_exposure_sast.py` (конфиг `config/semgrep-file-exposure.yaml`,
фикстуры `targets/sast-file-exposure/`):

```powershell
python -m app.file_exposure_sast source_scan targets/sast-file-exposure
docker compose --profile agent run --rm --no-deps --entrypoint python agent -m benchmark.verify_file_exposure_sast
```

## Проверки

```powershell
pytest -q tests/test_ctf_engine.py tests/test_ctf_evidence.py tests/test_ctf_cli.py
```

> The minimal `agent.json` manifest (`name`/`version`/`entrypoint`) may
> require adjustment to your runner's validator before a production upload.
