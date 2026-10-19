# Устранение неполадок

## Docker

| Симптом | Решение |
| --- | --- |
| `docker info` не отвечает | запустите Docker Desktop/Engine; в Windows выберите Linux containers |
| Compose отсутствует | установите Docker Compose v2; команда — `docker compose version` |
| Порт занят | проверьте 3000–3007 и 8080; остановите конфликтующий процесс |
| Стенд unhealthy | `docker compose ps -a` и `docker compose logs --tail 100 <service>` |
| MongoDB не готова | используйте профиль `nosqli-mongo`; проверьте `nosqli-mongo` и `nosqli-mongo-api` |
| Apple Silicon `exec format error` | уберите ручной `linux/amd64`, пересоберите arm64-образ |
| Нет прав на `runs` | задайте корректные UID/GID; не используйте `chmod 777` Docker socket |

После изменения кода или `.env`:

```powershell
.\run.ps1 ui
```

Wrapper собирает локальный образ и делает `force-recreate` UI. Bind-mounted
`runs`, `logs`, `reports` сохраняются. Для ручного варианта:

```powershell
docker compose --profile ui build ui
docker compose --profile ui up -d --no-deps --force-recreate --wait ui
```

## Scanner

| Симптом | Решение |
| --- | --- |
| Semgrep/Nuclei не найден | пересоберите agent-образ; host-установка не нужна |
| SAST сообщает scan errors | откройте raw log конкретного run и проверьте source mount |
| Semgrep scanned no files | проверьте registry `source_path` и поддерживаемые расширения |
| DAST target unreachable | запустите benchmark через wrapper и дождитесь healthcheck |
| Неожиданный Nuclei finding | сравните template ID, matcher evidence и baseline evaluation |
| Baseline missed | проверьте версии tool, rule/template и fixture; не меняйте expected без анализа |

Валидация конфигураций в образе:

```powershell
docker compose --profile agent run --rm --no-deps --entrypoint semgrep agent --metrics off --validate --config /agent/config/semgrep.yaml
docker compose --profile agent run --rm --no-deps --entrypoint nuclei agent -validate -disable-update-check -t /agent/config/nuclei
```

## LLM

| Симптом | Решение |
| --- | --- |
| Chat показывает `unchecked` | нажмите «Проверить подключение» или выполните `doctor --check-llm` |
| HTTP 401/403 | проверьте локальный API key и разрешения модели; не печатайте key |
| Model unavailable | укажите точный model ID из разрешённого provider |
| `brief_response_truncated` | Brief уже делает один concise retry; смотрите safe attempts в summary |
| `brief_schema_validation_error` | выполняется один terminal schema repair; смотрите `{field,type}` |
| `chat_response_truncated` | полезная часть остаётся в UI с follow-up actions |
| Provider outage | используйте `--no-llm`; scanner и отчёты работают независимо |

AI Brief выполняет не более трёх логических попыток. Chat Analyst — не более двух.
Transport retries также ограничены. Raw model response, reasoning, API key и
ValidationError input не сохраняются.

## Отчёты и состояния

- `completed`: обязательные этапы завершены;
- `completed_with_warnings`: scanner результаты сохранены, optional LLM-stage мог упасть;
- `failed`: обязательный scanner/report/planner путь завершился ошибкой;
- `skipped`: этап отключён, например через `--no-llm`.

Ищите причину в:

- `runs/<id>/reports/summary.json`;
- `runs/<id>/reports/agent_trace.json`;
- `runs/<id>/logs/raw_semgrep.json`;
- `runs/<id>/logs/raw_nuclei.jsonl`.

`ai_brief.json` при ошибке содержит только status, а не невалидный ответ модели.
Не вставляйте содержимое `.env` или необработанные provider bodies в issue/log.

## UI и Chat

| Симптом | Решение |
| --- | --- |
| UI не открывается | проверьте `http://127.0.0.1:8080/healthz` и logs UI |
| CSRF error | обновите страницу после recreate |
| Нужный benchmark отсутствует | проверьте registry и пересоберите/recreate UI |
| Chat обсуждает не тот run | явно выберите run и при необходимости очистите finding |
| Scan уже выполняется | дождитесь single-flight job; параллельный запуск отклоняется |
| Job потерян после restart | откройте сохранённый run через историю |

Chat не запускает scanner без отдельного подтверждения и никогда не принимает
произвольные URL/path/shell. При ошибке Intent Parser для выбранного run запрос
переходит только в read-only Analyst.

## Безопасность

Если для исправления предлагают host network, Docker socket, `NET_ADMIN`,
`CAP_NET_RAW`, отключение target validation или произвольные Nuclei templates —
это нарушение модели проекта, а не допустимый workaround.
