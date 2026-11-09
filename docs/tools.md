# Покрытие scanner

Проект использует только локальные проверенные правила и шаблоны. Это небольшой
учебный набор сигналов, а не замена полноценному аудиту безопасности. Находка
показывает наблюдение scanner; она не доказывает эксплуатацию уязвимости.

## Nuclei DAST

Шаблоны находятся в `config/nuclei/`. Они обращаются только к URL, прошедшему
local-only валидацию приложения. В набор входят:

- безопасные проверки HTTP-заголовков, cookie, CORS и server banner;
- SQLite error-сигнал для локального OWASP Juice Shop;
- учебные проверки NoSQLi для отдельного Juice Shop и MongoDB lab;
- детерминированная DAN-симуляция без реальной LLM;
- локальная SSRF-симуляция без произвольного URL и metadata endpoint;
- обнаружение раскрытия одного синтетического training key.

Часть учебных шаблонов отправляет контролируемые GET или POST-запросы на заранее
заданные пути стенда. Они не меняют состояние приложения, не переходят на внешние
адреса и не выполняют destructive/exploit действия. Полные исходные ответы Nuclei
сохраняются только в `raw_nuclei.jsonl`; Finding содержит нормализованное evidence.

## Semgrep SAST

Правила находятся в `config/semgrep.yaml`. Базовый набор проверяет опасные вызовы
subprocess, небезопасную десериализацию, отключение TLS-проверки, hardcoded secrets,
`eval` и режим debug. Интегрированные контуры добавляют:

- SQL Injection для Python, JavaScript/TypeScript и PHP;
- LFI и RFI для PHP;
- prompt injection pattern для DAN-lab;
- NoSQLi data flow и небезопасные MongoDB filters;
- SSRF data flow от HTTP input к server-side request;
- статические ARP/DNS spoofing patterns без запуска fixture-кода.

Для каждого контура есть vulnerable и benign fixtures. Benign-файлы нужны как
negative controls и не должны создавать ожидаемые находки. Правила имеют уникальные
ID; parser отклоняет некорректный scanner contract вместо формирования ложного
успешного результата.

## Проверка конфигурации

```powershell
docker compose --profile agent run --rm --no-deps --entrypoint semgrep agent --metrics off --validate --config /agent/config/semgrep.yaml
docker compose --profile agent run --rm --no-deps --entrypoint nuclei agent -validate -disable-update-check -t /agent/config/nuclei
```

Без Docker можно проверить структуру registry и тестовые контракты:

```powershell
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
```

Состав benchmark и ожидаемые baselines описаны в [BENCHMARKS.md](BENCHMARKS.md).
