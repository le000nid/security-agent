# Реестр учебных benchmark

`config/benchmarks.yaml` — единственный источник разрешённых benchmark. Запись
проверяется Pydantic до запуска scanner. Chat и LLM не могут добавлять benchmark,
URL, путь или Docker service.

## Состав реестра

| ID | Возможности | Baseline | Особенность |
| --- | --- | ---: | --- |
| `sample-sast` | SAST | 9 | базовые Python/JavaScript fixtures |
| `juice-shop` | DAST | — | локальный OWASP Juice Shop |
| `demo-full` | FULL | 7 | стабильные 4 SAST + 3 DAST одного проекта |
| `sast-contours` | SAST | 6 | SQL Injection, LFI, RFI |
| `dan-lab` | FULL | 2 | симуляция prompt injection |
| `nosqli-sast` | SAST | — | NoSQLi source fixtures |
| `nosqli-dast` | DAST | — | Juice Shop NoSQLi |
| `nosqli-mongo-full` | FULL | 5 типов | MongoDB API и безопасные пары |
| `ssrf-lab` | FULL | 2 | локальная SSRF-симуляция |
| `spoofing-sast` | SAST | 2 | только статические ARP/DNS-паттерны |
| `security-key-lab` | FULL | 2 | только synthetic training key |

Baseline считает ожидаемые типы находок. Некоторые acceptance-тесты дополнительно
проверяют число экземпляров и differential evidence.

## Поля записи

```yaml
- id: example-lab
  name: Пример
  description: Русское пользовательское описание.
  description_ru: Русское пользовательское описание.
  capabilities: [sast, dast]
  source_path: /targets/example-lab
  target_url: http://example-lab:3000
  docker_service: example-lab
  expected_findings: example-lab.json
  tags: [educational, same-application]
```

- `id` и `docker_service` — одноуровневые DNS-имена без точки.
- `source_path` начинается с `/targets/` и не содержит traversal.
- DAST URL использует только `http` и разрешённый локальный host.
- FULL требует SAST и DAST одного проекта и тег `same-application`.
- `expected_findings` указывает только имя JSON в `config/expected`.
- Duplicate benchmark ID отклоняется при загрузке.

## Безопасность стендов

- host-порты публикуются только на `127.0.0.1`;
- Docker socket не монтируется;
- сервисы получают `no-new-privileges` и `cap_drop: [ALL]`;
- MongoDB находится во внутренней network без host-порта;
- source mounts доступны agent только read-only;
- SSRF не принимает произвольный URL;
- spoofing fixture никогда не запускается;
- DAN и security-key используют synthetic marker/key.

## Добавление benchmark

1. Создайте vulnerable и safe/benign fixtures.
2. Добавьте локальные Semgrep/Nuclei checks с уникальными ID.
3. Добавьте registry-запись и, при необходимости, expected JSON.
4. Добавьте Docker service только для DAST.
5. Добавьте unit и acceptance-тесты.
6. Выполните pytest, Ruff, Semgrep/Nuclei validation и smoke с `--no-llm`.
7. Убедитесь, что `summary.llm_usage.total.requests == 0`.

Registry не является способом разрешить внешние цели. Новая цель требует
reviewed кода, fixture, тестов и явного изменения конфигурации.
