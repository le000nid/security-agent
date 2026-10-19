# AI Security Agent 0.4.1

Учебная платформа для локального анализа безопасности приложений. Проект объединяет
SAST через Semgrep, DAST через Nuclei, нормализацию находок, эталонные benchmark,
отчёты, Web UI и необязательное LLM-обогащение. Все сетевые проверки ограничены
зарегистрированными локальными стендами.

Проект предназначен для обучения, демонстраций и регрессионных проверок. Он не
заменяет профессиональный аудит и не доказывает возможность эксплуатации найденных
паттернов.

## Возможности

- SAST: проверка локальных исходников набором проверяемых Semgrep rules.
- DAST: безопасные HTTP-проверки локальных стендов через Nuclei templates.
- FULL: SAST и DAST одного зарегистрированного проекта, если benchmark это гарантирует.
- `scan`: фиксированная последовательность без решений LLM.
- `agent`: ограниченный Planner выбирает только из зарегистрированных действий.
- единая модель `Finding` для SAST и DAST;
- отдельные raw-логи сканеров и нормализованные JSON/Markdown-отчёты;
- Web UI на loopback-адресе;
- Chat Analyst для обсуждения уже сохранённого запуска;
- полностью рабочий режим `--no-llm` с нулём LLM-запросов;
- эталонная оценка ожидаемых, найденных и неожиданных находок.

## Архитектура

```text
CLI / Web UI / Chat
        │
        ▼
  RunRequest + registry
        │
        ▼
    RunService
        │
        ├── SAST → Semgrep → raw JSON ─┐
        ├── DAST → Nuclei → raw JSONL ├→ Finding[]
        ├── enrichment, если включён ──┤
        ├── AI Brief, если включён ────┤
        └── отчёты и summary ◀─────────┘
```

`RunService` остаётся единственной точкой запуска. Registry задаёт разрешённые
исходники, HTTP-цели, режимы и Docker services. LLM возвращает только данные и не
получает shell, Docker socket, произвольный URL, путь или scanner arguments.

## Режимы анализа

| Режим | Что выполняется | Требования |
| --- | --- | --- |
| SAST | Semgrep по зарегистрированным исходникам | локальный `source_path` |
| DAST | Nuclei по зарегистрированному HTTP-стенду | локальный `target_url` |
| FULL | SAST и DAST | обе возможности у одного benchmark |

`scan` выполняет разрешённые этапы детерминированно. `agent` использует LLM Planner,
но Planner не создаёт инструменты и аргументы: Validator допускает только следующий
разрешённый шаг конечного автомата.

## Доступные benchmark

| ID | Режим | Назначение |
| --- | --- | --- |
| `sample-sast` | SAST | базовые Python/JavaScript-паттерны, девять ожидаемых находок |
| `juice-shop` | DAST | локальный OWASP Juice Shop |
| `demo-full` | FULL | один проект; стабильный baseline 4 SAST + 3 DAST |
| `sast-contours` | SAST | SQL Injection, LFI, RFI и безопасные контрольные примеры |
| `dan-lab` | FULL | учебная детерминированная симуляция prompt injection |
| `nosqli-sast` | SAST | NoSQLi в JavaScript и безопасные контрольные примеры |
| `nosqli-dast` | DAST | локальная проверка NoSQLi в Juice Shop |
| `nosqli-mongo-full` | FULL | MongoDB API, три NoSQLi-сценария и безопасные пары |
| `ssrf-lab` | FULL | локальная SSRF-симуляция без произвольных URL |
| `spoofing-sast` | SAST | статический поиск ARP/DNS spoofing-паттернов |
| `security-key-lab` | FULL | синтетический training key в коде и локальном HTTP-ответе |

Список из установленного проекта:

```powershell
python -m app.main benchmarks list
```

### Границы учебных контуров

- DAN DAST раскрывает только синтетический маркер по фиксированному условию. Это не
  настоящая LLM и не доказательство jailbreak реальной модели.
- SSRF DAST не принимает внешний URL, не обращается к cloud metadata и не выполняет
  исходящие HTTP-запросы. Он сравнивает два локальных детерминированных endpoint.
- Spoofing — только SAST. Код не импортируется и не выполняется; пакеты не
  отправляются. В Compose нет host network, `NET_ADMIN` и `CAP_NET_RAW`.
- Security Key использует только строку с префиксом `TRAINING_KEY_`. Реальные `.env`,
  credentials и пользовательские секреты стенд не читает.
- MongoDB не публикуется на host и доступна API только через внутреннюю Docker network.

## Быстрый старт в Windows

Требования: Windows 10/11, Docker Desktop с Linux containers, PowerShell 5.1 или 7,
Git. Установка Semgrep/Nuclei на host не требуется.

```powershell
git clone <URL-репозитория>
Set-Location security-agent
Copy-Item .env.example .env
.\run.ps1 doctor --check-benchmarks
.\run.ps1 ui
```

Откройте `http://127.0.0.1:8080`.

После изменения `.env` повторите `.\run.ps1 ui`. Wrapper собирает локальный образ,
поднимает зарегистрированные HTTP-стенды и делает `force-recreate` контейнера UI.
Каталоги `runs`, `logs`, `reports` bind-mounted и не удаляются.

## Быстрый старт в Linux

Требования: Docker Engine, Compose v2, Git и доступ текущего пользователя к Docker.
Не используйте `chmod 777` для Docker socket.

```bash
git clone <URL-репозитория>
cd security-agent
cp .env.example .env
./run.sh doctor --check-benchmarks
./run.sh ui
```

Wrapper передаёт UID/GID текущего пользователя, поэтому отчёты не должны создаваться
от имени root.

## Быстрый старт в macOS

Установите Docker Desktop и Git. На Apple Silicon используйте обычный Linux arm64
режим Docker Desktop без принудительного `linux/amd64`.

```bash
git clone <URL-репозитория>
cd security-agent
cp .env.example .env
./run.sh doctor --check-benchmarks
./run.sh ui
```

Образ поддерживает `linux/amd64` и `linux/arm64`. Полный smoke желательно выполнить
на той архитектуре, на которой проект будет демонстрироваться.

## Docker и CLI

Проверка конфигурации и сборка:

```powershell
docker compose config --quiet
docker compose --profile agent build agent
```

Примеры запуска без LLM:

```powershell
.\run.ps1 scan --benchmark demo-full --mode full --no-llm
.\run.ps1 scan --benchmark sast-contours --mode sast --no-llm
.\run.ps1 scan --benchmark dan-lab --mode full --no-llm
.\run.ps1 scan --benchmark nosqli-mongo-full --mode full --no-llm
.\run.ps1 scan --benchmark ssrf-lab --mode full --no-llm
.\run.ps1 scan --benchmark spoofing-sast --mode sast --no-llm
.\run.ps1 scan --benchmark security-key-lab --mode full --no-llm
```

В Linux/macOS замените `.\run.ps1` на `./run.sh`.

Прямой Compose-запуск:

```powershell
docker compose --profile agent run --rm --no-deps agent scan --benchmark demo-full --mode full --no-llm
```

Для MongoDB-стенда wrapper автоматически включает профиль `nosqli-mongo`.

## Web UI

```powershell
.\run.ps1 ui
```

UI доступен только на `127.0.0.1:8080`. Он читает registry, поэтому новые benchmark
появляются без жёстко заданного списка в JavaScript. Карточка показывает доступные
SAST/DAST/FULL, русское описание и размер baseline. Категории находок отображаются
понятными русскими названиями, а технические ID остаются неизменными.

UI поддерживает Guided Scan, прогресс этапов, историю запусков, фильтры findings,
просмотр отчётов, состояния Planner/enrichment/AI Brief и Chat Analyst.

UI не управляет Docker и не монтирует Docker socket. Wrapper заранее поднимает
стенды. Запуск нового scan из Chat требует отдельного подтверждения.

## Chat Analyst

Chat анализирует только сохранённый run. Он умеет ранжировать findings, отделять
наблюдение сканера от интерпретации, перечислять ручные проверки, составлять краткий
remediation plan и сравнивать SAST/DAST.

Примеры вопросов:

- «Что здесь самое опасное и почему?»
- «Какие утверждения подтверждены сканерами, а какие требуют ручной проверки?»
- «Что исправлять первым?»
- «Сравни SAST и DAST».

Chat не должен повышать HIGH до CRITICAL и не считает найденный паттерн доказанной
эксплуатацией. Выполненный enrichment не равен exploit validation.

При truncation Analyst делает один краткий retry. Если ответ снова обрезан, UI
сохраняет полезную часть, показывает предупреждение и пять готовых follow-up действий.

## Настройка LLM

LLM необязательна. Заполните локальный `.env`:

```dotenv
LLM_PROVIDER=openai_compatible
LLM_BASE_URL=https://your-approved-provider.example/api
LLM_MODEL=exact-model-id
LLM_API_KEY=replace_me
```

Не коммитьте `.env`. Проверка подключения выполняется только явно:

```powershell
.\run.ps1 doctor --check-llm
```

Бюджеты задаются переменными `LLM_PLANNER_*`, `LLM_ENRICHMENT_*`,
`LLM_BRIEF_*` и `LLM_CHAT_*` из `.env.example`.

AI Brief имеет ограниченный pipeline: обычная попытка, один concise retry после
truncation и один schema repair после ошибки JSON/schema. Максимум три логические
попытки. Raw-ответ и reasoning не сохраняются; безопасная диагностика находится в
`summary.json`.

Запуск с LLM:

```powershell
.\run.ps1 scan --benchmark demo-full --mode full
.\run.ps1 agent --benchmark demo-full --mode full
```

## Работа без LLM

```powershell
.\run.ps1 scan --benchmark demo-full --mode full --no-llm
```

Planner, enrichment и AI Brief пропускаются, а `llm_usage.total.requests` равен
нулю. Semgrep, Nuclei, baseline и отчёты работают полностью.

## Отчёты

```text
runs/<run-id>/
├── logs/
│   ├── raw_semgrep.json
│   └── raw_nuclei.jsonl
└── reports/
    ├── findings.json
    ├── summary.json
    ├── report.md
    ├── agent_trace.json
    └── ai_brief.json
```

Raw scanner output остаётся только в `logs`. Нормализованный `Finding` содержит
`raw_output_ref`, но не полный record. Последний запуск: `.\run.ps1 latest`.

## Проверка разработки

```powershell
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
docker compose config --quiet
```

Инструментальная проверка в образе:

```powershell
docker compose --profile agent run --rm --no-deps --entrypoint semgrep agent --metrics off --validate --config /agent/config/semgrep.yaml
docker compose --profile agent run --rm --no-deps --entrypoint nuclei agent -validate -disable-update-check -t /agent/config/nuclei
```

## Как добавить benchmark

1. Добавьте fixture в `targets/<id>`; FULL должен анализировать один проект.
2. Добавьте Semgrep rule и/или безопасный Nuclei template.
3. Зарегистрируйте benchmark в `config/benchmarks.yaml`.
4. Добавьте `config/expected/<id>.json`, если нужен baseline.
5. HTTP-service публикуйте только на loopback, с `no-new-privileges` и `cap_drop: [ALL]`.
6. Добавьте vulnerable и benign/safe controls.
7. Добавьте parser, registry, acceptance и offline-тесты.
8. Проверьте уникальность rule/template/benchmark ID.
9. Выполните pytest, Ruff, валидацию tools и Docker smoke.

URL, путь, shell-команда и scanner flags не могут приходить из Chat/LLM.

## Диагностика

| Симптом | Что проверить |
| --- | --- |
| Docker недоступен | запустите Docker Desktop/Engine и выполните `docker info` |
| Стенд unhealthy | `docker compose ps -a` и `docker compose logs --tail 100 <service>` |
| Порт занят | остановите конфликтующий локальный процесс |
| UI видит старый `.env` | повторите `run.ps1 ui` или `run.sh ui` |
| UI содержит старый код | выполните build и затем `force-recreate` UI |
| LLM недоступна | используйте `doctor --check-llm`; offline scan продолжает работать |
| Brief failed | смотрите `llm_components.brief.attempts` в `summary.json` |
| DAST target unreachable | поднимите нужный benchmark через wrapper и дождитесь healthcheck |
| Нет прав на отчёты | проверьте владельца `runs/logs/reports` и UID/GID |
| MongoDB benchmark не готов | проверьте профиль `nosqli-mongo`, Mongo health и API logs |

Подробности: [устранение неполадок](docs/TROUBLESHOOTING.md),
[реестр benchmark](docs/BENCHMARKS.md), [архитектура](docs/ARCHITECTURE.md).

## Модель безопасности и ограничения

- DAST разрешён только для `localhost`, `127.0.0.1` и зарегистрированных
  одноуровневых Docker service names; `0.0.0.0` не является целью сканирования.
- Nuclei работает с локальными HTTP templates, без Interactsh, DNS/TCP и updates.
- Semgrep использует локальный curated config без registry/login.
- Docker socket не монтируется; scanner container не получает capabilities.
- LLM не выполняет shell, не меняет цель и не создаёт findings.
- ARP/DNS poisoning отсутствует.
- SSRF и DAN — simulation, Security Key — synthetic data.
- Enrichment не меняет scanner identity.
- Успешный baseline подтверждает учебные индикаторы, а не безопасность приложения.

Версия 0.4.1 остаётся локальной однопользовательской учебной платформой. Для
production нужны отдельные auth, multi-user isolation, audit storage и deployment review.
