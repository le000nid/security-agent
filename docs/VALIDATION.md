# Проверка интегрированной версии

Этот файл фиксирует только результаты текущей integration-ветки. Он не выдаёт
исторические проверки прежних веток за проверку нового состава benchmark.

## Offline-проверки

Проверено 19 октября 2026 года на Windows и Docker Desktop Linux `x86_64`:

| Проверка | Результат |
| --- | --- |
| `python -m pytest -q` | 595 passed, 1 skip: host не разрешил создание symlink |
| `ruff check .` | пройдено |
| `ruff format --check .` | 109 файлов отформатированы |
| JavaScript syntax | пройдено через Node.js |
| Bash syntax | `run.sh`, `common.sh`, `check-nosqli.sh` прошли `bash -n` через Git for Windows |
| `docker compose config --quiet` | пройдено |
| Agent image | собран, Semgrep 1.120.0 и Nuclei 3.4.10 запускаются non-root |
| Semgrep config | 25 rules, 0 configuration errors |
| Nuclei config | 17 templates, validation пройдена также с `--network none` |
| UI recreate | wrapper прошёл; health `ok`, версия 0.4.1, registry содержит 11 benchmark |

Остаётся одно non-fatal предупреждение о deprecated связке Starlette TestClient и
`httpx`; после tests Windows также не смог удалить служебный pytest symlink. Оба
случая не изменили exit code и не относятся к логике приложения.

## Docker smoke

Минимальный scanner-only набор без LLM:

```powershell
.\run.ps1 scan --benchmark demo-full --mode full --no-llm
.\run.ps1 scan --benchmark sast-contours --mode sast --no-llm
.\run.ps1 scan --benchmark dan-lab --mode full --no-llm
.\run.ps1 scan --benchmark nosqli-mongo-full --mode full --no-llm
.\run.ps1 scan --benchmark ssrf-lab --mode full --no-llm
.\run.ps1 scan --benchmark spoofing-sast --mode sast --no-llm
.\run.ps1 scan --benchmark security-key-lab --mode full --no-llm
```

После каждого запуска `summary.json` должен содержать ноль LLM requests. Для
benchmark с baseline следует также запускать соответствующий verifier. Реальный
DeepSeek этими командами не вызывается.

Результат текущего прогона:

| Benchmark | Findings | Baseline | LLM requests |
| --- | ---: | ---: | ---: |
| `demo-full` FULL | 4 SAST + 3 DAST | 7/7 | 0 |
| `sast-contours` SAST | 6 SAST | 6/6 | 0 |
| `dan-lab` FULL | 1 SAST + 1 DAST | 2/2 | 0 |
| `nosqli-mongo-full` FULL | 3 SAST + 3 DAST | 5/5 уникальных типов | 0 |
| `ssrf-lab` FULL | 1 SAST + 1 DAST | 2/2 | 0 |
| `spoofing-sast` SAST | 2 SAST | 2/2 | 0 |
| `security-key-lab` FULL | 1 SAST + 1 DAST | 2/2 | 0 |

Строгий NoSQLi verifier дополнительно подтвердил 8 scanned files, 3 dangerous и
3 safe annotated cases, все три DAST-сценария и сохранённое comparison evidence.

Дополнительно через RunService проверены остальные записи registry:
`sample-sast` — 9 SAST, `juice-shop` — 4 DAST, `nosqli-sast` — 2 SAST,
`nosqli-dast` — 5 DAST. Все четыре run завершены успешно с 0 LLM requests. Таким
образом, scanner-only smoke выполнен для всех 11 benchmark.

## Границы заявления о проверке

Semgrep `--validate`, Nuclei `-validate`, сборка image и семь Docker smoke выполнены
при доступном Docker daemon. Эти результаты относятся к указанной Windows/x86_64
среде; успешный Compose config или unit tests сами по себе не заменяют scanner run.

Реальный LLM provider, физический macOS/Apple Silicon и remote CI не проверяются
автоматически. Provider-ответы в tests подменяются контролируемыми fixtures.
