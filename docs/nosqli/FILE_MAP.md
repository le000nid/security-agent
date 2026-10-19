# Карта файлов NoSQLi

| Файл или каталог | Что делает |
|---|---|
| `targets/nosqli-lab/src/server.js` | Соединение с БД, загрузка учебных данных и запуск API |
| `targets/nosqli-lab/src/app.js` | HTTP, JSON, маршрутизация, ограничения размера и ответы с ошибками |
| `targets/nosqli-lab/src/db.js` | Клиент настоящей MongoDB, таймауты и проверка соединения |
| `targets/nosqli-lab/src/seed.js` | Три товара и два заказа с постоянными учебными ID |
| `targets/nosqli-lab/src/validation.js` | Проверки объектов, разрешённых ключей и строк |
| `targets/nosqli-lab/src/routes/operator.js` | Объектный оператор вместо строки и безопасная пара |
| `targets/nosqli-lab/src/routes/filter.js` | Пользовательский фильтр целиком и безопасная пара |
| `targets/nosqli-lab/src/routes/scope.js` | Перезапись владельца и безопасная пара |
| `targets/nosqli-lab/test/` | Проверки валидации и реальные HTTP-запросы к API с MongoDB |
| `targets/nosqli-lab/package*.json` | Версии зависимостей и lock-файл |
| `targets/nosqli-lab/Dockerfile` | Образ Node.js API |
| `config/semgrep.yaml` | Новые правила `javascript-nosqli-scalar-operator` и `javascript-nosqli-untrusted-filter` |
| `config/nuclei/nosqli-mongo-*.yaml` | Три DAST-проверки с обычным, изменённым и контрольным запросами |
| `config/nosqli-scenarios.json` | Инвентарь запросов и ожидаемых ID для приёмочной проверки HTTP |
| `config/expected/nosqli-mongo-full.json` | Ожидаемые типы находок общего evaluator |
| `config/benchmarks.yaml` | Запись `nosqli-mongo-full`, связывающая код и API одного приложения |
| `app/parser.py` | Сохранение ограниченного по размеру доказательства из Nuclei в общей находке |
| `benchmark/verify_nosqli.py` | Проверка HTTP-результатов уязвимых и безопасных маршрутов |
| `benchmark/verify_nosqli_sast.py` | Сверка реального Semgrep JSON с аннотациями исходников |
| `benchmark/verify_nosqli_templates.py` | Настоящий Nuclei на положительных и отрицательных HTTP-фикстурах |
| `benchmark/verify_nosqli_run.py` | Проверка общего FULL-отчёта и точных мест SAST |
| `tests/nosqli/` | Автотесты проверяющих функций, ошибок, конфигурации и доказательств |
| `scripts/check-nosqli.sh` | Полная последовательность приёмочных проверок одной командой |
| `docker-compose.nosqli.yml` | Старый Juice Shop плюс отдельные профили MongoDB, API и тестов |
| `.github/workflows/nosqli.yml` | Запуск Docker-проверок в GitHub Actions и сохранение отчётов |
| `pyproject.toml` | Включение новой конфигурации в установленный пакет агента |

Для объяснения начать с `routes/operator.js`, затем открыть соответствующее
правило в `config/semgrep.yaml`, шаблон Nuclei и полученный `report.md`.

Предыдущие файлы `targets/nosqli/` и `juice-shop-nosqli-reviews.yaml`
относятся к первому сценарию `$where` и сохраняют прежние команды запуска.
