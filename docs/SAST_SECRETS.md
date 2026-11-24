# SAST: кандидаты в секреты

Правила ищут потенциальные секреты в Python, JavaScript/TypeScript, текстовых
конфигурациях и PEM-подобных блоках. Это эвристические кандидаты, а не
подтверждённые действующие credentials или private keys.

Поддерживаются метки `api_key` / `apiKey`, `secret_key` / `secretKey`,
`access_token` / `accessToken`, `auth_token` / `authToken`, `client_secret` /
`clientSecret`, `token` и `password`. Generic-правило также обрабатывает
однострочные пары в `.txt`, `.md`, `.json`, `.yaml`, `.yml`, `.ini`, `.conf`,
`.cfg`, `.env`, `.properties` и `.toml`, исключая очевидные заглушки.

Правило PEM проверяет только форму согласованного `BEGIN/END ... PRIVATE KEY`
блока и похожее на base64 содержимое. Оно не выполняет криптографическую
валидацию. Рекомендация всегда предполагает ручную проверку контекста.

Benchmark `sast-secrets` содержит только очевидно синтетические строки
`TRAINING_ONLY_*`: 12 ожидаемых совпадений в 16 файлах, включая 8 безопасных
контрольных файлов. Fixtures не исполняются и не содержат реальных ключей.

```powershell
.\run.ps1 scan --benchmark sast-secrets --mode sast --no-llm
docker compose --profile agent run --rm --no-deps --entrypoint python agent -m benchmark.verify_sast_regressions
```

`--no-llm` запускает только SAST. Наличие находки не подтверждает exploitability
и не должно интерпретироваться как утечка без ручной проверки.


## Аудит локальной истории Git

Передайте путь к корню своей локальной рабочей копии. Требуется Git в PATH.

```powershell
security-agent-history-audit .
# Из исходников без установки команды
python -m app.git_history_audit . --limit 50
```

Команда выводит в JSON только SHA коммитов, где менялись строки с именами,
похожими на поля учётных данных, и признак усечения списка. Проверяются
коммиты, доступные из локальных ссылок Git. Совпадение требует проверки
владельцем репозитория. Пустой список не гарантирует отсутствия утечек.
