# Разработка

## Подготовка

```powershell
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
docker compose config --quiet
```

Unit-тесты запрещают реальные network calls. Provider и scanner subprocess должны
быть mocked. Реальные tool smoke выполняются отдельно в Docker.

## Правила изменений

- используйте существующие RunService, AgentState, Validator и ToolRegistry;
- не добавляйте subprocess interface для LLM;
- не принимайте arbitrary URL/path/flags из UI или Chat;
- raw scanner records не помещайте в `Finding`;
- новые правила должны иметь vulnerable и safe/benign fixtures;
- новые benchmark ID, Semgrep rule ID и Nuclei template ID уникальны;
- пользовательские описания и UI-тексты пишите по-русски;
- technical enum/ID/command сохраняйте стабильными.

## Проверка parser

Semgrep fixture должна содержать `results`, `errors` и `paths.scanned`. Finding path
обязан присутствовать в scanned list. Duplicate JSON keys, scan errors, пустой scan,
skipped rules и некорректные позиции отклоняются.

Nuclei evidence ограничен matcher/template ID и bounded extracted results. Полный
HTTP response остаётся в raw JSONL.

## Tests

- parser/model/config — unit;
- registry/mode/local-only — contract;
- vulnerable/safe fixture — unit или local HTTP;
- RunService — mocked scanners;
- real Semgrep/Nuclei — Docker smoke;
- UI renderer — Node DOM contract;
- LLM — только mocked envelopes, включая length/schema/transport paths.

`tests/test_integrated_contours.py` проверяет полный registry, уникальность ID,
границы SSRF/security-key/spoofing и Compose capabilities. Branch-specific tests
проверяют SQL/LFI/RFI, DAN и NoSQLi.

## Docker smoke

Для каждого required benchmark запускайте scanner-only режим и проверяйте:

- status completed;
- baseline без missed/unexpected;
- expected SAST/DAST counts;
- `llm_usage.total.requests == 0`;
- raw logs и все отчёты существуют.

Не вызывайте реальный provider в CI. `doctor --check-llm` — только явная ручная
проверка.

## Release hygiene

Не включайте `.env`, runs/logs/reports, caches, random YAML/JSON, screenshots и
декоративные изображения. Packaging scripts используют tracked clean tree и
`git archive`; commit/push/release требуют отдельного решения пользователя.
