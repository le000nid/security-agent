# ai-security-agent v0.2.2

An educational, LLM-assisted security testing harness for a local OWASP Juice
Shop lab. It is deterministic by design:

```text
validated input
  -> fixed reviewed SAST / DAST tools
  -> normalized findings
  -> one-time /models preflight when LLM is enabled
  -> optional OpenAI-compatible enrichment
  -> deterministic reports
```

This is not autonomous pentesting software. The LLM does not discover findings,
choose targets, call tools, construct subprocess arguments, or execute commands.
The DAST allowlist contains only `localhost`, `127.0.0.1`, and `juice-shop`.

## Components

- **SAST** examines local source without executing or modifying it. Semgrep runs
  only the reviewed rules in `config/semgrep.yaml`; registry rules, Semgrep Cloud,
  builds, autofix, and telemetry are disabled.
- **DAST** sends low-impact HTTP GET requests to the local lab. Nuclei runs only
  the templates under `config/nuclei/`; redirects, Interactsh, updates, global
  templates, external targets, exploits, and credential attacks are disabled.
- **Finding normalization** maps both scanners to one strict Pydantic model while
  leaving complete scanner output under `logs/`.
- **LLM enrichment** may update only description, normalized category, severity,
  and recommendation for an existing finding. The scanner category is preserved;
  `reasoning_short` is stored separately in the summary.

The current scanner-only sample baseline has produced 12 findings: 9 SAST and
3 DAST. Counts can change if the sample, Juice Shop image, or reviewed rules are
updated; this is a regression baseline, not a claim about real-world coverage.

## Reports

- `logs/raw_nuclei.jsonl` and `logs/raw_semgrep.json`: complete scanner output.
- `reports/findings.json`: normalized findings without complete raw records.
- `reports/report.md`: compact human-readable findings.
- `reports/summary.json`: deterministic counts, LLM status and metadata, short
  rationales, and aggregate token usage.

Severity ordering is always critical, high, medium, low, info, unknown. Equal
severities use deterministic source, tool, title, location, and ID ordering.

## OpenAI-compatible LLM configuration

Copy `.env.example` to `.env` and replace only the API key:

```dotenv
LLM_PROVIDER=openai_compatible
LLM_BASE_URL=https://deepcode.ci.nsu.ru/api
LLM_MODEL=deepseek-ai/DeepSeek-V4-Flash-0731
LLM_API_KEY=replace_me
```

The model ID is exact; the display name `DeepSeek-V4-Flash` is not an API model
ID. Endpoints are constructed from the configured base without adding `/api` or
`/v1`:

- `GET {LLM_BASE_URL}/models`
- `POST {LLM_BASE_URL}/chat/completions`

Before the first completion, the client calls `/models` once and verifies the
exact configured ID in `data[].id`. A successful discovery is cached for the
client process. Authentication, access, endpoint, rate-limit, backend, malformed
response, and missing-model failures are reported distinctly. Timeouts, HTTP 429,
and HTTP 5xx receive at most two short retries; deterministic failures are not
retried.

Only `choices[0].message.content` is parsed. Provider `message.reasoning` is
ignored and never stored or reported. Successful completion usage is aggregated:

```json
{
  "requests": 3,
  "prompt_tokens": 1234,
  "completion_tokens": 456,
  "total_tokens": 1690
}
```

No monetary cost is estimated. Scanner results are written even if model
discovery or enrichment fails; `summary.json` records `llm_status: "failed"`,
the CLI returns a failure code, and the scanner-only findings remain usable.

## LLM privacy boundary

The LLM receives a dedicated `LLMFindingInput`, never `Finding.model_dump_json()`.
By default it contains only ID, title, source, tool, category, severity,
confidence, normalized location, and the deterministic scanner message. SAST
paths are reduced to filename and line.

It does not receive complete source files, Semgrep source snippets, raw HTTP
bodies, scanner logs, `raw_output_ref`, environment variables, API keys, or
authorization headers. `--include-evidence-in-llm` explicitly adds only the
already-normalized short evidence string; raw logs remain excluded. Technical
prose such as `` `debug=True` `` and `` `X-Content-Type-Options` `` is permitted
because generated text is inert data and is never executed.

The enrichment schema contains `description`, optional `normalized_category`,
`severity`, `recommendation`, and `reasoning_short`. Normalized categories use a
small fixed vocabulary; scanner-only findings serialize `normalized_category`
as `null`. The prompt requires facts observed by the scanner to be distinguished
from possible implications and unobserved conditions. In particular, wildcard
CORS is never described as enabling credentialed reads: browsers reject `*` for
credentialed CORS requests.

## Windows PowerShell workflow

Build the pinned non-root agent and start Juice Shop:

```powershell
docker compose build agent
docker compose up -d juice-shop
```

Scanner-only DAST:

```powershell
docker compose run --rm agent `
  --mode dast `
  --target-url http://juice-shop:3000 `
  --no-llm
```

DAST with LLM enrichment:

```powershell
Copy-Item .env.example .env
notepad .env
docker compose run --rm agent `
  --mode dast `
  --target-url http://juice-shop:3000
```

Full SAST + DAST without LLM:

```powershell
docker compose run --rm agent `
  --mode full `
  --target-url http://juice-shop:3000 `
  --source-path /targets/sample-app `
  --no-llm
```

Full SAST + DAST with LLM enrichment:

```powershell
docker compose run --rm agent `
  --mode full `
  --target-url http://juice-shop:3000 `
  --source-path /targets/sample-app
```

Compose passes the four LLM variables only at runtime. The image contains no API
key, the agent publishes no port, targets are mounted read-only, and Juice Shop's
healthcheck uses `/nodejs/bin/node` against `http://127.0.0.1:3000`.

Native development and tests require Python 3.11+:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
```

Native DAST is also available when `nuclei.exe` is in `PATH`:

```powershell
python -m app.main --mode dast --target-url http://localhost:3000 --no-llm
```

## Curated coverage and benchmark

The local HTTP templates and Semgrep rules are documented in
[docs/tools.md](docs/tools.md). `targets/sample-app/` intentionally contains one
example for each local Semgrep rule. The fixture evaluator reports expected,
detected, missed, and unexpected signals plus simple set precision/recall:

```powershell
python -m benchmark.evaluator reports/findings.json
```

This benchmark measures only curated fixture coverage, not pentest quality.

## Validation

```powershell
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
docker build -t ai-security-agent:0.2.2 .
docker compose config
```

Pytest mocks all LLM traffic. CI does not call the NSU gateway, require secrets,
or scan external hosts. It runs Python 3.11/3.12 tests, Ruff, and a Docker build.
