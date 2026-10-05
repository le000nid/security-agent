# AI Security Agent 0.4.1

A local educational AI-assisted application security analysis platform.
Semgrep analyzes source code; Nuclei performs reviewed, low-impact HTTP checks.
Use the CLI or the local Web UI. The primary Web UI is in Russian; this guide is in English. AI is optional: the complete scanner-only demo
works without a provider account or Internet access once images are available.

This is a training harness, not an autonomous pentester or security certification.
Intentionally vulnerable fixtures must never be deployed publicly.

## Scope and orchestration are separate

| Choice | Options | Meaning |
| --- | --- | --- |
| Scope (`--mode`) | sast / dast / full | Source, HTTP, or both |
| Orchestration | scan / agent | Fixed sequence, or validated AI choice |
| AI analysis | enabled / `--no-llm` | Enrichment and AI Security Brief |

`scan --mode full --no-llm` runs both scanners without any LLM request.
`agent` requires LLM access. Its primary meaningful choice today is which
scanner runs first in FULL mode; later single-option actions are automatic,
not extra Planner requests. `deterministic` remains an alias for `scan`.

## Built-in benchmarks

| ID | Default scope | Source / service | Curated baseline |
| --- | --- | --- | --- |
| sample-sast | SAST | `/targets/sample-app` | Nine Semgrep findings |
| juice-shop | DAST | `http://juice-shop:3000` | No fixed acceptance baseline |
| demo-full | FULL | `/targets/demo-full` and `http://demo-full:3000` | Four SAST + three DAST indicators |

The registry is reviewed static `config/benchmarks.yaml`, validated with Pydantic.
Juice Shop has no bundled matching source, so SAST/FULL selection is rejected.
Demo Full's source mount and running server belong to the **same project**.
Its standard-library HTTP server serves constant text; wildcard CORS, missing
CSP and missing Referrer-Policy are deliberate configuration indicators.
Source-only shell/pickle/debug/secret examples are never imported by the server.
Coverage is curated local benchmark coverage, not real-world detection accuracy.

Juice Shop is pinned to the verified official `bkimminich/juice-shop:v20.2.0`
tag. Demo Full uses `python:3.11.14-slim-bookworm`. Tags are not immutable
digests; changing source, templates or images may change results.

## Requirements

Git, Docker Desktop with Linux containers (Windows/macOS), or Docker Engine
with Compose v2 (Linux). Normal Docker usage needs **no host Python, scanners,
Go, Node or frontend build tool**. Keep adequate Docker disk space available.
Python 3.11+ is only needed for native development.

Linux amd64/arm64 images and Windows/Linux/macOS test jobs are configured in CI.
Do not interpret CI configuration as physical macOS/Apple Silicon validation.
Linux wrappers map your UID/GID for writable reports; never make the Docker
socket world-writable.

## Quick start — Windows PowerShell

On Windows 10/11 x64 install Git and Docker Desktop, select Linux containers,
and wait for the Docker engine to be running. Open PowerShell in your projects folder:

```powershell
git clone https://github.com/le000nid/security-agent.git
cd security-agent
.\scripts\bootstrap.ps1
.\scripts\doctor.ps1
.\run.ps1 benchmarks
.\run.ps1 scan --benchmark demo-full --mode full --no-llm
.\run.ps1 latest
.\run.ps1 ui
```

Open [AI Security Agent UI](http://127.0.0.1:8080).
Lab browser addresses: [Juice Shop](http://127.0.0.1:3000) and
[Demo Full](http://127.0.0.1:3001).

If PowerShell script execution is blocked, follow your organization's policy.
If policy permits, use only a process-scoped exception in this terminal:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\bootstrap.ps1
```

Do not change machine-wide policy.

## Quick start — Linux

Install Git, Docker Engine and the Compose v2 plugin using your distribution's
supported installation procedure. Start Docker and ensure your account is allowed
to use it (`docker info`, `docker compose version`). Docker-group membership is
privileged; follow local policy. Never use `chmod 777 /var/run/docker.sock`.

```bash
git clone https://github.com/le000nid/security-agent.git
cd security-agent
./scripts/bootstrap.sh
./scripts/doctor.sh
./run.sh benchmarks
./run.sh scan --benchmark demo-full --mode full --no-llm
./run.sh latest
./run.sh ui
```

## Quick start — macOS (Intel and Apple Silicon)

Install Git (for example via Command Line Tools) and Docker Desktop for your Mac's
architecture. Start Docker Desktop and wait for its engine. In Terminal:

```bash
git clone https://github.com/le000nid/security-agent.git
cd security-agent
./scripts/bootstrap.sh
./scripts/doctor.sh
./run.sh ui
```

Open [the local UI](http://127.0.0.1:8080), then follow the no-LLM demo below.
Do not force amd64 on Apple Silicon unless deliberately testing emulation.
The project retains amd64/arm64 build support and macOS CI, but this patch does
not claim physical macOS/Apple Silicon validation.

## What bootstrap and UI startup do

Bootstrap preserves an existing `.env`, otherwise copies `.env.example`;
creates runs/logs/reports; validates Docker; builds the agent or pulls
`AGENT_IMAGE`; starts Juice Shop and Demo Full; waits for health; runs all
three registered demos without LLM. It never installs Docker or contacts an LLM.
First image build needs network access. Subsequent scans use local rules/assets.

`ui` starts bundled lab services and the long-running UI service. The browser
process itself has no Docker socket and never starts containers. Stop only the
UI with `docker compose --profile ui stop ui`. To stop the whole lab:
`docker compose --profile ui --profile agent down` (reports remain on the host).

## First demo without LLM — Russian UI walkthrough

1. Open **Сканирование**, select **Demo Full**, **Тип анализа: FULL**.
2. Choose **Обычное сканирование**, leave **Использовать ИИ** unchecked.
3. Click **Запустить анализ** and follow **Ход анализа**.
4. Open **Открыть результаты**: expect four SAST + three DAST findings, baseline
   detected 7/7, no missed/unexpected findings, and AI stages skipped.
5. Filter findings by severity/source/category; open one for evidence,
   description and recommendation. Read/download the plain-text Markdown report.

AI Agent is disabled until AI is enabled. Tone professional/concise/funny and
language ru/en apply to the brief, not scanner evidence. Evidence transmission
is a separate opt-in. A failed provider must not erase scanner results.

**История запусков** reads persisted reports (including v0.3 runs), newest first, at most
500 entries. Malformed histories are skipped. It is not a database.
One UI scan job is allowed at a time; a second start returns
`scan_already_running`. The last 50 jobs and 100 events/job are in memory.
A UI restart loses job handles; check Runs for surviving reports. Do not restart
during a scan: background work is not a durable queue. Separate CLI processes
are not governed by the UI's in-process lock.

## Chat: discuss a saved run, or propose a controlled scan

**ИИ-помощник** has two distinct purposes:

1. Analyze existing results. Select **Текущий запуск** (latest readable run by
   default) and optionally **Находка**. **Обсудить этот запуск** on run detail and
   **Объяснить в ИИ-помощнике** on finding detail select those exact IDs.
2. Propose a new registered-benchmark scan. No scan starts before a separate
   **Запустить** confirmation. **Отмена** discards it. Proposals expire after
   five minutes, are one-use, and disappear when the UI restarts.

Useful Russian questions:

- “Что здесь плохого и что исправлять первым?”
- “Что здесь хорошего?”
- “Есть ли реально опасные проблемы?”
- “Сравни результаты SAST и DAST.”
- “Дай план исправления на 5 шагов.”
- “Объясни эту находку.” / “Почему это high?”
- “Какие находки могут быть false positive?”
- “Какие утверждения точно подтверждены сканерами, а какие являются предположениями?”
- “Назови три приоритета исправления и необходимые ручные проверки.”

The read-only Chat Run Analyst uses only a compact projection of stored findings.
It cannot create Finding objects, change targets or run tools/scanners. Replies
normally use strict Pydantic-validated JSON with a short `summary`,
`confirmed_points`, `assumptions_or_manual_checks` and `remediation_priorities`.
The UI renders these as **Подтверждено сканерами**, **Требует ручной проверки** and
**Почему это важно / приоритеты исправления**, plus existing-finding links,
caveats and suggested questions. Unknown/duplicate IDs are rejected. Observations,
interpretations and uncertainty must be distinguished; positive run coverage is
not proof that the application is secure. A scanner pattern is not proof of
exploitability: risks are conditional on input reachability and manual validation.
Stored severity and enrichment stage status are also displayed independently of
AI prose. Narrow contradiction guards correct unsupported CRITICAL claims and
claims that completed enrichment was absent; these are not a general fact checker.

Local shortcuts work without an LLM: “Покажи HIGH”, “Сколько нашёл SAST?”,
“Покажи результаты DAST”, “Где отчёт?”, “Какие стенды доступны?”.
An offline analytical question returns the selected/highest-severity stored
finding, description, recommendation and saved rationale with a clear limitation.

“Проверь demo-full полностью” proposes FULL / ordinary scan / AI off.
“Проверь demo-full полностью агентом” proposes FULL / agent / AI on.
These exact known-registry phrases need no intent-parser request.
Neither URLs nor source paths can be passed through chat.

Click **Проверить подключение к LLM** to explicitly check model discovery before
free-form AI analysis. This chat health indicator is separate from a scan's actual
component outcomes; successful CLI/Guided Scan use does not mark a newly created
chat client checked. RunService always performs its own authoritative preflight.
Transport/authentication/discovery failure latches unavailable until an explicit
check. Invalid JSON and schema failures report safe content errors without
changing available connectivity. The intent parser still has no automatic retry.
If classification fails with a content error and a saved run exists, the controller
falls back to read-only Analyst, never to a scan proposal. This prevents an intent
parser truncation (600-token budget) from bypassing analyst recovery entirely.

### Long Chat Analyst answers

Only the **Chat Run Analyst** makes one concise retry on provider truncation
(`finish_reason=length`) or an otherwise valid answer exceeding output limits.
Independent environment settings (also forwarded by Compose) are:

| Setting | Default | Purpose |
| --- | --- | --- |
| `LLM_CHAT_MAX_TOKENS` | `2400` | Initial analyst completion budget |
| `LLM_CHAT_RETRY_MAX_TOKENS` | `3600` | Single concise-retry budget |

Both accept 256–8192; retry must exceed the initial budget. They do not change
Planner, enrichment or brief budgets. Existing `.env` files are not overwritten.
Rebuild the image after code changes; recreate UI after environment changes.

Useful partial text is retained even when the retry also truncates or fails.
The API returns `analysis.status=completed_with_warnings`, `truncated=true` and
`error_code=chat_response_truncated`, not an empty error placeholder. The UI shows
**Ответ сокращён из-за ограничения длины. Показана первая часть.** above the
available text and offers **Продолжить**, **Сжать ответ**, **Разобрать по одной
находке**, **Только подтверждённые факты**, and **Только то, что требует ручной
проверки**. A successful concise retry is shown normally; the first partial
remains available in an expandable block. If neither attempt contains readable
answer text, the fallback shows stored observations with an explicit warning.

Partial JSON recovery extracts only bounded display fields, never reasoning,
tool calls or a raw envelope. An incomplete answer is not a fully validated
conclusion; finding-reference links are omitted until a complete reply validates.
No partial answer is written to scan reports/logs or used as tool input.

Only the current question and explicit run/finding context are sent, not general
chat history. Explicit follow-up buttons additionally send at most 2400 characters
of the displayed answer as untrusted, ephemeral context for the same run/finding;
they cannot start a scan. The analyst receives at most 50 severity-ranked findings (selected
finding first), with title <=120 and description/recommendation/rationale <=180
characters. No raw logs, source code, locations, evidence or environment are sent.
Structured answers have summary <=350 characters and at most seven points total,
each <=180 (at most four per block). The legacy answer <=1800 remains supported.
There are <=7 unique supplied finding IDs and <=4 caveats/questions each.
Input coverage counts disclose truncation of the projection.
Chat intent parsing and analysis have separate in-memory usage counters, outside
scan summaries. The last 30 displayed messages remain only in the browser tab.

The closed intent set adds ANALYZE_RUN, PRIORITIZE_FINDINGS, REMEDIATION_PLAN and
COMPARE_SAST_DAST; EXPLAIN_FINDING and SUMMARIZE_RUN now use the analyst when
available. Planner remains a different role inside the controlled scan loop.

## LLM unavailable / offline demo

```powershell
.\run.ps1 scan --benchmark demo-full --mode full --no-llm
```

Semgrep, Nuclei, normalization, baseline evaluation, findings, summary and report
remain available. Planner, enrichment, AI Security Brief and free-form AI parsing
are unavailable. Skipped AI stages are expected, not a failure.
Quick-action Chat and Guided Scan remain usable.

When the provider is available, these are **manual opt-ins**, not test steps:

```powershell
.\scripts\doctor.ps1 --check-llm
.\run.ps1 agent --benchmark demo-full --mode full
```

Linux/macOS equivalents are `./scripts/doctor.sh --check-llm` and
`./run.sh agent --benchmark demo-full --mode full`.

## Optional LLM configuration

Edit `.env` locally; keep scanner-only runs available while configuring access:

```dotenv
LLM_PROVIDER=openai_compatible
LLM_BASE_URL=https://deepcode.ci.nsu.ru/api
LLM_MODEL=deepseek-ai/DeepSeek-V4-Flash-0731
LLM_API_KEY=replace_me
AGENT_MAX_STEPS=8
AGENT_MAX_PLANNER_CALLS=8
LLM_PLANNER_MAX_TOKENS=320
LLM_PLANNER_RETRY_MAX_TOKENS=512
LLM_ENRICHMENT_BATCH_SIZE=1
LLM_ENRICHMENT_MAX_TOKENS=1200
LLM_ENRICHMENT_RETRY_MAX_TOKENS=2200
LLM_BRIEF_ENABLED=true
LLM_BRIEF_MAX_TOKENS=2000
LLM_BRIEF_RETRY_MAX_TOKENS=3200
LLM_REPORT_TONE=funny
LLM_REPORT_LANGUAGE=ru
```

Never commit `.env`, paste an API key into Git, or print resolved Compose
configuration containing secrets. Use `docker compose config --quiet`.
Bootstrap preserves your existing settings, including older token budgets. When
upgrading, explicitly update the Planner and brief values above in your local
.env; otherwise old 1000/1600 brief overrides will still take effect. Recreate
the UI after editing .env (`.\run.ps1 ui` or `./run.sh ui`). Set
`LLM_ENRICHMENT_BATCH_SIZE=1` explicitly when upgrading: this is the safe default
in code, Compose and .env.example. An HTTPS base URL is required; do not
append `/models` or `/chat/completions`. The exact model ID must be available
to your account; the example is not a promise of provider availability.

To explicitly test model discovery/connectivity without an analysis completion:

```powershell
.\scripts\doctor.ps1 --check-llm
```

```bash
./scripts/doctor.sh --check-llm
```

This opt-in sends only GET /models; it does not print the key. Real provider
access is not part of automated tests or bootstrap.

### Reliable finding enrichment

Batch size 1 makes more HTTP requests, with smaller structured responses and the
highest reliability. Each finding is independent: a malformed response preserves
that scanner finding, records a safe ID/error code, and continues with the next.
Successful enrichments are not rolled back. Count, identity and scanner category
remain unchanged. The technical prompt stays formal regardless of report tone.

Truncated enrichment gets **one** retry with a larger `max_tokens` budget
(1200 → 2200 by default) and a concise JSON-only repair instruction. Empty,
malformed, schema-invalid or identity-changing output is not accepted and gets
no content retry. Existing transport retries for timeout/429/5xx remain bounded
to two retries per completion attempt; all attempts count in usage.

Batch sizes 2–20 are experimental: fewer requests, larger responses and greater
truncation risk. A batch is validated atomically; if it still fails, that batch's
scanner findings are kept and the next batch proceeds. The configured token
budget is per request, not multiplied by batch size. `retried` counts findings
included in a truncation retry, not transport retries or HTTP requests.

`summary.json.enrichment` contains `requested`, `completed`, `failed`, `retried`
and `failures` (finding_id + error_code only). `stages.enrichment` is completed
when every requested finding succeeds, completed_with_failures for a mixture,
failed when none succeeds, or skipped when disabled/no findings exist.
Model-output failures do not fail otherwise successful scanner/report stages:
the overall status becomes completed_with_warnings and exit code remains 0.

Planner budgets must be 256–2048; enrichment and brief budgets 256–8192.
Each retry budget must strictly exceed its normal budget. The current compatible client sends `max_tokens`, not a speculative
provider-specific parameter. No provider reasoning is sent back on retries.

### Planner truncation recovery

The first Planner request uses LLM_PLANNER_MAX_TOKENS (320). Only if the immediately
preceding decision was rejected as planner_response_truncated does the next
request use LLM_PLANNER_RETRY_MAX_TOKENS (512). Other content errors do not raise
the budget. The existing AGENT_MAX_PLANNER_CALLS and three-consecutive-rejections
limits still apply; there are no hidden transport retries. Short reasoning is
requested as one concise sentence, not chain-of-thought. A normal FULL run should
need one Planner request; single-option stages make none.

## AI Security Brief

These roles are separate:

| Role | Responsibility |
| --- | --- |
| Scanner | Produces candidate findings using reviewed rules/templates |
| Finding enrichment | Explains each existing finding in technical terms |
| AI Security Brief | Summarizes the whole run for the human reader |
| Planner | Chooses between multiple currently permitted actions |
| Chat Intent Parser | Classifies the current UI request into a fixed intent |
| Chat Run Analyst | Discusses stored results without mutating or executing anything |

```text
Semgrep / Nuclei
       |
       v
   Finding[]
       |
       v
Finding enrichment
       |
       v
AI Security Brief
       |
       v
   report.md
```

`GENERATE_AI_BRIEF` is a fixed analysis-only action after scanner/enrichment
stages become terminal, before reporting. It is available in both `scan` and
`agent`. It never creates Finding objects, changes scan scope or executes tools.
The input contains stage/counter metadata and compact normalized IDs, titles,
sources, severities, categories and short descriptions—not paths, URLs, raw
references, source files, evidence, HTTP bodies or environment values.

Descriptions in its input are capped at 120 characters. Output limits are headline
100, overall summary 450, finding explanation 180, each next step 180,
limitations 300 and closing line 160 characters.

Strict output validation limits the headline, summary, up to three existing
finding references, up to four next steps, limitations and closing line.
Unknown and duplicate IDs are rejected. The brief is prompted not to invent
vulnerabilities, claim unobserved exploitation or treat zero findings as proof
of security. It receives trusted same-application metadata for demo-full, and warns about unverified correspondence for legacy direct inputs. Prose accuracy still requires human review.

The brief is displayed near the top of report.md and saved in ai_brief.json.
Console output shows only its headline/summary and report paths. If generation
fails, successful enrichment and all scanner findings remain; the ordinary report
is generated with a warning. `ai_brief.json` then contains a small status object
such as `{"status":"failed"}` or `{"status":"skipped"}`, never raw model output.

The brief has its own 2000-token budget and at most one truncation retry at 3200
tokens with a stricter concise prompt. Completed JSON/schema-invalid output gets
one fresh schema-repair attempt, also at 3200, using compact original data and
safe field/type diagnostics, not raw provider text. Maximum: **three logical
attempts** (normal → concise retry → schema repair). Repair is terminal even if
it truncates; repeated truncation stops after two attempts. Transport retries
remain separately bounded (up to two retries per logical attempt).
Usage counts actual HTTP requests: `llm_usage.planner`, `enrichment`, `brief`, `total`.
`summary.json → llm_components.brief.attempts` retains budgets, safe error codes,
validation field/types, finish_reason, content length and a reasoning-present
boolean. Unknown field names become `<unknown>`; no values, raw text or reasoning
are saved. The UI shows these under **Безопасная диагностика AI Brief**.
The schema stays small: headline, overall_summary, at most three top findings,
four steps, limitations and closing_line.
Set `LLM_BRIEF_ENABLED=false` to disable synthesis without disabling enrichment.
`--no-llm` skips both and makes **zero** LLM requests.

See [LLM reliability diagnosis and Windows live-test commands](docs/LLM_RELIABILITY.md).

### Tone and language (brief only)

`LLM_REPORT_TONE` accepts only professional (default), concise or funny.
Professional suits engineering reports/university defense; concise is short
and direct; funny adds one or two restrained metaphors for demos. Humor must not
trivialize high severity, replace recommendations, joke about victims or real
harm, or include profanity, emojis or meme spam.

For a Russian demo, edit the local Windows `.env`:

```dotenv
LLM_REPORT_TONE=funny
LLM_REPORT_LANGUAGE=ru
```

Use `LLM_REPORT_TONE=professional` for formal reports, or `concise` for a short
brief. Languages are `ru` (default) and `en`; finding IDs are never translated.
Only the high-level AI Security Brief changes tone/language. Detailed findings
remain technical and do not receive the humor instructions. Both settings are
recorded as `report_tone` and `report_language` in summary.json.

## CLI compatibility and target resolution

```text
security-agent benchmarks
security-agent benchmarks list
security-agent benchmarks show demo-full
security-agent scan --benchmark sample-sast --no-llm
security-agent scan --benchmark juice-shop --no-llm
security-agent scan --benchmark demo-full --mode full --no-llm
security-agent agent --benchmark demo-full --mode full
security-agent doctor --check-benchmarks
security-agent ui
```

Benchmark plus direct source/target is rejected. Unsupported scopes are rejected,
not silently changed. Defaults derive from capabilities. Direct commands remain:

```powershell
.\run.ps1 scan --mode sast --source-path /targets/sample-app --no-llm
.\run.ps1 scan --mode dast --target-url http://juice-shop:3000 --no-llm
.\run.ps1 scan --mode full --target-url http://juice-shop:3000 --source-path /targets/sample-app --no-llm
```

The last legacy example analyzes **different applications**, which the report
explicitly warns about. Direct inputs never claim same-application identity.
Wrappers do not start DAST services for SAST-only scans, benchmarks, latest or
default doctor. DAST/FULL/UI may start both local HTTP targets.

Native development: `python -m app.main scan ...` and
`python -m app.main ui` (127.0.0.1:8080). Registry service names resolve inside
Compose, not normally on the host; run benchmark-aware HTTP scans through Docker.
Direct native DAST can use a loopback published port. Legacy flag-only invocation
`python -m app.main --mode ...` retains its previous deterministic contract and
root logs/reports paths. Use subcommands for v0.4 per-run artifacts.

## Architecture and artifacts

CLI / Guided Scan / Chat → strict RunRequest → RunService → deterministic loop
or AgentState/Planner/Validator → fixed ToolRegistry → Semgrep/Nuclei → Findings
→ optional enrichment → optional brief → shared reports.
UI observes typed events, not console output, and never shells out to the CLI.

```text
runs/<UTC timestamp>-<random suffix>/
  logs/raw_semgrep.json
  logs/raw_nuclei.jsonl
  reports/findings.json
  reports/summary.json
  reports/report.md
  reports/agent_trace.json
  reports/ai_brief.json
runs/latest.json
```

Raw scanner records stay in logs; normalized findings contain references only.
Summary preserves version, status, stages, counts, warnings, planner usage,
enrichment statistics and adds benchmark ID/name, mode, same-application flag,
and optional baseline evaluation. Trace records short decisions, not provider
chain-of-thought. AI brief is a validated object or a small skipped/failed status.
`latest.json` points to the most recently started run. UI history reads summaries
independently, including legacy runs with no benchmark metadata.

For independent AI outcomes read `llm_components.planner` (status/requests/failures),
`llm_components.enrichment` (requested/completed/failed) and `llm_components.brief`
(status/error_code). The legacy `llm_status` remains for older consumers.
A completed enrichment does not imply a successful brief. The Russian UI banner
uses actual stage outcomes and reports optional failures without claiming AI was off.

Report existence is not proof of success. Read summary.status and all stages:
completed; completed_with_warnings (optional AI failed); or failed (partial work).
Exit codes remain 0 success/warnings, 2 invalid input, 3 scanner failure,
4 fatal agent LLM preflight, 5 planner failure/limit, 6 environment/report failure.
The UI shows failed stages and preserved findings even after a partial run.

## Security boundaries

- Loopback host publishing only: 3000, 3001, 8080. Native UI defaults to loopback;
  `--host 0.0.0.0` is for container-internal binding only. Never publish on a LAN.
- HTTP scan hosts: localhost, 127.0.0.1, trusted static registry service hosts.
  Public domains, IP ranges/lists, credentials, UNC source paths and 0.0.0.0 targets
  are rejected. A configured HTTPS LLM provider is separate explicit egress.
- UI/Chat accept benchmark IDs, never arbitrary targets/paths/flags.
  Strict Pydantic contracts and application validation remain authoritative.
- Fixed local scanner commands; no remote rules, DNS/network template sweep,
  redirects, Interactsh, destructive operations, autofix or source execution.
- UI has no Docker socket, runs non-root, drops capabilities and uses
  no-new-privileges. Targets are read-only. No multi-user/authentication promise.
- Same-origin CSRF token on every POST; Host/Origin checks, no CORS, CSP,
  escaped templates and DOM textContent. Reports are served as plain text.
  Download filenames are allowlisted; run IDs and filesystem containment checked.
- LLM output is data. Secrets stay server-side; no keys/raw provider responses
  appear in UI. Review findings/evidence before sharing local artifacts.

Local malware or another process under the same user is outside this trust
boundary. Scanner findings may be false positives; AI prose may be wrong.
Source/target equivalence is declared by reviewed registry configuration, not
cryptographically proven. No cloud scanning, new scanners, accounts or database.

## Development, packaging and troubleshooting

```text
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
docker compose config --quiet
```

Tests mock provider access. Never run real completion/model-discovery calls in CI.
Doctor checks tools, writable runs, local rules, registry and source directories;
only `--check-benchmarks` probes registered HTTP targets, and only
`--check-llm` contacts the provider.

After reviewing and committing the release, `scripts/package.ps1` or
`scripts/package.sh` creates `dist/security-agent-v0.4.1.zip` using git archive
of clean committed HEAD. Untracked files are never included; tracked secret-like
filenames cause failure. Export rules exclude runtime directories, .env, caches
and archives. Scripts refuse to overwrite an existing release archive.
This is not a secret-content scanner: review committed text before release.
Do not commit credentials just to make packaging succeed.

See the worked [benchmark extension guide](docs/BENCHMARKS.md), [architecture](docs/ARCHITECTURE.md), [development](docs/DEVELOPMENT.md),
[troubleshooting](docs/TROUBLESHOOTING.md), [rules/tools](docs/tools.md) and
[validation record](docs/VALIDATION.md). Optional
`AGENT_IMAGE=ghcr.io/owner/repository:0.4.1` selects your published image;
otherwise bootstrap builds locally.
## Manual Windows real-provider acceptance (not automated)

Review the safe .env example above and set your own key locally. Do not print it.
With Docker running and no scan in progress:

```powershell
.\scripts\bootstrap.ps1
.\scripts\doctor.ps1
.\run.ps1 scan --benchmark demo-full --mode full --no-llm
.\scripts\doctor.ps1 --check-llm
.\run.ps1 agent --benchmark demo-full --mode full
.\run.ps1 latest
.\run.ps1 ui
```

Expected scanner baseline is 4 SAST + 3 DAST, 7/7. With a successful provider,
expect all stages completed, enrichment 7/7 and a concise Russian brief in the
selected tone; ideally Planner requests=1 and failures=0. Content/provider
failures remain possible and must be reported honestly. In the browser select
that run, press **Обсудить этот запуск**, explicitly check Chat connectivity,
and ask “Что здесь плохого и что исправлять первым?”. No scanner should rerun.
