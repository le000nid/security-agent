# AI Security Agent 0.3.2

## Two independent choices

| Choice | Values | Meaning |
| --- | --- | --- |
| Scan scope (`--mode`) | `sast` / `dast` / `full` | What to analyze |
| Orchestration (subcommand) | `scan` / `agent` | Who selects the next approved action |

SAST = Semgrep analyzes source code. DAST = Nuclei checks a running HTTP
application. FULL includes both SAST and DAST. SCAN is a deterministic Python
workflow. AGENT lets the LLM Planner choose between multiple currently valid,
approved actions. **Agent mode is not required to run both scanners.**

This is an educational, local-only security testing harness, not an automated
pentester. The current agent is a controlled planning runtime, not yet an interactive chat interface.

## Prerequisites and supported hosts

Normal Docker usage requires Git, Docker and Docker Compose v2. You do **not**
need host Semgrep, Nuclei, Go, Python or Python dependencies.

| Host | Docker runtime | Image architecture |
| --- | --- | --- |
| Windows 10/11 x64 | Docker Desktop with Linux containers | amd64 |
| Linux | Docker Engine + Compose v2 | amd64 / arm64 |
| macOS Intel | Docker Desktop | amd64 |
| macOS Apple Silicon | Docker Desktop | arm64 |

Images are intended for Linux amd64 and arm64. Builds check both scanner binaries.
Use your native architecture; do not force amd64 on Apple Silicon unnecessarily.
The lab binds port 3000 only on the host loopback interface.

## First run — Windows PowerShell

Start Docker Desktop, then:

```powershell
git clone https://github.com/le000nid/security-agent.git
cd security-agent
.\scripts\bootstrap.ps1
.\scripts\doctor.ps1
```

If script execution is blocked and your organization's policy permits it, use
`Set-ExecutionPolicy -Scope Process Bypass` in this terminal only. Do not
permanently disable PowerShell security policies.

Bootstrap creates runtime directories, copies `.env.example` only if `.env`
does not already exist, builds the agent (or pulls `AGENT_IMAGE`), starts Juice
Shop, waits for health, and runs a deterministic full smoke scan with `--no-llm`.
It never overwrites an existing `.env` or calls an LLM.

Doctor checks Docker/Compose, architecture, image, tools, rules, writable report
paths, the sample source mount, Juice Shop DNS/reachability and configuration.
Default doctor never contacts the LLM API and never prints the key.

Open the lab in a browser at [localhost:3000](http://localhost:3000).
Inside the agent container, use `http://juice-shop:3000`: container localhost
means the agent itself, not Juice Shop.

## First run — Linux

```bash
git clone https://github.com/le000nid/security-agent.git
cd security-agent
./scripts/bootstrap.sh
./scripts/doctor.sh
```

Docker should be usable by your current account. Diagnose permission errors with
`docker info` and your installation's Docker access configuration; do not use
`chmod 777` on the Docker socket or run the scanner as unrestricted root.
Linux wrappers map your UID/GID for writable bind mounts. Docker group membership
grants powerful host access; follow your administrator's policy.

## First run — macOS Intel / Apple Silicon

Install and start Docker Desktop, then:

```bash
git clone https://github.com/le000nid/security-agent.git
cd security-agent
./scripts/bootstrap.sh
./scripts/doctor.sh
```

The commands are identical for Intel (amd64) and Apple Silicon (arm64).
Build locally if no compatible published image is available.

## Optional LLM configuration

Edit `.env` locally; keep scanner-only runs available while configuring access:

```dotenv
LLM_PROVIDER=openai_compatible
LLM_BASE_URL=https://deepcode.ci.nsu.ru/api
LLM_MODEL=deepseek-ai/DeepSeek-V4-Flash-0731
LLM_API_KEY=replace_me
AGENT_MAX_STEPS=8
AGENT_MAX_PLANNER_CALLS=8
LLM_ENRICHMENT_BATCH_SIZE=1
LLM_ENRICHMENT_MAX_TOKENS=1200
LLM_ENRICHMENT_RETRY_MAX_TOKENS=2200
LLM_BRIEF_ENABLED=true
LLM_BRIEF_MAX_TOKENS=1000
LLM_BRIEF_RETRY_MAX_TOKENS=1600
LLM_REPORT_TONE=professional
LLM_REPORT_LANGUAGE=ru
```

Never commit `.env`, paste an API key into Git, or print resolved Compose
configuration containing secrets. Use `docker compose config --quiet`.
Bootstrap preserves your existing settings, including an older batch size. Set
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

All token budgets must be 256–8192; each retry budget must exceed its normal
budget. The current compatible client sends `max_tokens`, not a speculative
provider-specific parameter. No provider reasoning is sent back on retries.

## AI Security Brief

These roles are separate:

| Role | Responsibility |
| --- | --- |
| Scanner | Produces candidate findings using reviewed rules/templates |
| Finding enrichment | Explains each existing finding in technical terms |
| AI Security Brief | Summarizes the whole run for the human reader |
| Planner | Chooses between multiple currently permitted actions |

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

Strict output validation limits the headline, summary, up to five existing
finding references, up to five next steps, limitations and closing line.
Unknown and duplicate IDs are rejected. The brief is prompted not to invent
vulnerabilities, claim unobserved exploitation or treat zero findings as proof
of security. It also receives the warning that the educational FULL inputs are
different applications. Prose accuracy still requires human review.

The brief is displayed near the top of report.md and saved in ai_brief.json.
Console output shows only its headline/summary and report paths. If generation
fails, successful enrichment and all scanner findings remain; the ordinary report
is generated with a warning. `ai_brief.json` then contains a small status object
such as `{"status":"failed"}` or `{"status":"skipped"}`, never raw model output.

The brief has its own 1000-token budget and at most one truncation retry at 1600
tokens. Usage is separate: `llm_usage.planner`, `enrichment`, `brief`, `total`.
Set `LLM_BRIEF_ENABLED=false` to disable synthesis without disabling enrichment.
`--no-llm` skips both and makes **zero** LLM requests.

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

## Run SAST

Windows, scanner-only:

```powershell
.\run.ps1 scan --mode sast --source-path /targets/sample-app --no-llm
```

Linux/macOS:

```bash
./run.sh scan --mode sast --source-path /targets/sample-app --no-llm
```

Controlled agent equivalents:

```powershell
.\run.ps1 agent --mode sast --source-path /targets/sample-app
```

```bash
./run.sh agent --mode sast --source-path /targets/sample-app
```

Only SAST is in scope. There is no scanner-order choice, so the Planner needs
zero completion calls; enrichment and the enabled AI brief still use the LLM.

## Run DAST

Windows, scanner-only:

```powershell
.\run.ps1 scan --mode dast --target-url http://juice-shop:3000 --no-llm
```

Linux/macOS:

```bash
./run.sh scan --mode dast --target-url http://juice-shop:3000 --no-llm
```

Controlled agent equivalents:

```powershell
.\run.ps1 agent --mode dast --target-url http://juice-shop:3000
```

```bash
./run.sh agent --mode dast --target-url http://juice-shop:3000
```

Only DAST is in scope. The agent cannot choose SAST, replace the target, alter
scanner arguments or add tools. Single-option stages are automatic, so Planner
completion count is zero; enrichment and the enabled brief still make API requests.

## Run FULL

Deterministic Windows:

```powershell
.\run.ps1 scan --mode full --target-url http://juice-shop:3000 --source-path /targets/sample-app --no-llm
```

Linux/macOS:

```bash
./run.sh scan --mode full --target-url http://juice-shop:3000 --source-path /targets/sample-app --no-llm
```

This runs **both Semgrep and Nuclei without an LLM Planner or any LLM calls**.
Omit `--no-llm` to enable finding enrichment and the optional AI brief while retaining fixed
Python scanner ordering. `deterministic` is an alias for `scan`.

Controlled agent Windows:

```powershell
.\run.ps1 agent --mode full --target-url http://juice-shop:3000 --source-path /targets/sample-app
```

Linux/macOS:

```bash
./run.sh agent --mode full --target-url http://juice-shop:3000 --source-path /targets/sample-app
```

Initially both scanner actions may be valid; Planner may select SAST or DAST
first. All later stages normally have only one allowed action, so the application
selects them automatically. A successful normal full agent flow uses **one**
Planner completion, plus separate enrichment and brief requests.

### Important: the educational FULL example has two different subjects

SAST analyzes `/targets/sample-app`, an intentionally vulnerable sample.
DAST analyzes the running OWASP Juice Shop. These findings do **not** all belong
to Juice Shop. Reports list SAST source and DAST target separately; the runtime
cannot prove that arbitrary source and URL inputs correspond to the same app.

For a true same-application scan, mount the source corresponding to your running
target read-only. For example, put a matching checkout at `targets/juice-shop`
(the Compose `./targets:/targets:ro` mount already exposes it), then use
`--source-path /targets/juice-shop` with the matching local Juice Shop deployment.
Do not mount your whole home directory or secrets. Rules are educational and
language-specific; matching source does not guarantee comprehensive coverage.

Wrappers provide default source and target when omitted and start the lab.
Specify `--mode` explicitly to avoid surprises: with both default inputs and
no mode, scope is full. Direct CLI use requires the relevant paths/URL.
Legacy `python -m app.main --mode ...` remains deterministic and writes to
root `logs/` and `reports/`; it retains the legacy enrichment contract. Use
`scan`/`agent` subcommands for isolated per-run artifacts, resilient enrichment
and the new AI brief.

## What is the agent?

The CLI supplies the scope; there is no conversation or interactive chat UI.
The internal loop observes a minimized AgentState (availability, stage statuses,
counts and allowed actions), not source files, URLs, raw logs or API keys.
Planner selects between multiple approved actions; the validator remains
authoritative. The fixed registry executes application-owned scanner commands,
returns results to the state, and permits enrichment/reporting only when their
preconditions hold. A future chat/UI could sit above this runtime.

Approved actions are RUN_SAST, RUN_DAST, ENRICH_FINDINGS, GENERATE_AI_BRIEF,
GENERATE_REPORT, FINISH.
The model has no arbitrary shell access, cannot invent tools, change command
lines, repeat completed/failed scanners or change scan targets.

Agent step limits count executed actions. Planner limits count actual completion
HTTP attempts, including failed requests; automatic transitions do not consume
that budget. Three consecutive rejected/unavailable planner decisions terminate
the run; a lower configured request budget terminates earlier. Planner transport
has no hidden retry loop. Enrichment may retry timeout/429/5xx at most twice.
Token counts come from provider usage when available, not local estimates.

## Where reports are stored

```text
runs/
  latest.json
  <run_id>/
    logs/
      raw_semgrep.json
      raw_nuclei.jsonl
    reports/
      findings.json
      summary.json
      report.md
      agent_trace.json
      ai_brief.json
```

| File | Contents |
| --- | --- |
| findings.json | Normalized machine-readable findings; no complete raw scanner records |
| summary.json | Status, finish reason, stage statuses, counts, LLM metadata/usage and safe error codes |
| report.md | Human-readable report, separate source/target and visible failure/partial status |
| agent_trace.json | Sequence of decisions/actions, decision sources and safe diagnostics |
| ai_brief.json | Validated structured brief, or a small failed/skipped/not_started status object |
| raw_semgrep.json | Raw Semgrep JSON, only when that scanner ran |
| raw_nuclei.jsonl | Raw Nuclei JSONL, only when that scanner ran |

Raw data stays in logs/. Findings refer to it rather than embedding it.
Treat scanner logs, findings and short rationale as sensitive local artifacts.
Application diagnostics are printed to the terminal (JSON logging); they are not
a raw HTTP dump. No provider reasoning/chain-of-thought is persisted.
`latest.json` points to the most recently **started** run, not necessarily the
most recently finished one during concurrent runs.

### Open latest reports — Windows

```powershell
.\run.ps1 latest
$latest = Get-Content .\runs\latest.json | ConvertFrom-Json
$run = ".\runs\$($latest.run_id)"
Get-ChildItem "$run\reports"
Get-Content "$run\reports\summary.json"
Get-Content "$run\reports\agent_trace.json"
Get-Content -Encoding UTF8 "$run\reports\ai_brief.json"
notepad "$run\reports\report.md"
explorer "$run\reports"
```

### Open latest reports — Linux/macOS

```bash
./run.sh latest
ls -1 runs/
# Copy the printed run ID into the following path:
cat runs/<run_id>/reports/summary.json
cat runs/<run_id>/reports/agent_trace.json
cat runs/<run_id>/reports/ai_brief.json
less runs/<run_id>/reports/report.md
```

Replace `<run_id>` before running these filesystem commands.
No jq or host Python is needed. `latest` prints run ID, status and paths,
without starting the lab or using an LLM. Container-relative `runs/` paths
correspond to the repository's host `runs/` mount.

## How to know whether a run succeeded

Check **summary.json**, not just the existence of report.md. For a successful
full run, `status=completed`, `finish_reason=completed`, SAST/DAST/report stages
are completed, enrichment is completed or skipped, and ai_brief is completed
or skipped. `llm_status=skipped` and `ai_brief_status=skipped`
in scanner-only runs is expected.

If enrichment or the brief fails, otherwise successful scanners/reporting yield
`status=completed_with_warnings`, `finish_reason=completed_with_warnings`, exit 0.
Check the enrichment counters/failures and ai_brief_status. A failed enrichment
stage can coexist with a completed brief summarizing scanner-only findings.
If a planner aborts, `status=failed` and finish_reason can be
`planner_rejections_exhausted` or `agent_limit_reached`; scanner stages may be
not_started. `outcome` mirrors the finish reason for convenient classification.
`last_error_code`, `last_error`, stages and trace show what completed.
Best-effort finalization can produce report.md even after failure; that file
does **not** prove a complete full scan.

Exit codes: 0 success, 2 invalid input/configuration, 3 scanner failure,
4 fatal agent LLM preflight failure, 5 planner failure/limit,
6 environment/report/precondition failure. Optional analysis warnings alone exit 0.
The first failure retains its exit code; inspect all stages for later failures.

### Reading the trace

A normal full run follows RUN_SAST → RUN_DAST → ENRICH_FINDINGS →
GENERATE_AI_BRIEF → GENERATE_REPORT → FINISH, or the reverse scanner order.
That is six executed actions and normally one Planner completion. All five
actions after the initial scanner choice use deterministic_single_option.

- `decision_source=llm_planner`: model selected between multiple permitted options.
- `decision_source=deterministic_single_option`: application selected the only
  valid action, spending no Planner request.
- `decision_source=deterministic`: fixed `scan` workflow, never Planner.
- Rejected decisions appear as separate trace entries; `agent_steps` counts
  executed actions, so trace length may be larger.

JSON output accepts plain objects, surrounding whitespace, one JSON fenced
block, or unambiguous plain prose around one object. Multiple objects, duplicate
keys, malformed JSON and forbidden schema fields are rejected. Schema checks
are not relaxed by extraction. Repair retries send a concise instruction, not
accumulated provider responses.

## Copy-paste verification checklist

The agent and explicit LLM-check commands below are manual opt-ins to your
configured provider; only execute them after configuring access.

Windows:

```powershell
.\scripts\bootstrap.ps1
.\scripts\doctor.ps1
.\scripts\doctor.ps1 --check-llm
.\run.ps1 scan --mode dast --no-llm
.\run.ps1 agent --mode dast --target-url http://juice-shop:3000
.\run.ps1 latest
$latest = Get-Content .\runs\latest.json | ConvertFrom-Json
Get-Content ".\runs\$($latest.run_id)\reports\summary.json"
Get-Content ".\runs\$($latest.run_id)\reports\agent_trace.json"
Get-Content -Encoding UTF8 ".\runs\$($latest.run_id)\reports\ai_brief.json"
.\run.ps1 agent --mode full --target-url http://juice-shop:3000 --source-path /targets/sample-app
.\run.ps1 latest
$latest = Get-Content .\runs\latest.json | ConvertFrom-Json
Get-Content ".\runs\$($latest.run_id)\reports\summary.json"
Get-Content ".\runs\$($latest.run_id)\reports\agent_trace.json"
Get-Content -Encoding UTF8 ".\runs\$($latest.run_id)\reports\ai_brief.json"
notepad ".\runs\$($latest.run_id)\reports\report.md"
```

Linux/macOS:

```bash
./scripts/bootstrap.sh
./scripts/doctor.sh
./scripts/doctor.sh --check-llm
./run.sh scan --mode dast --no-llm
./run.sh agent --mode dast --target-url http://juice-shop:3000
./run.sh latest
# Inspect the summary.json and agent_trace.json paths printed above.
./run.sh agent --mode full --target-url http://juice-shop:3000 --source-path /targets/sample-app
./run.sh latest
# Inspect the new summary, trace, ai_brief.json and report.md before judging success.
```

For automated offline development checks (Python 3.11+):

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
docker compose config --quiet
```

Tests mock all provider HTTP access and guard against real network connections.

## Expected educational baseline

The intentionally vulnerable sample has historically produced nine SAST findings.
The tested Juice Shop version produced around three low/info configuration
findings. These are not acceptance thresholds: exact results depend on source,
target version and rules. Juice Shop still uses the upstream `latest` tag,
so DAST counts can change. Passing tests is not a security certification.

## Troubleshooting

Start with doctor and see [full troubleshooting](docs/TROUBLESHOOTING.md).

| Symptom | First check |
| --- | --- |
| Docker daemon unavailable | Start Docker Desktop/service; run `docker info` |
| Compose unavailable | `docker compose version`; use Compose v2 |
| Juice Shop unhealthy | `docker compose ps -a juice-shop` and `docker compose logs --tail 80 juice-shop` |
| Port conflict | Free host port 3000 or change only the host-side mapping |
| Permission denied | Check Docker access and ownership of runs/logs/reports; no world-writable socket |
| Shell script CRLF | Fresh Git checkout honors .gitattributes; keep shell files LF and executable |
| Wrong architecture | Inspect image/engine architecture and rebuild for amd64 or arm64 |
| LLM 401/403 | Check credentials/access locally; never paste the key into diagnostics |
| Model ID not found | Check exact ID using opt-in doctor model discovery |
| Planner invalid response | Inspect trace error_code, summary last_error and terminal application logs |
| Enrichment validation failure | Inspect those same files; original scanner findings are preserved |
| Report exists but status failed | Check finish_reason and each stage, not merely file existence |

Planner errors distinguish HTTP, timeout, rate limiting, empty/truncated content,
JSON parsing, schema validation, unknown actions and actions not currently
allowed. Enrichment also distinguishes invalid category, identity mismatch and
missing/extra/duplicate batch IDs. Safe diagnostic messages omit model input
values and HTTP response bodies. Generic unexpected exceptions remain sanitized.

## Security model and limitations

Targets are limited to `localhost`, `127.0.0.1` and `juice-shop`; `0.0.0.0`
and arbitrary Internet scan targets are forbidden. Target/source validation is
authoritative and rechecked before dispatch. Source must be a permitted local
path, not a root/UNC/network path. The configured HTTPS LLM API is a separate,
explicit outbound connection, not a scan target.

Only registered tools run. Nuclei uses reviewed local low-impact HTTP templates,
without unrelated DNS/network templates, redirects, Interactsh or updates.
Semgrep uses local rules without cloud rules, autofix or source execution.
No exploit or destructive workflow is added.

LLM output is data, never shell commands or executable code. Strict schemas and
the registry prohibit model-provided tool arguments. Enrichment updates only
description, normalized category, severity and recommendation of existing
findings; identity, scanner category, location, evidence and count stay fixed.
Rationale is separate metadata. Evidence transmission is off by default; enable
`--include-evidence-in-llm` only after reviewing privacy implications.
Provider reasoning is ignored and API keys are not written to reports.
Prompts and the narrow CORS/Referrer-Policy regression guards are not proof of factual accuracy:
review enrichment prose before relying on it.

See [architecture](docs/ARCHITECTURE.md), [development](docs/DEVELOPMENT.md),
[rules and tools](docs/tools.md) and [validation record](docs/VALIDATION.md).
Optional `AGENT_IMAGE=ghcr.io/owner/repository:0.3.2` selects a published image;
otherwise bootstrap builds locally. Release publication needs repository
permissions and is not required for local usage.
