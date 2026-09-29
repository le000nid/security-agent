# v0.3.2 reliability and AI brief validation

Validated on 2026-09-28 with no real DeepSeek/NSU model discovery or completion.
All provider responses are mocked; tests prohibit real socket connections.

| Check | Result |
| --- | --- |
| Windows / Python 3.12 pytest | 288 passed |
| Linux / Python 3.11 pytest | 288 passed |
| Ruff check | Passed on Windows and Linux |
| Ruff format --check | Passed, 49 Python files |
| Compose config --quiet | Passed, no expanded secrets printed |
| Docker image | ai-security-agent:0.3.2 built, linux/amd64 |
| Final scanner-only FULL smoke | 9 SAST + 3 DAST, status completed |
| No-LLM usage | Zero planner, enrichment and brief requests/tokens |
| AI brief on no-LLM smoke | skipped; ai_brief.json contains a status object |
| latest wrapper | Passed, including AI brief path |

Final smoke: `runs/20260928T140821Z-79b55196d086/`. Juice Shop remained healthy.
Scanners used unchanged local rules/templates. The upstream Semgrep
pkg_resources deprecation warning does not prevent the build or scan.

## Reliability changes

The previous runtime treated enrichment as an all-or-nothing operation: a single
exception prevented committing any earlier successes. The new enrich_independently
path commits each validated finding independently, retaining the original object
for failed units and continuing. Experimental batches remain atomic per batch.
Default batch size is 1 in Settings, Compose, .env.example and documentation.
Existing user .env is intentionally preserved and may need a manual setting update.

Truncation gets one content retry with a larger bounded max_tokens budget:
enrichment 1200 → 2200, brief 1000 → 1600. All configured budgets are 256–8192
and retry budgets must exceed normal budgets. The existing compatible max_tokens
request field is retained. Non-truncation schema/content failures are isolated,
not relaxed. Transport retries remain separately bounded and counted.

EnrichmentStats records requested/completed/failed/retried and safe ID/error-code
failures. Optional analysis problems yield completed_with_warnings and exit 0
if scanners/reporting otherwise succeed. Scanner, Planner and report failures
remain fatal. No additional per-finding Agent actions are created.

## Brief architecture and artifacts

GENERATE_AI_BRIEF is the sixth fixed action, between enrichment and reporting.
Its validator accepts only terminal scanner/enrichment stages. Normal FULL still
needs one Planner request; later transitions are deterministic_single_option.
Brief input is a compact explicit projection without locations, target/source,
raw logs, evidence or environment. Known secrets are redacted before truncating
text. Strict AIBrief validates bounded text/lists and exact unique existing IDs.
The stage cannot create/modify findings or invoke tools.

Tone is a professional/concise/funny enum; language is ru/en (default ru).
These instructions are used only for synthesis, never technical enrichment.
The brief appears near the report top, as ai_brief.json and as a short console
headline/summary. Failed/skipped briefs get a small status object. Separate
planner/enrichment/brief usage and total are reported. No-LLM skips all analysis.

## Tests and files

New tests cover isolated successes/failures, one truncation retry with larger
budget, 12 findings with 11 enriched and one preserved, atomic batch isolation,
all tones/languages, strict IDs/schema, warning semantics, brief retry/failure,
no-LLM, zero findings, validator ordering, console/report rendering, provider
reasoning omission, API-key echoes and redaction-before-truncation. Referrer-Policy
prompt/regression checks reject the tested overclaim; existing CORS checks remain.

Added app/enrichment.py, app/brief.py and tests/test_brief_and_enrichment.py.
Updated settings/LLM transport, agent models/validator/registry/loop/planner/reporting,
CLI/latest, safe logging, Compose defaults, version metadata/CI tag, README and
supporting docs. Existing regression tests were updated for the sixth action,
new budgets and optional warning outcomes. No scanner command/rule/allowlist
expansion, arbitrary subprocess interface, interactive chat, commit or push.

Limitations: live gateway output remains untested; schema and narrow semantic
guards cannot prove prose accuracy. Humor/language are prompt instructions, not
a factual verifier. Experimental batch failures preserve the whole batch.
The legacy flag-only CLI/helper APIs retain their previous enrichment contract;
use scan/agent for v0.3.2 features. macOS/arm64 were not rerun for this patch.
Original user settings, archives and historical runs were preserved.

## Historical v0.3.1 stabilization validation

Validated on 2026-09-28. No real DeepSeek/NSU discovery or completion was made.
Provider HTTP responses were mocked; unit tests prohibit real socket connections.

| Check | Result |
| --- | --- |
| Windows / Python 3.12 full suite | 241 passed |
| Linux container / Python 3.11 full suite | 241 passed |
| Ruff check | Passed on Windows and Linux |
| Ruff format --check | Passed, 46 Python files |
| Compose config --quiet | Passed without printing resolved secrets |
| Docker image build | Passed, ai-security-agent:0.3.1, linux/amd64 |
| PowerShell bootstrap / doctor | Passed; doctor used no --check-llm |
| PowerShell latest | Passed; prints local report, summary and trace paths |
| Juice Shop | Healthy, host loopback port 3000 |
| Final deterministic full smoke | 9 SAST + 3 DAST = 12 findings, status completed |
| Smoke LLM usage | Zero Planner/enrichment requests and tokens |
| Updated wrapper syntax / git diff --check | Passed |

Final bootstrap smoke: `runs/20260928T105657Z-3fcda84ce255/`.
All requested stages completed, enrichment was skipped, finish_reason=completed.
The report explicitly separates sample-app SAST from Juice Shop DAST.
Docker build and doctor emit an upstream Semgrep pkg_resources deprecation
warning; scanner version checks and execution still pass.

## Causes and changes

Confirmed code-level causes: Planner was called even with one allowed action;
its request limit also blocked automatic progress; direct model_validate_json
rejected fenced/prose-wrapped objects; broad exception handlers discarded
specific planner/enrichment failures. Prior real-run logs cannot establish which
provider response shape or transport error actually caused those failures.

The existing state/validator/registry architecture is preserved. The new shared
llm_output module conservatively extracts exactly one JSON object, rejects
multiple objects/duplicate keys and applies the original strict Pydantic schemas.
Safe fixed codes cover HTTP, timeout, rate limit, empty/truncated content,
JSON/schema errors, unknown/disallowed actions, invalid normalized category and
batch/identity violations. No raw provider bodies, validation values or reasoning
are persisted. Scanner findings survive LLM failures.

Planner now runs only for multiple choices, with bounded repair retries and no
hidden transport retry loop. Actual attempted completion requests are counted;
automatic transitions consume neither Planner calls nor tokens. Normal full
agent tests in either scanner order require one Planner completion. DAST-only
regression reproduces three scanner findings followed by enrichment failure and
still finishes reporting with zero Planner completions.

Trace adds decision_source/error_code; summary adds last_error_code, outcome and
failure counts. Existing status=failed compatibility is retained while the finish
reason distinguishes completed_with_failures from aborted runs. Markdown reports
show FAILED / PARTIAL prominently and list separate SAST source/DAST target.
README is now an operational guide, including platform setup, commands, scope
warnings, latest-report inspection, diagnostics and the non-chat agent model.

## Files touched by this patch

- Added `app/llm_output.py` and `tests/test_stabilization.py`.
- Updated `app/llm.py`; `app/agent/{models,planner,loop,tools,reporting}.py`.
- Updated `app/{cli,main,runs,__init__}.py`, `run.ps1`, `run.sh` for latest/version.
- Updated `tests/test_agent.py`, `tests/test_llm_openai_compatible.py`,
  `tests/test_report.py`, `tests/test_rules_and_benchmark.py`.
- Updated `pyproject.toml`, `docker-compose.yml`, `.env.example`,
  `.github/workflows/ci.yml` for consistent version/default documentation.
- Rewrote `README.md`; updated architecture, development, troubleshooting and
  validation documents. Scanner commands, local rules, templates and target
  allowlist were not expanded; no exploit or generic shell execution was added.

Tests cover real-compatible response envelopes, ignored provider reasoning,
plain/fenced/whitespace/prose JSON, malformed and ambiguous JSON, schema/enum
errors, safe diagnostics, actual attempt accounting, single/multiple/zero
choices, bounded retries and recovery, both scanner orders, enrichment/batch
failures and identity preservation, separate report scopes and read-only latest.

Limits: live gateway behavior still requires the user's manual validation.
Native macOS/Apple Silicon and the arm64 build were not rerun for this patch;
the earlier multi-architecture validation is recorded below. CI is configured
but was not remotely executed or published. Provider token counts can be absent
on failed requests. Semantic accuracy of enrichment prose still needs review.
The educational full example deliberately combines two different applications.

Existing unrelated work, `.env`, historical runs and README.zip were preserved.
No commit or push was made.

## Historical v0.3.0 validation record

Validation on 2026-09-27 used Windows PowerShell, Docker Desktop's Linux engine,
and the project's bundled Python runtime. No real NSU discovery or completion
was performed. Unit tests forbid real socket connections.

| Check | Result |
| --- | --- |
| Windows Python unit tests | 188 passed |
| Linux container / Python 3.11 unit tests | 188 passed |
| Ruff check | Passed |
| Ruff format --check | Passed, 43 Python files |
| Compose config (default and agent profile) | Passed |
| Docker amd64 image build | Passed, ai-security-agent:0.3.0 |
| Final Buildx linux/amd64 + linux/arm64 build | Passed, cache-only, no push |
| arm64 Semgrep/Nuclei version execution | Passed under emulation during build |
| PowerShell bootstrap | Passed; existing .env preserved |
| PowerShell doctor | Passed; no LLM request |
| PowerShell run wrapper | Passed, full scanner-only scan |
| Juice Shop health | Healthy using /nodejs/bin/node |
| Full lab smoke | 9 SAST + 3 DAST = 12 findings |
| Offline real-scanner smoke | Passed with --network none |
| Curated Semgrep benchmark | All expected fixtures detected, no unexpected findings |
| Shell / PowerShell syntax | Passed |
| Shell executable flags in Git | 100755 |

The final lab run wrote `runs/20260927T112822Z-2bf7a7d447e7/`: counts were
high=1, medium=8, low=1, info=2. Planner and enrichment token usage were both
zero. Raw results, findings, summary, Markdown and trace were preserved per run.

The first console-entry-point smoke exposed missing installed rule resources;
this was fixed by packaging curated rules/templates in the wheel under
`share/ai-security-agent/config`. A repeated real scan validated the installed
resource paths. Regression tests also cover a source disappearing between
validation and dispatch, so prior findings still receive a final report.

Cross-platform CI is configured for native Python 3.11 on Windows, Linux and
macOS. Native macOS execution and GHCR publishing were not performed here.
The full real-scanner lab smoke ran on amd64; arm64 was build/version validated,
not subjected to a full lab scan on physical Apple Silicon hardware.
The release workflow is prepared but unexecuted. Real planner behavior against
the NSU model remains intentionally untested; the complete agent cycle is tested
with mocked planner/HTTP responses, including error paths and privacy checks.

## File inventory

Added:

- `app/agent/__init__.py`, `models.py`, `planner.py`, `validator.py`, `tools.py`,
  `loop.py`, `reporting.py`: explicit controlled state machine.
- `app/cli.py`, `config.py`, `runs.py`, `resources.py`, `safe_logging.py`,
  `doctor.py`: CLI, configuration, isolation, packaged rules and diagnostics.
- `run.ps1`, `run.sh`, `scripts/common.ps1`, `scripts/common.sh`,
  `scripts/bootstrap.ps1`, `scripts/bootstrap.sh`, `scripts/doctor.ps1`,
  `scripts/doctor.sh`: portable entry points.
- `.gitattributes`, `.github/workflows/release.yml`.
- `tests/test_agent.py`, `tests/conftest.py`.
- `docs/ARCHITECTURE.md`, `docs/DEVELOPMENT.md`, `docs/TROUBLESHOOTING.md`,
  `docs/VALIDATION.md`.

Important changes: `app/llm.py` (shared transport, distinct role usage, batching),
`app/main.py` (compatible dispatch), `app/nuclei.py` and `app/semgrep.py` (installed
resources), `app/report.py` and `app/__init__.py` (version), `Dockerfile`,
`docker-compose.yml`, `pyproject.toml`, `.env.example`, `.gitignore`,
`.dockerignore`, `.github/workflows/ci.yml`, `README.md`, and existing LLM/report/
Compose regression tests. Scanner rules and templates themselves are unchanged.

Only the new `.sh` scripts were staged to persist Git executable mode 100755;
no commit or push was made. Generated runs remain ignored.

Known limits: legacy flag-only CLI retains shared compatibility output paths;
use new subcommands for concurrent runs. Dependency versions are pinned for the
main tools/base images, not every transitive Python package. Juice Shop retains
its existing latest tag. The CORS guard is narrow, not a general semantic verifier.
