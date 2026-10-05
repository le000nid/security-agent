# v0.4.1 LLM reliability diagnosis

Focused diagnostic patch, not a new architecture or version. No live DeepSeek
discovery/completion was performed during implementation.

## Evidence

Running UI budgets were Brief **2000/3200**, Chat Analyst **2400/3600**. SHA-256
hashes of chat.py, chat_analysis.py, llm.py and ui/static/app.js matched the
workspace. Compose forwards these settings through its shared service definition.
No 1000/1600 Brief defaults remain in the active path. Settings → RunService →
ToolRegistry → generate_ai_brief passes budgets directly to complete_json.

Existing reports were inspected without reading provider bodies or secrets:

| Run | Brief error | Requests | Completion tokens | Findings / enrichment |
| --- | --- | --- | --- | --- |
| 20261005T103311Z-df0a57b43bd4 | brief_response_truncated | 2 | 2600 | 7 / 7 |
| 20261005T103621Z-f655e35ed899 | brief_schema_validation_error | 2 | 4035 | 7 / 7 |
| 20261005T114059Z-9d5423a7ea79 | brief_response_truncated | 2 | 5200 | 7 / 7 |

The last run exhausted 2000+3200. The client classifies truncation only from
choices[0].finish_reason=length, not token/character counts or reasoning presence.
Stop plus high usage is not length. Content comes only from message.content;
reasoning/reasoning_content and tool calls never become an answer. Without saved
response envelopes we cannot establish whether the provider spent its budget on
reasoning, final text, or another mechanism. No provider-specific cause is asserted.

## Brief failure path and bounded fix

Previously only truncation was retried. A completed response failing strict
length/type/extra-field/ID validation immediately failed the stage, including after
a truncation retry. The schema was already small: six fields, three references,
four steps. There was no repair or retained field diagnostic; retry used a generic
instruction without concrete tighter per-field targets. The specific invalid
field in the historical 4035-token run is unrecoverable: it was never recorded.

The prompt now aims below schema maxima. Strict Pydantic and exact-ID checks remain.

1. Normal generation: 2000 tokens by default.
2. On length: one concise retry at 3200, original input, shorter fields, no
   metaphors/preamble. A second length stops.
3. On completed invalid JSON/schema/IDs: one terminal fresh schema repair at 3200,
   original input plus safe field/type errors. No raw failed output is sent back.
   Repair failure, including length, stops.

Maximum **three logical attempts**. Normal → repair takes two; normal → length →
length takes two. Existing timeout/429/5xx transport retries stay bounded to two
per logical request (conservative bound nine HTTP attempts). Actual HTTP requests
and tokens are tracked separately in llm_usage.brief. No attempt changes findings,
scan target, scanner flags, Planner decisions or tools.

The extractor already accepted plain prose around one JSON object and a sole
fenced object. It rejected prose around a fenced object. Brief now accepts that
single unambiguous form. Multiple objects/fences, duplicate keys, nested salvage
from broken JSON, or brace/bracket-containing outer prose remain rejected.

Safe diagnostics survive success/failure in
`runs/<id>/reports/summary.json → llm_components.brief.attempts` and the UI's
**Безопасная диагностика AI Brief**. Records contain attempt kind, budget, safe
error code, finish_reason, content_chars, reasoning_present and up to ten
`{field,type}` issues. Unknown names become `<unknown>`. Values, validator messages,
ctx, raw JSON, reasoning and keys are excluded. ai_brief.json still contains a
validated brief or only status. A failed brief yields completed_with_warnings
without losing scanner findings, enrichment or reports.

## Chat recovery bypass

Analyst already retained partial content; the deployed files matched. A wide
question outside the exact shortcuts first entered Intent Parser (role=chat,
max_tokens=600). The transport preserves length content only for chat_analysis.
For chat it raised LLMError; ChatLLM mapped it to chat_response_truncated; interpret
propagated the API error. The UI displayed its fixed placeholder and never called
chatReply with analysis. The discarded text was incomplete *classification JSON*,
not an analytical answer, and Analyst was never invoked.

This is reproduced with mocked HTTP envelopes through the real API. Historical
chat envelopes were not saved, so this cannot be proved the sole cause of the
earlier incident. Current hashes do not support stale deployment; the code-path
bypass is confirmed.

Parser content failures now fall back only to read-only Analyst when a valid saved
run exists. Partial intent never becomes START_SCAN. Without a run, the safe error
remains. Transport failures still change health; content failures do not. Analyst
truncation returns HTTP 200, useful partial text, completed_with_warnings,
chat_response_truncated and five fixed follow_up_actions. No scanner rerun.

Context separates scanner_observation, model_interpretation,
manual_validation_required and exploit_validation_performed=false. Enrichment is
not exploitation validation. Narrow guards cover the reported pickle claim,
HIGH/«критичный», and «Обогащение и проверка эксплуатации не выполнялись» examples;
stored severity/status are displayed independently. These are not a general
semantic validator for every possible paraphrase.

## Windows rebuild and manual live test

Use PowerShell from the project root. Credentials stay in local .env. Wait for
active UI scans/chat before recreating the service. Building the shared image
does not recreate existing containers. run.ps1 ui uses Compose up without --build;
after code changes use the explicit build below. Normal caching remains enabled.

```powershell
Set-Location 'C:\Users\le000nid\Documents\secur_agent\security-agent'
docker compose config --quiet
docker compose --profile ui build ui
docker compose up -d --wait --wait-timeout 180 juice-shop demo-full
docker compose --profile ui up -d --no-deps --force-recreate --wait --wait-timeout 180 ui
```

These next commands intentionally contact the real configured provider; they are
for the user and were **not executed** during automated verification:

```powershell
docker compose --profile agent run --rm --no-deps agent doctor --check-llm
docker compose --profile agent run --rm --no-deps agent agent --benchmark demo-full --mode full
```

Inspect only safe diagnostic fields:

```powershell
$runPointer = Get-Content -Raw -Encoding UTF8 '.\runs\latest.json' | ConvertFrom-Json
$runSummary = Get-Content -Raw -Encoding UTF8 (Join-Path '.\runs' ($runPointer.run_id + '\reports\summary.json')) | ConvertFrom-Json
$runSummary.llm_components.brief | ConvertTo-Json -Depth 8
$runSummary.llm_usage.brief | ConvertTo-Json
$runSummary.enrichment | Select-Object requested, completed, failed
```

Reload http://127.0.0.1:8080/ for a fresh CSRF token, check LLM connectivity,
select that exact run, clear the selected finding, and ask the wide
facts-versus-assumptions question. Expect compact blocks or a partial warning
with five follow-up buttons. Provider failure after all bounded attempts is still
possible; inspect safe diagnostics rather than claiming success.

Offline smoke, making zero provider calls:

```powershell
docker compose --profile agent run --rm --no-deps agent scan --benchmark demo-full --mode full --no-llm
docker compose --profile agent run --rm --no-deps --entrypoint python agent -m benchmark.verify_run
```

## Files in this patch

- app/brief.py, app/llm.py, app/llm_output.py: tighter prompts, bounded repair,
  safe schema/envelope diagnostics and unambiguous Brief JSON extraction.
- app/agent/models.py, app/agent/reporting.py: bounded attempt metadata and summary.
- app/chat.py, app/chat_analysis.py: parser fallback, provenance and claim guards,
  explicit fixed follow-up actions.
- app/ui/static/app.js: Brief diagnostics, factual status, parser-specific error.
- tests/test_llm_reliability_patch.py and tests/test_brief_and_enrichment.py:
  new regressions and updated expectations for the single repair attempt.
- README.md, docs/ARCHITECTURE.md, docs/TROUBLESHOOTING.md,
  docs/LLM_RELIABILITY.md, docs/VALIDATION.md: diagnosis and operational guidance.

Pre-existing uncommitted changes from earlier v0.4.1 work are preserved. No commit,
push, new scanner/benchmark, shell interface or security-policy change.
