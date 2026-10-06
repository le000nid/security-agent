# Development — 0.4.1

Normal users need only Docker. For native development use Python 3.11+:

```text
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
```

`app/main.py` is the legacy entry point/dispatcher; `cli.py` implements new
commands. `config.py`, `runs.py`, `safe_logging.py`, and `doctor.py` contain
runtime infrastructure. `agent/` contains strict models, planner projection,
validator, registry, loop and run reporting. Existing parser/scanner modules
remain at their old import paths. `llm.py` supplies shared transport and the
separate finding enrichment schema. `config/` holds reviewed checks; `targets/`
and `benchmark/` hold educational fixtures. No host scanner installation is
required by unit tests.

To add an AgentTool: first add an enum value and a deterministic validator
precondition. Implement a fixed operation returning ToolResult, register it in
ToolRegistry and map its status transition. Add successful, rejected, duplicate
and failed-action tests. Never introduce model-supplied command arguments.

To add a Semgrep rule: edit `config/semgrep.yaml`, assign stable ID/category/
confidence/recommendation, add vulnerable and benign fixtures, and update
`benchmark/expected_findings.json`. To add a Nuclei check: add a reviewed,
low-impact HTTP GET template under `config/nuclei/`; avoid callbacks, redirects,
payload execution and external hosts. Test parser behavior with small local
JSON/JSONL fixtures rather than scanner-specific objects in downstream reports.

Agent tests inject planner responses and scanner functions. HTTP tests replace
the compatible client transport. `tests/conftest.py` forbids real socket
connections; never add NSU keys to CI. Cross-platform CI runs tests on Windows,
Linux and macOS, plus Linux multi-architecture builds and a no-LLM lab smoke run.

```text
docker compose config --quiet
docker build -t ai-security-agent:0.4.1 .
docker buildx build --platform linux/amd64,linux/arm64 --output type=cacheonly .
```

Use a docker-container Buildx builder if your Docker installation cannot build
multiple platforms with its default driver. QEMU is needed for foreign-arch
Python install/version-check steps. Nuclei cross-compilation runs on the native
build platform. GHCR release workflow is prepared for `v*` tags; no push is
performed by local bootstrap.

Shell scripts must be executable in Git and use LF (`.gitattributes`). Test
PowerShell scripts with Windows PowerShell 5.1-compatible syntax; do not use
PowerShell-only constructs in bash or GNU-only host flags on macOS.

The v0.3.2 `enrichment.py` isolates errors without changing Finding identity.
`brief.py` owns the strict read-only synthesis contract and minimized input.
Add tests to `test_brief_and_enrichment.py` using mocked compatible HTTP responses;
never use a real provider key or enable doctor --check-llm in automated checks.

## Add a benchmark (no Chat prompt edits)

See the complete worked [benchmark extension guide](BENCHMARKS.md), including
Russian metadata, capability restrictions, Compose health and no-LLM validation.

1. Add reviewed source/runtime fixtures under `targets/<id>`. Unsafe examples
   must never execute on startup or HTTP requests. Keep benign controls too.
2. Add a strict entry to `config/benchmarks.yaml`: lowercase ID, capabilities,
   `/targets/...` source for SAST, local service URL for DAST, optional baseline.
   Runtime source validation rejects missing or escaping paths. Registry config
   is trusted code-review input, never user/LLM-editable HTTP data.
3. For DAST add a non-root Compose service, loopback-only host publishing and a
   deterministic healthcheck. Never mount the Docker socket. Update host startup
   helpers to start the service. Register only a service you own in this lab.
4. Add `config/expected/<id>.json` when stable controlled expectations exist;
   keys are tool/title/source/category. Keep the historical nine-finding
   `benchmark/expected_findings.json` sample baseline in sync with its registry
   copy. Do not label these metrics real-world security accuracy.
5. Add registry/default-mode/rejection/service/UI tests. UI selections and Chat
   metadata are generated from the registry; no manually hardcoded prompt list.
6. Rebuild, run doctor, opt-in `doctor --check-benchmarks`, then a no-LLM smoke.
   Verify same-application claims only for deliberately corresponding fixtures.

## UI and test seams

`create_app(service=..., runs_dir=..., llm=...)` supports injected dependencies.
Use ASGI TestClient with base URL `http://localhost` so the Host boundary stays
enabled. Obtain the CSRF token from `/` and submit `X-CSRF-Token` for every POST.
Production errors never expose Pydantic input values or exception tracebacks.
Never add a provider check merely to load a page. Windows asyncio creates a
stdlib loopback socketpair internally; the test network guard permits exactly
that call site, not arbitrary localhost or external connections.

The UI server uses one process/worker: multiple Uvicorn workers would create
independent locks and CSRF tokens, and are unsupported. Job snapshots are copies;
events are bounded; reports are the only persistent record. Test concurrency
with events/barriers, not real scans or provider requests.

## Clean release archive

Review and commit changes first, then run `scripts/package.ps1` or
`scripts/package.sh`. Both require committed HEAD version 0.4.1 and no tracked
diff, check secret-like tracked filenames, and call git archive. `.gitattributes`
excludes runtime/caches/secrets/ZIPs; untracked files are not archived. Scripts
refuse to overwrite an existing output. The workflow does not detect credentials
embedded in ordinary source files: review content before committing. Local build
does not authorize a commit, push, GitHub release or image publication.
## v0.4.1 regression seams

Use `test_v041_reliability.py` for budget, trace, usage, brief preservation and
actual-outcome banner tests. Use `test_v041_chat.py` for selected context, strict
analyst references, no artifact mutation/scanner execution, connectivity
classification and one-use confirmation/CSRF/expiry tests. Mock HTTP envelopes,
not only final prose, when testing transport truncation/accounting. No live
provider discovery or completion belongs in CI. Preserve existing .env overrides.

`test_chat_recovery.py` covers two-attempt analyst recovery, bounded partial JSON,
character/point overflow, role isolation, read-only follow-ups and metadata
contradictions. `tests/chat_ui.cjs` executes the production renderer/handlers in
a minimal DOM using Node (no npm dependencies); pytest invokes it when Node is
available, and CI installs Node explicitly. It checks text-only rendering, the
truncation banner, structured blocks and all five follow-up actions. This is a
DOM contract test, not a visual browser or live-provider acceptance test.

Russian labels are presentation only. Internal enums/API names stay English;
registry descriptions drive benchmark cards. Use textContent, not HTML injection.
Chat output is never passed to ToolRegistry or a subprocess. Rebuild the shared
agent/UI image after Python or UI asset changes; the UI is packaged into the wheel.
