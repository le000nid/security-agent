# Development — 0.3.2

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
docker build -t ai-security-agent:0.3.2 .
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
