# Troubleshooting — 0.3.2

Start with `scripts/doctor.ps1` (PowerShell) or `scripts/doctor.sh` (Linux/macOS).
Diagnostic commands below never require printing `.env` or API credentials.
Use `docker compose config --quiet`; plain config output expands secrets.

| Symptom | Diagnosis and remedy |
| --- | --- |
| Docker command not found | Install Docker Desktop on Windows/macOS or Docker Engine on Linux; reopen the terminal. Bootstrap never installs Docker. |
| Daemon not running | Run `docker info`; start Docker Desktop or your system Docker service. |
| Windows Linux engine unavailable | Select Linux containers in Docker Desktop and wait until its engine is running. No host WSL/bash command is required by our scripts. |
| Compose missing | Check `docker compose version`; install/update the Compose plugin or Docker Desktop. The old `docker-compose` executable is not used. |
| PowerShell scripts blocked | For this terminal only, if permitted by your organization's policy: `Set-ExecutionPolicy -Scope Process Bypass`; rerun bootstrap. |
| Juice Shop unhealthy | `docker compose ps -a juice-shop`, `docker compose logs --tail 80 juice-shop`; healthcheck uses `/nodejs/bin/node`, not PATH lookup. Retry `docker compose up -d --wait --wait-timeout 180 juice-shop`. |
| Port 3000 already in use | Stop the other application/container, or change only the host side of the Compose port mapping. Container target stays `http://juice-shop:3000`. |
| Wrong architecture / exec format error | Inspect `docker image inspect ai-security-agent:0.3.2 --format '{{.Os}}/{{.Architecture}}'` and `docker info --format '{{.Architecture}}'`; rebuild for the host architecture. |
| Apple Silicon image issue | Use arm64 release/build; remove manual amd64 platform overrides. Check `docker buildx ls`. Both scanners must pass image build version checks. |
| CRLF shell failure | Restore LF line endings with Git `.gitattributes`; a fresh clone honors them. Shell scripts need executable permissions (`chmod +x run.sh scripts/*.sh`). |
| Bind mount permission denied | Linux wrappers use your UID/GID. Ensure your account owns `runs`, `logs`, `reports`; set AGENT_UID/AGENT_GID only if needed. Do not run scans as unrestricted root. Docker Desktop may require sharing the repository folder. |
| Reports directory unwritable | Check container doctor output and host directory permissions. New runs use `runs/<id>/reports`; legacy flags use `reports/`. Scanner logs already written remain available. |
| Cannot resolve juice-shop | Run through Compose on its project network, not bare `docker run`; check `docker compose ps`. |
| Cannot connect to juice-shop | Wait for health; `localhost` in the agent is the agent itself. Use `http://juice-shop:3000`. |
| .env missing | Bootstrap copies `.env.example` only when absent. Never paste credentials into logs or Git. |
| LLM variables missing | Set LLM_PROVIDER, LLM_BASE_URL, LLM_MODEL, LLM_API_KEY. Doctor reports names only. Scanner-only mode works without them. |
| LLM 401/403 | Correct the key or gateway permission. Optional `doctor --check-llm` performs only GET /models. |
| Model missing | Set the exact ID in `.env`; display names are not IDs. Discovery must return it in data[].id. |
| Endpoint wrong | Base must be HTTPS API root, e.g. `https://deepcode.ci.nsu.ru/api`; do not append `/models` or `/chat/completions`. |
| Nuclei missing | Rebuild image; host Nuclei installation is not required. |
| Semgrep failure | Inspect that run's raw JSON and source mount, then rebuild if version check fails. No remote registry or Semgrep login is required. |
| Planner stops after rejected decisions | Inspect agent_trace.json and summary finish_reason. Three consecutive invalid decisions terminate; scanners already completed are preserved. |
| Limit reached | Defaults: eight executed actions and eight actual Planner completion HTTP attempts. Single-option transitions use no Planner budget. Check trace for bounded retries before raising limits. |
| Planner format/schema failure | Inspect summary.json last_error_code and agent_trace.json error_code plus terminal JSON application logs. Plain/fenced JSON is supported; multiple objects and forbidden fields are rejected. Three consecutive rejections abort with best-effort reports. |
| Enrichment failure | Codes distinguish HTTP/timeout, empty/truncated response, JSON/schema, invalid_category, identity_mismatch and batch missing/extra/duplicate IDs. Original scanner findings remain in findings.json; no raw provider response is logged. |
| Report exists but full scan failed | Check summary status, finish_reason and all stages. report.md is also generated for partial runs. A completed_with_failures outcome is still status=failed and a nonzero exit. |
| GHCR pull fails | Package may be private/unpublished. Remove AGENT_IMAGE and bootstrap a local image. |

Doctor's default mode makes no LLM requests. `--check-llm` explicitly opts into
discovery only; do not use it in automated offline validation.

## Enrichment and brief warnings (v0.3.2)

- Use LLM_ENRICHMENT_BATCH_SIZE=1; bootstrap preserves existing .env, so an old
  value of 3 is not automatically replaced. Larger batches are experimental.
- A truncated enrichment gets one retry at LLM_ENRICHMENT_RETRY_MAX_TOKENS (2200
  by default, versus normal 1200). Persisting failure keeps that original finding
  and continues. summary.enrichment.failures lists safe IDs and codes.
- completed_with_warnings is not a scanner failure: successful changes remain,
  stage status shows partial enrichment, and ai_brief_status independently shows
  synthesis availability. Check both statuses even when process exit is 0.
- Brief truncation gets one retry (1000 → 1600 by default). Unknown/duplicate IDs
  or schema failures reject the brief without affecting scanner/enrichment results.
  ai_brief.json is then a small status object; report.md still exists.
- Budget values must be 256–8192 and retry budgets strictly larger than normal.
  Invalid tone/language settings are rejected; use professional/concise/funny and
  ru/en. Tone affects the brief only. LLM_BRIEF_ENABLED=false disables synthesis.
- In Windows PowerShell use Get-Content -Encoding UTF8 for Russian ai_brief.json.
  Reports themselves are UTF-8. Do not print .env or unredacted provider bodies.
