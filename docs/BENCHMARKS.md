# Extending the reviewed benchmark registry — v0.4.1

This is a developer guide, not a request to add more benchmarks to v0.4.1.
The shipped set remains sample-sast, juice-shop and demo-full. Adding a benchmark
is a code-reviewed change to trusted local configuration, never a Chat operation.
No prompt or JavaScript ID list needs editing.

## Worked example: a second same-project FULL fixture

The example below uses `example-lab` as a placeholder for a future reviewed
fixture. Do not assume arbitrary source matches a running target.

1. **Create the fixture folder.** Add `targets/example-lab/`. For a minimal
   same-project example, copy the reviewed `server.py`, `training_patterns.py`
   and Dockerfile structure from `targets/demo-full/`, then review every file.
   Keep the HTTP server's response constant and never import/execute unsafe
   training functions. Preserve benign controls when extending SAST examples.
   Do not clone/download arbitrary repositories from user or model input.

2. **Choose capabilities.** Use `[sast]` for source only, `[dast]` for HTTP only,
   or `[sast, dast]` only when the source and running service are the same project.
   SAST requires `source_path`; DAST requires `target_url`. FULL is available only
   for both. The default mode derives from these capabilities. Juice Shop remains
   DAST-only because matching source is not bundled.

3. **Add one registry entry** to `config/benchmarks.yaml`:

   ```yaml
   - id: example-lab
     name: Example Lab
     description: Reviewed same-project source and constant HTTP training service.
     description_ru: Учебный проект с исходниками и постоянным HTTP-ответом; доступны SAST и DAST.
     capabilities: [sast, dast]
     source_path: /targets/example-lab
     target_url: http://example-lab:3000
     docker_service: example-lab
     expected_findings: example-lab.json
     tags: [educational, same-application, curated]
     enabled: true
   ```

   IDs are lowercase letters/digits/hyphens. Source stays under `/targets/`;
   path traversal, UNC paths and external target domains are forbidden. Service
   names must be single labels. `description` stays English for developers;
   `description_ru` supplies Russian UI copy. If omitted, UI falls back to the
   English description; add Russian text before shipping. Baseline count is
   derived from the expected-findings file, not manually repeated in JavaScript.

4. **Add the local Compose service** for DAST/FULL. The following assumes the
   copied Dockerfile/server bind internally to port 3000 and expose `/healthz`:

   ```yaml
   example-lab:
     build: ./targets/example-lab
     image: ai-security-example-lab:0.4.1
     user: "1000:1000"
     read_only: true
     security_opt: ["no-new-privileges:true"]
     cap_drop: [ALL]
     ports: ["127.0.0.1:3002:3000"]
     volumes: ["./targets/example-lab:/lab:ro"]
     healthcheck:
       test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3000/healthz', timeout=2)"]
       interval: 5s
       timeout: 3s
       retries: 15
   ```

   Choose an unused host port and publish loopback only. The agent uses the
   service name/container port, not the host port. Never mount the Docker socket.
   Update the reviewed startup helpers (`scripts/common.ps1` / `common.sh`) if
   this service should start with bootstrap/UI; browser code must not run Docker.

5. **Keep rules local and low-impact.** Existing Semgrep rules and reviewed
   Nuclei HTTP GET templates suffice for the copied fixture. Do not enable broad
   network/DNS template discovery, callbacks, external updates, autofix, payload
   execution or destructive requests. See [tools.md](tools.md).

6. **Create a baseline only if expectations are stable.** For an unchanged copy
   of Demo Full, review and copy `config/expected/demo-full.json` to
   `config/expected/example-lab.json`. Its seven entries use exact
   `tool`, `title`, `source` and scanner `category`, for example:

   ```json
   {"tool":"semgrep","title":"python-debug-enabled","source":"SAST","category":"configuration"}
   ```

   Confirm the exact rule title/category in actual normalized output before
   committing expectations. Do not fabricate a baseline to hide missing findings.
   If the fixture differs, enumerate its reviewed indicators and benign controls.
   If no meaningful stable baseline exists, omit `expected_findings` entirely.
   Curated precision/recall does not measure real-world security accuracy.

7. **Add tests.** Cover registry validation, default/unsupported modes, source
   containment, safe service hosts, Russian metadata and expected baseline count.
   Cover RunService for each supported scope and no-LLM operation. Verify the UI
   and Chat automatically list the entry without per-ID translations or prompt
   edits. Keep provider HTTP and scanners mocked in unit tests; real local smoke
   is separate. Update hardcoded test inventories deliberately, not blanket snapshots.

8. **Run checks and rebuild.** From the checkout:

   ```text
   python -m pytest -q
   python -m ruff check .
   python -m ruff format --check .
   docker compose config --quiet
   docker compose --profile agent build agent example-lab
   docker compose up -d --wait example-lab
   ```

   Never print expanded Compose secrets. The shared agent/UI image packages the
   registry; rebuild/recreate UI after changing it. Existing targets mount
   read-only; the new source folder appears under `/targets/example-lab`.

9. **Check doctor without an LLM.** On Windows:

   ```powershell
   .\run.ps1 benchmarks show example-lab
   .\scripts\doctor.ps1
   .\scripts\doctor.ps1 --check-benchmarks
   ```

   Linux/macOS use `./run.sh` and `./scripts/doctor.sh`. Default doctor inspects
   tools, rules, writable directories and sources. `--check-benchmarks` explicitly
   probes only registered local HTTP targets. Do not add `--check-llm` here.

10. **Run a scanner-only smoke.** With the service healthy:

    ```powershell
    .\run.ps1 scan --benchmark example-lab --mode full --no-llm
    .\run.ps1 latest
    ```

    Inspect the exact run's findings, stages and baseline in summary.json. An
    unchanged copy of Demo Full should yield four SAST + three DAST indicators;
    confirm, do not assume. All LLM request/token counters must be zero and
    enrichment/brief skipped. Do not use `benchmark.verify_run` unchanged for this
    new ID: that command intentionally verifies the shipped demo-full contract.

11. **Verify UI and document coverage.** Recreate UI with `run.ps1 ui` / `run.sh ui`.
    Check the new card's Russian purpose, source/HTTP availability, capability
    choices and baseline count. Verify unsupported modes cannot launch. Use
    «Обсудить этот запуск» for saved results; Chat may propose only registered
    scopes and still requires explicit confirmation. Record real smoke results
    and limitations, not a claim that the fixture/application is secure.

See [DEVELOPMENT.md](DEVELOPMENT.md), [ARCHITECTURE.md](ARCHITECTURE.md) and
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) for the surrounding contracts.
