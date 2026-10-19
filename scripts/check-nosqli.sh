#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
export AGENT_UID="${AGENT_UID:-$(id -u)}"
export AGENT_GID="${AGENT_GID:-$(id -g)}"
mkdir -p runs logs reports

compose=(docker compose -f docker-compose.yml -f docker-compose.nosqli.yml
  --profile agent --profile nosqli-mongo --profile nosqli-tests)

"${compose[@]}" config --quiet
"${compose[@]}" build agent nosqli-mongo-api
"${compose[@]}" up -d --wait --wait-timeout 180 nosqli-mongo-api
"${compose[@]}" run --rm --no-deps nosqli-mongo-tests
"${compose[@]}" run --rm --no-deps --entrypoint python agent \
  -m benchmark.verify_nosqli --output runs/nosqli-http-acceptance.json
"${compose[@]}" run --rm --no-deps --entrypoint python agent \
  -m benchmark.verify_nosqli_templates
"${compose[@]}" run --rm --no-deps agent scan \
  --benchmark nosqli-mongo-full --mode full --no-llm
"${compose[@]}" run --rm --no-deps --entrypoint python agent \
  -m benchmark.verify_nosqli_run

printf '\nNoSQLi acceptance checks passed. The lab is available at http://localhost:3005\n'
