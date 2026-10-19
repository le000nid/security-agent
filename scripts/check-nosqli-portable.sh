#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
export AGENT_UID="${AGENT_UID:-$(id -u)}"
export AGENT_GID="${AGENT_GID:-$(id -g)}"
mkdir -p runs logs reports

compose=(docker compose -f docker-compose.yml -f docker-compose.nosqli.yml
  --profile agent --profile nosqli-mongo --profile nosqli-tests --profile nosqli-portable)

"${compose[@]}" config --quiet
"${compose[@]}" build agent nosqli-mongo-api
"${compose[@]}" up -d --wait --wait-timeout 180 nosqli-mongo-api nosqli-portable-api
"${compose[@]}" run --rm --no-deps nosqli-mongo-tests

for benchmark in nosqli-profile-catalog nosqli-profile-catalog-safe \
  nosqli-profile-inventory nosqli-profile-inventory-safe; do
  "${compose[@]}" run --rm --no-deps agent scan \
    --benchmark "$benchmark" --mode dast --no-llm
  "${compose[@]}" run --rm --no-deps --entrypoint python agent \
    -m benchmark.verify_nosqli_portable --benchmark "$benchmark"
done

printf '\nPortable NoSQLi acceptance passed. Second API: http://localhost:3006\n'
