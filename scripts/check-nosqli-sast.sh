#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
export AGENT_UID="${AGENT_UID:-$(id -u)}"
export AGENT_GID="${AGENT_GID:-$(id -g)}"
mkdir -p runs logs reports

compose=(docker compose --profile agent)
"${compose[@]}" config --quiet
"${compose[@]}" build agent
"${compose[@]}" run --rm --no-deps agent scan \
  --benchmark nosqli-sast-matrix --mode sast --no-llm
"${compose[@]}" run --rm --no-deps --entrypoint python agent \
  -m benchmark.verify_nosqli_sast_matrix

printf '\nNoSQLi SAST matrix acceptance passed: 40 dangerous and 40 safe cases.\n'
