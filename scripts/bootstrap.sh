#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
[ -f .env ] || cp .env.example .env
runtime_dirs
check_docker
ensure_image
start_lab
for benchmark in sample-sast juice-shop demo-full; do
  docker compose --profile agent run --rm --no-deps agent scan --benchmark "$benchmark" --no-llm || fail 'Scanner smoke test failed.'
done
printf 'Bootstrap complete. Run ./scripts/doctor.sh and ./run.sh ui. LLM is optional.\n'
