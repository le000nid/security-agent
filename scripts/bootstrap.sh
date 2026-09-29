#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
[ -f .env ] || cp .env.example .env
runtime_dirs
check_docker
ensure_image
start_lab
docker compose --profile agent run --rm agent scan --mode full --target-url http://juice-shop:3000 --source-path /targets/sample-app --no-llm || fail 'Scanner smoke test failed.'
printf 'Bootstrap complete. Configure LLM_API_KEY in .env, then run:\n./scripts/doctor.sh\n./run.sh agent\n'
