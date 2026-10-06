#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
check_docker
[ -f .env ] || printf 'WARNING: .env missing. Run ./scripts/bootstrap.sh\n'
[ -d targets/sample-app ] || fail 'targets/sample-app missing; restore repository fixtures.'
runtime_dirs
docker compose images agent
docker image inspect "$(agent_image)" --format '{{.Os}}/{{.Architecture}}' || fail 'Agent image missing; run bootstrap.'
docker compose ps -a juice-shop
docker compose --profile agent run --rm --no-deps agent doctor "$@" || fail 'Container diagnostics failed; see messages above.'
