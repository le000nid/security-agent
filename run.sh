#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scripts/common.sh"
check_docker
runtime_dirs
mode="${1:-agent}"
if [ "$#" -gt 0 ]; then shift; fi
case "$mode" in agent|scan|deterministic|doctor|latest) ;; *) fail 'Use agent, scan, deterministic, doctor, or latest.' ;; esac
if [ "$mode" != doctor ] && [ "$mode" != latest ]; then
  start_lab
  has_target=false; has_source=false
  for arg in "$@"; do
    case "$arg" in --target-url|--target-url=*) has_target=true ;; --source-path|--source-path=*) has_source=true ;; esac
  done
  $has_target || set -- --target-url http://juice-shop:3000 "$@"
  $has_source || set -- --source-path /targets/sample-app "$@"
fi
docker compose --profile agent run --rm --no-deps agent "$mode" "$@"
