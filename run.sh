#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scripts/common.sh"
check_docker
runtime_dirs
command="${1:-agent}"
if [ "$#" -gt 0 ]; then shift; fi
case "$command" in agent|scan|deterministic|doctor|latest|ui|benchmarks) ;; *) fail 'Use agent, scan, deterministic, doctor, latest, ui, or benchmarks.' ;; esac
if [ "$command" = ui ]; then
  start_lab
  docker compose --profile ui up -d --wait --wait-timeout 180 ui
  printf 'AI Security Agent UI: http://127.0.0.1:8080\n'
  exit 0
fi
case "$command" in agent|scan|deterministic)
  scope=""; benchmark=""; previous=""; has_target=false; has_source=false
  for arg in "$@"; do
    case "$previous" in --mode) scope="$arg" ;; --benchmark) benchmark="$arg" ;; esac
    case "$arg" in
      --mode=*) scope="${arg#--mode=}" ;;
      --benchmark=*) benchmark="${arg#--benchmark=}" ;;
      --target-url|--target-url=*) has_target=true ;;
      --source-path|--source-path=*) has_source=true ;;
    esac
    previous="$arg"
  done
  if [ -z "$scope" ]; then
    if [ "$benchmark" = sample-sast ] || { [ -z "$benchmark" ] && $has_source && ! $has_target; }; then scope=sast
    elif [ "$benchmark" = juice-shop ] || { [ -z "$benchmark" ] && $has_target && ! $has_source; }; then scope=dast
    else scope=full; fi
  fi
  [ "$scope" = sast ] || start_lab
  if [ -z "$benchmark" ]; then
    if [ "$scope" != sast ] && ! $has_target; then set -- --target-url http://juice-shop:3000 "$@"; fi
    if [ "$scope" != dast ] && ! $has_source; then set -- --source-path /targets/sample-app "$@"; fi
  fi
;; esac
docker compose --profile agent run --rm --no-deps agent "$command" "$@"
