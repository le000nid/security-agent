#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
export AGENT_UID="${AGENT_UID:-$(id -u)}"
export AGENT_GID="${AGENT_GID:-$(id -g)}"
fail() { printf 'ERROR: %s\nSee docs/TROUBLESHOOTING.md\n' "$*" >&2; exit 6; }
check_docker() {
  command -v docker >/dev/null 2>&1 || fail 'Docker not found. Install Docker Desktop/Engine first.'
  docker info --format '{{.OSType}}/{{.Architecture}}' || fail 'Start Docker Desktop or Docker Engine.'
  [ "$(docker info --format '{{.OSType}}')" = linux ] || fail 'Switch Docker Desktop to Linux containers.'
  docker compose version || fail 'Install the Docker Compose v2 plugin.'
  printf 'Host: %s/%s\n' "$(uname -s)" "$(uname -m)"
  docker compose config --quiet || fail 'Invalid Compose configuration.'
}
runtime_dirs() { mkdir -p runs logs reports; }
ensure_image() {
  local selected
  selected="$(agent_image)"
  if [[ "$selected" == ai-security-agent:* ]]; then
    docker compose build agent || fail 'Agent build failed; check network and architecture.'
  else
    docker compose --profile agent pull agent || fail 'Image pull failed; unset AGENT_IMAGE for local build.'
  fi
}
agent_image() {
  docker compose --profile agent config --images agent
}
start_benchmark_lab() {
  local benchmark="$1" service="" profile=()
  case "$benchmark" in
    juice-shop) service=juice-shop ;;
    demo-full) service=demo-full ;;
    dan-lab) service=dan-lab ;;
    nosqli-dast) service=nosqli-lab ;;
    nosqli-mongo-full) service=nosqli-mongo-api; profile=(--profile nosqli-mongo) ;;
    ssrf-lab) service=ssrf-lab ;;
    security-key-lab) service=security-key-lab ;;
    *) return 0 ;;
  esac
  docker compose "${profile[@]}" up -d --wait --wait-timeout 180 "$service" || fail "Benchmark $benchmark is unhealthy."
}
start_all_benchmark_labs() {
  docker compose --profile nosqli-mongo up -d --wait --wait-timeout 180 \
    juice-shop demo-full dan-lab nosqli-lab nosqli-mongo-api ssrf-lab security-key-lab \
    || fail 'One or more registered HTTP benchmarks are unhealthy.'
}
