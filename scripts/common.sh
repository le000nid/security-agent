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
start_lab() {
  docker compose up -d --wait --wait-timeout 180 juice-shop demo-full || fail 'Benchmark unhealthy. Check ports 3000/3001 and docker compose logs juice-shop demo-full.'
}
