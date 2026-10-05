#!/usr/bin/env bash
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail_package() { printf 'ERROR: %s\n' "$*" >&2; exit 6; }
version=0.4.1
head_version="$(git show HEAD:app/__init__.py)"
[[ "$head_version" == *'__version__ = "0.4.1"'* ]] || fail_package 'Commit the reviewed v0.4.1 release first. Packaging uses committed HEAD only.'
git diff --quiet HEAD -- . || fail_package 'Commit reviewed tracked changes before packaging. Untracked files are never included.'
while IFS= read -r name; do
  [ "$name" = .env.example ] && continue
  case "$name" in .env|.env.*|*/.env|*/.env.*|*.pem|*.key|id_rsa|*/id_rsa|id_ed25519|*/id_ed25519) fail_package 'Potential secret file tracked in HEAD; remove it before packaging.' ;; esac
done < <(git ls-tree -r --name-only HEAD)
mkdir -p dist
output="dist/security-agent-v$version.zip"
[ ! -e "$output" ] || fail_package 'Release archive already exists; move it before packaging again.'
git archive --format=zip --output="$output" HEAD
printf 'Created %s from committed HEAD. Untracked files and local runtime artifacts excluded.\n' "$output"
