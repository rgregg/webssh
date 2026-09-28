#!/usr/bin/env bash
# Runs the browser end-to-end tests in tests/e2e against a throwaway stack
# (an unprivileged sshd plus the app in user-hosts mode), then tears it down.
#
# Needs: .venv with the app's requirements, /usr/sbin/sshd, and Playwright
# (`npm install`). connect.js uses a Chromium already cached under
# ~/.cache/ms-playwright; `npx playwright install chromium` provides one.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL="$REPO/.claude/skills/run-webssh"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/webssh-e2e.XXXXXX")"
trap '"$SKILL/stop-stack.sh" "$WORKDIR" >/dev/null' EXIT

mkdir -p "$WORKDIR/data"
export WEBSSH_APP_ARGS="--user_hosts --userdatadir=$WORKDIR/data"
# start-stack.sh prints `export WEBSSH_*=...` lines (our own script, paths
# we just created); eval is how the skill documents consuming them.
eval "$("$SKILL/start-stack.sh" "$WORKDIR")"

cd "$REPO"
# Pass test files to run a subset: scripts/run_e2e.sh tests/e2e/foo.test.js
if [ "$#" -gt 0 ]; then
  node --test --test-concurrency=1 "$@"
else
  node --test --test-concurrency=1 tests/e2e/*.test.js
fi
