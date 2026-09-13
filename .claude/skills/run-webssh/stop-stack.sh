#!/usr/bin/env bash
# Tears down what start-stack.sh brought up. Safe to run twice.
set -uo pipefail
WORKDIR="${1:-$PWD/.webssh-run}"
[ -f "$WORKDIR/webssh.pid" ] && kill "$(cat "$WORKDIR/webssh.pid")" 2>/dev/null
[ -f "$WORKDIR/ssh/sshd.pid" ] && kill "$(cat "$WORKDIR/ssh/sshd.pid")" 2>/dev/null
sleep 1
rm -f "$WORKDIR/webssh.pid" "$WORKDIR/ssh/sshd.pid"
echo "stopped"
