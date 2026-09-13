#!/usr/bin/env bash
# Brings up everything needed to drive WebSSH in a browser: a throwaway sshd
# to connect to, and the app itself. Everything lands in $WORKDIR; nothing
# touches ~/.ssh or the system sshd.
#
# Usage: start-stack.sh [workdir]   (default: ./.webssh-run)
# Prints the environment the driver script needs.
set -euo pipefail

WORKDIR="${1:-$PWD/.webssh-run}"
SSH_PORT="${SSH_PORT:-2222}"
APP_PORT="${APP_PORT:-8899}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

mkdir -p "$WORKDIR/ssh"
cd "$WORKDIR/ssh"

# A dedicated host key and user key, so the run needs no existing credentials
# and leaves no trace in the user's authorized_keys.
[ -f hostkey ] || ssh-keygen -q -t ed25519 -N '' -f hostkey
[ -f userkey ] || ssh-keygen -q -t ed25519 -N '' -f userkey
cp userkey.pub authorized_keys
chmod 600 authorized_keys hostkey userkey

# StrictModes off because the key files live under a world-readable tmp dir.
# internal-sftp is REQUIRED: the transfer UI lists directories and moves files
# over SFTP, so a server without it leaves the dialogs empty and broken.
cat > sshd_config <<CONF
Port $SSH_PORT
ListenAddress 127.0.0.1
HostKey $WORKDIR/ssh/hostkey
AuthorizedKeysFile $WORKDIR/ssh/authorized_keys
PasswordAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
PidFile $WORKDIR/ssh/sshd.pid
Subsystem sftp internal-sftp
CONF

# sshd runs unprivileged here. That works only because the account it logs in
# as is the account running it -- it never has to change user.
/usr/sbin/sshd -f "$WORKDIR/ssh/sshd_config" -E "$WORKDIR/ssh/sshd.log"

cd "$REPO"
# --policy=autoadd: the throwaway host key is unknown, and a host-key prompt
# would stall the connect form.
# --hostfile keeps the accepted host key inside $WORKDIR. Without it webssh
# writes ./known_hosts in the repo, and the NEXT run -- which generates a fresh
# throwaway host key -- is refused with "Bad host key." in the status bar.
nohup .venv/bin/python run.py --port="$APP_PORT" --address=127.0.0.1 \
  --policy=autoadd --hostfile="$WORKDIR/known_hosts" \
  > "$WORKDIR/webssh.log" 2>&1 &
echo $! > "$WORKDIR/webssh.pid"

for _ in $(seq 30); do
  if curl -sf -o /dev/null "http://127.0.0.1:$APP_PORT/"; then break; fi
  sleep 0.3
done
curl -sf -o /dev/null "http://127.0.0.1:$APP_PORT/" \
  || { echo "webssh did not come up; see $WORKDIR/webssh.log" >&2; exit 1; }

ssh -i "$WORKDIR/ssh/userkey" -p "$SSH_PORT" -o BatchMode=yes \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR localhost true \
  || { echo "sshd did not accept the key; see $WORKDIR/ssh/sshd.log" >&2; exit 1; }

cat <<ENV
export WEBSSH_WORKDIR=$WORKDIR
export WEBSSH_URL=http://127.0.0.1:$APP_PORT
export WEBSSH_SSH_PORT=$SSH_PORT
export WEBSSH_KEY=$WORKDIR/ssh/userkey
ENV
