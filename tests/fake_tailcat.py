"""A stand-in for the tailcat CLI, for tests that must not need a network.

Run as `fake_tailcat.py <config.json> <tailcat args...>`, via a wrapper
script the tests write (see tests/test_tailcat.py make_fake_binary). It
records its argv and environment to the config's "log" path, then, like
`tailcat <address> <port>`, joins stdin/stdout to a TCP connection -- here
to 127.0.0.1:<config "port">, the test SSH server.

Modes (config "mode"):
  bridge       the default, described above
  ignore-term  bridge, but ignore SIGTERM so close() has to SIGKILL
  stderr-exit  print a secret-looking line to stderr and exit at once
"""

import json
import os
import signal
import socket
import sys
import threading


def main():
    with open(sys.argv[1]) as f:
        config = json.load(f)
    with open(config['log'], 'a') as f:
        f.write(json.dumps({'argv': sys.argv[2:],
                            'env': dict(os.environ),
                            'pid': os.getpid()}) + '\n')

    mode = config.get('mode', 'bridge')
    if mode == 'stderr-exit':
        sys.stderr.write(
            'dial failed for tcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n')
        sys.stderr.flush()
        sys.exit(1)
    if mode == 'ignore-term':
        signal.signal(signal.SIGTERM, signal.SIG_IGN)

    sock = socket.create_connection(('127.0.0.1', config['port']))
    stdin = sys.stdin.buffer.raw
    stdout = sys.stdout.buffer.raw

    def upstream():
        while True:
            data = stdin.read(65536)
            if not data:
                sock.shutdown(socket.SHUT_WR)
                return
            sock.sendall(data)

    threading.Thread(target=upstream, daemon=True).start()
    while True:
        data = sock.recv(65536)
        if not data:
            break
        while data:
            data = data[stdout.write(data):]
    if mode == 'ignore-term':
        # Linger like a wedged child would.
        threading.Event().wait(60)


if __name__ == '__main__':
    main()
