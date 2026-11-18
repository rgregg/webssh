"""Reach SSH servers through a tailcat tunnel.

tailcat (https://github.com/tailscale/tailcat) carries a TCP connection over
Tailscale's data plane -- WireGuard plus DERP relays -- without a Tailscale
account or control plane. A tailcat server prints an address ("tc...") and a
client that knows the address can dial a port on it. webssh runs the tailcat
CLI as a child process, `tailcat <address> <port>`, and speaks SSH over its
stdin/stdout, the same trick `tailcat ssh` plays with OpenSSH's ProxyCommand.

Two values are secret here and must never reach a log line, an error
message, or (for administrator hosts) the browser:

* the tailcat address: it embeds a WireGuard pre-shared key, so anyone who
  knows it can connect -- with `serve no-auth-ssh`, straight to a shell;
* a client identity key ("privkey:..."), which servers started with
  `tailcat serve --allow=nodekey:...` use to decide who may connect.

This module imports nothing from the rest of webssh, so settings.py and
user_data.py can both use it without an import cycle.
"""

import base64
import binascii
import collections
import hashlib
import json
import logging
import os
import re
import secrets
import select
import shutil
import subprocess
import tempfile
import threading
import weakref

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

logger = logging.getLogger(__name__)

# The release the container image ships and the tests run against. tailcat
# makes no CLI or wire-format stability promises, so anything else is
# untested and gets a startup warning.
PINNED_VERSION = '0.7.0'

# The form value that selects a tailcat host: "tailcat:<id>". A tailcat host
# has no hostname, and its address is a secret, so the browser only ever
# sees this opaque handle.
HOST_PREFIX = 'tailcat:'

# "tc" + unpadded base64url CBOR. A typical address is ~140 characters; one
# with embedded DERP details is longer. The bounds are generous sanity caps.
ADDRESS_RE = re.compile(r'^tc[A-Za-z0-9_-]{40,4096}$')

# Administrator ids start with "a", user ids with "u", so a user can never
# mint an id that names an administrator host.
ID_RE = re.compile(r'^[au][0-9a-f]{16}$')
USER_ID_RE = re.compile(r'^u[0-9a-f]{16}$')

PRIVATE_KEY_RE = re.compile(r'^privkey:[0-9a-f]{64}$')

# Anything shaped like an address or a private key, for scrubbing text that
# came from somewhere we do not control (tailcat's stderr, OS errors).
_SECRET_RE = re.compile(r'tc[A-Za-z0-9_-]{20,}|privkey:[0-9A-Fa-f]+')

MAX_KEY_FILE_SIZE = 64 * 1024
STDERR_LINES = 20
TERMINATE_GRACE = 2.0

DEFAULT_NAME = 'Tailcat host'


def redact(text):
    """Replace anything that looks like a tailcat secret with a marker."""
    return _SECRET_RE.sub('<redacted>', str(text))


def is_tailcat(host):
    return isinstance(host, dict) and host.get('transport') == 'tailcat'


def validate_address(value, name=DEFAULT_NAME):
    """Return the normalized address, or raise ValueError.

    Messages name the host, never the value: the value is the secret.
    """
    if not isinstance(value, str):
        raise ValueError(  # noqa: TRY004 -- callers map ValueError to a 400
            f'Tailcat address for {name!r} must be a string')
    value = value.strip()
    if not value:
        raise ValueError(f'Tailcat address for {name!r} is required')
    if not ADDRESS_RE.match(value):
        raise ValueError(
            f'Tailcat address for {name!r} is not a valid tailcat address '
            '(expected the "tc..." value a tailcat server prints)')
    body = value[2:]
    try:
        base64.urlsafe_b64decode(body + '=' * (-len(body) % 4))
    except (binascii.Error, ValueError):
        raise ValueError(
            f'Tailcat address for {name!r} is not a valid tailcat address')
    return value


def admin_host_id(address, port):
    """A stable, non-reversible id for an administrator tailcat host.

    Derived from the address so it survives config reloads. The address
    carries a 256-bit pre-shared key, so a truncated hash of it reveals
    nothing usable.
    """
    digest = hashlib.sha256(
        f'webssh-tailcat\0{address}\0{port}'.encode()).hexdigest()
    return 'a' + digest[:16]


def new_user_host_id():
    return 'u' + secrets.token_hex(8)


def host_label(host):
    """The name a tailcat host goes by in logs, errors and host-key lookups."""
    return HOST_PREFIX + host['id']


def host_identity(host):
    """The key two host entries collide on when merging admin and user lists."""
    if is_tailcat(host):
        return ('tailcat', host.get('tailcat_address'), host.get('port'))
    return ('ssh', host.get('hostname'), host.get('port'))


def public_host(host, owner=False):
    """The view of a host entry that is safe to send to a browser.

    SSH entries are returned as they are. Tailcat entries lose their address
    and any key path, and gain a `hostname` of "tailcat:<id>" so the connect
    form can select them like any other host. `owner` adds the fields only
    the user who saved the entry needs in order to edit it.
    """
    if not is_tailcat(host):
        return dict(host)
    view = {
        'id': host['id'],
        'name': host['name'],
        'transport': 'tailcat',
        'hostname': host_label(host),
        'port': host['port'],
        'host_keys': list(host.get('host_keys', [])),
    }
    if owner:
        view['username'] = host.get('username', '')
        view['default_command'] = host.get('default_command', '')
        view['tailcat_identity'] = bool(host.get('tailcat_identity'))
        view['tailcat_address_saved'] = True
    return view


# ---------------------------------------------------------------------------
# Client identity keys
#
# A tailcat client key file is the JSON `tailcat genkey --client` writes:
# {"Private": "privkey:<64 hex>", "Public": {...}}. A client only reads
# "Private" (cmd/tailcat clientKey()), so webssh stores just that field. The
# key is a Curve25519 scalar; its public half, "nodekey:<64 hex>", is what a
# server lists in --allow.


def _clamp(raw):
    # Matches tailscale's key.NewNode. X25519 clamps on use anyway, so this
    # only keeps stored keys byte-identical to ones tailcat would generate.
    b = bytearray(raw)
    b[0] &= 248
    b[31] = (b[31] & 127) | 64
    return bytes(b)


def generate_private_key():
    return 'privkey:' + _clamp(os.urandom(32)).hex()


def public_key(private_key):
    raw = bytes.fromhex(private_key[len('privkey:'):])
    pub = X25519PrivateKey.from_private_bytes(raw).public_key()
    return 'nodekey:' + pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def parse_private_key(text, require_json=False):
    """Return the normalized "privkey:..." from an imported key.

    Accepts a tailcat *.private.json file or, unless require_json, a bare
    "privkey:..." line. Error messages never echo the input.
    """
    if isinstance(text, bytes):
        if len(text) > MAX_KEY_FILE_SIZE:
            raise ValueError('Tailcat key is too large')
        try:
            text = text.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError('Tailcat key is not text')
    if not isinstance(text, str):
        raise ValueError('Tailcat key must be text')  # noqa: TRY004
    if len(text) > MAX_KEY_FILE_SIZE:
        raise ValueError('Tailcat key is too large')
    stripped = text.strip()
    if stripped.startswith('{'):
        try:
            data = json.loads(stripped)
        except ValueError:
            raise ValueError('Tailcat key file is not valid JSON')
        if not isinstance(data, dict):
            raise ValueError('Tailcat key file must be a JSON object')
        candidate = data.get('Private')
    elif require_json:
        raise ValueError(
            'Tailcat key file must be the JSON written by '
            '"tailcat genkey --client"')
    else:
        candidate = stripped
    if not isinstance(candidate, str):
        raise ValueError(  # noqa: TRY004 -- callers map ValueError to a 400
            'Not a tailcat client key (expected "privkey:..." or the '
            'file "tailcat genkey --client" writes)')
    candidate = candidate.strip().lower()
    if not PRIVATE_KEY_RE.match(candidate):
        raise ValueError(
            'Not a tailcat client key (expected "privkey:..." or the '
            'file "tailcat genkey --client" writes)')
    if candidate == 'privkey:' + '0' * 64:
        raise ValueError('Tailcat key is all zeros')
    return candidate


def key_file_body(private_key):
    return (json.dumps({'Private': private_key}) + '\n').encode()


def load_key_file(path):
    """Validate an administrator's key file and return its private key.

    The file itself is handed to tailcat with --key, so it has to be in the
    JSON form tailcat reads, not a bare "privkey:" line.
    """
    if not isinstance(path, str) or not os.path.isabs(path):
        raise ValueError('tailcat_key must be an absolute path')
    try:
        with open(path, 'rb') as f:
            data = f.read(MAX_KEY_FILE_SIZE + 1)
    except OSError as exc:
        raise ValueError(
            f'Cannot read tailcat_key {path!r}: {exc.strerror or exc}')
    try:
        return parse_private_key(data, require_json=True)
    except ValueError as exc:
        raise ValueError(f'Invalid tailcat_key {path!r}: {exc}')


# ---------------------------------------------------------------------------
# Running tailcat


class TailcatSettings:
    """Process-wide knobs, from the `tailcat:` block of the config file."""

    def __init__(self, binary='tailcat', timeout=30.0, derpmap_url='',
                 state_dir=''):
        self.binary = binary
        self.timeout = timeout
        self.derpmap_url = derpmap_url
        self.state_dir = state_dir or default_state_dir()


def default_state_dir(user_data_dir=''):
    # Inside the user data directory a leading dot cannot collide with a
    # user: sanitize_username rejects names that start with one.
    if user_data_dir:
        return os.path.join(user_data_dir, '.tailcat')
    return os.path.join(tempfile.gettempdir(), f'webssh-tailcat-{os.getuid()}')


def resolve_binary(binary):
    path = shutil.which(binary) if binary else None
    if not path:
        raise FileNotFoundError(f'tailcat binary {binary!r} not found')
    return path


def build_argv(binary, address, port, key_path=None, derpmap_url=''):
    """The child's argv. Never run through a shell.

    --key is always passed. Without it tailcat silently loads a saved key
    named "client-default" if one exists, so the identity used would depend
    on whatever happens to be on disk rather than on the host entry.
    """
    if key_path is not None and not os.path.isabs(key_path):
        # tailcat treats a --key value without a slash as a key *name*.
        raise ValueError('tailcat key path must be absolute')
    argv = [binary, '--key=' + (key_path or 'new')]
    if derpmap_url:
        argv.append('--derpmap-url=' + derpmap_url)
    argv += [validate_address(address), str(int(port))]
    return argv


_PASSTHROUGH_ENV = (
    'LANG', 'LC_ALL', 'TZ', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
    'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY',
    'https_proxy', 'http_proxy', 'no_proxy',
)


def build_env(state_dir):
    """A minimal environment for the child.

    HOME and the XDG directories point at a private state directory, so
    tailcat's DERP map cache and config never land in (or get read from) the
    service account's real home. Nothing else is inherited: in particular no
    TAILCAT_* or TS_* variables, which change tailcat's behaviour.
    """
    env = {
        'PATH': os.environ.get('PATH', os.defpath),
        'HOME': state_dir,
        'XDG_CONFIG_HOME': os.path.join(state_dir, 'config'),
        'XDG_CACHE_HOME': os.path.join(state_dir, 'cache'),
    }
    for name in _PASSTHROUGH_ENV:
        if name in os.environ:
            env[name] = os.environ[name]
    return env


def ensure_state_dir(state_dir):
    for sub in ('', 'config', 'cache'):
        os.makedirs(os.path.join(state_dir, sub), mode=0o700, exist_ok=True)


def _reap(process):
    """Stop a tailcat child and collect it, so it never lingers or zombies."""
    if process.poll() is None:
        try:
            process.terminate()
            process.wait(timeout=TERMINATE_GRACE)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=TERMINATE_GRACE)
            except subprocess.TimeoutExpired:
                logger.error(f'tailcat process {process.pid} did not exit')
        except ProcessLookupError:
            pass
    for pipe in (process.stdin, process.stdout, process.stderr):
        if pipe is not None:
            try:
                pipe.close()
            except OSError:
                pass


def _drain_stderr(pipe, tail):
    # Always drained: a full stderr pipe would block the child. Kept only
    # as a short, redacted tail for diagnostics.
    try:
        for line in iter(pipe.readline, b''):
            text = line.decode('utf-8', 'replace').rstrip()
            if text:
                tail.append(redact(text))
    except (OSError, ValueError):
        pass


class TailcatProxy(paramiko.ProxyCommand):
    """A socket-like pipe to a `tailcat <address> <port>` child process.

    Subclasses paramiko's ProxyCommand for the interface paramiko expects,
    but replaces each method:

    * argv is a list, never shlex-split or run through a shell;
    * error messages carry the host's label, not the command line, which
      would contain the address;
    * recv returns b'' at end of file, which paramiko treats as a closed
      connection; ProxyCommand spins on a dead child instead;
    * close waits for the child (and kills it if it ignores SIGTERM) rather
      than signalling it and leaving a zombie behind.
    """

    def __init__(self, argv, env, label):
        # Deliberately no super().__init__(): it takes a command string.
        self.cmd = [label]
        self.label = label
        self.timeout = None
        self._lock = threading.Lock()
        self._shut = False
        self._stderr_tail = collections.deque(maxlen=STDERR_LINES)
        self.process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=env,
            close_fds=True,
            start_new_session=True,
        )
        # A safety net for a proxy dropped without close(), e.g. by a code
        # path that raised before handing it to paramiko. Holds the process,
        # not self, so it does not keep the proxy alive.
        self._finalizer = weakref.finalize(self, _reap, self.process)
        # The thread gets the pipe and the deque, not self: a reference to
        # self would keep a dropped proxy alive, and the finalizer above
        # would never run.
        self._stderr_thread = threading.Thread(
            target=_drain_stderr, args=(self.process.stderr, self._stderr_tail),
            name=f'tailcat-stderr-{self.process.pid}', daemon=True)
        self._stderr_thread.start()

    def stderr_summary(self):
        return ' | '.join(self._stderr_tail)[-800:]

    def _failure(self, exc):
        return paramiko.ProxyCommandFailure(
            self.label, redact(getattr(exc, 'strerror', None) or exc))

    def send(self, content):
        try:
            written = self.process.stdin.write(content)
        except (OSError, ValueError) as exc:
            raise self._failure(exc)
        return len(content) if written is None else written

    def recv(self, size):
        try:
            fd = self.process.stdout.fileno()
            readable, _, _ = select.select([fd], [], [], self.timeout)
            if not readable:
                raise TimeoutError()
            return os.read(fd, size)
        except TimeoutError:
            raise
        except (OSError, ValueError) as exc:
            raise self._failure(exc)

    def close(self):
        with self._lock:
            if self._shut:
                return
            self._shut = True
        self._finalizer()
        self._stderr_thread.join(timeout=1)

    @property
    def closed(self):
        return self._shut or self.process.poll() is not None


def open_proxy(settings, address, port, label, key_path=None,
               extra_env=None):
    """Start tailcat for one SSH connection. The caller must close() it.

    Raises OSError when tailcat cannot be started. extra_env exists for the
    test suite only.
    """
    binary = resolve_binary(settings.binary)
    ensure_state_dir(settings.state_dir)
    argv = build_argv(binary, address, port, key_path=key_path,
                      derpmap_url=settings.derpmap_url)
    env = build_env(settings.state_dir)
    if extra_env:
        env.update(extra_env)
    return TailcatProxy(argv, env, label)


class TailcatHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Host key policy for connections made through a tailcat tunnel.

    The tunnel has already authenticated the server: the address pins the
    server's WireGuard public key, and only the holder of the matching
    private key can complete the handshake. So an unpinned host key is
    accepted, as `tailcat ssh` does, and never written to known_hosts --
    the lookup name is a label, and the server's key can change whenever
    its host key file does. A key pinned in the host entry is still
    enforced, by paramiko, before this policy is consulted.
    """

    def missing_host_key(self, client, hostname, key):
        logger.debug(
            f'Accepting {key.get_name()} host key for {hostname}: '
            'authenticated by the tailcat tunnel')


def check_binary(binary):
    """Log (never raise) whether the configured tailcat binary looks usable."""
    try:
        path = resolve_binary(binary)
    except FileNotFoundError:
        logger.warning(
            f'Tailcat hosts are configured but the tailcat binary {binary!r} '
            'was not found; tailcat connections will fail.')
        return False
    try:
        result = subprocess.run(
            [path, '--version'], capture_output=True, timeout=10,
            check=False, env=build_env(tempfile.gettempdir()))
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning(f'Could not run {path} --version: {exc}')
        return False
    version = (result.stdout or result.stderr).decode(
        'utf-8', 'replace').strip()
    if version != 'v' + PINNED_VERSION:
        logger.warning(
            f'tailcat at {path} reports {version!r}; webssh is tested '
            f'against v{PINNED_VERSION} only.')
    else:
        logger.info(f'Using tailcat {version} at {path}')
    return True
