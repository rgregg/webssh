"""Tests for Tailcat hosts.

Three layers:

* unit tests of webssh.tailcat and the Tailcat parts of settings/user_data;
* app tests that connect through tests/fake_tailcat.py -- a stand-in that
  pipes stdin/stdout to the test SSH server -- so the whole connect path
  runs with no network;
* TestRealTailcat, which drives the real tailcat binary end to end through
  an in-process local DERP relay. It is skipped unless TAILCAT_BIN names
  the binary (the release the Dockerfile pins), e.g.
  TAILCAT_BIN=/usr/local/bin/tailcat pytest tests/test_tailcat.py
"""

import base64
import gc
import hashlib
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from typing import ClassVar
from unittest import mock

import paramiko
import yaml
from tornado.options import options

from tests.sshserver import run_ssh_server
from tests.test_app import UserDataTestBase
from webssh import handler, settings, tailcat, user_data
from webssh.utils import to_str
from webssh.worker import clients

HERE = os.path.dirname(os.path.abspath(__file__))

# RFC 7748 section 6.1, Alice's key pair. tailcat node keys are X25519.
RFC7748_PRIVATE = ('77076d0a7318a57d3c16c17251b26645'
                   'df4c2f87ebc0992ab177fba51db92c2a')
RFC7748_PUBLIC = ('8520f0098930a754748b7ddcb43ef75a'
                  '0dbf3a0d26381af4eba4a98eaa9b4e6a')


def make_address(seed='a'):
    """A syntactically valid tailcat address: "tc" + base64url bytes."""
    raw = hashlib.sha512(seed.encode()).digest() * 2
    return 'tc' + base64.urlsafe_b64encode(raw[:100]).decode().rstrip('=')


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def make_fake_binary(directory, port, mode='bridge'):
    """Write a `tailcat` that runs fake_tailcat.py; return (path, log)."""
    config = os.path.join(directory, f'fake-{mode}.json')
    log = os.path.join(directory, f'fake-{mode}.log')
    with open(config, 'w') as f:
        json.dump({'port': port, 'log': log, 'mode': mode}, f)
    path = os.path.join(directory, f'tailcat-{mode}')
    with open(path, 'w') as f:
        f.write('#!/bin/sh\n'
                f'exec "{sys.executable}" '
                f'"{os.path.join(HERE, "fake_tailcat.py")}" "{config}" "$@"\n')
    os.chmod(path, 0o755)
    return path, log


def read_log(log):
    if not os.path.exists(log):
        return []
    with open(log) as f:
        return [json.loads(line) for line in f if line.strip()]


def pid_gone(pid, wait=5.0):
    """True once pid has exited and been reaped (no zombie left in /proc)."""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if not os.path.exists(f'/proc/{pid}'):
            return True
        time.sleep(0.05)
    return False


def start_echo_server():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    sock.listen(5)

    def serve():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            with conn:
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    conn.sendall(data)

    threading.Thread(target=serve, daemon=True).start()
    return sock


class TempDirMixin:

    def make_tempdir(self):
        path = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, path, ignore_errors=True)
        return path


# ---------------------------------------------------------------------------
# Unit tests


class TestAddress(unittest.TestCase):

    def test_accepts_a_tailcat_address(self):
        address = make_address()
        self.assertEqual(tailcat.validate_address(' ' + address + '\n'),
                         address)

    def test_rejects_non_addresses_without_echoing_them(self):
        secret = 'tc' + 'x' * 10
        for value in ('', 'example.com', 'tc$' + 'a' * 50, secret,
                      make_address() + ' extra', 'TC' + 'a' * 50):
            with self.assertRaises(ValueError) as ctx:
                tailcat.validate_address(value, 'lab')
            self.assertNotIn(value or 'unused', str(ctx.exception))
            self.assertIn("'lab'", str(ctx.exception))

    def test_rejects_non_strings(self):
        with self.assertRaises(ValueError):
            tailcat.validate_address(None)

    def test_redact_hides_addresses_and_private_keys(self):
        address = make_address()
        text = tailcat.redact(f'dial {address} with privkey:{"ab" * 32}')
        self.assertNotIn(address, text)
        self.assertNotIn('ab' * 32, text)
        self.assertEqual(text.count('<redacted>'), 2)


class TestIdsAndViews(unittest.TestCase):

    def test_admin_id_is_stable_and_not_the_address(self):
        address = make_address()
        first = tailcat.admin_host_id(address, 22)
        self.assertEqual(first, tailcat.admin_host_id(address, 22))
        self.assertNotEqual(first, tailcat.admin_host_id(address, 2222))
        self.assertRegex(first, tailcat.ID_RE)
        self.assertTrue(first.startswith('a'))
        self.assertNotIn(first[1:], address)

    def test_user_ids_cannot_collide_with_admin_ids(self):
        self.assertRegex(tailcat.new_user_host_id(), tailcat.USER_ID_RE)
        self.assertIsNone(
            tailcat.USER_ID_RE.match(tailcat.admin_host_id(make_address(), 22)))

    def test_public_view_drops_address_and_key_path(self):
        host = {'name': 'lab', 'transport': 'tailcat', 'id': 'a' + '1' * 16,
                'tailcat_address': make_address(), 'port': 22,
                'host_keys': [], 'tailcat_key': '/secret/key.json'}
        view = tailcat.public_host(host)
        self.assertEqual(view['hostname'], 'tailcat:a' + '1' * 16)
        self.assertNotIn('tailcat_address', view)
        self.assertNotIn('tailcat_key', view)
        self.assertNotIn(host['tailcat_address'], json.dumps(view))
        self.assertNotIn('/secret/', json.dumps(view))
        self.assertNotIn('username', view)

    def test_owner_view_adds_edit_fields(self):
        host = {'name': 'mine', 'transport': 'tailcat', 'id': 'u' + '2' * 16,
                'tailcat_address': make_address(), 'port': 22,
                'host_keys': [], 'username': 'me', 'default_command': 'top',
                'tailcat_identity': True}
        view = tailcat.public_host(host, owner=True)
        self.assertEqual(view['username'], 'me')
        self.assertIs(view['tailcat_identity'], True)
        self.assertIs(view['tailcat_address_saved'], True)
        self.assertNotIn(host['tailcat_address'], json.dumps(view))

    def test_ssh_view_is_unchanged(self):
        host = {'name': 'a', 'hostname': 'a.lan', 'port': 22, 'host_keys': []}
        self.assertEqual(tailcat.public_host(host), host)

    def test_identity_distinguishes_transports(self):
        address = make_address()
        self.assertEqual(
            tailcat.host_identity({'transport': 'tailcat',
                                   'tailcat_address': address, 'port': 22}),
            ('tailcat', address, 22))
        self.assertEqual(tailcat.host_identity({'hostname': 'h', 'port': 22}),
                         ('ssh', 'h', 22))


class TestKeys(TempDirMixin, unittest.TestCase):

    def test_public_key_matches_rfc7748_vector(self):
        self.assertEqual(tailcat.public_key('privkey:' + RFC7748_PRIVATE),
                         'nodekey:' + RFC7748_PUBLIC)

    def test_generated_keys_parse_and_are_clamped(self):
        key = tailcat.generate_private_key()
        self.assertEqual(tailcat.parse_private_key(key), key)
        raw = bytes.fromhex(key[len('privkey:'):])
        self.assertEqual(raw[0] & 7, 0)
        self.assertEqual(raw[31] & 0xC0, 0x40)
        self.assertNotEqual(key, tailcat.generate_private_key())

    def test_parses_tailcat_genkey_json(self):
        # The shape `tailcat genkey --client` writes.
        text = json.dumps({'Private': 'privkey:' + RFC7748_PRIVATE,
                           'Public': {'ServerPublic': 'nodekey:00'}},
                          indent='\t')
        self.assertEqual(tailcat.parse_private_key(text),
                         'privkey:' + RFC7748_PRIVATE)
        self.assertEqual(tailcat.parse_private_key(text.encode()),
                         'privkey:' + RFC7748_PRIVATE)

    def test_normalizes_case_and_whitespace(self):
        self.assertEqual(
            tailcat.parse_private_key('  PRIVKEY:' + RFC7748_PRIVATE.upper()),
            'privkey:' + RFC7748_PRIVATE)

    def test_rejects_bad_keys_without_echoing_them(self):
        bad = ['', 'privkey:abc', 'nodekey:' + RFC7748_PUBLIC,
               '{"Private": 5}', '{"Nope": "x"}', '[1, 2]', '{bad json',
               'privkey:' + '0' * 64, 'x' * (tailcat.MAX_KEY_FILE_SIZE + 1),
               b'\xff\xfe']
        for value in bad:
            with self.assertRaises(ValueError) as ctx:
                tailcat.parse_private_key(value)
            if isinstance(value, str) and len(value) >= 16:
                self.assertNotIn(value[:40], str(ctx.exception))

    def test_require_json_rejects_bare_line(self):
        with self.assertRaises(ValueError):
            tailcat.parse_private_key('privkey:' + RFC7748_PRIVATE,
                                      require_json=True)

    def test_key_file_body_round_trips(self):
        body = tailcat.key_file_body('privkey:' + RFC7748_PRIVATE)
        self.assertEqual(json.loads(body), {'Private': 'privkey:' + RFC7748_PRIVATE})

    def test_load_key_file(self):
        directory = self.make_tempdir()
        path = os.path.join(directory, 'c.private.json')
        with open(path, 'wb') as f:
            f.write(tailcat.key_file_body('privkey:' + RFC7748_PRIVATE))
        self.assertEqual(tailcat.load_key_file(path),
                         'privkey:' + RFC7748_PRIVATE)
        with self.assertRaises(ValueError):
            tailcat.load_key_file('relative/c.private.json')
        with self.assertRaises(ValueError):
            tailcat.load_key_file(os.path.join(directory, 'missing.json'))


class TestArgvAndEnv(TempDirMixin, unittest.TestCase):

    def test_always_passes_key_so_saved_defaults_are_never_used(self):
        address = make_address()
        self.assertEqual(tailcat.build_argv('/bin/tailcat', address, 22),
                         ['/bin/tailcat', '--key=new', address, '22'])
        self.assertEqual(
            tailcat.build_argv('/bin/tailcat', address, 2222,
                               key_path='/k/c.private.json',
                               derpmap_url='https://derp.example/map.json'),
            ['/bin/tailcat', '--key=/k/c.private.json',
             '--derpmap-url=https://derp.example/map.json', address, '2222'])

    def test_rejects_relative_key_and_bad_address(self):
        with self.assertRaises(ValueError):
            tailcat.build_argv('tailcat', make_address(), 22,
                               key_path='client-default')
        with self.assertRaises(ValueError):
            tailcat.build_argv('tailcat', '--help', 22)

    def test_env_is_minimal_and_private(self):
        state = self.make_tempdir()
        with mock.patch.dict(os.environ, {
                'TAILCAT_DERPMAP_URL': 'https://evil.example/',
                'TS_DEBUG_TAILCAT_LOCAL_DERP': '1',
                'SECRET_TOKEN': 'x', 'HTTPS_PROXY': 'http://proxy:3128'}):
            env = tailcat.build_env(state)
        self.assertEqual(env['HOME'], state)
        self.assertEqual(env['XDG_CONFIG_HOME'], os.path.join(state, 'config'))
        self.assertEqual(env['HTTPS_PROXY'], 'http://proxy:3128')
        for name in env:
            self.assertFalse(name.startswith(('TAILCAT_', 'TS_')), name)
        self.assertNotIn('SECRET_TOKEN', env)


class TestProxy(TempDirMixin, unittest.TestCase):

    def setUp(self):
        self.echo = start_echo_server()
        self.addCleanup(self.echo.close)
        self.dir = self.make_tempdir()
        self.address = make_address()

    def make_proxy(self, mode='bridge', register=True):
        binary, log = make_fake_binary(
            self.dir, self.echo.getsockname()[1], mode)
        proxy = tailcat.TailcatProxy(
            [binary, '--key=new', self.address, '22'],
            tailcat.build_env(self.dir), 'tailcat:a' + '0' * 16)
        if register:
            self.addCleanup(proxy.close)
        return proxy, log

    def recv_exactly(self, proxy, n):
        proxy.settimeout(5)
        data = b''
        while len(data) < n:
            chunk = proxy.recv(n - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def test_round_trip_and_reaped_on_close(self):
        proxy, log = self.make_proxy()
        self.assertEqual(proxy.send(b'hello'), 5)
        self.assertEqual(self.recv_exactly(proxy, 5), b'hello')
        self.assertEqual(read_log(log)[0]['argv'],
                         ['--key=new', self.address, '22'])
        pid = proxy.process.pid
        proxy.close()
        self.assertTrue(proxy.closed)
        self.assertIsNotNone(proxy.process.returncode)
        self.assertTrue(pid_gone(pid))
        proxy.close()  # idempotent

    def test_recv_returns_empty_at_eof_and_stderr_is_redacted(self):
        proxy, _ = self.make_proxy('stderr-exit')
        self.assertEqual(self.recv_exactly(proxy, 1), b'')
        proxy.process.wait(5)
        proxy._stderr_thread.join(5)
        summary = proxy.stderr_summary()
        self.assertIn('dial failed', summary)
        self.assertNotIn('tcAAAA', summary)

    def test_send_failure_names_the_label_not_the_command(self):
        proxy, _ = self.make_proxy('stderr-exit')
        proxy.process.wait(5)
        with self.assertRaises(paramiko.ProxyCommandFailure) as ctx:
            for _ in range(50):
                proxy.send(b'x' * 65536)
        self.assertNotIn(self.address, str(ctx.exception))
        self.assertIn('tailcat:a', str(ctx.exception))

    def test_recv_times_out(self):
        proxy, _ = self.make_proxy()
        proxy.settimeout(0.2)
        with self.assertRaises(socket.timeout):
            proxy.recv(1)

    def test_close_kills_a_child_that_ignores_sigterm(self):
        proxy, log = self.make_proxy('ignore-term')
        proxy.send(b'x')
        self.assertEqual(self.recv_exactly(proxy, 1), b'x')
        with mock.patch.object(tailcat, 'TERMINATE_GRACE', 0.3):
            proxy.close()
        self.assertEqual(proxy.process.returncode, -9)
        self.assertTrue(pid_gone(read_log(log)[0]['pid']))

    def test_dropped_proxy_is_reaped(self):
        proxy, _ = self.make_proxy(register=False)
        process = proxy.process
        del proxy
        gc.collect()
        self.assertIsNotNone(process.returncode)

    def test_open_proxy_uses_settings(self):
        binary, log = make_fake_binary(self.dir, self.echo.getsockname()[1])
        state = os.path.join(self.dir, 'state')
        conf = tailcat.TailcatSettings(binary=binary, state_dir=state,
                                       derpmap_url='https://d.example/m.json')
        proxy = tailcat.open_proxy(conf, self.address, 2222, 'tailcat:x')
        self.addCleanup(proxy.close)
        self.assertEqual(self.recv_or_send(proxy), b'ping')
        record = read_log(log)[0]
        self.assertEqual(record['argv'], [
            '--key=new', '--derpmap-url=https://d.example/m.json',
            self.address, '2222'])
        self.assertEqual(record['env']['HOME'], state)
        self.assertTrue(os.path.isdir(os.path.join(state, 'cache')))
        self.assertEqual(stat.S_IMODE(os.stat(state).st_mode), 0o700)

    def recv_or_send(self, proxy):
        proxy.send(b'ping')
        return self.recv_exactly(proxy, 4)

    def test_open_proxy_missing_binary_raises_oserror(self):
        conf = tailcat.TailcatSettings(binary='/nonexistent/tailcat',
                                       state_dir=self.dir)
        with self.assertRaises(OSError):
            tailcat.open_proxy(conf, self.address, 22, 'tailcat:x')


class TestParseHostEntry(TempDirMixin, unittest.TestCase):

    def setUp(self):
        self.address = make_address()

    def test_admin_tailcat_entry(self):
        host = settings.parse_host_entry({
            'name': 'lab', 'transport': 'tailcat',
            'tailcat_address': self.address, 'port': 2222})
        self.assertEqual(host['transport'], 'tailcat')
        self.assertEqual(host['tailcat_address'], self.address)
        self.assertEqual(host['port'], 2222)
        self.assertEqual(host['id'], tailcat.admin_host_id(self.address, 2222))
        self.assertNotIn('hostname', host)

    def test_admin_address_file_and_key_file(self):
        directory = self.make_tempdir()
        address_file = os.path.join(directory, 'addr')
        key_file = os.path.join(directory, 'c.private.json')
        with open(address_file, 'w') as f:
            f.write(self.address + '\n')
        with open(key_file, 'wb') as f:
            f.write(tailcat.key_file_body(tailcat.generate_private_key()))
        host = settings.parse_host_entry({
            'transport': 'tailcat', 'tailcat_address_file': address_file,
            'tailcat_key': key_file})
        self.assertEqual(host['tailcat_address'], self.address)
        self.assertEqual(host['tailcat_key'], key_file)
        self.assertEqual(host['name'], 'Tailcat host')

    def test_errors_never_contain_the_address(self):
        cases = [
            {'transport': 'tailcat', 'tailcat_address': self.address,
             'hostname': 'x'},
            {'transport': 'tailcat', 'tailcat_address': self.address,
             'port': 0},
            {'transport': 'tailcat', 'tailcat_address': self.address,
             'host_key': 'ssh-dss AAAA'},
            {'transport': 'tailcat', 'tailcat_address': self.address,
             'tailcat_key': '/nonexistent/key.json'},
            {'transport': 'tailcat', 'tailcat_address': self.address,
             'tailcat_address_file': '/x'},
            {'transport': 'tailcat', 'tailcat_address': self.address,
             'tailcat_identity': True},
            {'transport': 'tailcat', 'tailcat_address': self.address + '!'},
        ]
        for entry in cases:
            with self.assertRaises(ValueError) as ctx:
                settings.parse_host_entry(entry)
            self.assertNotIn(self.address, str(ctx.exception), entry)

    def test_unknown_transport(self):
        with self.assertRaises(ValueError):
            settings.parse_host_entry({'hostname': 'h', 'transport': 'telnet'})

    def test_ssh_entries_are_unchanged(self):
        self.assertEqual(
            settings.parse_host_entry({'hostname': 'h', 'transport': 'ssh'}),
            {'name': 'h', 'hostname': 'h', 'port': 22, 'host_keys': []})

    def test_user_scope_cannot_reach_server_files(self):
        for extra in ({'tailcat_key': '/etc/passwd'},
                      {'tailcat_address_file': '/etc/passwd'}):
            entry = {'transport': 'tailcat', 'tailcat_address': self.address}
            entry.update(extra)
            with self.assertRaises(ValueError):
                settings.parse_host_entry(entry, scope='user')

    def test_user_scope_ids(self):
        host = settings.parse_host_entry(
            {'transport': 'tailcat', 'tailcat_address': self.address},
            scope='user')
        self.assertRegex(host['id'], tailcat.USER_ID_RE)
        self.assertIs(host['tailcat_identity'], False)
        kept = settings.parse_host_entry(
            {'transport': 'tailcat', 'tailcat_address': self.address,
             'id': host['id'], 'tailcat_identity': True}, scope='user')
        self.assertEqual(kept['id'], host['id'])
        # An admin-shaped id is never accepted from a user.
        forged = settings.parse_host_entry(
            {'transport': 'tailcat', 'tailcat_address': self.address,
             'id': tailcat.admin_host_id(self.address, 22)}, scope='user')
        self.assertTrue(forged['id'].startswith('u'))
        with self.assertRaises(ValueError):
            settings.parse_host_entry(
                {'transport': 'tailcat', 'tailcat_address': self.address,
                 'tailcat_identity': 'yes'}, scope='user')


class TestApplyTailcatConfig(unittest.TestCase):

    def opts(self, **overrides):
        values = {'tailcat_binary': 'tailcat', 'tailcat_timeout': 30,
                  'tailcat_derpmap_url': '', 'tailcat_state_dir': ''}
        values.update(overrides)
        return type('Options', (), values)()

    def test_applies_block(self):
        opts = self.opts()
        settings.apply_tailcat_config(opts, {
            'binary': '/usr/local/bin/tailcat', 'timeout': 45,
            'derpmap_url': 'https://derp.example/map.json',
            'state_dir': '/data/tailcat'})
        self.assertEqual(opts.tailcat_binary, '/usr/local/bin/tailcat')
        self.assertEqual(opts.tailcat_timeout, 45)
        self.assertEqual(opts.tailcat_derpmap_url,
                         'https://derp.example/map.json')
        self.assertEqual(opts.tailcat_state_dir, '/data/tailcat')

    def test_cli_wins(self):
        opts = self.opts(tailcat_binary='/opt/tailcat')
        settings.apply_tailcat_config(opts, {'binary': '/usr/bin/tailcat'})
        self.assertEqual(opts.tailcat_binary, '/opt/tailcat')

    def test_rejects_bad_values(self):
        for block in ('x', {'binary': ''}, {'timeout': 0},
                      {'timeout': 'soon'}, {'derpmap_url': 'file:///x'},
                      {'derpmap_url': 'https://a b'},
                      {'state_dir': 'relative'}, {'typo': 1}):
            with self.assertRaises(ValueError, msg=block):
                settings.apply_tailcat_config(self.opts(), block)


class TestUserDataTailcat(TempDirMixin, unittest.TestCase):

    def setUp(self):
        self.base = self.make_tempdir()
        self.address = make_address()

    def test_rejected_unless_allowed(self):
        with self.assertRaises(ValueError) as ctx:
            user_data.validate_hosts(
                [{'transport': 'tailcat', 'tailcat_address': self.address}])
        self.assertIn('not enabled', str(ctx.exception))

    def test_saved_address_is_kept_by_id(self):
        stored = user_data.write_hosts(self.base, 'alice', [
            {'transport': 'tailcat', 'name': 'lab',
             'tailcat_address': self.address}], allow_tailcat=True)
        host_id = stored[0]['id']
        again = user_data.write_hosts(self.base, 'alice', [
            {'transport': 'tailcat', 'name': 'renamed', 'id': host_id}],
            allow_tailcat=True)
        self.assertEqual(again[0]['tailcat_address'], self.address)
        self.assertEqual(again[0]['name'], 'renamed')
        self.assertEqual(again[0]['id'], host_id)

    def test_new_host_needs_an_address(self):
        with self.assertRaises(ValueError):
            user_data.validate_hosts(
                [{'transport': 'tailcat', 'id': 'u' + '9' * 16}],
                existing=[], allow_tailcat=True)

    def test_duplicate_ids_are_split(self):
        result = user_data.validate_hosts([
            {'transport': 'tailcat', 'tailcat_address': self.address,
             'id': 'u' + '1' * 16},
            {'transport': 'tailcat', 'tailcat_address': self.address,
             'id': 'u' + '1' * 16}], allow_tailcat=True)
        self.assertNotEqual(result[0]['id'], result[1]['id'])

    def test_identity_round_trip_is_private(self):
        self.assertEqual(user_data.read_tailcat_identity(self.base, 'alice'), '')
        key = tailcat.generate_private_key()
        public = user_data.write_tailcat_identity(self.base, 'alice', key)
        self.assertEqual(public, tailcat.public_key(key))
        path = user_data.tailcat_identity_path(self.base, 'alice')
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(user_data.read_tailcat_identity(self.base, 'alice'),
                         key)
        # The file is in the form tailcat itself reads.
        self.assertEqual(tailcat.load_key_file(path), key)
        user_data.delete_tailcat_identity(self.base, 'alice')
        self.assertFalse(os.path.exists(path))
        user_data.delete_tailcat_identity(self.base, 'alice')

    def test_identity_rejects_bad_usernames(self):
        with self.assertRaises(ValueError):
            user_data.tailcat_identity_path(self.base, '../bob')


# ---------------------------------------------------------------------------
# App tests through the fake binary


class TailcatAppBase(TempDirMixin, UserDataTestBase):
    """A config with two admin Tailcat hosts and one plain SSH host.

    The fake tailcat joins every connection to the test SSH server, so a
    successful connect proves the whole path: form value -> host lookup ->
    child process -> paramiko over its pipes -> shell -> worker.
    """

    user_tailcat = False
    binary_mode = 'bridge'
    missing_binary = False
    headers: ClassVar[dict] = {'Cookie': '_xsrf=yummy',
                               'X-Authentik-Username': 'alice'}

    def setUp(self):
        self.tmp = self.make_tempdir()
        self.ssh_port = free_port()
        threading.Thread(target=run_ssh_server, args=(self.ssh_port, True),
                         daemon=True).start()
        self.binary, self.log = make_fake_binary(
            self.tmp, self.ssh_port, self.binary_mode)
        self.address = make_address('admin')
        self.keyed_address = make_address('keyed')
        self.key_file = os.path.join(self.tmp, 'admin-client.private.json')
        with open(self.key_file, 'wb') as f:
            f.write(tailcat.key_file_body(tailcat.generate_private_key()))
        os.chmod(self.key_file, 0o600)
        address_file = os.path.join(self.tmp, 'keyed.addr')
        with open(address_file, 'w') as f:
            f.write(self.keyed_address)
        self.config_path = os.path.join(self.tmp, 'config.yaml')
        with open(self.config_path, 'w') as f:
            yaml.safe_dump({'hosts': [
                {'name': 'lab', 'transport': 'tailcat',
                 'tailcat_address': self.address},
                {'name': 'keyed', 'transport': 'tailcat',
                 'tailcat_address_file': address_file,
                 'tailcat_key': self.key_file},
                {'name': 'plain', 'hostname': '127.0.0.1',
                 'port': self.ssh_port},
            ]}, f)
        self.admin_id = tailcat.admin_host_id(self.address, 22)
        self.keyed_id = tailcat.admin_host_id(self.keyed_address, 22)
        self.override_options(
            config=self.config_path,
            tailcat_binary=('/nonexistent/tailcat' if self.missing_binary
                            else self.binary),
            tailcat_state_dir=os.path.join(self.tmp, 'state'),
            tailcat_timeout=10.0,
            tailcat_derpmap_url='',
            user_tailcat_hosts=self.user_tailcat,
            encoding='utf-8',
            shell_integration=False,
            maxconn=20,
        )
        super().setUp()

    def tearDown(self):
        for workers in list(clients.values()):
            for worker in list(workers.values()):
                worker.close(reason='test teardown')
        super().tearDown()

    def post_connect(self, hostname, password='foo', port=None):
        body = (f'hostname={hostname}&username=robey&password={password}'
                '&_xsrf=yummy')
        if port is not None:
            body += f'&port={port}'
        response = self.fetch('/', method='POST', body=body,
                              headers=self.headers)
        return json.loads(to_str(response.body))

    def put_json(self, path, payload, method='PUT'):
        hdrs = dict(self.headers)
        hdrs['Content-Type'] = 'application/json'
        hdrs['X-Xsrftoken'] = 'yummy'
        return self.fetch(path, method=method,
                          body=json.dumps(payload) if payload is not None
                          else None,
                          headers=hdrs, allow_nonstandard_methods=True)

    def worker_for(self, result):
        for workers in clients.values():
            if result['id'] in workers:
                return workers[result['id']]
        return None


class TestTailcatAdminHosts(TailcatAppBase):

    def test_index_page_never_contains_secrets(self):
        body = to_str(self.fetch('/', headers=self.headers).body)
        self.assertIn('tailcat:' + self.admin_id, body)
        self.assertIn('tailcat:' + self.keyed_id, body)
        self.assertNotIn(self.address, body)
        self.assertNotIn(self.keyed_address, body)
        self.assertNotIn(self.key_file, body)

    def test_api_and_settings_pane_never_contain_secrets(self):
        for path in ('/api/hosts', '/settings-pane'):
            body = to_str(self.fetch(path, headers=self.headers).body)
            self.assertNotIn(self.address, body, path)
            self.assertNotIn(self.keyed_address, body, path)
            self.assertNotIn(self.key_file, body, path)
            self.assertNotIn('tailcat_address"', body, path)
        data = json.loads(to_str(
            self.fetch('/api/hosts', headers=self.headers).body))
        lab = data['admin_hosts'][0]
        self.assertEqual(lab['hostname'], 'tailcat:' + self.admin_id)
        self.assertEqual(lab['transport'], 'tailcat')

    def test_connects_through_tailcat_and_reaps_the_child(self):
        with self.assertLogs('webssh', level='DEBUG') as logs:
            result = self.post_connect('tailcat:' + self.admin_id)
        self.assertIsNone(result['status'])
        self.assertIsNotNone(result['id'])
        record = read_log(self.log)[-1]
        self.assertEqual(record['argv'], ['--key=new', self.address, '22'])
        for line in logs.output:
            self.assertNotIn(self.address, line)
        worker = self.worker_for(result)
        self.assertEqual(worker.dst_addr[0], 'tailcat:' + self.admin_id)
        proxy = worker.ssh.tailcat_proxy
        worker.close(reason='done')
        self.assertIsNotNone(proxy.process.returncode)
        self.assertTrue(pid_gone(record['pid']))

    def test_port_in_the_form_is_ignored(self):
        result = self.post_connect('tailcat:' + self.admin_id, port=2200)
        self.assertIsNone(result['status'])
        self.assertEqual(read_log(self.log)[-1]['argv'][-1], '22')

    def test_admin_key_file_is_passed_to_tailcat(self):
        result = self.post_connect('tailcat:' + self.keyed_id)
        self.assertIsNone(result['status'])
        self.assertEqual(read_log(self.log)[-1]['argv'],
                         ['--key=' + self.key_file, self.keyed_address, '22'])

    def test_failed_auth_reaps_the_child(self):
        result = self.post_connect('tailcat:' + self.admin_id, password='bad')
        self.assertEqual(result['status'], 'Authentication failed.')
        self.assertTrue(pid_gone(read_log(self.log)[-1]['pid']))

    def test_unknown_and_malformed_ids_are_rejected(self):
        result = self.post_connect('tailcat:a' + 'f' * 16)
        self.assertIn('not allowed', result['status'])
        result = self.post_connect('tailcat:../../etc')
        self.assertIn('Invalid Tailcat host', result['status'])
        self.assertEqual(read_log(self.log), [])

    def test_plain_ssh_still_works_and_allowlist_still_applies(self):
        result = self.post_connect('127.0.0.1', port=self.ssh_port)
        self.assertIsNone(result['status'])
        self.assertEqual(read_log(self.log), [])
        result = self.post_connect('127.0.0.2', port=self.ssh_port)
        self.assertIn('is not allowed', result['status'])

    def test_user_tailcat_api_is_off(self):
        self.assertEqual(self.fetch('/api/tailcat-identity',
                                    headers=self.headers).code, 403)
        response = self.put_json('/api/hosts', {'hosts': [
            {'transport': 'tailcat', 'tailcat_address': make_address('u')}]})
        self.assertEqual(response.code, 400)
        self.assertIn('not enabled', to_str(response.body))


class TestTailcatMissingBinary(TailcatAppBase):

    missing_binary = True

    def test_reports_unavailable(self):
        result = self.post_connect('tailcat:' + self.admin_id)
        self.assertEqual(result['status'],
                         'Tailcat is not available on this server.')


class TestTailcatChildExits(TailcatAppBase):

    binary_mode = 'stderr-exit'

    def test_reports_failure_without_secrets(self):
        with self.assertLogs('webssh', level='DEBUG') as logs:
            result = self.post_connect('tailcat:' + self.admin_id)
        self.assertEqual(result['status'],
                         'Unable to connect to lab over Tailcat.')
        joined = '\n'.join(logs.output)
        self.assertNotIn(self.address, joined)
        self.assertNotIn('tcAAAAAAAA', joined)
        self.assertTrue(pid_gone(read_log(self.log)[-1]['pid']))


class TestTailcatUserHosts(TailcatAppBase):

    user_tailcat = True

    def save_user_host(self, **fields):
        host = {'transport': 'tailcat', 'name': 'mine',
                'tailcat_address': make_address('user')}
        host.update(fields)
        response = self.put_json('/api/hosts', {'hosts': [host]})
        self.assertEqual(response.code, 200, response.body)
        return json.loads(to_str(response.body))['user_hosts'][0]

    def stored_hosts(self):
        return user_data.read_hosts(self.data_dir, 'alice')

    def test_address_is_write_only(self):
        saved = self.save_user_host()
        user_address = make_address('user')
        self.assertRegex(saved['id'], tailcat.USER_ID_RE)
        self.assertTrue(saved['tailcat_address_saved'])
        self.assertNotIn('tailcat_address', saved)
        for path in ('/api/hosts', '/'):
            self.assertNotIn(user_address,
                             to_str(self.fetch(path, headers=self.headers).body))
        self.assertEqual(self.stored_hosts()[0]['tailcat_address'], user_address)
        # Saving again with just the id keeps the stored address.
        again = self.put_json('/api/hosts', {'hosts': [
            {'transport': 'tailcat', 'name': 'renamed', 'id': saved['id']}]})
        self.assertEqual(again.code, 200)
        self.assertEqual(self.stored_hosts()[0]['tailcat_address'], user_address)
        self.assertEqual(self.stored_hosts()[0]['name'], 'renamed')

    def test_bad_input_is_rejected_without_echo(self):
        secret = 'tc' + 'Q' * 30 + '$'
        response = self.put_json('/api/hosts', {'hosts': [
            {'transport': 'tailcat', 'tailcat_address': secret}]})
        self.assertEqual(response.code, 400)
        self.assertNotIn('Q' * 30, to_str(response.body))
        response = self.put_json('/api/hosts', {'hosts': [
            {'transport': 'tailcat', 'tailcat_address': make_address('x'),
             'tailcat_key': self.key_file}]})
        self.assertEqual(response.code, 400)

    def test_connect_to_own_host(self):
        saved = self.save_user_host()
        result = self.post_connect(saved['hostname'])
        self.assertIsNone(result['status'])
        self.assertEqual(read_log(self.log)[-1]['argv'],
                         ['--key=new', make_address('user'), '22'])

    def test_identity_is_required_when_selected(self):
        saved = self.save_user_host(tailcat_identity=True)
        result = self.post_connect(saved['hostname'])
        self.assertIn('Generate or import', result['status'])
        self.assertEqual(read_log(self.log), [])

    def test_identity_api_and_connect_with_identity(self):
        response = self.put_json('/api/tailcat-identity', {'generate': True},
                                 method='POST')
        self.assertEqual(response.code, 200)
        data = json.loads(to_str(response.body))
        self.assertTrue(data['public_key'].startswith('nodekey:'))
        self.assertNotIn('privkey', to_str(response.body))
        got = json.loads(to_str(self.fetch('/api/tailcat-identity',
                                           headers=self.headers).body))
        self.assertEqual(got['public_key'], data['public_key'])

        saved = self.save_user_host(tailcat_identity=True)
        result = self.post_connect(saved['hostname'])
        self.assertIsNone(result['status'])
        path = user_data.tailcat_identity_path(self.data_dir, 'alice')
        self.assertEqual(read_log(self.log)[-1]['argv'][0], '--key=' + path)

    def test_identity_import_and_delete(self):
        text = json.dumps({'Private': 'privkey:' + RFC7748_PRIVATE,
                           'Public': {}})
        response = self.put_json('/api/tailcat-identity', {'import': text},
                                 method='POST')
        self.assertEqual(json.loads(to_str(response.body))['public_key'],
                         'nodekey:' + RFC7748_PUBLIC)
        bad = self.put_json('/api/tailcat-identity',
                            {'import': 'privkey:not-a-key-0123456789'},
                            method='POST')
        self.assertEqual(bad.code, 400)
        self.assertNotIn('not-a-key-0123456789', to_str(bad.body))
        # The bad import did not replace the good key.
        got = json.loads(to_str(self.fetch('/api/tailcat-identity',
                                           headers=self.headers).body))
        self.assertEqual(got['public_key'], 'nodekey:' + RFC7748_PUBLIC)
        gone = self.put_json('/api/tailcat-identity', None, method='DELETE')
        self.assertEqual(json.loads(to_str(gone.body))['has_key'], False)

    def test_identity_writes_need_the_xsrf_token(self):
        hdrs = dict(self.headers)
        hdrs['Content-Type'] = 'application/json'
        response = self.fetch('/api/tailcat-identity', method='POST',
                              body=json.dumps({'generate': True}),
                              headers=hdrs)
        self.assertEqual(response.code, 403)

    def test_users_are_isolated(self):
        saved = self.save_user_host()
        bob = dict(self.headers, **{'X-Authentik-Username': 'bob'})
        body = (f'hostname={saved["hostname"]}&username=robey&password=foo'
                '&_xsrf=yummy')
        response = self.fetch('/', method='POST', body=body, headers=bob)
        self.assertIn('not allowed', json.loads(to_str(response.body))['status'])

    def test_user_copy_of_admin_host_does_not_shadow_it(self):
        self.save_user_host(tailcat_address=self.address)
        result = self.post_connect('tailcat:' + self.admin_id)
        self.assertIsNone(result['status'])


class TestTailcatUserHostsSwitchedOff(TailcatAppBase):
    """Hosts saved while user_tailcat_hosts was on, after it is turned off."""

    user_tailcat = False

    def setUp(self):
        super().setUp()
        self.saved = user_data.write_hosts(self.data_dir, 'alice', [
            {'transport': 'tailcat', 'name': 'old',
             'tailcat_address': make_address('old')}], allow_tailcat=True)[0]

    def test_hidden_unusable_and_preserved(self):
        data = json.loads(to_str(self.fetch('/api/hosts',
                                            headers=self.headers).body))
        self.assertEqual(data['user_hosts'], [])
        result = self.post_connect('tailcat:' + self.saved['id'])
        self.assertIn('not allowed', result['status'])
        response = self.put_json('/api/hosts', {'hosts': [
            {'hostname': 'new.lan'}]})
        self.assertEqual(response.code, 200)
        stored = user_data.read_hosts(self.data_dir, 'alice')
        self.assertEqual([h.get('hostname') for h in stored],
                         ['new.lan', None])
        self.assertEqual(stored[1]['tailcat_address'], make_address('old'))


class TestTailcatOptionsLeak(unittest.TestCase):

    watched = ('config', 'tailcat_binary', 'tailcat_state_dir',
               'tailcat_timeout', 'user_tailcat_hosts', 'encoding',
               'shell_integration', 'user_hosts', 'userdatadir')

    def test_app_tests_restore_options(self):
        before = {name: getattr(options, name) for name in self.watched}
        suite = unittest.TestLoader().loadTestsFromTestCase(
            TestTailcatAdminHosts)
        suite.run(unittest.TestResult())
        after = {name: getattr(options, name) for name in self.watched}
        self.assertEqual(before, after)


# ---------------------------------------------------------------------------
# The real binary, end to end, with no network beyond loopback


REAL_BINARY = os.environ.get('TAILCAT_BIN', '')


@unittest.skipUnless(REAL_BINARY, 'set TAILCAT_BIN to run against real tailcat')
class TestRealTailcat(TempDirMixin, unittest.TestCase):

    def setUp(self):
        self.dir = self.make_tempdir()
        self.settings = tailcat.TailcatSettings(
            binary=REAL_BINARY, timeout=20,
            state_dir=os.path.join(self.dir, 'client'))

    def start_server(self, *serve_args):
        """`tailcat serve` with its own in-process DERP relay on loopback."""
        home = os.path.join(self.dir, 'server')
        os.makedirs(home, exist_ok=True)
        addr_file = os.path.join(self.dir, f'addr-{len(os.listdir(self.dir))}')
        env = tailcat.build_env(home)
        env.update(TS_DEBUG_TAILCAT_LOCAL_DERP='1', TAILCAT_ADDR_FILE=addr_file)
        server = subprocess.Popen(
            [REAL_BINARY, 'serve', '--key=new', *serve_args],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        self.addCleanup(tailcat._reap, server)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if os.path.exists(addr_file) and os.path.getsize(addr_file):
                with open(addr_file) as f:
                    return f.read().strip()
            time.sleep(0.2)
        self.fail('tailcat server did not publish an address')

    def connect(self, address, key_path=None, timeout=20):
        label = 'tailcat:a' + '0' * 16
        settings = tailcat.TailcatSettings(
            binary=REAL_BINARY, timeout=timeout,
            state_dir=self.settings.state_dir)
        proxy = tailcat.open_proxy(settings, address, 22, label,
                                   key_path=key_path)
        client = handler.SSHClient()
        client._system_host_keys = paramiko.HostKeys()
        client._host_keys = paramiko.HostKeys()
        client.set_missing_host_key_policy(tailcat.TailcatHostKeyPolicy())
        client.allow_auth_none = True
        client.tailcat_proxy = proxy
        self.addCleanup(client.close)
        client.connect(label, 22, username='tester', password='', pkey=None,
                       sock=proxy, timeout=timeout, banner_timeout=timeout,
                       auth_timeout=timeout)
        return client, proxy

    def run_echo(self, client):
        _, stdout, _ = client.exec_command('echo webssh-tailcat-ok', timeout=20)
        return stdout.read().decode()

    def test_version_is_the_pinned_release(self):
        out = subprocess.run([REAL_BINARY, '--version'], capture_output=True,
                             check=True).stdout.decode().strip()
        self.assertEqual(out, 'v' + tailcat.PINNED_VERSION)

    def test_no_auth_ssh_session(self):
        address = self.start_server('no-auth-ssh')
        client, proxy = self.connect(address)
        self.assertIn('webssh-tailcat-ok', self.run_echo(client))
        pid = proxy.process.pid
        client.close()
        self.assertTrue(pid_gone(pid))

    def test_allow_list_admits_only_our_identity(self):
        private = tailcat.generate_private_key()
        key_path = os.path.join(self.dir, 'me.private.json')
        with open(key_path, 'wb') as f:
            f.write(tailcat.key_file_body(private))
        address = self.start_server(
            '--allow=' + tailcat.public_key(private), 'no-auth-ssh')
        client, _ = self.connect(address, key_path=key_path)
        self.assertIn('webssh-tailcat-ok', self.run_echo(client))
        # An ephemeral key is silently ignored by the server.
        with self.assertRaises((paramiko.SSHException, OSError, EOFError)):
            self.connect(address, timeout=5)

    def test_genkey_interop(self):
        key_path = os.path.join(self.dir, 'gen.private.json')
        env = tailcat.build_env(os.path.join(self.dir, 'gen'))
        os.makedirs(env['HOME'], exist_ok=True)
        out = subprocess.run(
            [REAL_BINARY, 'genkey', '--client', '--key=' + key_path],
            capture_output=True, check=True, env=env).stdout.decode().strip()
        self.assertEqual(tailcat.public_key(tailcat.load_key_file(key_path)),
                         out)


class TestConfigReload(TempDirMixin, unittest.TestCase):
    """`hosts:` -- Tailcat entries included -- hot-reloads from the YAML
    file, which is the only administrator configuration surface."""

    def write(self, path, hosts):
        with open(path, 'w') as f:
            yaml.safe_dump({'hosts': hosts}, f)

    def test_tailcat_hosts_reload_and_bad_reload_keeps_old_config(self):
        from webssh.main import reload_config
        path = os.path.join(self.make_tempdir(), 'config.yaml')
        good, bad = make_address('good'), make_address('bad')
        self.write(path, [{'name': 'lab', 'transport': 'tailcat',
                           'tailcat_address': good}])
        live = {}
        reload_config(path, live, None)
        self.assertEqual(live['allowed_hosts'][0]['tailcat_address'], good)

        # A bad entry (here, a key file that does not exist) must not
        # replace the working config, and the log must not carry the
        # address of either entry.
        self.write(path, [{'name': 'lab2', 'transport': 'tailcat',
                           'tailcat_address': bad,
                           'tailcat_key': '/nonexistent/k.json'}])
        with self.assertLogs('webssh', level='ERROR') as logs:
            reload_config(path, live, None)
        self.assertEqual(live['allowed_hosts'][0]['tailcat_address'], good)
        joined = '\n'.join(logs.output)
        self.assertNotIn(good, joined)
        self.assertNotIn(bad, joined)
