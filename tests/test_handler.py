import base64
import io
import tempfile
import unittest

import paramiko
import tornado.web
from tornado.httputil import HTTPServerRequest
from tornado.options import options

from tests.utils import make_tests_data_path, read_file
from webssh import handler, user_data, user_keys
from webssh.handler import (
    IndexHandler,
    InvalidValueError,
    MixinHandler,
    PrivateKey,
    SSHClient,
    WsockHandler,
)

try:
    from unittest.mock import Mock, patch
except ImportError:
    from unittest.mock import Mock, patch


class TestMixinHandler(unittest.TestCase):

    def test_is_forbidden(self):
        mhandler = MixinHandler()
        handler.redirecting = True
        options.fbidhttp = True

        context = Mock(
            address=('8.8.8.8', 8888),
            trusted_downstream=['127.0.0.1'],
            _orig_protocol='http'
        )
        hostname = '4.4.4.4'
        self.assertTrue(mhandler.is_forbidden(context, hostname))

        context = Mock(
            address=('8.8.8.8', 8888),
            trusted_downstream=[],
            _orig_protocol='http'
        )
        hostname = 'www.google.com'
        self.assertEqual(mhandler.is_forbidden(context, hostname), False)

        context = Mock(
            address=('8.8.8.8', 8888),
            trusted_downstream=[],
            _orig_protocol='http'
        )
        hostname = '4.4.4.4'
        self.assertTrue(mhandler.is_forbidden(context, hostname))

        context = Mock(
            address=('192.168.1.1', 8888),
            trusted_downstream=[],
            _orig_protocol='http'
        )
        hostname = 'www.google.com'
        self.assertIsNone(mhandler.is_forbidden(context, hostname))

        options.fbidhttp = False
        self.assertIsNone(mhandler.is_forbidden(context, hostname))

        hostname = '4.4.4.4'
        self.assertIsNone(mhandler.is_forbidden(context, hostname))

        handler.redirecting = False
        self.assertIsNone(mhandler.is_forbidden(context, hostname))

        context._orig_protocol = 'https'
        self.assertIsNone(mhandler.is_forbidden(context, hostname))

    def test_get_redirect_url(self):
        mhandler = MixinHandler()
        hostname = 'www.example.com'
        uri = '/'
        port = 443

        self.assertEqual(
            mhandler.get_redirect_url(hostname, port, uri=uri),
            'https://www.example.com/'
        )

        port = 4433
        self.assertEqual(
            mhandler.get_redirect_url(hostname, port, uri),
            'https://www.example.com:4433/'
        )

    def test_get_client_addr(self):
        mhandler = MixinHandler()
        client_addr = ('8.8.8.8', 8888)
        context_addr = ('127.0.0.1', 1234)
        options.xheaders = True

        mhandler.context = Mock(address=context_addr)
        mhandler.get_real_client_addr = lambda: None
        self.assertEqual(mhandler.get_client_addr(), context_addr)

        mhandler.context = Mock(address=context_addr)
        mhandler.get_real_client_addr = lambda: client_addr
        self.assertEqual(mhandler.get_client_addr(), client_addr)

        options.xheaders = False
        mhandler.context = Mock(address=context_addr)
        mhandler.get_real_client_addr = lambda: client_addr
        self.assertEqual(mhandler.get_client_addr(), context_addr)

    def test_get_real_client_addr(self):
        x_forwarded_for = '1.1.1.1'
        x_forwarded_port = 1111
        x_real_ip = '2.2.2.2'
        x_real_port = 2222
        fake_port = 65535

        mhandler = MixinHandler()
        mhandler.request = HTTPServerRequest(uri='/')
        mhandler.request.remote_ip = x_forwarded_for

        self.assertIsNone(mhandler.get_real_client_addr())

        mhandler.request.headers.add('X-Forwarded-For', x_forwarded_for)
        self.assertEqual(mhandler.get_real_client_addr(),
                         (x_forwarded_for, fake_port))

        mhandler.request.headers.add('X-Forwarded-Port', str(fake_port + 1))
        self.assertEqual(mhandler.get_real_client_addr(),
                         (x_forwarded_for, fake_port))

        mhandler.request.headers['X-Forwarded-Port'] = x_forwarded_port
        self.assertEqual(mhandler.get_real_client_addr(),
                         (x_forwarded_for, x_forwarded_port))

        mhandler.request.remote_ip = x_real_ip

        mhandler.request.headers.add('X-Real-Ip', x_real_ip)
        self.assertEqual(mhandler.get_real_client_addr(),
                         (x_real_ip, fake_port))

        mhandler.request.headers.add('X-Real-Port', str(fake_port + 1))
        self.assertEqual(mhandler.get_real_client_addr(),
                         (x_real_ip, fake_port))

        mhandler.request.headers['X-Real-Port'] = x_real_port
        self.assertEqual(mhandler.get_real_client_addr(),
                         (x_real_ip, x_real_port))


class TestPrivateKey(unittest.TestCase):

    def get_pk_obj(self, fname, password=None):
        key = read_file(make_tests_data_path(fname))
        return PrivateKey(key, password=password, filename=fname)

    def _test_with_encrypted_key(self, fname, password, klass):
        pk = self.get_pk_obj(fname, password='')
        with self.assertRaises(InvalidValueError) as ctx:
            pk.get_pkey_obj()
        self.assertIn('Need a passphrase', str(ctx.exception))

        pk = self.get_pk_obj(fname, password='wrongpass')
        with self.assertRaises(InvalidValueError) as ctx:
            pk.get_pkey_obj()
        self.assertIn('wrong passphrase', str(ctx.exception))
        self.assertNotIn('wrongpass', str(ctx.exception))

        pk = self.get_pk_obj(fname, password=password)
        self.assertIsInstance(pk.get_pkey_obj(), klass)

    def test_class_with_invalid_key_length(self):
        key = 'a' * (PrivateKey.max_length + 1)

        with self.assertRaises(InvalidValueError) as ctx:
            PrivateKey(key)
        self.assertIn('Invalid key length', str(ctx.exception))

    def test_get_pkey_obj_with_invalid_key(self):
        key = 'a b c'
        fname = 'abc'

        pk = PrivateKey(key, filename=fname)
        with self.assertRaises(InvalidValueError) as ctx:
            pk.get_pkey_obj()
        self.assertIn(f'Invalid key {fname}', str(ctx.exception))

    def test_get_pkey_obj_with_plain_rsa_key(self):
        pk = self.get_pk_obj('test_rsa.key')
        self.assertIsInstance(pk.get_pkey_obj(), paramiko.RSAKey)

    def test_get_pkey_obj_with_plain_ed25519_key(self):
        pk = self.get_pk_obj('test_ed25519.key')
        self.assertIsInstance(pk.get_pkey_obj(), paramiko.Ed25519Key)

    def test_get_pkey_obj_with_encrypted_rsa_key(self):
        fname = 'test_rsa_password.key'
        password = 'television'
        self._test_with_encrypted_key(fname, password, paramiko.RSAKey)

    def test_get_pkey_obj_with_encrypted_ed25519_key(self):
        fname = 'test_ed25519_password.key'
        password = 'abc123'
        self._test_with_encrypted_key(fname, password, paramiko.Ed25519Key)

    def test_get_pkey_obj_with_encrypted_new_rsa_key(self):
        fname = 'test_new_rsa_password.key'
        password = '123456'
        self._test_with_encrypted_key(fname, password, paramiko.RSAKey)

    def test_get_pkey_obj_rejects_plain_new_dsa_key(self):
        pk = self.get_pk_obj('test_new_dsa.key')
        with self.assertRaises(InvalidValueError):
            pk.get_pkey_obj()

    def test_parse_name(self):
        key = '-----BEGIN PRIVATE KEY-----'
        pk = PrivateKey(key)
        name, _ = pk.parse_name(pk.iostr, pk.tag_to_name)
        self.assertIsNone(name)

        key = '-----BEGIN xxx PRIVATE KEY-----'
        pk = PrivateKey(key)
        name, _ = pk.parse_name(pk.iostr, pk.tag_to_name)
        self.assertIsNone(name)

        key = '-----BEGIN  RSA PRIVATE KEY-----'
        pk = PrivateKey(key)
        name, _ = pk.parse_name(pk.iostr, pk.tag_to_name)
        self.assertIsNone(name)

        key = '-----BEGIN RSA  PRIVATE KEY-----'
        pk = PrivateKey(key)
        name, _ = pk.parse_name(pk.iostr, pk.tag_to_name)
        self.assertIsNone(name)

        key = '-----BEGIN RSA PRIVATE  KEY-----'
        pk = PrivateKey(key)
        name, _ = pk.parse_name(pk.iostr, pk.tag_to_name)
        self.assertIsNone(name)

        for tag, to_name in PrivateKey.tag_to_name.items():
            key = f'-----BEGIN {tag} PRIVATE KEY----- \r\n'
            pk = PrivateKey(key)
            name, length = pk.parse_name(pk.iostr, pk.tag_to_name)
            self.assertEqual(name, to_name)
            self.assertEqual(length, len(key))


class TestWsockHandler(unittest.TestCase):

    def test_check_origin(self):
        request = HTTPServerRequest(uri='/')
        obj = Mock(spec=WsockHandler, request=request)

        obj.origin_policy = 'same'
        request.headers['Host'] = 'www.example.com:4433'
        origin = 'https://www.example.com:4433'
        self.assertTrue(WsockHandler.check_origin(obj, origin))

        origin = 'https://www.example.com'
        self.assertFalse(WsockHandler.check_origin(obj, origin))

        obj.origin_policy = 'primary'
        self.assertTrue(WsockHandler.check_origin(obj, origin))

        origin = 'https://blog.example.com'
        self.assertTrue(WsockHandler.check_origin(obj, origin))

        origin = 'https://blog.example.org'
        self.assertFalse(WsockHandler.check_origin(obj, origin))

        origin = 'https://blog.example.org'
        obj.origin_policy = {'https://blog.example.org'}
        self.assertTrue(WsockHandler.check_origin(obj, origin))

        origin = 'http://blog.example.org'
        obj.origin_policy = {'http://blog.example.org'}
        self.assertTrue(WsockHandler.check_origin(obj, origin))

        origin = 'http://blog.example.org'
        obj.origin_policy = {'https://blog.example.org'}
        self.assertFalse(WsockHandler.check_origin(obj, origin))

        obj.origin_policy = '*'
        origin = 'https://blog.example.org'
        self.assertTrue(WsockHandler.check_origin(obj, origin))

    def test_failed_weak_ref(self):
        request = HTTPServerRequest(uri='/')
        obj = Mock(spec=WsockHandler, request=request)
        obj.src_addr = ("127.0.0.1", 8888)

        class FakeWeakRef:
            def __init__(self):
                self.count = 0

            def __call__(self):
                self.count += 1

        ref = FakeWeakRef()
        obj.worker_ref = ref
        WsockHandler.on_message(obj, b'{"data": "somestuff"}')
        self.assertGreaterEqual(ref.count, 1)
        obj.close.assert_called_with(reason='No worker found')

    def test_worker_closed(self):
        request = HTTPServerRequest(uri='/')
        obj = Mock(spec=WsockHandler, request=request)
        obj.src_addr = ("127.0.0.1", 8888)

        class Worker:
            def __init__(self):
                self.closed = True

        class FakeWeakRef:
            def __call__(self):
                return Worker()

        ref = FakeWeakRef()
        obj.worker_ref = ref
        WsockHandler.on_message(obj, b'{"data": "somestuff"}')
        obj.close.assert_called_with(reason='Worker closed')

class TestIndexHandlerAllowedHosts(unittest.TestCase):

    def _make_handler(self, allowed_hosts=None):
        handler_obj = Mock(spec=IndexHandler)
        # A real handler starts with an empty per-request cache;
        # a Mock would otherwise hand back a Mock for it.
        handler_obj._effective_hosts = None
        handler_obj.allowed_hosts = allowed_hosts or []
        handler_obj.get_user_hosts = list
        handler_obj.get_effective_hosts = lambda: \
            IndexHandler.get_effective_hosts(handler_obj)
        handler_obj.check_allowed_hosts = lambda h, p: \
            IndexHandler.check_allowed_hosts(handler_obj, h, p)
        return handler_obj

    def test_no_allowed_hosts_allows_any(self):
        h = self._make_handler([])
        # Should not raise
        h.check_allowed_hosts('any.host', 22)

    def test_allowed_host_passes(self):
        hosts = [
            {'name': 'Server', 'hostname': '10.0.1.5', 'port': 22},
        ]
        h = self._make_handler(hosts)
        # Should not raise
        h.check_allowed_hosts('10.0.1.5', 22)

    def test_disallowed_host_rejected(self):
        hosts = [
            {'name': 'Server', 'hostname': '10.0.1.5', 'port': 22},
        ]
        h = self._make_handler(hosts)
        with self.assertRaises(tornado.web.HTTPError) as ctx:
            h.check_allowed_hosts('evil.host', 22)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_wrong_port_rejected(self):
        hosts = [
            {'name': 'Server', 'hostname': '10.0.1.5', 'port': 22},
        ]
        h = self._make_handler(hosts)
        with self.assertRaises(tornado.web.HTTPError) as ctx:
            h.check_allowed_hosts('10.0.1.5', 2222)
        self.assertEqual(ctx.exception.status_code, 403)


class FakeHostKeys:
    """Records what load_configured_host_key/_add_host_key actually store,
    so tests can assert against the paramiko host key store itself rather
    than just the merged host list."""

    def __init__(self):
        self.added = []

    def add(self, hostname, key_type, key):
        self.added.append((hostname, key_type, key))


class TestLoadConfiguredHostKey(unittest.TestCase):

    # Two distinct, valid ed25519 public keys (different key material).
    admin_key = ('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrAb7GEqLHlbAF9gMdvD'
                 'ZzdKnd2MlrZ2sAs5qF7XMRF')
    user_key = ('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEF7nSZPAVEiuuEjgBzsnv'
                'kt5yRbRIRTS8tYY7eyhEVV')

    def _key_object(self, key_str):
        b64 = key_str.strip().split()[1]
        return paramiko.Ed25519Key(data=base64.b64decode(b64))

    def _make_handler(self, allowed_hosts):
        handler_obj = Mock(spec=IndexHandler)
        # A real handler starts with an empty per-request cache;
        # a Mock would otherwise hand back a Mock for it.
        handler_obj._effective_hosts = None
        handler_obj.allowed_hosts = allowed_hosts
        handler_obj.get_effective_hosts = lambda: \
            IndexHandler.get_effective_hosts(handler_obj)
        handler_obj.load_configured_host_key = lambda h, p: \
            IndexHandler.load_configured_host_key(handler_obj, h, p)
        handler_obj._add_host_key = lambda h, p, k: \
            IndexHandler._add_host_key(handler_obj, h, p, k)
        handler_obj.ssh_client = Mock()
        handler_obj.ssh_client._host_keys = FakeHostKeys()
        return handler_obj

    def test_admin_key_wins_collision(self):
        # Admin and user both pin a DIFFERENT key for the same hostname:port.
        # The admin key must be what reaches the paramiko host key store,
        # and the user's key must never appear there.
        admin = [{'name': 'prod', 'hostname': '10.0.1.5', 'port': 22,
                  'host_keys': [self.admin_key]}]
        user = [{'name': 'mine', 'hostname': '10.0.1.5', 'port': 22,
                 'host_keys': [self.user_key]}]
        h = self._make_handler(admin)
        h.get_user_hosts = lambda: user

        h.load_configured_host_key('10.0.1.5', 22)

        added = h.ssh_client._host_keys.added
        self.assertEqual(len(added), 1)
        hostname, key_type, key = added[0]
        self.assertEqual(hostname, '10.0.1.5')
        self.assertEqual(key_type, 'ssh-ed25519')
        self.assertEqual(key, self._key_object(self.admin_key))
        self.assertNotEqual(key, self._key_object(self.user_key))

    def test_no_admin_allowlist_still_loads_user_key(self):
        # This is the dropped-guard branch: no administrator allowlist is
        # configured at all, but a personal host's pinned key must still
        # load into the paramiko store.
        user = [{'name': 'mine', 'hostname': '10.0.1.5', 'port': 22,
                 'host_keys': [self.user_key]}]
        h = self._make_handler([])
        h.get_user_hosts = lambda: user

        h.load_configured_host_key('10.0.1.5', 22)

        added = h.ssh_client._host_keys.added
        self.assertEqual(len(added), 1)
        hostname, _key_type, key = added[0]
        self.assertEqual(hostname, '10.0.1.5')
        self.assertEqual(key, self._key_object(self.user_key))

    def test_feature_disabled_user_key_not_loaded(self):
        # Drive the real get_user_hosts gating (not a stub) so this proves
        # the disabled-feature path, not just an empty-list stand-in.
        h = self._make_handler([])
        h.user_hosts_enabled = False
        h.user_data_dir = '/nonexistent-should-never-be-read'
        h.user_header = 'X-Authentik-Username'
        h.request = Mock(headers={'X-Authentik-Username': 'alice'})
        h.get_user_hosts = lambda: IndexHandler.get_user_hosts(h)

        with patch.object(user_data, 'read_hosts', return_value=[
                {'name': 'mine', 'hostname': '10.0.1.5', 'port': 22,
                 'host_keys': [self.user_key]}]) as mock_read:
            h.load_configured_host_key('10.0.1.5', 22)
            mock_read.assert_not_called()

        self.assertEqual(h.ssh_client._host_keys.added, [])


class TestIndexHandler(unittest.TestCase):
    def test_null_in_encoding(self):
        handler = Mock(spec=IndexHandler)
        # A real handler starts with an empty per-request cache;
        # a Mock would otherwise hand back a Mock for it.
        handler._effective_hosts = None

        # This is a little nasty, but the index handler has a lot of
        # dependencies to mock. Mocking out everything but the bits
        # we want to test lets us test this case without needing to
        # refactor the relevant code out of IndexHandler
        def parse_encoding(data):
            return IndexHandler.parse_encoding(handler, data)
        handler.parse_encoding = parse_encoding

        ssh = Mock(spec=SSHClient)
        stdin = io.BytesIO()
        stdout = io.BytesIO(initial_bytes=b"UTF-8\0")
        stderr = io.BytesIO()
        ssh.exec_command.return_value = (stdin, stdout, stderr)

        encoding = IndexHandler.get_default_encoding(handler, ssh)
        self.assertEqual("utf-8", encoding)


class TestEncodingDetection(unittest.TestCase):
    """Both probes are driven end to end, as get_default_encoding runs them
    in order and the second one is what a macOS server actually answers."""

    def detect(self, *outputs):
        handler = Mock(spec=IndexHandler)
        handler._effective_hosts = None
        handler.parse_encoding = lambda data: IndexHandler.parse_encoding(
            handler, data
        )

        ssh = Mock(spec=SSHClient)
        ssh.exec_command.side_effect = [
            (io.BytesIO(), io.BytesIO(initial_bytes=out), io.BytesIO())
            for out in outputs
        ]

        return IndexHandler.get_default_encoding(handler, ssh)

    def test_ascii_is_not_taken_as_the_server_encoding(self):
        # A shell that reports US-ASCII has told us nothing: browsers map
        # that label to windows-1252, so honouring it would mangle every
        # multi-byte character the terminal emits.
        self.assertEqual('utf-8', self.detect(b'US-ASCII\r\n',
                                              b'US-ASCII\r\n'))
        self.assertEqual('utf-8', self.detect(b'ANSI_X3.4-1968\r\n',
                                              b'ANSI_X3.4-1968\r\n'))

    def test_login_shell_answer_wins(self):
        # The macOS case: the login shell sources the profile that exports
        # LANG, the interactive one does not.
        self.assertEqual('UTF-8', self.detect(b'UTF-8\r\n',
                                              b'US-ASCII\r\n'))

    def test_second_probe_answers_when_the_first_is_useless(self):
        self.assertEqual('GBK', self.detect(b'US-ASCII\r\n', b'GBK\r\n'))

    def test_real_encoding_is_still_honoured(self):
        self.assertEqual('UTF-8', self.detect(b'UTF-8\r\n'))


class TestIndexHandlerStoredKey(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.username = 'testuser'
        user_keys.generate_key_pair(self.tmpdir, self.username)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_handler(self, headers=None, arguments=None):
        handler_obj = Mock(spec=IndexHandler)
        # A real handler starts with an empty per-request cache;
        # a Mock would otherwise hand back a Mock for it.
        handler_obj._effective_hosts = None
        handler_obj.user_key_dir = self.tmpdir
        handler_obj.user_header = 'X-Authentik-Username'
        handler_obj.policy = Mock()

        request = HTTPServerRequest(uri='/')
        if headers:
            for k, v in headers.items():
                request.headers[k] = v
        handler_obj.request = request

        handler_obj.allowed_hosts = []
        handler_obj.check_allowed_hosts = lambda h, p: None
        handler_obj.ssh_client = Mock()

        def get_argument(name, default=''):
            if arguments and name in arguments:
                return arguments[name]
            return default
        handler_obj.get_argument = get_argument

        def get_value(name):
            val = get_argument(name, None)
            if not val:
                raise InvalidValueError(f'Missing value {name}')
            return val
        handler_obj.get_value = get_value

        handler_obj.get_privatekey = lambda: ('', '')
        handler_obj.get_hostname = lambda: '10.0.0.1'
        handler_obj.get_port = lambda: 22

        return handler_obj

    def test_get_args_with_stored_key(self):
        h = self._make_handler(
            headers={'X-Authentik-Username': self.username},
            arguments={
                'hostname': '10.0.0.1',
                'port': '22',
                'username': 'sshuser',
                'key_source': 'stored',
            }
        )
        args = IndexHandler.get_args(h)
        hostname, _port, _username, _password, pkey = args
        self.assertEqual(hostname, '10.0.0.1')
        self.assertIsInstance(pkey, paramiko.Ed25519Key)

    def test_get_args_without_user_header(self):
        h = self._make_handler(
            headers={},
            arguments={
                'hostname': '10.0.0.1',
                'port': '22',
                'username': 'sshuser',
                'key_source': 'stored',
            }
        )
        with self.assertRaises(InvalidValueError) as ctx:
            IndexHandler.get_args(h)
        self.assertIn('No authenticated user', str(ctx.exception))

    def test_get_args_stored_key_missing(self):
        h = self._make_handler(
            headers={'X-Authentik-Username': 'nonexistent'},
            arguments={
                'hostname': '10.0.0.1',
                'port': '22',
                'username': 'sshuser',
                'key_source': 'stored',
            }
        )
        with self.assertRaises(InvalidValueError) as ctx:
            IndexHandler.get_args(h)
        self.assertIn('No stored key', str(ctx.exception))

