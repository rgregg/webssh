import json
import os
import random
import tempfile
import threading
import unittest
from unittest import mock
import tornado.websocket
import tornado.gen

from tornado.testing import AsyncHTTPTestCase
from tornado.httpclient import HTTPError
from tornado.options import options
from tests.sshserver import run_ssh_server, banner, Server
from tests.test_transfer import FakeSFTP, FakeAttr
from tests.utils import encode_multipart_formdata, read_file, make_tests_data_path  # noqa
from webssh import handler
from webssh.main import make_app, make_handlers
from webssh.settings import (
    get_app_settings, get_server_settings, max_body_size
)
from webssh.utils import to_str
from webssh import worker
from webssh.worker import clients

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode


swallow_http_errors = handler.swallow_http_errors
server_encodings = {e.strip() for e in Server.encodings}


class OptionsRestoreMixin(object):
    """Restore tornado's global options after a test mutates them.

    ``options`` is process-global, so a test class that sets an option
    and does not put it back leaks that value into whichever test runs
    next. Snapshot the previous value of every option a test overrides
    and restore exactly that, rather than a hardcoded guess at what it
    used to be.
    """

    def override_options(self, **overrides):
        saved = {}
        for name in overrides:
            saved[name] = getattr(options, name)
        # Registered before anything is mutated, so a failure partway
        # through still restores whatever was already changed.
        self.addCleanup(self._restore_options_snapshot, saved)
        for name, value in overrides.items():
            setattr(options, name, value)

    def _restore_options_snapshot(self, saved):
        for name, value in saved.items():
            setattr(options, name, value)


class TestOptionsRestoreMixin(unittest.TestCase):

    class Case(OptionsRestoreMixin, unittest.TestCase):
        overrides = {}
        raises = False

        def runTest(self):
            self.override_options(**self.overrides)
            if self.raises:
                raise RuntimeError('boom')

    def run_case(self, overrides, raises=False):
        case = self.Case()
        case.overrides = overrides
        case.raises = raises
        case.run(unittest.TestResult())

    def test_restores_previous_values(self):
        self.addCleanup(setattr, options, 'policy', options.policy)
        self.addCleanup(setattr, options, 'user_hosts', options.user_hosts)
        options.policy = 'warning'
        options.user_hosts = False

        self.run_case({'policy': 'reject', 'user_hosts': True})

        self.assertEqual(options.policy, 'warning')
        self.assertIs(options.user_hosts, False)

    def test_restores_when_the_test_fails(self):
        self.addCleanup(setattr, options, 'policy', options.policy)
        options.policy = 'warning'

        self.run_case({'policy': 'reject'}, raises=True)

        self.assertEqual(options.policy, 'warning')

    def test_leaves_untouched_options_alone(self):
        self.addCleanup(setattr, options, 'policy', options.policy)
        self.addCleanup(setattr, options, 'origin', options.origin)
        options.policy = 'warning'
        options.origin = 'same'

        self.run_case({'policy': 'reject'})

        self.assertEqual(options.origin, 'same')


class TestSuiteLeavesOptionsClean(unittest.TestCase):
    """The suite is the only automated guard on the security invariants,
    so it must not depend on which test happened to run first.

    Run the classes that mutate the most options and assert every one of
    them is handed back as it was found.
    """

    watched = ('debug', 'xsrf', 'policy', 'hostfile', 'syshostfile',
               'tdstream', 'origin', 'user_hosts', 'userdatadir',
               'userheader', 'config', 'maxconn')

    def assert_no_leak(self, cls):
        before = {}
        for name in self.watched:
            before[name] = getattr(options, name)

        suite = unittest.TestLoader().loadTestsFromTestCase(cls)
        suite.run(unittest.TestResult())

        leaked = {}
        for name in self.watched:
            after = getattr(options, name)
            if after != before[name]:
                leaked[name] = (before[name], after)
        self.assertEqual(leaked, {})

    def test_user_host_key_isolation_leaves_options_clean(self):
        self.assert_no_leak(TestUserHostKeyIsolation)

    def test_user_data_api_leaves_options_clean(self):
        self.assert_no_leak(TestUserDataApi)


class TestAppBase(OptionsRestoreMixin, AsyncHTTPTestCase):

    def get_httpserver_options(self):
        return get_server_settings(options)

    def assert_response(self, bstr, response):
        if swallow_http_errors:
            self.assertEqual(response.code, 200)
            self.assertIn(bstr, response.body)
        else:
            self.assertEqual(response.code, 400)
            self.assertIn(b'Bad Request', response.body)

    def assert_status_in(self, status, data):
        self.assertIsNone(data['encoding'])
        self.assertIsNone(data['id'])
        self.assertIn(status, data['status'])

    def assert_status_equal(self, status, data):
        self.assertIsNone(data['encoding'])
        self.assertIsNone(data['id'])
        self.assertEqual(status, data['status'])

    def assert_status_none(self, data):
        self.assertIsNotNone(data['encoding'])
        self.assertIsNotNone(data['id'])
        self.assertIsNone(data['status'])

    def fetch_request(self, url, method='GET', body='', headers={}, sync=True):
        if not sync and url.startswith('/'):
            url = self.get_url(url)

        if isinstance(body, dict):
            body = urlencode(body)

        if not headers:
            headers = self.headers
        else:
            headers.update(self.headers)

        client = self if sync else self.get_http_client()
        return client.fetch(url, method=method, body=body, headers=headers)

    def sync_post(self, url, body, headers={}):
        return self.fetch_request(url, 'POST', body, headers)

    def async_post(self, url, body, headers={}):
        return self.fetch_request(url, 'POST', body, headers, sync=False)


class TestAppBasic(TestAppBase):

    running = [True]
    sshserver_port = 2200
    body = 'hostname=127.0.0.1&port={}&_xsrf=yummy&username=robey&password=foo'.format(sshserver_port) # noqa
    headers = {'Cookie': '_xsrf=yummy'}

    def get_app(self):
        self.body_dict = {
            'hostname': '127.0.0.1',
            'port': str(self.sshserver_port),
            'username': 'robey',
            'password': '',
            '_xsrf': 'yummy'
        }
        loop = self.io_loop
        options.debug = False
        options.policy = random.choice(['warning', 'autoadd'])
        options.hostfile = ''
        options.syshostfile = ''
        options.tdstream = ''
        options.delay = 0.1
        app = make_app(make_handlers(loop, options), get_app_settings(options))
        return app

    @classmethod
    def setUpClass(cls):
        print('='*20)
        t = threading.Thread(
            target=run_ssh_server, args=(cls.sshserver_port, cls.running)
        )
        t.setDaemon(True)
        t.start()

    @classmethod
    def tearDownClass(cls):
        cls.running.pop()
        print('='*20)

    def test_app_with_invalid_form_for_missing_argument(self):
        response = self.fetch('/')
        self.assertEqual(response.code, 200)

        body = 'port=7000&username=admin&password&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assert_response(b'Missing argument hostname', response)

        body = 'hostname=127.0.0.1&port=7000&password&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assert_response(b'Missing argument username', response)

        body = 'hostname=&port=&username=&password&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assert_response(b'Missing value hostname', response)

        body = 'hostname=127.0.0.1&port=7000&username=&password&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assert_response(b'Missing value username', response)

    def test_app_with_invalid_form_for_invalid_value(self):
        body = 'hostname=127.0.0&port=22&username=&password&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assert_response(b'Invalid hostname', response)

        body = 'hostname=http://www.googe.com&port=22&username=&password&_xsrf=yummy'  # noqa
        response = self.sync_post('/', body)
        self.assert_response(b'Invalid hostname', response)

        body = 'hostname=127.0.0.1&port=port&username=&password&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assert_response(b'Invalid port', response)

        body = 'hostname=127.0.0.1&port=70000&username=&password&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assert_response(b'Invalid port', response)

    def test_app_with_wrong_hostname_ip(self):
        body = 'hostname=127.0.0.2&port=2200&username=admin&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assertEqual(response.code, 200)
        self.assertIn(b'Unable to connect to', response.body)

    def test_app_with_wrong_hostname_domain(self):
        body = 'hostname=xxxxxxxxxxxx&port=2200&username=admin&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assertEqual(response.code, 200)
        self.assertIn(b'Unable to connect to', response.body)

    def test_app_with_wrong_port(self):
        body = 'hostname=127.0.0.1&port=7000&username=admin&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assertEqual(response.code, 200)
        self.assertIn(b'Unable to connect to', response.body)

    def test_app_with_wrong_credentials(self):
        response = self.sync_post('/', self.body + 's')
        self.assert_status_in('Authentication failed.', json.loads(to_str(response.body))) # noqa

    def test_app_with_correct_credentials(self):
        response = self.sync_post('/', self.body)
        self.assert_status_none(json.loads(to_str(response.body)))

    def test_app_with_correct_credentials_but_with_no_port(self):
        default_port = handler.DEFAULT_PORT
        handler.DEFAULT_PORT = self.sshserver_port

        # with no port value
        body = self.body.replace(str(self.sshserver_port), '')
        response = self.sync_post('/', body)
        self.assert_status_none(json.loads(to_str(response.body)))

        # with no port argument
        body = body.replace('port=&', '')
        response = self.sync_post('/', body)
        self.assert_status_none(json.loads(to_str(response.body)))

        handler.DEFAULT_PORT = default_port

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_timeout(self):
        url = self.get_url('/')
        response = yield self.async_post(url, self.body)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        yield tornado.gen.sleep(options.delay + 0.1)
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertIsNone(msg)
        self.assertEqual(ws.close_reason, 'Websocket authentication failed.')

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_but_ip_not_matched(self):
        url = self.get_url('/')
        response = yield self.async_post(url, self.body)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

        clients = handler.clients
        handler.clients = {}
        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertIsNone(msg)
        self.assertEqual(ws.close_reason, 'Websocket authentication failed.')
        handler.clients = clients

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_user_robey(self):
        url = self.get_url('/')
        response = yield self.async_post(url, self.body)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertEqual(to_str(msg, data['encoding']), banner)
        ws.close()

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_but_without_id_argument(self):
        url = self.get_url('/')
        response = yield self.async_post(url, self.body)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

        url = url.replace('http', 'ws')
        ws_url = url + 'ws'
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertIsNone(msg)
        self.assertIn('Missing argument id', ws.close_reason)

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_but_empty_id(self):
        url = self.get_url('/')
        response = yield self.async_post(url, self.body)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id='
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertIsNone(msg)
        self.assertIn('Missing value id', ws.close_reason)

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_but_wrong_id(self):
        url = self.get_url('/')
        response = yield self.async_post(url, self.body)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=1' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertIsNone(msg)
        self.assertIn('Websocket authentication failed', ws.close_reason)

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_user_bar(self):
        body = self.body.replace('robey', 'bar')
        url = self.get_url('/')
        response = yield self.async_post(url, body)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertEqual(to_str(msg, data['encoding']), banner)

        # messages below will be ignored silently
        yield ws.write_message('hello')
        yield ws.write_message('"hello"')
        yield ws.write_message('[hello]')
        yield ws.write_message(json.dumps({'resize': []}))
        yield ws.write_message(json.dumps({'resize': {}}))
        yield ws.write_message(json.dumps({'resize': 'ab'}))
        yield ws.write_message(json.dumps({'resize': ['a', 'b']}))
        yield ws.write_message(json.dumps({'resize': {'a': 1, 'b': 2}}))
        yield ws.write_message(json.dumps({'resize': [100]}))
        yield ws.write_message(json.dumps({'resize': [100]*10}))
        yield ws.write_message(json.dumps({'resize': [-1, -1]}))
        yield ws.write_message(json.dumps({'data': [1]}))
        yield ws.write_message(json.dumps({'data': (1,)}))
        yield ws.write_message(json.dumps({'data': {'a': 2}}))
        yield ws.write_message(json.dumps({'data': 1}))
        yield ws.write_message(json.dumps({'data': 2.1}))
        yield ws.write_message(json.dumps({'key-non-existed': 'hello'}))
        # end - those just for testing webssh websocket stablity

        yield ws.write_message(json.dumps({'resize': [79, 23]}))
        msg = yield ws.read_message()
        self.assertEqual(b'resized', msg)

        yield ws.write_message(json.dumps({'data': 'bye'}))
        msg = yield ws.read_message()
        self.assertEqual(b'bye', msg)
        ws.close()

    @tornado.testing.gen_test
    def test_app_auth_with_valid_pubkey_by_urlencoded_form(self):
        url = self.get_url('/')
        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        self.body_dict.update(privatekey=privatekey)
        response = yield self.async_post(url, self.body_dict)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertEqual(to_str(msg, data['encoding']), banner)
        ws.close()

    @tornado.testing.gen_test
    def test_app_auth_with_valid_pubkey_by_multipart_form(self):
        url = self.get_url('/')
        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }
        response = yield self.async_post(url, body, headers=headers)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertEqual(to_str(msg, data['encoding']), banner)
        ws.close()

    @tornado.testing.gen_test
    def test_app_auth_with_invalid_pubkey_for_user_robey(self):
        url = self.get_url('/')
        privatekey = 'h' * 1024
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }

        if swallow_http_errors:
            response = yield self.async_post(url, body, headers=headers)
            self.assertIn(b'Invalid key', response.body)
        else:
            with self.assertRaises(HTTPError) as ctx:
                yield self.async_post(url, body, headers=headers)
            self.assertIn('Bad Request', ctx.exception.message)

    @tornado.testing.gen_test
    def test_app_auth_with_pubkey_exceeds_key_max_size(self):
        url = self.get_url('/')
        privatekey = 'h' * (handler.PrivateKey.max_length + 1)
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }
        if swallow_http_errors:
            response = yield self.async_post(url, body, headers=headers)
            self.assertIn(b'Invalid key', response.body)
        else:
            with self.assertRaises(HTTPError) as ctx:
                yield self.async_post(url, body, headers=headers)
            self.assertIn('Bad Request', ctx.exception.message)

    @tornado.testing.gen_test
    def test_app_auth_with_pubkey_cannot_be_decoded_by_multipart_form(self):
        url = self.get_url('/')
        privatekey = 'h' * 1024
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        body = body.encode('utf-8')
        # added some gbk bytes to the privatekey, make it cannot be decoded
        body = body[:-100] + b'\xb4\xed\xce\xf3' + body[-100:]
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }
        if swallow_http_errors:
            response = yield self.async_post(url, body, headers=headers)
            self.assertIn(b'Invalid unicode', response.body)
        else:
            with self.assertRaises(HTTPError) as ctx:
                yield self.async_post(url, body, headers=headers)
            self.assertIn('Bad Request', ctx.exception.message)

    def test_app_post_form_with_large_body_size_by_multipart_form(self):
        privatekey = 'h' * (2 * max_body_size)
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }
        response = self.sync_post('/', body, headers=headers)
        self.assertIn(response.code, [400, 599])

    def test_app_post_form_with_large_body_size_by_urlencoded_form(self):
        privatekey = 'h' * (2 * max_body_size)
        body = self.body + '&privatekey=' + privatekey
        response = self.sync_post('/', body)
        self.assertIn(response.code, [400, 599])

    @tornado.testing.gen_test
    def test_app_with_user_keyonly_for_bad_authentication_type(self):
        self.body_dict.update(username='keyonly', password='foo')
        response = yield self.async_post('/', self.body_dict)
        self.assertEqual(response.code, 200)
        self.assert_status_in('Bad authentication type', json.loads(to_str(response.body))) # noqa

    @tornado.testing.gen_test
    def test_app_with_user_pass2fa_with_correct_passwords(self):
        self.body_dict.update(username='pass2fa', password='password',
                              totp='passcode')
        response = yield self.async_post('/', self.body_dict)
        self.assertEqual(response.code, 200)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

    @tornado.testing.gen_test
    def test_app_with_user_pass2fa_with_wrong_pkey_correct_passwords(self):
        url = self.get_url('/')
        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        self.body_dict.update(username='pass2fa', password='password',
                              privatekey=privatekey, totp='passcode')
        response = yield self.async_post(url, self.body_dict)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

    @tornado.testing.gen_test
    def test_app_with_user_pkey2fa_with_correct_passwords(self):
        url = self.get_url('/')
        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        self.body_dict.update(username='pkey2fa', password='password',
                              privatekey=privatekey, totp='passcode')
        response = yield self.async_post(url, self.body_dict)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

    @tornado.testing.gen_test
    def test_app_with_user_pkey2fa_with_wrong_password(self):
        url = self.get_url('/')
        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        self.body_dict.update(username='pkey2fa', password='wrongpassword',
                              privatekey=privatekey, totp='passcode')
        response = yield self.async_post(url, self.body_dict)
        data = json.loads(to_str(response.body))
        self.assert_status_in('Authentication failed', data)

    @tornado.testing.gen_test
    def test_app_with_user_pkey2fa_with_wrong_passcode(self):
        url = self.get_url('/')
        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        self.body_dict.update(username='pkey2fa', password='password',
                              privatekey=privatekey, totp='wrongpasscode')
        response = yield self.async_post(url, self.body_dict)
        data = json.loads(to_str(response.body))
        self.assert_status_in('Authentication failed', data)

    @tornado.testing.gen_test
    def test_app_with_user_pkey2fa_with_empty_passcode(self):
        url = self.get_url('/')
        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        self.body_dict.update(username='pkey2fa', password='password',
                              privatekey=privatekey, totp='')
        response = yield self.async_post(url, self.body_dict)
        data = json.loads(to_str(response.body))
        self.assert_status_in('Need a verification code', data)


class OtherTestBase(TestAppBase):
    sshserver_port = 3300
    headers = {'Cookie': '_xsrf=yummy'}
    debug = False
    policy = None
    xsrf = True
    hostfile = ''
    syshostfile = ''
    tdstream = ''
    maxconn = 20
    origin = 'same'
    encodings = []
    body = {
        'hostname': '127.0.0.1',
        'port': '',
        'username': 'robey',
        'password': 'foo',
        '_xsrf': 'yummy'
    }

    def get_app(self):
        self.body.update(port=str(self.sshserver_port))
        loop = self.io_loop
        options.debug = self.debug
        options.xsrf = self.xsrf
        options.policy = self.policy if self.policy else random.choice(['warning', 'autoadd'])  # noqa
        options.hostfile = self.hostfile
        options.syshostfile = self.syshostfile
        options.tdstream = self.tdstream
        options.maxconn = self.maxconn
        options.origin = self.origin
        app = make_app(make_handlers(loop, options), get_app_settings(options))
        return app

    def setUp(self):
        print('='*20)
        self.running = True
        OtherTestBase.sshserver_port += 1

        t = threading.Thread(
            target=run_ssh_server,
            args=(self.sshserver_port, self.running, self.encodings)
        )
        t.setDaemon(True)
        t.start()
        super(OtherTestBase, self).setUp()

    def tearDown(self):
        self.running = False
        print('='*20)
        super(OtherTestBase, self).tearDown()


class TestAppInDebugMode(OtherTestBase):

    debug = True

    def assert_response(self, bstr, response):
        if swallow_http_errors:
            self.assertEqual(response.code, 200)
            self.assertIn(bstr, response.body)
        else:
            self.assertEqual(response.code, 500)
            self.assertIn(b'Uncaught exception', response.body)

    def test_server_error_for_post_method(self):
        body = dict(self.body, error='raise')
        response = self.sync_post('/', body)
        self.assert_response(b'"status": "Internal Server Error"', response)

    def test_html(self):
        response = self.fetch('/', method='GET')
        self.assertIn(b'novalidate>', response.body)


class TestAppWithLargeBuffer(OtherTestBase):

    @tornado.testing.gen_test
    def test_app_for_sending_message_with_large_size(self):
        url = self.get_url('/')
        response = yield self.async_post(url, dict(self.body, username='foo'))
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertEqual(to_str(msg, data['encoding']), banner)

        send = 'h' * (64 * 1024) + '\r\n\r\n'
        yield ws.write_message(json.dumps({'data': send}))
        lst = []
        while True:
            msg = yield ws.read_message()
            lst.append(msg)
            if msg.endswith(b'\r\n\r\n'):
                break
        recv = b''.join(lst).decode(data['encoding'])
        self.assertEqual(send, recv)
        ws.close()


class TestAppWithRejectPolicy(OtherTestBase):

    policy = 'reject'
    hostfile = make_tests_data_path('known_hosts_example')

    @tornado.testing.gen_test
    def test_app_with_hostname_not_in_hostkeys(self):
        response = yield self.async_post('/', self.body)
        data = json.loads(to_str(response.body))
        message = 'Connection to {}:{} is not allowed.'.format(self.body['hostname'], self.sshserver_port) # noqa
        self.assertEqual(message, data['status'])


class TestAppWithBadHostKey(OtherTestBase):

    policy = random.choice(['warning', 'autoadd', 'reject'])
    hostfile = make_tests_data_path('test_known_hosts')

    def setUp(self):
        self.sshserver_port = 2222
        super(TestAppWithBadHostKey, self).setUp()

    @tornado.testing.gen_test
    def test_app_with_bad_host_key(self):
        response = yield self.async_post('/', self.body)
        data = json.loads(to_str(response.body))
        self.assertEqual('Bad host key.', data['status'])


class TestAppWithTrustedStream(OtherTestBase):
    tdstream = '127.0.0.2'

    def test_with_forbidden_get_request(self):
        response = self.fetch('/', method='GET')
        self.assertEqual(response.code, 403)
        self.assertIn('Forbidden', response.error.message)

    def test_with_forbidden_post_request(self):
        response = self.sync_post('/', self.body)
        self.assertEqual(response.code, 403)
        self.assertIn('Forbidden', response.error.message)

    def test_with_forbidden_put_request(self):
        response = self.fetch_request('/', method='PUT', body=self.body)
        self.assertEqual(response.code, 403)
        self.assertIn('Forbidden', response.error.message)


class TestAppNotFoundHandler(OtherTestBase):

    custom_headers = handler.MixinHandler.custom_headers

    def test_with_not_found_get_request(self):
        response = self.fetch('/pathnotfound', method='GET')
        self.assertEqual(response.code, 404)
        self.assertEqual(
            response.headers['Server'], self.custom_headers['Server']
        )
        self.assertIn(b'404: Not Found', response.body)

    def test_with_not_found_post_request(self):
        response = self.sync_post('/pathnotfound', self.body)
        self.assertEqual(response.code, 404)
        self.assertEqual(
            response.headers['Server'], self.custom_headers['Server']
        )
        self.assertIn(b'404: Not Found', response.body)

    def test_with_not_found_put_request(self):
        response = self.fetch_request('/pathnotfound', method='PUT',
                                      body=self.body)
        self.assertEqual(response.code, 404)
        self.assertEqual(
            response.headers['Server'], self.custom_headers['Server']
        )
        self.assertIn(b'404: Not Found', response.body)


class TestAppWithHeadRequest(OtherTestBase):

    def test_with_index_path(self):
        response = self.fetch('/', method='HEAD')
        self.assertEqual(response.code, 200)

    def test_with_ws_path(self):
        response = self.fetch('/ws', method='HEAD')
        self.assertEqual(response.code, 405)

    def test_with_not_found_path(self):
        response = self.fetch('/notfound', method='HEAD')
        self.assertEqual(response.code, 404)


class TestAppWithPutRequest(OtherTestBase):

    xsrf = False

    @tornado.testing.gen_test
    def test_app_with_method_not_supported(self):
        with self.assertRaises(HTTPError) as ctx:
            yield self.fetch_request('/', 'PUT', self.body, sync=False)
        self.assertIn('Method Not Allowed', ctx.exception.message)


class TestAppWithTooManyConnections(OtherTestBase):

    maxconn = 1

    def setUp(self):
        clients.clear()
        super(TestAppWithTooManyConnections, self).setUp()

    @tornado.testing.gen_test
    def test_app_with_too_many_connections(self):
        clients['127.0.0.1'] = {'fake_worker_id': None}

        url = self.get_url('/')
        response = yield self.async_post(url, self.body)
        data = json.loads(to_str(response.body))
        self.assertEqual('Too many live connections.', data['status'])

        clients['127.0.0.1'].clear()
        response = yield self.async_post(url, self.body)
        self.assert_status_none(json.loads(to_str(response.body)))


class TestAppWithCrossOriginOperation(OtherTestBase):

    origin = 'http://www.example.com'

    @tornado.testing.gen_test
    def test_app_with_wrong_event_origin(self):
        body = dict(self.body, _origin='localhost')
        response = yield self.async_post('/', body)
        self.assert_status_equal('Cross origin operation is not allowed.', json.loads(to_str(response.body))) # noqa

    @tornado.testing.gen_test
    def test_app_with_wrong_header_origin(self):
        headers = dict(Origin='localhost')
        response = yield self.async_post('/', self.body, headers=headers)
        self.assert_status_equal('Cross origin operation is not allowed.', json.loads(to_str(response.body)), ) # noqa

    @tornado.testing.gen_test
    def test_app_with_correct_event_origin(self):
        body = dict(self.body, _origin=self.origin)
        response = yield self.async_post('/', body)
        self.assert_status_none(json.loads(to_str(response.body)))
        self.assertIsNone(response.headers.get('Access-Control-Allow-Origin'))

    @tornado.testing.gen_test
    def test_app_with_correct_header_origin(self):
        headers = dict(Origin=self.origin)
        response = yield self.async_post('/', self.body, headers=headers)
        self.assert_status_none(json.loads(to_str(response.body)))
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'), self.origin
        )


class TestAppWithBadEncoding(OtherTestBase):

    encodings = [u'\u7f16\u7801']

    @tornado.testing.gen_test
    def test_app_with_a_bad_encoding(self):
        response = yield self.async_post('/', self.body)
        dic = json.loads(to_str(response.body))
        self.assert_status_none(dic)
        self.assertIn(dic['encoding'], server_encodings)


class TestAppWithUnknownEncoding(OtherTestBase):

    encodings = [u'\u7f16\u7801', u'UnknownEncoding']

    @tornado.testing.gen_test
    def test_app_with_a_unknown_encoding(self):
        response = yield self.async_post('/', self.body)
        self.assert_status_none(json.loads(to_str(response.body)))
        dic = json.loads(to_str(response.body))
        self.assert_status_none(dic)
        self.assertEqual(dic['encoding'], 'utf-8')


class UserDataTestBase(TestAppBase):

    headers = {'Cookie': '_xsrf=yummy',
               'X-Authentik-Username': 'alice'}
    user_hosts = True

    def get_app(self):
        self.data_dir = tempfile.mkdtemp()
        self.override_options(
            debug=False,
            xsrf=True,
            policy='warning',
            hostfile='',
            syshostfile='',
            tdstream='',
            origin='same',
            # config is deliberately not overridden here: subclasses set it
            # before get_app runs, and clobbering it would drop their
            # admin allowlist.
            user_hosts=self.user_hosts,
            userdatadir=self.data_dir,
            userheader='X-Authentik-Username',
        )
        return make_app(make_handlers(self.io_loop, options),
                        get_app_settings(options))


class TestUserDataApi(UserDataTestBase):

    def put(self, path, payload, headers=None):
        body = json.dumps(payload)
        hdrs = dict(headers if headers is not None else self.headers)
        hdrs['Content-Type'] = 'application/json'
        hdrs['X-Xsrftoken'] = 'yummy'
        return self.fetch(path, method='PUT', body=body, headers=hdrs)

    def test_get_hosts_empty(self):
        response = self.fetch('/api/hosts', headers=self.headers)
        self.assertEqual(response.code, 200)
        data = json.loads(to_str(response.body))
        self.assertEqual(data['user_hosts'], [])
        self.assertIn('admin_hosts', data)

    def test_put_then_get_hosts(self):
        response = self.put('/api/hosts', {'hosts': [{'hostname': 'nas.lan',
                                                      'port': 2222}]})
        self.assertEqual(response.code, 200)
        response = self.fetch('/api/hosts', headers=self.headers)
        data = json.loads(to_str(response.body))
        self.assertEqual(len(data['user_hosts']), 1)
        self.assertEqual(data['user_hosts'][0]['port'], 2222)

    def test_put_invalid_host_returns_400_and_preserves_data(self):
        self.put('/api/hosts', {'hosts': [{'hostname': 'good.lan'}]})
        response = self.put('/api/hosts',
                            {'hosts': [{'hostname': 'bad', 'port': 0}]})
        self.assertEqual(response.code, 400)
        response = self.fetch('/api/hosts', headers=self.headers)
        data = json.loads(to_str(response.body))
        self.assertEqual(data['user_hosts'][0]['hostname'], 'good.lan')

    def test_put_malformed_json_returns_400(self):
        response = self.fetch(
            '/api/hosts', method='PUT', body='{not json',
            headers=dict(self.headers, **{'X-Xsrftoken': 'yummy',
                                          'Content-Type': 'application/json'}))
        self.assertEqual(response.code, 400)

    def test_missing_auth_header_returns_401(self):
        response = self.fetch('/api/hosts', headers={'Cookie': '_xsrf=yummy'})
        self.assertEqual(response.code, 401)

    def test_invalid_username_returns_400(self):
        response = self.fetch('/api/hosts', headers={
            'Cookie': '_xsrf=yummy', 'X-Authentik-Username': '../etc'})
        self.assertEqual(response.code, 400)

    def test_put_without_xsrf_returns_403(self):
        response = self.fetch(
            '/api/hosts', method='PUT', body=json.dumps({'hosts': []}),
            headers=self.headers)
        self.assertEqual(response.code, 403)
        self.assertIn(
            'application/json', response.headers.get('Content-Type', ''))
        data = json.loads(to_str(response.body))
        self.assertIn('error', data)

    def test_settings_round_trip(self):
        response = self.put('/api/settings', {'settings': {'font_size': 15}})
        self.assertEqual(response.code, 200)
        response = self.fetch('/api/settings', headers=self.headers)
        data = json.loads(to_str(response.body))
        self.assertEqual(data['settings']['font_size'], 15)

    def test_settings_drops_secrets(self):
        self.put('/api/settings',
                 {'settings': {'font_size': 15, 'password': 'hunter2'}})
        response = self.fetch('/api/settings', headers=self.headers)
        data = json.loads(to_str(response.body))
        self.assertNotIn('password', data['settings'])

    def test_users_are_isolated(self):
        self.put('/api/hosts', {'hosts': [{'hostname': 'alice.lan'}]})
        response = self.fetch('/api/hosts', headers={
            'Cookie': '_xsrf=yummy', 'X-Authentik-Username': 'bob'})
        data = json.loads(to_str(response.body))
        self.assertEqual(data['user_hosts'], [])

    def test_put_hosts_missing_key_returns_400_and_preserves_data(self):
        self.put('/api/hosts', {'hosts': [{'hostname': 'good.lan'}]})
        response = self.put('/api/hosts', {})
        self.assertEqual(response.code, 400)
        response = self.put('/api/hosts', {'hosts_typo': []})
        self.assertEqual(response.code, 400)
        response = self.fetch('/api/hosts', headers=self.headers)
        data = json.loads(to_str(response.body))
        self.assertEqual(len(data['user_hosts']), 1)
        self.assertEqual(data['user_hosts'][0]['hostname'], 'good.lan')

    def test_put_hosts_explicit_empty_clears_data(self):
        self.put('/api/hosts', {'hosts': [{'hostname': 'good.lan'}]})
        response = self.put('/api/hosts', {'hosts': []})
        self.assertEqual(response.code, 200)
        response = self.fetch('/api/hosts', headers=self.headers)
        data = json.loads(to_str(response.body))
        self.assertEqual(data['user_hosts'], [])

    def test_put_settings_missing_key_returns_400_and_preserves_data(self):
        self.put('/api/settings', {'settings': {'font_size': 15}})
        response = self.put('/api/settings', {})
        self.assertEqual(response.code, 400)
        response = self.fetch('/api/settings', headers=self.headers)
        data = json.loads(to_str(response.body))
        self.assertEqual(data['settings']['font_size'], 15)

    def test_put_settings_explicit_empty_clears_data(self):
        self.put('/api/settings', {'settings': {'font_size': 15}})
        response = self.put('/api/settings', {'settings': {}})
        self.assertEqual(response.code, 200)
        response = self.fetch('/api/settings', headers=self.headers)
        data = json.loads(to_str(response.body))
        self.assertEqual(data['settings'], {})

    def test_put_invalid_host_returns_json_error_with_message(self):
        response = self.put(
            '/api/hosts', {'hosts': [{'hostname': 'bad', 'port': 0}]})
        self.assertEqual(response.code, 400)
        self.assertIn(
            'application/json', response.headers.get('Content-Type', ''))
        data = json.loads(to_str(response.body))
        self.assertIn('error', data)
        self.assertTrue(data['error'])
        self.assertNotIn('<html', data['error'].lower())
        # The message describes the caller's own input, not server state.
        self.assertIn('port', data['error'].lower())

    def test_put_hosts_write_failure_returns_500_without_leaking_path(self):
        secret_path = '/very/secret/user/data/dir'
        message = (
            'Cannot create data directory for user {!r}: permission '
            'denied. Check ownership of {!r}'.format('alice', secret_path)
        )

        def boom(base_dir, username, hosts):
            raise ValueError(message)

        with mock.patch('webssh.user_data.write_hosts', side_effect=boom):
            with self.assertLogs(level='ERROR') as cm:
                response = self.put(
                    '/api/hosts', {'hosts': [{'hostname': 'ok.lan'}]})

        self.assertEqual(response.code, 500)
        body = to_str(response.body)
        self.assertNotIn(secret_path, body)
        self.assertNotIn(self.data_dir, body)
        data = json.loads(body)
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Failed to save hosts.')
        self.assertNotIn('/', data['error'])
        # The real detail, including the path, must still be logged
        # server-side for operators to diagnose.
        self.assertTrue(any(secret_path in msg for msg in cm.output))

    def test_put_settings_write_failure_returns_500_without_leaking_path(self):
        secret_path = '/very/secret/user/data/dir'
        message = (
            'Cannot create data directory for user {!r}: permission '
            'denied. Check ownership of {!r}'.format('alice', secret_path)
        )

        def boom(base_dir, username, settings):
            raise ValueError(message)

        with mock.patch('webssh.user_data.write_settings', side_effect=boom):
            with self.assertLogs(level='ERROR') as cm:
                response = self.put(
                    '/api/settings', {'settings': {'font_size': 15}})

        self.assertEqual(response.code, 500)
        body = to_str(response.body)
        self.assertNotIn(secret_path, body)
        self.assertNotIn(self.data_dir, body)
        data = json.loads(body)
        self.assertIn('error', data)
        self.assertEqual(data['error'], 'Failed to save settings.')
        self.assertNotIn('/', data['error'])
        self.assertTrue(any(secret_path in msg for msg in cm.output))

    def test_settings_pane_returns_fragment(self):
        response = self.fetch('/settings-pane', headers=self.headers)
        self.assertEqual(response.code, 200)
        self.assertIn(b'settings-pane', response.body)
        self.assertNotIn(b'<html', response.body)


class TestUserDataApiDisabled(UserDataTestBase):

    user_hosts = False

    def test_get_hosts_returns_403(self):
        response = self.fetch('/api/hosts', headers=self.headers)
        self.assertEqual(response.code, 403)

    def test_get_settings_returns_403(self):
        response = self.fetch('/api/settings', headers=self.headers)
        self.assertEqual(response.code, 403)

    def test_settings_pane_returns_404(self):
        response = self.fetch('/settings-pane', headers=self.headers)
        self.assertEqual(response.code, 404)


class TestEffectiveHosts(unittest.TestCase):
    """Unit-level checks of the admin/user host merge."""

    def _handler(self, admin_hosts, user_hosts):
        from webssh.handler import IndexHandler
        h = IndexHandler.__new__(IndexHandler)
        h.allowed_hosts = admin_hosts
        h._user_hosts = user_hosts
        h.get_user_hosts = lambda: h._user_hosts
        return h

    def test_admin_host_wins_collision(self):
        from webssh.handler import IndexHandler
        admin = [{'name': 'prod', 'hostname': '10.0.1.5', 'port': 22,
                  'host_keys': ['ssh-ed25519 AAAAadmin']}]
        user = [{'name': 'mine', 'hostname': '10.0.1.5', 'port': 22,
                 'host_keys': ['ssh-ed25519 AAAAuser']}]
        h = self._handler(admin, user)
        effective = IndexHandler.get_effective_hosts(h)
        self.assertEqual(len(effective), 1)
        self.assertEqual(effective[0]['host_keys'], ['ssh-ed25519 AAAAadmin'])

    def test_different_port_is_not_a_collision(self):
        from webssh.handler import IndexHandler
        admin = [{'name': 'prod', 'hostname': '10.0.1.5', 'port': 22,
                  'host_keys': []}]
        user = [{'name': 'mine', 'hostname': '10.0.1.5', 'port': 2222,
                 'host_keys': []}]
        h = self._handler(admin, user)
        self.assertEqual(len(IndexHandler.get_effective_hosts(h)), 2)

    def test_user_hosts_appended(self):
        from webssh.handler import IndexHandler
        h = self._handler([{'name': 'a', 'hostname': 'a.com', 'port': 22,
                            'host_keys': []}],
                          [{'name': 'b', 'hostname': 'b.com', 'port': 22,
                            'host_keys': []}])
        names = [x['name'] for x in IndexHandler.get_effective_hosts(h)]
        self.assertEqual(names, ['a', 'b'])


class ConnectHostsTestBase(UserDataTestBase):
    """Admin allowlist that deliberately excludes the user's saved host."""

    admin_hostname = '10.9.9.9'

    def setUp(self):
        import yaml
        fd, self.config_path = tempfile.mkstemp(suffix='.yaml')
        with os.fdopen(fd, 'w') as f:
            yaml.safe_dump({'hosts': [
                {'name': 'other', 'hostname': self.admin_hostname,
                 'port': 22}]}, f)
        self.override_options(config=self.config_path)
        super(ConnectHostsTestBase, self).setUp()
        from webssh.user_data import write_hosts
        write_hosts(self.data_dir, 'alice',
                    [{'hostname': '127.0.0.1', 'port': 7000}])

    def tearDown(self):
        os.unlink(self.config_path)
        super(ConnectHostsTestBase, self).tearDown()

    def post_hostname(self, hostname):
        body = ('hostname={}&port=7000&username=robey&password=foo'
                '&_xsrf=yummy').format(hostname)
        return self.fetch('/', method='POST', body=body,
                          headers=self.headers)


class TestConnectWithUserHostsEnabled(ConnectHostsTestBase):

    user_hosts = True

    def test_user_host_passes_the_allowlist(self):
        # The allowlist must not reject it. The SSH connection itself will
        # fail (no server on that port), which is fine and not what we assert.
        self.assertNotIn(b'is not allowed',
                         self.post_hostname('127.0.0.1').body)

    def test_host_in_neither_list_is_rejected(self):
        self.assertIn(b'is not allowed',
                      self.post_hostname('127.0.0.2').body)


class TestConnectWithUserHostsDisabled(ConnectHostsTestBase):

    user_hosts = False

    def test_user_host_is_rejected_when_feature_disabled(self):
        self.assertIn(b'is not allowed',
                      self.post_hostname('127.0.0.1').body)

    def test_host_in_neither_list_is_rejected(self):
        self.assertIn(b'is not allowed',
                      self.post_hostname('127.0.0.2').body)


class TestUserHostKeyIsolation(TestAppBase):
    """A user's personal host key pin must not leak into other requests.

    Under `policy: reject` with no administrator `hosts:` allowlist,
    check_allowed_hosts returns early and lookup_hostname is the only gate.
    If a user's pin lands in the process-wide HostKeys store, that user's
    private bookmark silently becomes a global allowlist entry.
    """

    # Any syntactically valid key; it never has to match a real server.
    user_key = ('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINwZGQmNFADnAAlm5uFLQ'
                'TrdxqpNxHdgg4JPbB3sR2kr')
    # Loopback with nothing listening: the allowlist gate runs, then the
    # connection fails fast instead of hanging on an unroutable address.
    hostname = '127.0.0.9'
    port = 7009

    def get_app(self):
        self.data_dir = tempfile.mkdtemp()
        self.override_options(
            debug=False,
            xsrf=True,
            policy='reject',
            # A hostfile is required for the reject policy, and it
            # deliberately does not contain self.hostname.
            hostfile=make_tests_data_path('known_hosts_example'),
            syshostfile=make_tests_data_path('known_hosts_example'),
            tdstream='',
            origin='same',
            config='',
            user_hosts=True,
            userdatadir=self.data_dir,
            userheader='X-Authentik-Username',
        )
        return make_app(make_handlers(self.io_loop, options),
                        get_app_settings(options))

    def setUp(self):
        super(TestUserHostKeyIsolation, self).setUp()
        from webssh.user_data import write_hosts
        write_hosts(self.data_dir, 'alice',
                    [{'hostname': self.hostname, 'port': self.port,
                      'host_key': [self.user_key]}])

    def post_as(self, username):
        headers = {'Cookie': '_xsrf=yummy'}
        if username:
            headers['X-Authentik-Username'] = username
        body = ('hostname={}&port={}&username=robey&password=foo'
                '&_xsrf=yummy').format(self.hostname, self.port)
        return self.fetch('/', method='POST', body=body, headers=headers)

    def test_alice_reaches_her_own_host(self):
        # Her own pin satisfies the reject gate for her own request.
        self.assertNotIn(b'is not allowed', self.post_as('alice').body)

    def test_alice_pin_does_not_leak_to_another_user(self):
        self.assertNotIn(b'is not allowed', self.post_as('alice').body)
        self.assertIn(b'is not allowed', self.post_as('bob').body)

    def test_alice_pin_does_not_leak_to_anonymous_request(self):
        self.assertNotIn(b'is not allowed', self.post_as('alice').body)
        self.assertIn(b'is not allowed', self.post_as(None).body)


class TestLiveWorkerRegistry(unittest.TestCase):

    def make_worker(self, worker_id='wid'):
        class FakeChan(object):
            def fileno(self):
                return 0

            def close(self):
                pass

        class FakeSSH(object):
            def close(self):
                pass

        w = worker.Worker(None, FakeSSH(), FakeChan(), ('1.2.3.4', 22))
        w.id = worker_id
        w.src_addr = ('9.9.9.9', 1234)
        return w

    def tearDown(self):
        worker.live_workers.clear()
        worker.clients.clear()

    def test_registering_makes_a_worker_reachable_by_id(self):
        w = self.make_worker()
        worker.register_live_worker(w)
        self.assertIs(worker.live_workers.get('wid'), w)

    def test_unregistering_removes_it(self):
        w = self.make_worker()
        worker.register_live_worker(w)
        worker.unregister_live_worker(w)
        self.assertIsNone(worker.live_workers.get('wid'))

    def test_unregistering_an_absent_worker_is_harmless(self):
        # close() may run without the websocket ever having attached.
        worker.unregister_live_worker(self.make_worker())

    def test_a_new_worker_starts_with_no_transfers(self):
        self.assertEqual(self.make_worker().transfers, 0)

    def test_close_unregisters_so_a_dead_id_cannot_be_reached(self):
        w = self.make_worker()
        worker.clients['9.9.9.9'] = {'wid': None}
        worker.register_live_worker(w)
        w.close(reason='test')
        self.assertIsNone(worker.live_workers.get('wid'))


class TransferTestBase(TestAppBase):
    """Handler-level transfer tests with SFTP mocked at the open_sftp seam.

    tests/sshserver.py implements no SFTP subsystem, and writing one just to
    test our code would mean trusting a fake server. Patching open_sftp tests
    the code we actually control.
    """

    headers = {'Cookie': '_xsrf=yummy'}

    def get_app(self):
        self.override_options(
            debug=False, xsrf=True, policy='warning', hostfile='',
            syshostfile='', tdstream='', origin='same', maxconn=20,
        )
        return make_app(make_handlers(self.io_loop, options),
                        get_app_settings(options))

    def setUp(self):
        super(TransferTestBase, self).setUp()
        worker.live_workers.clear()
        self.addCleanup(worker.live_workers.clear)
        self.sftp = FakeSFTP(files={'/home/ryan/a.txt': b'hello'},
                             dirs={'/home/ryan': [FakeAttr('a.txt', size=5)]})
        self.worker = self.make_live_worker()

    def make_live_worker(self, worker_id='tid', client_ip='127.0.0.1'):
        test_sftp = self.sftp

        class FakeChan(object):
            def fileno(self):
                return 0

            def close(self):
                pass

        class FakeSSH(object):
            def open_sftp(self):
                return test_sftp

            def close(self):
                pass

        w = worker.Worker(self.io_loop, FakeSSH(), FakeChan(),
                          ('10.0.0.1', 22))
        w.id = worker_id
        w.src_addr = (client_ip, 1234)
        worker.live_workers[worker_id] = w
        return w


class TestTransferList(TransferTestBase):

    def test_lists_the_requested_directory(self):
        response = self.fetch('/transfer/list?id=tid&path=/home/ryan',
                              headers=self.headers)
        self.assertEqual(response.code, 200)
        data = json.loads(to_str(response.body))
        self.assertEqual(data['path'], '/home/ryan')
        self.assertEqual(data['entries'][0]['name'], 'a.txt')
        self.assertFalse(data['truncated'])

    def test_unknown_worker_id_is_404(self):
        response = self.fetch('/transfer/list?id=nope&path=/home/ryan',
                              headers=self.headers)
        self.assertEqual(response.code, 404)

    def test_valid_id_from_a_different_client_ip_is_404(self):
        # The security property the transfer endpoints rest on: a leaked
        # worker id is useless from anywhere but the session's own address.
        self.worker.src_addr = ('203.0.113.7', 1234)
        response = self.fetch('/transfer/list?id=tid&path=/home/ryan',
                              headers=self.headers)
        self.assertEqual(response.code, 404)

    def test_missing_directory_is_404_with_the_remote_message(self):
        response = self.fetch('/transfer/list?id=tid&path=/nope',
                              headers=self.headers)
        self.assertEqual(response.code, 404)

    def test_closed_worker_is_410(self):
        self.worker.closed = True
        response = self.fetch('/transfer/list?id=tid&path=/home/ryan',
                              headers=self.headers)
        self.assertEqual(response.code, 410)


class TestContentDisposition(unittest.TestCase):

    def test_ascii_filename_uses_the_plain_form(self):
        value = handler.content_disposition('report.pdf')
        self.assertIn('filename="report.pdf"', value)

    def test_non_ascii_filename_gets_rfc5987_encoding(self):
        value = handler.content_disposition('отчёт.pdf')
        self.assertIn("filename*=UTF-8''", value)
        # An ASCII fallback must still be present for older clients.
        self.assertIn('filename="', value)

    def test_quotes_are_escaped_not_passed_through(self):
        value = handler.content_disposition('we"ird.txt')
        self.assertNotIn('we"ird', value)

    def test_newline_in_filename_is_rejected(self):
        # Header injection vector: a remote filename is attacker-controlled
        # if the user can be induced to download from a hostile host.
        with self.assertRaises(ValueError):
            handler.content_disposition('evil\r\nSet-Cookie: x=1')


class TestTransferDownload(TransferTestBase):

    def test_streams_the_file_with_an_attachment_header(self):
        response = self.fetch('/transfer/download?id=tid&path=/home/ryan/a.txt',
                              headers=self.headers)
        self.assertEqual(response.code, 200)
        self.assertEqual(response.body, b'hello')
        disposition = response.headers['Content-Disposition']
        self.assertIn('attachment', disposition)
        self.assertIn('a.txt', disposition)

    def test_missing_file_is_404(self):
        response = self.fetch('/transfer/download?id=tid&path=/home/ryan/no.txt',
                              headers=self.headers)
        self.assertEqual(response.code, 404)

    def test_directory_is_400(self):
        response = self.fetch('/transfer/download?id=tid&path=/home/ryan',
                              headers=self.headers)
        self.assertEqual(response.code, 400)

    def test_wrong_client_ip_is_404(self):
        self.worker.src_addr = ('203.0.113.7', 1234)
        response = self.fetch('/transfer/download?id=tid&path=/home/ryan/a.txt',
                              headers=self.headers)
        self.assertEqual(response.code, 404)

    def test_transfer_counter_is_released_after_the_download(self):
        self.fetch('/transfer/download?id=tid&path=/home/ryan/a.txt',
                   headers=self.headers)
        self.assertEqual(self.worker.transfers, 0)

    def test_concurrency_cap_returns_429(self):
        self.worker.transfers = handler.TransferMixin.MAX_CONCURRENT_TRANSFERS
        response = self.fetch('/transfer/download?id=tid&path=/home/ryan/a.txt',
                              headers=self.headers)
        self.assertEqual(response.code, 429)


class TestTransferDownloadCancellation(unittest.TestCase):
    """Pins the fix for a disconnect that arrives before ``_download``
    exists (while ``open_sftp``/``Download.open`` are still running on the
    executor). Without hardening, that disconnect callback finds
    ``_download is None`` and does nothing, so once ``_download`` is
    assigned afterward there is no further callback to cancel it.
    """

    class FakeDownload(object):
        def __init__(self):
            self.cancelled = False

        def cancel(self):
            self.cancelled = True

    def make_handler(self):
        instance = handler.TransferDownloadHandler.__new__(
            handler.TransferDownloadHandler)
        instance._download = None
        instance._aborted = False
        return instance

    def test_disconnect_before_download_exists_is_recorded(self):
        instance = self.make_handler()
        instance.on_connection_close()
        self.assertTrue(instance._aborted)

    def test_download_bound_after_early_disconnect_is_cancelled(self):
        instance = self.make_handler()
        # The disconnect races ahead of open_sftp/Download.open finishing.
        instance.on_connection_close()

        download = self.FakeDownload()
        instance._bind_download(download)

        self.assertTrue(download.cancelled)

    def test_late_disconnect_still_cancels_the_bound_download(self):
        # Ordinary ordering: _download already exists when the client
        # disconnects. Must keep working after the hardening.
        instance = self.make_handler()
        download = self.FakeDownload()
        instance._bind_download(download)

        instance.on_connection_close()

        self.assertTrue(download.cancelled)


class TestTransferUpload(TransferTestBase):

    def upload(self, query, body, headers=None):
        hdrs = dict(headers if headers is not None else self.headers)
        hdrs['X-Xsrftoken'] = 'yummy'
        hdrs['Content-Type'] = 'application/octet-stream'
        return self.fetch('/transfer/upload?' + query, method='POST',
                          body=body, headers=hdrs)

    def test_writes_the_body_to_the_destination(self):
        response = self.upload(
            'id=tid&path=/home/ryan/new.txt&filename=new.txt', b'payload')
        self.assertEqual(response.code, 200)
        data = json.loads(to_str(response.body))
        self.assertEqual(data['path'], '/home/ryan/new.txt')
        self.assertEqual(data['bytes'], 7)
        self.assertEqual(self.sftp.files['/home/ryan/new.txt'], b'payload')

    def test_existing_destination_is_409_and_leaves_the_file_alone(self):
        response = self.upload(
            'id=tid&path=/home/ryan/a.txt&filename=a.txt', b'clobber')
        self.assertEqual(response.code, 409)
        self.assertEqual(self.sftp.files['/home/ryan/a.txt'], b'hello')

    def test_reissuing_with_overwrite_succeeds(self):
        response = self.upload(
            'id=tid&path=/home/ryan/a.txt&filename=a.txt&overwrite=true',
            b'clobber')
        self.assertEqual(response.code, 200)
        self.assertEqual(self.sftp.files['/home/ryan/a.txt'], b'clobber')

    def test_directory_destination_appends_the_filename(self):
        response = self.upload(
            'id=tid&path=/home/ryan&filename=fresh.txt', b'x')
        self.assertEqual(response.code, 200)
        data = json.loads(to_str(response.body))
        self.assertEqual(data['path'], '/home/ryan/fresh.txt')

    def test_wrong_client_ip_is_404(self):
        self.worker.src_addr = ('203.0.113.7', 1234)
        response = self.upload(
            'id=tid&path=/home/ryan/new.txt&filename=new.txt', b'x')
        self.assertEqual(response.code, 404)

    def test_missing_xsrf_header_is_rejected(self):
        response = self.fetch(
            '/transfer/upload?id=tid&path=/home/ryan/new.txt&filename=new.txt',
            method='POST', body=b'x', headers=self.headers)
        self.assertEqual(response.code, 403)

    def test_transfer_counter_is_released_after_the_upload(self):
        self.upload('id=tid&path=/home/ryan/new.txt&filename=new.txt', b'x')
        self.assertEqual(self.worker.transfers, 0)

    def test_concurrency_cap_returns_429(self):
        self.worker.transfers = handler.TransferMixin.MAX_CONCURRENT_TRANSFERS
        response = self.upload(
            'id=tid&path=/home/ryan/new.txt&filename=new.txt', b'x')
        self.assertEqual(response.code, 429)
