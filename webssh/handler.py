import asyncio
import io
import json
import logging
import posixpath
import socket
import struct
import time
import traceback
import weakref
import paramiko
import tornado.gen
import tornado.web

from concurrent.futures import ThreadPoolExecutor
from tornado.ioloop import IOLoop
from tornado.options import options
from tornado.process import cpu_count
from urllib.parse import quote
from webssh.utils import (
    is_valid_ip_address, is_valid_port, is_valid_hostname, to_bytes, to_str,
    to_int, to_ip_address, UnicodeType, is_ip_hostname, is_same_primary_domain,
    is_valid_encoding
)
from webssh.worker import (
    Worker, recycle_worker, clients, register_live_worker  # noqa
)
from webssh import worker as worker_module
from webssh.settings import max_upload_size
from webssh import transfer
from webssh import user_data
from webssh import user_keys
from webssh._version import __version__

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


DEFAULT_PORT = 22

swallow_http_errors = True
redirecting = None

# Asks the shell to report its working directory on every prompt. Written
# once when the shell starts, then scrubbed from the screen and from bash
# history. Kept to a single line: a partially delivered multi-line snippet
# would strand the shell at a continuation prompt.
SHELL_INTEGRATION_SNIPPET = (
    ' if [ -n "$ZSH_VERSION" ]; then '
    'precmd() { printf "\\033]7;file://%s%s\\033\\\\" "$HOST" "$PWD"; }; '
    'elif [ -n "$BASH_VERSION" ]; then '
    'PROMPT_COMMAND=\'printf "\\033]7;file://%s%s\\033\\\\" "$HOSTNAME" "$PWD"\'; '
    'fi; clear; history -d $((HISTCMD-1)) 2>/dev/null || true\n'
)


class InvalidValueError(Exception):
    pass


class SSHClient(paramiko.SSHClient):

    def handler(self, title, instructions, prompt_list):
        answers = []
        for prompt_, _ in prompt_list:
            prompt = prompt_.strip().lower()
            if prompt.startswith('password'):
                answers.append(self.password)
            elif prompt.startswith('verification'):
                answers.append(self.totp)
            else:
                raise ValueError('Unknown prompt: {}'.format(prompt_))
        return answers

    def auth_interactive(self, username, handler):
        if not self.totp:
            raise ValueError('Need a verification code for 2fa.')
        self._transport.auth_interactive(username, handler)

    def _auth(self, username, password, pkey, *args):
        self.password = password
        saved_exception = None
        two_factor = False
        allowed_types = set()
        two_factor_types = {'keyboard-interactive', 'password'}

        if pkey is not None:
            logging.info('Trying publickey authentication')
            try:
                allowed_types = set(
                    self._transport.auth_publickey(username, pkey)
                )
                two_factor = allowed_types & two_factor_types
                if not two_factor:
                    return
            except paramiko.SSHException as e:
                saved_exception = e

        if two_factor:
            logging.info('Trying publickey 2fa')
            return self.auth_interactive(username, self.handler)

        if password is not None:
            logging.info('Trying password authentication')
            try:
                self._transport.auth_password(username, password)
                return
            except paramiko.SSHException as e:
                saved_exception = e
                allowed_types = set(getattr(e, 'allowed_types', []))
                two_factor = allowed_types & two_factor_types

        if two_factor:
            logging.info('Trying password 2fa')
            return self.auth_interactive(username, self.handler)

        assert saved_exception is not None
        raise saved_exception


class PrivateKey(object):

    max_length = 16384  # rough number

    tag_to_name = {
        'RSA': 'RSA',
        'EC': 'ECDSA',
        'OPENSSH': 'Ed25519'
    }

    def __init__(self, privatekey, password=None, filename=''):
        self.privatekey = privatekey
        self.filename = filename
        self.password = password
        self.check_length()
        self.iostr = io.StringIO(privatekey)
        self.last_exception = None

    def check_length(self):
        if len(self.privatekey) > self.max_length:
            raise InvalidValueError('Invalid key length.')

    def parse_name(self, iostr, tag_to_name):
        name = None
        for line_ in iostr:
            line = line_.strip()
            if line and line.startswith('-----BEGIN ') and \
                    line.endswith(' PRIVATE KEY-----'):
                lst = line.split(' ')
                if len(lst) == 4:
                    tag = lst[1]
                    if tag:
                        name = tag_to_name.get(tag)
                        if name:
                            break
        return name, len(line_)

    def get_specific_pkey(self, name, offset, password):
        self.iostr.seek(offset)
        logging.debug('Reset offset to {}.'.format(offset))

        logging.debug('Try parsing it as {} type key'.format(name))
        pkeycls = getattr(paramiko, name+'Key')
        pkey = None

        try:
            pkey = pkeycls.from_private_key(self.iostr, password=password)
        except paramiko.PasswordRequiredException:
            raise InvalidValueError('Need a passphrase to decrypt the key.')
        except (paramiko.SSHException, ValueError) as exc:
            self.last_exception = exc
            logging.debug(str(exc))

        return pkey

    def get_pkey_obj(self):
        logging.info('Parsing private key {!r}'.format(self.filename))
        name, length = self.parse_name(self.iostr, self.tag_to_name)
        if not name:
            raise InvalidValueError('Invalid key {}.'.format(self.filename))

        offset = self.iostr.tell() - length
        password = to_bytes(self.password) if self.password else None
        pkey = self.get_specific_pkey(name, offset, password)

        if pkey is None and name == 'Ed25519':
            for name in ['RSA', 'ECDSA']:
                pkey = self.get_specific_pkey(name, offset, password)
                if pkey:
                    break

        if pkey:
            return pkey

        logging.error(str(self.last_exception))
        msg = 'Invalid key'
        if self.password:
            msg += ' or wrong passphrase for decrypting it.'
        raise InvalidValueError(msg)


class MixinHandler(object):

    custom_headers = {
        'Server': 'TornadoServer'
    }

    html = ('<html><head><title>{code} {reason}</title></head><body>{code} '
            '{reason}</body></html>')

    proxy_error_html = (
        '<html><head><title>403 Proxy Not Trusted</title>'
        '<style>body{{font-family:monospace;background:#0a0e14;color:#e2e8f0;'
        'display:flex;align-items:center;justify-content:center;min-height:100vh;'
        'margin:0}}div{{max-width:480px;padding:32px;border:1px solid #1e2a3a;'
        'border-radius:12px;background:#111720}}'
        'h1{{color:#f87171;font-size:18px;margin:0 0 12px}}'
        'p{{color:#8492a6;font-size:13px;line-height:1.6;margin:0 0 8px}}'
        'code{{color:#2dd4a8;background:#0d1219;padding:2px 6px;border-radius:4px;'
        'font-size:12px}}</style></head>'
        '<body><div><h1>403 &mdash; Proxy Not Trusted</h1>'
        '<p>Connection from <code>{ip}</code> was rejected because it is not '
        'in the trusted downstream list.</p>'
        '<p>Add this IP to <code>trusted_proxies</code> in your config, or pass '
        '<code>--tdstream={ip}</code> on the command line.</p>'
        '</div></body></html>'
    )

    def initialize(self, loop=None):
        self.check_request()
        self.loop = loop
        self.origin_policy = self.settings.get('origin_policy')

    def check_request(self):
        context = self.request.connection.context
        result = self.is_forbidden(context, self.request.host_name)
        self._transforms = []
        if result:
            self.set_status(403)
            ip = getattr(self, '_untrusted_ip', None)
            if ip:
                self.finish(self.proxy_error_html.format(ip=ip))
            else:
                self.finish(
                    self.html.format(
                        code=self._status_code, reason=self._reason)
                )
        elif result is False:
            to_url = self.get_redirect_url(
                self.request.host_name, options.sslport, self.request.uri
            )
            self.redirect(to_url, permanent=True)
        else:
            self.context = context

    def check_origin(self, origin):
        if self.origin_policy == '*':
            return True

        parsed_origin = urlparse(origin)
        netloc = parsed_origin.netloc.lower()
        logging.debug('netloc: {}'.format(netloc))

        host = self.request.headers.get('Host')
        logging.debug('host: {}'.format(host))

        if netloc == host:
            return True

        if self.origin_policy == 'same':
            return False
        elif self.origin_policy == 'primary':
            return is_same_primary_domain(netloc.rsplit(':', 1)[0],
                                          host.rsplit(':', 1)[0])
        else:
            return origin in self.origin_policy

    def is_forbidden(self, context, hostname):
        ip = context.address[0]
        settings = getattr(self, 'settings', None) or {}
        lst = settings.get('trusted_downstream') or context.trusted_downstream
        ip_address = None

        if lst and ip not in lst:
            logging.warning(
                'IP {!r} not found in trusted downstream {!r}'.format(ip, lst)
            )
            self._untrusted_ip = ip
            return True

        if context._orig_protocol == 'http':
            if redirecting and not is_ip_hostname(hostname):
                ip_address = to_ip_address(ip)
                if not ip_address.is_private:
                    # redirecting
                    return False

            if options.fbidhttp:
                if ip_address is None:
                    ip_address = to_ip_address(ip)
                if not ip_address.is_private:
                    logging.warning('Public plain http request is forbidden.')
                    return True

    def get_redirect_url(self, hostname, port, uri):
        port = '' if port == 443 else ':%s' % port
        return 'https://{}{}{}'.format(hostname, port, uri)

    def set_default_headers(self):
        for header in self.custom_headers.items():
            self.set_header(*header)

    def get_value(self, name):
        value = self.get_argument(name)
        if not value:
            raise InvalidValueError('Missing value {}'.format(name))
        return value

    def get_context_addr(self):
        return self.context.address[:2]

    def get_client_addr(self):
        if options.xheaders:
            return self.get_real_client_addr() or self.get_context_addr()
        else:
            return self.get_context_addr()

    def get_real_client_addr(self):
        ip = self.request.remote_ip

        if ip == self.request.headers.get('X-Real-Ip'):
            port = self.request.headers.get('X-Real-Port')
        elif ip in self.request.headers.get('X-Forwarded-For', ''):
            port = self.request.headers.get('X-Forwarded-Port')
        else:
            # not running behind an nginx server
            return

        port = to_int(port)
        if port is None or not is_valid_port(port):
            # fake port
            port = 65535

        return (ip, port)


class NotFoundHandler(MixinHandler, tornado.web.ErrorHandler):

    def initialize(self):
        super(NotFoundHandler, self).initialize()

    def prepare(self):
        raise tornado.web.HTTPError(404)


class IndexHandler(MixinHandler, tornado.web.RequestHandler):

    executor = ThreadPoolExecutor(max_workers=cpu_count()*5)

    # Per-request cache for get_effective_hosts. See its comment.
    _effective_hosts = None

    def initialize(self, loop, policy, host_keys_settings, allowed_hosts=None,
                   user_key_dir='', user_header='X-Authentik-Username',
                   user_data_dir='', user_hosts_enabled=False,
                   live_config=None):
        super(IndexHandler, self).initialize(loop)
        self.live_config = live_config if live_config is not None else {}
        self.policy = self.live_config.get('policy', policy)
        self.host_keys_settings = self.live_config.get(
            'host_keys_settings', host_keys_settings)
        self.allowed_hosts = self.live_config.get(
            'allowed_hosts', allowed_hosts) or []
        self.user_key_dir = user_key_dir
        self.user_header = user_header
        self.user_data_dir = user_data_dir
        self.user_hosts_enabled = user_hosts_enabled
        self.ssh_client = self.get_ssh_client()
        self.debug = self.settings.get('debug', False)
        self.font = self.settings.get('font', '')
        self.result = dict(id=None, status=None, encoding=None)

    def write_error(self, status_code, **kwargs):
        if swallow_http_errors and self.request.method == 'POST':
            exc_info = kwargs.get('exc_info')
            if exc_info:
                reason = getattr(exc_info[1], 'log_message', None)
                if reason:
                    self._reason = reason
            self.result.update(status=self._reason)
            self.set_status(200)
            self.finish(self.result)
        else:
            super(IndexHandler, self).write_error(status_code, **kwargs)

    def get_ssh_client(self):
        ssh = SSHClient()
        ssh._system_host_keys = self.host_keys_settings['system_host_keys']
        host_keys = self.host_keys_settings['host_keys']
        if self.user_hosts_enabled:
            # User-supplied host entries can contribute host key pins, and
            # paramiko's HostKeys.add() mutates the store in place (replacing
            # the key of a matching entry). Sharing the process-wide store
            # would let one user's pin leak into every other request, both
            # widening the reject-policy allowlist and downgrading the
            # administrator's pins. Give this request its own deep-enough
            # copy: new HostKeys, new HostKeyEntry objects, new hostname
            # lists. The PKey objects themselves are never mutated, only
            # rebound, so they can be shared.
            host_keys = self.copy_host_keys(host_keys)
        ssh._host_keys = host_keys
        ssh._host_keys_filename = self.host_keys_settings['host_keys_filename']
        ssh.set_missing_host_key_policy(self.policy)
        return ssh

    @staticmethod
    def copy_host_keys(host_keys):
        """Return a private copy of a paramiko HostKeys store."""
        private = paramiko.hostkeys.HostKeys()
        for entry in host_keys._entries:
            private._entries.append(
                paramiko.hostkeys.HostKeyEntry(
                    list(entry.hostnames), entry.key)
            )
        return private

    def get_privatekey(self):
        name = 'privatekey'
        lst = self.request.files.get(name)
        if lst:
            # multipart form
            filename = lst[0]['filename']
            data = lst[0]['body']
            value = self.decode_argument(data, name=name).strip()
        else:
            # urlencoded form
            value = self.get_argument(name, u'')
            filename = ''

        return value, filename

    def get_hostname(self):
        value = self.get_value('hostname')
        if not (is_valid_hostname(value) or is_valid_ip_address(value)):
            raise InvalidValueError('Invalid hostname: {}'.format(value))
        return value

    def get_port(self):
        value = self.get_argument('port', u'')
        if not value:
            return DEFAULT_PORT

        port = to_int(value)
        if port is None or not is_valid_port(port):
            raise InvalidValueError('Invalid port: {}'.format(value))
        return port

    def lookup_hostname(self, hostname, port):
        key = hostname if port == 22 else '[{}]:{}'.format(hostname, port)

        if self.ssh_client._system_host_keys.lookup(key) is None:
            if self.ssh_client._host_keys.lookup(key) is None:
                raise tornado.web.HTTPError(
                        403, 'Connection to {}:{} is not allowed.'.format(
                            hostname, port)
                    )

    def get_user_hosts(self):
        if not self.user_hosts_enabled or not self.user_data_dir:
            return []
        username = self.request.headers.get(self.user_header, '')
        if not username:
            return []
        try:
            return user_data.read_hosts(self.user_data_dir, username)
        except ValueError:
            return []

    def get_effective_hosts(self):
        # Memoized per request. A connect POST asks twice -- once for the
        # allowlist check, once for host-key pinning -- and each miss
        # re-reads and re-parses hosts.json from disk, synchronously on
        # the IOLoop thread. Tornado builds a handler per request, so an
        # instance attribute is per-request by construction.
        if self._effective_hosts is not None:
            return self._effective_hosts

        admin = self.allowed_hosts
        seen = set((h['hostname'], h['port']) for h in admin)
        merged = list(admin)
        for host in self.get_user_hosts():
            if not isinstance(host, dict):
                logging.warning(
                    'Skipping malformed user host entry: {!r}'.format(host))
                continue
            hostname = host.get('hostname')
            port = host.get('port')
            if hostname is None or port is None:
                logging.warning(
                    'Skipping malformed user host entry: {!r}'.format(host))
                continue
            if (hostname, port) not in seen:
                merged.append(host)
        self._effective_hosts = merged
        return merged

    def check_allowed_hosts(self, hostname, port):
        if not self.allowed_hosts:
            return
        for host in self.get_effective_hosts():
            if host['hostname'] == hostname and host['port'] == port:
                return
        raise tornado.web.HTTPError(
            403, 'Connection to {}:{} is not allowed.'.format(hostname, port)
        )

    def load_configured_host_key(self, hostname, port):
        for host in self.get_effective_hosts():
            if host['hostname'] == hostname and host['port'] == port:
                for key_str in host.get('host_keys', []):
                    self._add_host_key(hostname, port, key_str)
                return

    def _add_host_key(self, hostname, port, host_key_str):
        import base64
        parts = host_key_str.strip().split()
        key_type, key_data = parts[0], base64.b64decode(parts[1])

        key_classes = {
            'ssh-rsa': paramiko.RSAKey,
            'ssh-ed25519': paramiko.Ed25519Key,
            'ecdsa-sha2-nistp256': paramiko.ECDSAKey,
            'ecdsa-sha2-nistp384': paramiko.ECDSAKey,
            'ecdsa-sha2-nistp521': paramiko.ECDSAKey,
        }

        cls = key_classes.get(key_type)
        if not cls:
            return

        key = cls(data=key_data)

        # Use bracketed hostname for non-standard ports, matching paramiko
        if port == 22:
            host_entry = hostname
        else:
            host_entry = '[{}]:{}'.format(hostname, port)

        self.ssh_client._host_keys.add(host_entry, key_type, key)
        logging.debug(
            'Loaded configured host key ({}) for {}'.format(
                key_type, host_entry)
        )

    def get_args(self):
        hostname = self.get_hostname()
        port = self.get_port()
        username = self.get_value('username')
        password = self.get_argument('password', u'')
        passphrase = self.get_argument('passphrase', u'')
        totp = self.get_argument('totp', u'')

        key_source = self.get_argument('key_source', u'')

        if key_source == 'stored' and self.user_key_dir:
            auth_username = self.request.headers.get(self.user_header, '')
            if not auth_username:
                raise InvalidValueError('No authenticated user found.')
            try:
                user_keys.sanitize_username(auth_username)
            except ValueError:
                raise InvalidValueError('Invalid username.')
            if not user_keys.has_stored_key(self.user_key_dir, auth_username):
                raise InvalidValueError('No stored key found.')
            privatekey = user_keys.read_private_key(
                self.user_key_dir, auth_username
            )
            filename = 'stored_key'
            passphrase = ''
        else:
            privatekey, filename = self.get_privatekey()

        self.check_allowed_hosts(hostname, port)
        self.load_configured_host_key(hostname, port)

        if isinstance(self.policy, paramiko.RejectPolicy):
            self.lookup_hostname(hostname, port)

        if privatekey:
            pkey = PrivateKey(privatekey, passphrase, filename).get_pkey_obj()
        else:
            pkey = None

        self.ssh_client.totp = totp
        args = (hostname, port, username, password, pkey)
        logging.debug((hostname, port, username))

        return args

    def parse_encoding(self, data):
        try:
            encoding = to_str(data.strip(), 'ascii')
        except UnicodeDecodeError:
            return

        if is_valid_encoding(encoding):
            return encoding

    def get_default_encoding(self, ssh):
        commands = [
            '$SHELL -ilc "locale charmap"',
            '$SHELL -ic "locale charmap"'
        ]

        for command in commands:
            try:
                _, stdout, _ = ssh.exec_command(command,
                                                get_pty=True,
                                                timeout=1)
            except paramiko.SSHException as exc:
                logging.info(str(exc))
            else:
                try:
                    data = stdout.read()
                except socket.timeout:
                    pass
                else:
                    logging.debug('{!r} => {!r}'.format(command, data))
                    result = self.parse_encoding(data)
                    if result:
                        return result

        logging.warning('Could not detect the default encoding.')
        return 'utf-8'

    def ssh_connect(self, args):
        ssh = self.ssh_client
        dst_addr = args[:2]
        logging.info('Connecting to {}:{}'.format(*dst_addr))

        try:
            ssh.connect(*args, timeout=options.timeout)
        except socket.error:
            raise ValueError('Unable to connect to {}:{}'.format(*dst_addr))
        except paramiko.BadAuthenticationType:
            raise ValueError('Bad authentication type.')
        except paramiko.AuthenticationException:
            raise ValueError('Authentication failed.')
        except paramiko.BadHostKeyException:
            raise ValueError('Bad host key.')

        transport = ssh.get_transport()
        if transport:
            transport.set_keepalive(30)

        term = self.get_argument('term', u'') or u'xterm'
        chan = ssh.invoke_shell(term=term)
        chan.setblocking(0)
        worker = Worker(self.loop, ssh, chan, dst_addr)
        worker.encoding = options.encoding if options.encoding else \
            self.get_default_encoding(ssh)

        if options.shell_integration:
            try:
                chan.sendall(SHELL_INTEGRATION_SNIPPET)
            except (OSError, IOError, EOFError) as exc:
                # Never let this cost the user their session: the path box
                # is always available as a fallback. paramiko raises EOFError
                # (not an OSError) when the transport is already gone, e.g.
                # the remote end closed the connection right after the shell
                # was invoked.
                logging.warning(
                    'Shell integration not sent: {}'.format(exc))

        return worker

    def check_origin(self):
        event_origin = self.get_argument('_origin', u'')
        header_origin = self.request.headers.get('Origin')
        origin = event_origin or header_origin

        if origin:
            if not super(IndexHandler, self).check_origin(origin):
                raise tornado.web.HTTPError(
                    403, 'Cross origin operation is not allowed.'
                )

            if not event_origin and self.origin_policy != 'same':
                self.set_header('Access-Control-Allow-Origin', origin)

    def head(self):
        pass

    def get(self):
        user_key_enabled = False
        has_key = False
        public_key = ''
        auth_username = self.request.headers.get(self.user_header, '')

        if self.user_key_dir and auth_username:
            try:
                user_keys.sanitize_username(auth_username)
                user_key_enabled = True
                has_key = user_keys.has_stored_key(
                    self.user_key_dir, auth_username
                )
                if has_key:
                    public_key = user_keys.read_public_key(
                        self.user_key_dir, auth_username
                    )
            except ValueError:
                pass

        user_hosts = self.get_user_hosts()
        user_settings = {}
        if self.user_hosts_enabled and auth_username:
            try:
                user_settings = user_data.read_settings(
                    self.user_data_dir, auth_username)
            except ValueError:
                user_settings = {}

        self.render('index.html', debug=self.debug, font=self.font,
                    allowed_hosts=self.allowed_hosts,
                    user_key_enabled=user_key_enabled,
                    has_stored_key=has_key,
                    public_key=public_key,
                    auth_username=auth_username,
                    user_hosts_enabled=self.user_hosts_enabled,
                    user_hosts=user_hosts,
                    user_settings=user_settings,
                    version=__version__)

    @tornado.gen.coroutine
    def post(self):
        if self.debug and self.get_argument('error', u''):
            # for testing purpose only
            raise ValueError('Uncaught exception')

        ip, port = self.get_client_addr()
        workers = clients.get(ip, {})
        if workers and len(workers) >= options.maxconn:
            raise tornado.web.HTTPError(403, 'Too many live connections.')

        self.check_origin()

        try:
            args = self.get_args()
        except InvalidValueError as exc:
            raise tornado.web.HTTPError(400, str(exc))

        future = self.executor.submit(self.ssh_connect, args)

        try:
            worker = yield future
        except (ValueError, paramiko.SSHException) as exc:
            logging.warning('SSH connection failed: {}'.format(exc))
            logging.debug(traceback.format_exc())
            self.result.update(status=str(exc))
        else:
            if not workers:
                clients[ip] = workers
            worker.src_addr = (ip, port)
            workers[worker.id] = worker
            self.loop.call_later(options.delay, recycle_worker, worker)
            self.result.update(id=worker.id, encoding=worker.encoding)

        self.write(self.result)


class UserKeyHandler(MixinHandler, tornado.web.RequestHandler):

    executor = ThreadPoolExecutor(max_workers=4)

    def initialize(self, loop, user_key_dir, user_header):
        super(UserKeyHandler, self).initialize(loop)
        self.user_key_dir = user_key_dir
        self.user_header = user_header

    def get_auth_username(self):
        username = self.request.headers.get(self.user_header, '')
        if not username:
            raise tornado.web.HTTPError(401, 'No authenticated user found.')
        try:
            user_keys.sanitize_username(username)
        except ValueError:
            raise tornado.web.HTTPError(400, 'Invalid username.')
        return username

    def get(self):
        username = self.get_auth_username()
        has_key = user_keys.has_stored_key(self.user_key_dir, username)
        result = {'has_key': has_key, 'username': username}
        if has_key:
            result['public_key'] = user_keys.read_public_key(
                self.user_key_dir, username
            )
        self.write(result)

    @tornado.gen.coroutine
    def post(self):
        username = self.get_auth_username()
        future = self.executor.submit(
            user_keys.generate_key_pair, self.user_key_dir, username
        )
        try:
            public_key = yield future
        except Exception:
            logging.exception('Failed to generate key pair for user %s', username)
            self.set_status(500)
            self.write({'error': 'Failed to generate key pair.'})
            return
        self.write({
            'has_key': True,
            'username': username,
            'public_key': public_key
        })


class UserDataMixin(object):

    def initialize(self, loop, user_data_dir, user_header,
                   user_hosts_enabled, allowed_hosts=None, live_config=None):
        super(UserDataMixin, self).initialize(loop)
        self.user_data_dir = user_data_dir
        self.user_header = user_header
        self.user_hosts_enabled = user_hosts_enabled
        self.live_config = live_config if live_config is not None else {}
        self._allowed_hosts = allowed_hosts or []

    @property
    def allowed_hosts(self):
        return self.live_config.get('allowed_hosts', self._allowed_hosts) or []

    def check_feature_enabled(self):
        # user_hosts_enabled already ANDs in user_data_dir (see main.py's
        # make_handlers), so checking user_data_dir again here is dead.
        if not self.user_hosts_enabled:
            raise tornado.web.HTTPError(
                403, 'User host management is not enabled.')

    def get_auth_username(self):
        username = self.request.headers.get(self.user_header, '')
        if not username:
            raise tornado.web.HTTPError(401, 'No authenticated user found.')
        try:
            user_keys.sanitize_username(username)
        except ValueError:
            raise tornado.web.HTTPError(400, 'Invalid username.')
        return username

    def get_json_body(self, key):
        try:
            data = json.loads(self.request.body.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            raise tornado.web.HTTPError(400, 'Malformed JSON body.')
        if not isinstance(data, dict):
            raise tornado.web.HTTPError(400, 'Body must be a JSON object.')
        if key not in data:
            raise tornado.web.HTTPError(
                400, 'Missing "{}" key.'.format(key))
        return data[key]

    def write_error(self, status_code, **kwargs):
        reason = self._reason
        exc_info = kwargs.get('exc_info')
        if exc_info:
            log_message = getattr(exc_info[1], 'log_message', None)
            if log_message:
                reason = log_message
        self.finish({'error': reason})


class UserHostsHandler(UserDataMixin, MixinHandler,
                       tornado.web.RequestHandler):

    def get(self):
        self.check_feature_enabled()
        username = self.get_auth_username()
        self.write({
            'admin_hosts': self.allowed_hosts,
            'user_hosts': user_data.read_hosts(self.user_data_dir, username),
        })

    def put(self):
        self.check_feature_enabled()
        username = self.get_auth_username()
        hosts = self.get_json_body('hosts')
        # Validate first: ValueErrors from validation describe the
        # caller's own input (bad hostname, bad port, ...) and are safe
        # to return to the client as-is.
        try:
            user_data.validate_hosts(hosts)
        except ValueError as exc:
            raise tornado.web.HTTPError(400, str(exc))
        # A failure here is about server state (disk permissions, a bad
        # data directory, ...), never the client's input. That detail
        # must never reach the client -- log it and return a generic 500.
        try:
            stored = user_data.write_hosts(self.user_data_dir, username, hosts)
        except ValueError as exc:
            logging.error(
                'Failed to write hosts for user {!r}: {}'.format(
                    username, exc))
            raise tornado.web.HTTPError(500, 'Failed to save hosts.')
        self.write({'user_hosts': stored})


class UserSettingsHandler(UserDataMixin, MixinHandler,
                          tornado.web.RequestHandler):

    def get(self):
        self.check_feature_enabled()
        username = self.get_auth_username()
        self.write({
            'settings': user_data.read_settings(self.user_data_dir, username),
        })

    def put(self):
        self.check_feature_enabled()
        username = self.get_auth_username()
        settings = self.get_json_body('settings')
        # Validate first: ValueErrors from validation describe the
        # caller's own input and are safe to return to the client as-is.
        try:
            user_data.validate_settings(settings)
        except ValueError as exc:
            raise tornado.web.HTTPError(400, str(exc))
        # A failure here is about server state, never the client's input.
        # That detail must never reach the client -- log it and return a
        # generic 500.
        try:
            stored = user_data.write_settings(
                self.user_data_dir, username, settings)
        except ValueError as exc:
            logging.error(
                'Failed to write settings for user {!r}: {}'.format(
                    username, exc))
            raise tornado.web.HTTPError(500, 'Failed to save settings.')
        self.write({'settings': stored})


class SettingsPaneHandler(UserDataMixin, MixinHandler,
                          tornado.web.RequestHandler):

    def get(self):
        if not self.user_hosts_enabled or not self.user_data_dir:
            raise tornado.web.HTTPError(404)
        username = self.get_auth_username()
        self.render('settings.html',
                    auth_username=username,
                    admin_hosts=self.allowed_hosts)


def content_disposition(filename):
    """Build an attachment header that survives a non-ASCII filename.

    Remote filenames are attacker-controlled if a user can be induced to
    download from a hostile host, so CR and LF are rejected outright rather
    than encoded.
    """
    if '\r' in filename or '\n' in filename:
        raise ValueError('Invalid filename')

    fallback = filename.encode('ascii', 'replace').decode('ascii')
    fallback = fallback.replace('\\', '_').replace('"', '_')
    quoted = quote(filename.encode('utf-8'), safe='')
    return "attachment; filename=\"{}\"; filename*=UTF-8''{}".format(
        fallback, quoted)


class TransferMixin(MixinHandler):
    """Shared resolution for the file-transfer endpoints.

    A transfer is reachable exactly where its terminal is: the same 32-byte
    worker token, and the same client-IP check the websocket applies.
    """

    executor = ThreadPoolExecutor(max_workers=cpu_count() * 2)

    MAX_CONCURRENT_TRANSFERS = 3

    def initialize(self, loop):
        super(TransferMixin, self).initialize()
        self.loop = loop

    WORKER_ID_HEADER = 'X-Worker-Id'

    def get_live_worker(self):
        # A header, never a query parameter: the token authorises the whole
        # session, and a URL copy would persist in browser history and in
        # access logs.
        worker_id = self.request.headers.get(self.WORKER_ID_HEADER, '')
        if not worker_id:
            raise tornado.web.HTTPError(404)

        worker = worker_module.live_workers.get(worker_id)
        if worker is None:
            raise tornado.web.HTTPError(404)

        ip = self.get_client_addr()[0]
        if worker.src_addr[0] != ip:
            logging.warning(
                'Transfer request for worker {} from {}, which does not own '
                'it'.format(worker_id, ip))
            raise tornado.web.HTTPError(404)

        if worker.closed:
            raise tornado.web.HTTPError(410, 'The terminal session ended.')

        return worker

    def get_path(self):
        path = self.get_argument('path', '')
        if not path:
            raise tornado.web.HTTPError(400, 'Missing path')
        return path

    def transfer_error(self, exc):
        """Remote filesystem errors describe the user's own machine and are
        reported verbatim. Contrast handler.py's rule for server state."""
        # log_message is later formatted as "%d %s: " + log_message with
        # (status_code, reason) as the first two args. Passing exc.message
        # directly as log_message means any '%' it contains (e.g. a path
        # like /tmp/100%.txt) is interpreted as a format directive and
        # crashes the logging call. Passing it as a '%s' argument instead
        # keeps it a literal value.
        raise tornado.web.HTTPError(exc.status, '%s', exc.message)

    def write_error(self, status_code, **kwargs):
        reason = self._reason
        exc_info = kwargs.get('exc_info')
        if exc_info and isinstance(exc_info[1], tornado.web.HTTPError):
            exc = exc_info[1]
            if exc.log_message:
                # transfer_error() passes the remote message as a '%s' arg
                # rather than folding it into log_message directly (see
                # there for why), so it must be %-formatted back in here
                # the same way Tornado's own logging does, or this would
                # report the literal string '%s' instead of the message.
                reason = exc.log_message % exc.args if exc.args \
                    else exc.log_message
        self.set_header('Content-Type', 'application/json')
        self.finish({'status': reason})


class TransferListHandler(TransferMixin, tornado.web.RequestHandler):

    @tornado.gen.coroutine
    def get(self):
        worker = self.get_live_worker()
        path = self.get_path()
        # Truncated rather than rejected: matches_filter's cost is
        # proportional to len(needle) per entry, and an oversized filter
        # is a performance nuisance on the executor thread, not something
        # worth an error response over.
        name_filter = self.get_argument('filter', '')[:256]

        try:
            result = yield self.executor.submit(
                self._list, worker, path, name_filter)
        except transfer.TransferError as exc:
            self.transfer_error(exc)

        self.write(result)

    def _list(self, worker, path, name_filter):
        sftp = transfer.open_sftp(worker.ssh)
        try:
            return transfer.list_directory(sftp, path, name_filter)
        finally:
            sftp.close()


class TransferTicketHandler(TransferMixin, tornado.web.RequestHandler):
    """Mints the short-lived credential the download navigation redeems.

    A browser navigation cannot carry the X-Worker-Id header, so the
    download URL needs something it can hold in the clear. A ticket is
    that: one path, one address, one use, sixty seconds.
    """

    def post(self):
        live = self.get_live_worker()

        try:
            payload = json.loads(to_str(self.request.body or b'{}'))
        except ValueError:
            raise tornado.web.HTTPError(400, 'Invalid JSON')
        if not isinstance(payload, dict):
            raise tornado.web.HTTPError(400, 'Invalid JSON')

        path = payload.get('path')
        if path is not None and not isinstance(path, str):
            raise tornado.web.HTTPError(400, 'Invalid path')
        path = path or ''
        if not path:
            raise tornado.web.HTTPError(400, 'Missing path')

        try:
            ticket = worker_module.mint_ticket(
                live.id, path, self.get_client_addr()[0], time.time())
        except worker_module.TicketPathTooLong:
            raise tornado.web.HTTPError(400, 'Path too long')
        except worker_module.TicketStoreFull:
            logging.warning('Download ticket store full; refusing to mint')
            raise tornado.web.HTTPError(503, 'Too many pending downloads.')

        self.write({'ticket': ticket,
                    'expires_in': worker_module.TICKET_TTL})


class TransferDownloadHandler(TransferMixin, tornado.web.RequestHandler):

    _download = None
    # Set by on_connection_close() if the client disconnects before
    # _download exists (still on the executor in open_sftp/Download.open).
    # _bind_download() checks this immediately once _download is assigned,
    # so the cancellation is not missed.
    _aborted = False

    def _bind_download(self, download):
        self._download = download
        if self._aborted:
            download.cancel()

    @tornado.gen.coroutine
    def get(self):
        # A browser navigation cannot carry the X-Worker-Id header, so this
        # route authenticates with a single-use ticket instead. Both the
        # worker and the path come from the ticket: a ticket for one file
        # must not authorise another.
        #
        # The ticket is only *peeked* here, not consumed: the worker it
        # names is needed for the concurrency check below, and if that
        # check rejects the request with 429, the ticket must still be
        # usable for a retry rather than having been spent on a rejection.
        # It is consumed for real, below, only once the request is known
        # to proceed.
        ticket = self.get_argument('ticket', '')
        ip = self.get_client_addr()[0]
        now = time.time()
        claim = worker_module.peek_ticket(ticket, ip, now)
        if claim is None:
            raise tornado.web.HTTPError(404)

        worker = worker_module.live_workers.get(claim['worker_id'])
        if worker is None:
            raise tornado.web.HTTPError(404)
        if worker.closed:
            # Kept as defence in depth: Worker.close() unregisters from
            # live_workers and drops the worker's tickets in the same
            # step, so in practice a closed session's tickets always fail
            # the live_workers.get() above (or peek_ticket itself, once
            # consumed) and this branch is not reachable while that
            # invariant holds. It exists for a future code path that might
            # set `closed` without dropping tickets.
            raise tornado.web.HTTPError(410, 'The terminal session ended.')

        if worker.transfers >= self.MAX_CONCURRENT_TRANSFERS:
            raise tornado.web.HTTPError(429, 'Too many transfers in progress.')

        # The request is proceeding: spend the ticket now. Re-validates
        # expiry/address rather than trusting the peek above, so a ticket
        # that happened to expire in between is still refused correctly.
        claim = worker_module.consume_ticket(ticket, ip, now)
        if claim is None:
            raise tornado.web.HTTPError(404)
        path = claim['path']

        try:
            disposition = content_disposition(posixpath.basename(path))
        except ValueError:
            raise tornado.web.HTTPError(400, 'Invalid filename')

        sftp = None
        worker.begin_transfer()
        try:
            sftp = yield self.executor.submit(transfer.open_sftp, worker.ssh)
            self._bind_download(transfer.Download(sftp, path))
            size = yield self.executor.submit(self._download.open)

            self.set_header('Content-Type', 'application/octet-stream')
            self.set_header('Content-Length', str(size))
            self.set_header('Content-Disposition', disposition)

            while True:
                chunk = yield self.executor.submit(self._download.read)
                if not chunk:
                    break
                self.write(chunk)
                # The flush is the backpressure point against a slow browser.
                yield self.flush()
        except transfer.TransferError as exc:
            self.transfer_error(exc)
        finally:
            worker.end_transfer()
            if self._download is not None:
                yield self.executor.submit(self._download.close)
                self._download = None
            if sftp is not None:
                yield self.executor.submit(sftp.close)

    def on_connection_close(self):
        # Cancellation is connection teardown, not a message. Download.read
        # returns b'' once cancelled, which ends the chunk loop. _download
        # may not exist yet (open_sftp/Download.open still running on the
        # executor), so record the abort unconditionally too; _bind_download
        # checks it once _download is assigned.
        self._aborted = True
        if self._download is not None:
            self._download.cancel()
        super(TransferDownloadHandler, self).on_connection_close()


@tornado.web.stream_request_body
class TransferUploadHandler(TransferMixin, tornado.web.RequestHandler):

    # Set once a mid-stream SFTP write fails, so post() can report the
    # error and any further chunks are drained without being written.
    _write_error = None

    # Set by on_connection_close() if the client disconnects while
    # prepare() is still suspended on a yield (SFTP channel open, then
    # Upload.open()), before self.sftp/self.upload exist for
    # on_connection_close() to clean up itself. prepare() checks this flag
    # right after each such yield and finishes the cleanup there instead,
    # since on_connection_close() will not fire again for an
    # already-closed connection. Mirrors TransferDownloadHandler's
    # _aborted/_bind_download pattern.
    _aborted = False

    def _bind_sftp(self, sftp):
        self.sftp = sftp
        if self._aborted:
            self._cleanup(abort=True)
            return False
        return True

    @tornado.gen.coroutine
    def prepare(self):
        # The app-wide max_body_size is sized for form posts. Without this,
        # any upload over 1 MB is refused before the handler ever runs.
        self.request.connection.set_max_body_size(max_upload_size)

        self.worker = self.get_live_worker()
        if self.worker.transfers >= self.MAX_CONCURRENT_TRANSFERS:
            raise tornado.web.HTTPError(429, 'Too many transfers in progress.')

        # Reserve the slot immediately after the cap check, before the
        # first yield. Both open_sftp() and Upload.open() below hand off
        # to the executor; if the increment waited until prepare() was
        # about to return (as it used to), every prepare() racing in that
        # window would still read the pre-increment count, all pass the
        # cap check, and all open an SFTP channel before any of them
        # incremented -- the concurrency cap would not hold against
        # several uploads dropped at once. self.counted now exists before
        # any yield, so on_connection_close()/_cleanup() can always find
        # and release it. Every exception from here on must route through
        # _cleanup() so this reservation is never leaked; _cleanup() is
        # safe to call more than once (it guards on self.counted).
        self.worker.begin_transfer()
        self.counted = True

        try:
            path = self.get_path()
            filename = self.get_argument('filename', '') or posixpath.basename(path)
            overwrite = self.get_argument('overwrite', '') == 'true'

            # Blocking paramiko calls (SFTP channel open, then stat/open of
            # the destination) must run on the executor, never the IOLoop.
            # prepare() runs to completion before Tornado starts reading the
            # request body (stream_request_body awaits it), so making it a
            # coroutine here is safe and keeps those calls off the IOLoop
            # like every other blocking paramiko call in this handler.
            sftp = yield self.executor.submit(
                transfer.open_sftp, self.worker.ssh)
            if not self._bind_sftp(sftp):
                # on_connection_close() already fired while this yield was
                # pending, before self.sftp existed for it to close. It has
                # been cleaned up above; there is nothing left to do.
                return

            self.upload = transfer.Upload(self.sftp, path, filename,
                                          overwrite=overwrite)
            try:
                yield self.executor.submit(self.upload.open)
            except transfer.TransferError as exc:
                self._cleanup(abort=False)
                if self._aborted:
                    return
                self.transfer_error(exc)

            if self._aborted:
                # Same race as above, but the disconnect landed while
                # Upload.open() was pending instead. self.sftp/self.upload
                # already exist here, so on_connection_close() closed them
                # itself; nothing left to do but stop before counting this
                # as an in-progress transfer.
                self._cleanup(abort=True)
                return
        except Exception:
            # Anything that escapes above (e.g. get_path()'s 400 for a
            # missing path, or the HTTPError raised by transfer_error()
            # just above) must not leave the slot reserved. _cleanup() is
            # idempotent, so this is safe even when the branch that raised
            # had already cleaned up itself.
            self._cleanup(abort=True)
            raise

    def data_received(self, chunk):
        # Returning the Future is what makes backpressure real: Tornado stops
        # reading the socket until the SFTP write lands, so a slow host
        # throttles the browser instead of growing server memory. The
        # executor hands back a concurrent.futures.Future, which the IOLoop
        # cannot await directly, so it is wrapped for asyncio.
        if self._write_error is not None:
            # A previous chunk already failed. Keep draining the body
            # cheaply (no SFTP write, no backpressure future) so the
            # connection completes normally and post() can report the
            # error, instead of leaving the client hanging.
            return None
        return asyncio.wrap_future(
            self.executor.submit(self._write, chunk))

    def _write(self, chunk):
        # Runs on the executor. A TransferError here (e.g. ENOSPC) must not
        # escape as an exception on the wrapped future: Tornado's body-
        # reading loop only catches HTTPInputError, so anything else would
        # propagate uncaught, request._body_future would never resolve,
        # post() would never run, and the client would just see the
        # connection drop instead of the verbatim remote error. Recording
        # it here and letting the future resolve normally lets post()
        # surface it properly.
        #
        # self.upload is read into a local first: on_connection_close() ->
        # _cleanup(abort=True) runs on the IOLoop and sets self.upload =
        # None, and it can land while this call is already running on the
        # executor with a data_received() future still pending. Reading
        # self.upload a second time after that race would hit None (or,
        # worse, a handle that abort() is concurrently sftp.remove()-ing).
        # Binding it once up front makes this call consistent even if
        # self.upload changes underneath it mid-write.
        upload = self.upload
        if upload is None:
            return
        try:
            upload.write(chunk)
        except transfer.TransferError as exc:
            self._write_error = exc

    @tornado.gen.coroutine
    def post(self):
        if self._write_error is not None:
            # Abort so a truncated file isn't left under the real name,
            # then report the remote error verbatim, same as every other
            # transfer failure.
            self._cleanup(abort=True)
            self.transfer_error(self._write_error)
            return
        yield self.executor.submit(self.upload.close)
        result = {'path': self.upload.final_path,
                  'bytes': self.upload.bytes_written}
        self._cleanup(abort=False)
        self.write(result)

    def on_connection_close(self):
        # A cancelled upload leaves a truncated file under the real name
        # unless it is removed. This may fire while prepare() is still
        # suspended on a yield, before self.sftp/self.upload exist yet for
        # _cleanup() to find (it is a no-op then); record the abort
        # unconditionally too so prepare() can finish the cleanup itself
        # once the resource it was waiting on exists, since this callback
        # will not fire again for the same connection.
        self._aborted = True
        self._cleanup(abort=True)
        super(TransferUploadHandler, self).on_connection_close()

    def _cleanup(self, abort):
        if getattr(self, 'counted', False):
            self.worker.end_transfer()
            self.counted = False
        upload = getattr(self, 'upload', None)
        if upload is not None:
            if abort:
                upload.abort()
            else:
                upload.close()
            self.upload = None
        sftp = getattr(self, 'sftp', None)
        if sftp is not None:
            try:
                sftp.close()
            except Exception:
                pass
            self.sftp = None


class WsockHandler(MixinHandler, tornado.websocket.WebSocketHandler):

    def initialize(self, loop):
        super(WsockHandler, self).initialize(loop)
        self.worker_ref = None
        self._idle_timeout = None

    def open(self):
        self.src_addr = self.get_client_addr()
        logging.info('Connected from {}:{}'.format(*self.src_addr))

        workers = clients.get(self.src_addr[0])
        if not workers:
            self.close(reason='Websocket authentication failed.')
            return

        try:
            worker_id = self.get_value('id')
        except (tornado.web.MissingArgumentError, InvalidValueError) as exc:
            self.close(reason=str(exc))
        else:
            worker = workers.get(worker_id)
            if worker:
                workers[worker_id] = None
                register_live_worker(worker)
                self.set_nodelay(True)
                worker.set_handler(self)
                self.worker_ref = weakref.ref(worker)
                self.loop.add_handler(worker.fd, worker, IOLoop.READ)
                self._reset_idle_timeout()
            else:
                self.close(reason='Websocket authentication failed.')

    def _reset_idle_timeout(self):
        if self._idle_timeout:
            self.loop.remove_timeout(self._idle_timeout)
            self._idle_timeout = None
        timeout = options.idletimeout
        if timeout > 0:
            self._idle_timeout = self.loop.call_later(
                timeout, self._idle_disconnect
            )

    def _idle_disconnect(self):
        worker = self.worker_ref() if self.worker_ref else None
        if worker and worker.transfers:
            # A transfer is in flight on this connection. Closing now would
            # kill the SSH session it rides on, so re-arm instead.
            logging.debug('Idle timeout deferred: transfer in progress')
            self._reset_idle_timeout()
            return

        logging.info('Idle timeout for {}:{}'.format(*self.src_addr))
        if worker:
            worker.close(reason='Idle timeout.')

    def on_message(self, message):
        logging.debug('{!r} from {}:{}'.format(message, *self.src_addr))
        worker = self.worker_ref()
        if not worker:
            # The worker has likely been closed. Do not process.
            logging.debug(
                "received message to closed worker from {}:{}".format(
                    *self.src_addr
                )
            )
            self.close(reason='No worker found')
            return

        if worker.closed:
            self.close(reason='Worker closed')
            return

        try:
            msg = json.loads(message)
        except JSONDecodeError:
            return

        if not isinstance(msg, dict):
            return

        self._reset_idle_timeout()

        resize = msg.get('resize')
        if resize and len(resize) == 2:
            try:
                worker.chan.resize_pty(*resize)
            except (TypeError, struct.error, paramiko.SSHException):
                pass

        data = msg.get('data')
        if data and isinstance(data, UnicodeType):
            worker.data_to_dst.append(data)
            worker.on_write()

    def on_close(self):
        if self._idle_timeout:
            self.loop.remove_timeout(self._idle_timeout)
            self._idle_timeout = None
        logging.info('Disconnected from {}:{}'.format(*self.src_addr))
        if not self.close_reason:
            self.close_reason = 'client disconnected'

        worker = self.worker_ref() if self.worker_ref else None
        if worker:
            worker.close(reason=self.close_reason)
