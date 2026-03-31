import logging
import os.path
import ssl
import sys

import yaml
from tornado.options import define
from webssh.policy import (
    load_host_keys, get_policy_class, check_policy_setting
)
from webssh.utils import (
    to_ip_address, parse_origin_from_url, is_valid_encoding
)
from webssh._version import __version__


def print_version(flag):
    if flag:
        print(__version__)
        sys.exit(0)


define('address', default='', help='Listen address')
define('port', type=int, default=8888,  help='Listen port')
define('ssladdress', default='', help='SSL listen address')
define('sslport', type=int, default=4433,  help='SSL listen port')
define('certfile', default='', help='SSL certificate file')
define('keyfile', default='', help='SSL private key file')
define('debug', type=bool, default=False, help='Debug mode')
define('policy', default='warning',
       help='Missing host key policy, reject|autoadd|warning')
define('hostfile', default='', help='User defined host keys file')
define('syshostfile', default='', help='System wide host keys file')
define('tdstream', default='', help='Trusted downstream, separated by comma')
define('redirect', type=bool, default=True, help='Redirecting http to https')
define('fbidhttp', type=bool, default=True,
       help='Forbid public plain http incoming requests')
define('xheaders', type=bool, default=True, help='Support xheaders')
define('xsrf', type=bool, default=True, help='CSRF protection')
define('origin', default='same', help='''Origin policy,
'same': same origin policy, matches host name and port number;
'primary': primary domain policy, matches primary domain only;
'<domains>': custom domains policy, matches any domain in the <domains> list
separated by comma;
'*': wildcard policy, matches any domain, allowed in debug mode only.''')
define('wpintvl', type=float, default=30, help='Websocket ping interval')
define('timeout', type=float, default=3, help='SSH connection timeout')
define('idletimeout', type=int, default=1800,
       help='Idle timeout in seconds (0 to disable)')
define('delay', type=float, default=3, help='The delay to call recycle_worker')
define('maxconn', type=int, default=20,
       help='Maximum live connections (ssh sessions) per client')
define('font', default='', help='custom font filename')
define('encoding', default='',
       help='''The default character encoding of ssh servers.
Example: --encoding='utf-8' to solve the problem with some switches&routers''')
define('config', default='',
       help='YAML configuration file (hosts, userkeydir, userheader, trusted_proxies)')
define('userkeydir', default='',
       help='Directory to store per-user SSH key pairs')
define('userheader', default='X-Authentik-Username',
       help='HTTP header with authenticated username')
define('version', type=bool, help='Show version information',
       callback=print_version)


base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
font_dirs = ['webssh', 'static', 'css', 'fonts']
max_body_size = 1 * 1024 * 1024


class Font(object):

    def __init__(self, filename, dirs):
        self.family = self.get_family(filename)
        self.url = self.get_url(filename, dirs)

    def get_family(self, filename):
        return filename.split('.')[0]

    def get_url(self, filename, dirs):
        return '/'.join(dirs + [filename])


def get_app_settings(options):
    settings = dict(
        template_path=os.path.join(base_dir, 'webssh', 'templates'),
        static_path=os.path.join(base_dir, 'webssh', 'static'),
        websocket_ping_interval=options.wpintvl,
        debug=options.debug,
        xsrf_cookies=options.xsrf,
        font=Font(
            get_font_filename(options.font,
                              os.path.join(base_dir, *font_dirs)),
            font_dirs[1:]
        ),
        origin_policy=get_origin_setting(options)
    )
    return settings


def get_server_settings(options):
    settings = dict(
        xheaders=options.xheaders,
        max_body_size=max_body_size,
        trusted_downstream=get_trusted_downstream(options.tdstream)
    )
    return settings


def get_host_keys_settings(options):
    if not options.hostfile:
        host_keys_filename = os.path.join(base_dir, 'known_hosts')
    else:
        host_keys_filename = options.hostfile
    host_keys = load_host_keys(host_keys_filename)

    if not options.syshostfile:
        filename = os.path.expanduser('~/.ssh/known_hosts')
    else:
        filename = options.syshostfile
    system_host_keys = load_host_keys(filename)

    settings = dict(
        host_keys=host_keys,
        system_host_keys=system_host_keys,
        host_keys_filename=host_keys_filename
    )
    return settings


def get_policy_setting(options, host_keys_settings):
    policy_class = get_policy_class(options.policy)
    logging.info(policy_class.__name__)
    check_policy_setting(policy_class, host_keys_settings)
    return policy_class()


def get_ssl_context(options):
    if not options.certfile and not options.keyfile:
        return None
    elif not options.certfile:
        raise ValueError('certfile is not provided')
    elif not options.keyfile:
        raise ValueError('keyfile is not provided')
    elif not os.path.isfile(options.certfile):
        raise ValueError('File {!r} does not exist'.format(options.certfile))
    elif not os.path.isfile(options.keyfile):
        raise ValueError('File {!r} does not exist'.format(options.keyfile))
    else:
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(options.certfile, options.keyfile)
        return ssl_ctx


def get_trusted_downstream(tdstream):
    import ipaddress
    ips = set()
    networks = []
    for entry in tdstream.split(','):
        entry = entry.strip()
        if not entry:
            continue
        if '/' in entry:
            networks.append(ipaddress.ip_network(entry, strict=False))
        else:
            to_ip_address(entry)
            ips.add(entry)
    return TrustedDownstream(ips, networks)


class TrustedDownstream:
    """Set-like object that supports both exact IPs and CIDR networks."""
    def __init__(self, ips, networks):
        self.ips = ips
        self.networks = networks

    def __contains__(self, ip):
        import ipaddress
        if ip in self.ips:
            return True
        if self.networks:
            addr = ipaddress.ip_address(ip)
            for net in self.networks:
                if addr in net:
                    return True
        return False

    def __iter__(self):
        return iter(self.ips)

    def __bool__(self):
        return bool(self.ips) or bool(self.networks)

    def __repr__(self):
        parts = sorted(self.ips) + [str(n) for n in self.networks]
        return repr(parts)


def get_origin_setting(options):
    if options.origin == '*':
        if not options.debug:
            raise ValueError(
                'Wildcard origin policy is only allowed in debug mode.'
            )
        else:
            return '*'

    origin = options.origin.lower()
    if origin in ['same', 'primary']:
        return origin

    origins = set()
    for url in origin.split(','):
        orig = parse_origin_from_url(url)
        if orig:
            origins.add(orig)

    if not origins:
        raise ValueError('Empty origin list')

    return origins


def get_font_filename(font, font_dir):
    filenames = {f for f in os.listdir(font_dir) if not f.startswith('.')
                 and os.path.isfile(os.path.join(font_dir, f))}
    if font:
        if font not in filenames:
            raise ValueError(
                'Font file {!r} not found'.format(os.path.join(font_dir, font))
            )
    elif filenames:
        font = filenames.pop()

    return font


def check_encoding_setting(encoding):
    if encoding and not is_valid_encoding(encoding):
        raise ValueError('Unknown character encoding {!r}.'.format(encoding))


def load_config_file(filepath):
    if not os.path.isfile(filepath):
        raise ValueError(
            'Config file {!r} does not exist'.format(filepath)
        )

    with open(filepath, 'r') as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(
            'Config file must contain a YAML mapping'
        )

    return data


def _validate_host_key(host_key, hostname):
    import base64
    parts = host_key.strip().split()
    if len(parts) < 2:
        raise ValueError(
            'Invalid host_key for {!r}: expected "key-type base64-key"'.format(
                hostname)
        )
    key_type = parts[0]
    valid_types = (
        'ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256',
        'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
    )
    if key_type not in valid_types:
        raise ValueError(
            'Invalid host_key type {!r} for {!r}'.format(key_type, hostname)
        )
    try:
        base64.b64decode(parts[1], validate=True)
    except Exception:
        raise ValueError(
            'Invalid host_key base64 data for {!r}'.format(hostname)
        )


def parse_allowed_hosts(data):
    if 'hosts' not in data:
        return []

    hosts = data['hosts']
    if not isinstance(hosts, list) or not hosts:
        raise ValueError(
            'Config file "hosts" must be a non-empty list'
        )

    result = []
    for entry in hosts:
        if not isinstance(entry, dict):
            raise ValueError('Each host entry must be a mapping')
        if 'hostname' not in entry:
            raise ValueError('Each host entry must have a "hostname" field')
        raw_keys = entry.get('host_key', [])
        if isinstance(raw_keys, str):
            raw_keys = [raw_keys] if raw_keys else []
        elif not isinstance(raw_keys, list):
            raise ValueError(
                'host_key for {!r} must be a string or list'.format(
                    entry['hostname'])
            )
        for k in raw_keys:
            _validate_host_key(k, entry['hostname'])
        port = int(entry.get('port', 22))
        if port < 1 or port > 65535:
            raise ValueError(
                'Invalid port {!r} for host {!r}; must be 1-65535'.format(
                    port, entry['hostname'])
            )
        host = {
            'name': entry.get('name', entry['hostname']),
            'hostname': entry['hostname'],
            'port': port,
            'host_keys': raw_keys,
        }
        result.append(host)

    return result


def load_allowed_hosts(filepath):
    data = load_config_file(filepath)
    if 'hosts' not in data:
        raise ValueError(
            'Config file must contain a "hosts" key'
        )
    return parse_allowed_hosts(data)


def get_allowed_hosts_setting(options):
    if not options.config:
        return []
    data = load_config_file(options.config)
    return parse_allowed_hosts(data)


def get_config_settings(options):
    if not options.config:
        return {}
    return load_config_file(options.config)


def apply_config_settings(options):
    config = get_config_settings(options)
    if not config:
        return

    if options.policy == 'warning' and 'policy' in config:
        options.policy = config['policy']
    if not options.userkeydir and 'userkeydir' in config:
        options.userkeydir = config['userkeydir']
    if options.userheader == 'X-Authentik-Username' and 'userheader' in config:
        options.userheader = config['userheader']
    if 'idle_timeout' in config:
        raw = config['idle_timeout']
        try:
            timeout = int(raw)
        except (TypeError, ValueError):
            raise ValueError(
                'Invalid idle_timeout value {!r} in config; must be a non-negative integer'.format(raw)
            )
        if timeout < 0:
            raise ValueError(
                'Invalid idle_timeout value {!r} in config; must be a non-negative integer'.format(raw)
            )
        options.idletimeout = timeout
    if 'trusted_proxies' in config:
        import ipaddress
        proxies = config['trusted_proxies']
        if not isinstance(proxies, list):
            raise ValueError('trusted_proxies must be a list of IP addresses or CIDR ranges')
        proxy_entries = []
        for entry in proxies:
            entry = str(entry).strip()
            if entry:
                if '/' in entry:
                    ipaddress.ip_network(entry, strict=False)
                else:
                    to_ip_address(entry)
                proxy_entries.append(entry)
        if proxy_entries:
            existing = options.tdstream
            if existing:
                options.tdstream = existing + ',' + ','.join(proxy_entries)
            else:
                options.tdstream = ','.join(proxy_entries)


def check_user_key_dir(user_key_dir, tdstream=''):
    if not user_key_dir:
        return
    if not tdstream:
        logging.warning(
            'SECURITY WARNING: userkeydir is set but no trusted_proxies '
            'configured. The user header can be spoofed by any client.'
        )
    try:
        os.makedirs(user_key_dir, mode=0o700, exist_ok=True)
    except PermissionError:
        raise ValueError(
            'Cannot create user key directory {!r}: permission denied. '
            'Create the directory manually or run with appropriate '
            'permissions.'.format(user_key_dir)
        )
    except (FileExistsError, NotADirectoryError):
        raise ValueError(
            'User key directory {!r} is not a directory'.format(user_key_dir)
        )
    if not os.path.isdir(user_key_dir):
        raise ValueError(
            'User key directory {!r} is not a directory'.format(user_key_dir)
        )
