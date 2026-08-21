import ipaddress
import json
import re

try:
    from types import UnicodeType
except ImportError:
    UnicodeType = str

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


numeric = re.compile(r'[0-9]+$')
allowed = re.compile(r'(?!-)[a-z0-9-]{1,63}(?<!-)$', re.IGNORECASE)


def to_str(bstr, encoding='utf-8'):
    if isinstance(bstr, bytes):
        return bstr.decode(encoding)
    return bstr


def to_bytes(ustr, encoding='utf-8'):
    if isinstance(ustr, UnicodeType):
        return ustr.encode(encoding)
    return ustr


def json_encode_for_script(value):
    """JSON-encode a value for safe inline embedding in a <script> block.

    tornado.escape.json_encode backslash-escapes "</" so a literal
    "</script>" cannot appear, but that alone does not stop the HTML
    tokenizer: inside script data, a "<!--" followed by a case-insensitive
    "<script" -- with no closing tag needed -- switches the tokenizer into
    the "script data double escaped" state. That decision is made by the
    raw HTML parser scanning for '<', not by anything JS-level escaping
    can influence. Escaping every '<' to its unicode form removes every
    one of those trigger sequences ("</script>", "<!--", "<script") from
    the HTML source at once, which is why this replaces '<' outright
    rather than only the "</" pair tornado's own helper targets.
    """
    return json.dumps(value).replace('<', '\\u003c')


def to_int(string):
    try:
        return int(string)
    except (TypeError, ValueError):
        pass


def to_ip_address(ipstr):
    ip = to_str(ipstr)
    if ip.startswith('fe80::'):
        ip = ip.split('%')[0]
    return ipaddress.ip_address(ip)


def is_valid_ip_address(ipstr):
    try:
        to_ip_address(ipstr)
    except ValueError:
        return False
    return True


def is_valid_port(port):
    return 0 < port < 65536


def is_valid_encoding(encoding):
    try:
        u'test'.encode(encoding)
    except LookupError:
        return False
    except ValueError:
        return False
    return True


def is_ip_hostname(hostname):
    it = iter(hostname)
    if next(it) == '[':
        return True
    for ch in it:
        if ch != '.' and not ch.isdigit():
            return False
    return True


def is_valid_hostname(hostname):
    if hostname[-1] == '.':
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False

    labels = hostname.split('.')

    # the TLD must be not all-numeric
    if numeric.match(labels[-1]):
        return False

    return all(allowed.match(label) for label in labels)


def is_same_primary_domain(domain1, domain2):
    i = -1
    dots = 0
    l1 = len(domain1)
    l2 = len(domain2)
    m = min(l1, l2)

    while i >= -m:
        c1 = domain1[i]
        c2 = domain2[i]

        if c1 == c2:
            if c1 == '.':
                dots += 1
                if dots == 2:
                    return True
        else:
            return False

        i -= 1

    if l1 == l2:
        return True

    if dots == 0:
        return False

    c = domain1[i] if l1 > m else domain2[i]
    return c == '.'


def parse_origin_from_url(url):
    url = url.strip()
    if not url:
        return

    if not (url.startswith('http://') or url.startswith('https://') or
            url.startswith('//')):
        url = '//' + url

    parsed = urlparse(url)
    port = parsed.port
    scheme = parsed.scheme

    if scheme == '':
        scheme = 'https' if port == 443 else 'http'

    if port == 443 and scheme == 'https':
        netloc = parsed.netloc.replace(':443', '')
    elif port == 80 and scheme == 'http':
        netloc = parsed.netloc.replace(':80', '')
    else:
        netloc = parsed.netloc

    return '{}://{}'.format(scheme, netloc)
