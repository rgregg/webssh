import json
import logging
import os
import re
import tempfile
import time
import uuid

from webssh.settings import parse_host_entry
from webssh.user_keys import sanitize_username
from webssh.utils import is_valid_encoding

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
MAX_HOSTS = 200
MAX_FIELD_LENGTH = 512
MAX_CORRUPT_COPIES = 20

HOSTS_FILENAME = 'hosts.json'
SETTINGS_FILENAME = 'settings.json'

COLOR_RE = re.compile(r'^(#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6}|[a-zA-Z]{1,20})$')
TERM_RE = re.compile(r'^[a-zA-Z0-9._-]{1,32}$')

# Only these keys are ever persisted. Anything else — notably passwords,
# TOTP codes, and passphrases — is dropped.
COLOR_SETTINGS = ('background', 'foreground', 'cursor')
STRING_SETTINGS = ('last_hostname', 'last_username')


def get_user_data_dir(base_dir, username):
    sanitize_username(username)
    user_dir = os.path.join(base_dir, username)
    try:
        real_base = os.path.realpath(base_dir)
        real_user = os.path.realpath(user_dir)
    except OSError:
        # Callers only ever catch ValueError from this function.
        raise ValueError('Invalid username.')
    if not real_user.startswith(real_base + os.sep):
        raise ValueError('Invalid username.')
    return real_user


def _check_string(value, name, allow_empty=True):
    if not isinstance(value, str):
        # Deliberately ValueError, not TypeError: handler.py catches
        # ValueError at these call sites to return a 400 for malformed
        # request payloads; TypeError would surface as an unhandled 500.
        raise ValueError(f'{name} must be a string')  # noqa: TRY004
    if len(value) > MAX_FIELD_LENGTH:
        raise ValueError(f'{name} is too long')
    if not allow_empty and not value:
        raise ValueError(f'{name} must not be empty')
    return value


def validate_hosts(hosts):
    if not isinstance(hosts, list):
        # See _check_string above: ValueError is intentional here too, for
        # the same 400-vs-500 reason.
        raise ValueError('hosts must be a list')  # noqa: TRY004
    if len(hosts) > MAX_HOSTS:
        raise ValueError(f'Too many hosts; the limit is {MAX_HOSTS}')

    result = []
    for entry in hosts:
        host = parse_host_entry(entry)
        host['username'] = _check_string(
            entry.get('username', ''), 'username')
        host['default_command'] = _check_string(
            entry.get('default_command', ''), 'default_command')
        result.append(host)
    return result


def validate_settings(settings):
    if not isinstance(settings, dict):
        # See _check_string above: ValueError is intentional here too, for
        # the same 400-vs-500 reason.
        raise ValueError('settings must be a mapping')  # noqa: TRY004

    result = {}

    if 'font_size' in settings:
        value = settings['font_size']
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError('font_size must be an integer')
        if value < 6 or value > 40:
            raise ValueError('font_size must be between 6 and 40')
        result['font_size'] = value

    for name in COLOR_SETTINGS:
        if name in settings:
            value = settings[name]
            if not isinstance(value, str) or not COLOR_RE.match(value):
                raise ValueError(f'Invalid color for {name}')
            result[name] = value

    if 'cursor_blink' in settings:
        value = settings['cursor_blink']
        if not isinstance(value, bool):
            raise ValueError('cursor_blink must be a boolean')
        result['cursor_blink'] = value

    if 'encoding' in settings:
        value = settings['encoding']
        if not isinstance(value, str) or not is_valid_encoding(value):
            raise ValueError(f'Invalid encoding {value!r}')
        result['encoding'] = value

    if 'term' in settings:
        value = settings['term']
        if not isinstance(value, str) or not TERM_RE.match(value):
            raise ValueError(f'Invalid term {value!r}')
        result['term'] = value

    if 'key_source' in settings:
        value = settings['key_source']
        if value not in ('stored', 'upload'):
            raise ValueError('key_source must be "stored" or "upload"')
        result['key_source'] = value

    for name in STRING_SETTINGS:
        if name in settings:
            result[name] = _check_string(settings[name], name)

    if 'last_port' in settings:
        value = settings['last_port']
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError('last_port must be an integer')
        if value < 1 or value > 65535:
            raise ValueError('last_port must be between 1 and 65535')
        result['last_port'] = value

    return result


def quarantine_file(path):
    """Move an unreadable data file aside so a later write cannot destroy it.

    Returns the path the file was moved to, or None if it could not be
    moved. An existing .corrupt file is never overwritten; a numeric
    suffix is added instead, up to MAX_CORRUPT_COPIES -- beyond that, a
    name with enough entropy to not collide is used instead of giving up,
    since giving up would leave the unreadable file in place and reopen
    the exact data-loss path this function exists to prevent.
    """
    target = path + '.corrupt'
    suffix = 0
    while os.path.exists(target):
        suffix += 1
        if suffix > MAX_CORRUPT_COPIES:
            # A random suffix on top of the current time makes a
            # collision astronomically unlikely, but still check --
            # os.rename would otherwise silently overwrite an existing
            # target, destroying whatever was quarantined there.
            while True:
                target = f'{path}.corrupt.{int(time.time())}-{uuid.uuid4().hex[:8]}'
                if not os.path.exists(target):
                    break
            break
        target = f'{path}.corrupt.{suffix}'
    try:
        os.rename(path, target)
    except OSError as exc:
        logger.error(
            f'Could not quarantine unreadable file {path!r}: {exc}')
        return None
    return target


def _read_json(base_dir, username, filename, payload_key, empty):
    user_dir = get_user_data_dir(base_dir, username)
    path = os.path.join(user_dir, filename)
    if not os.path.isfile(path):
        return empty

    def give_up(reason):
        # The caller cannot distinguish "no data" from "unreadable data", and
        # a later save would overwrite the file with the empty payload. Move
        # the original aside so it stays recoverable.
        target = quarantine_file(path)
        moved = f'; moved to {target!r}' if target else ''
        logger.error(
            f'Unreadable {filename} for user {username!r}: {reason}{moved}'
        )
        return empty

    try:
        with open(path) as f:
            data = json.load(f)
    except (ValueError, OSError) as exc:
        return give_up(exc)
    if not isinstance(data, dict):
        return give_up('payload is not a mapping')
    payload = data.get(payload_key, empty)
    if not isinstance(payload, type(empty)):
        return give_up(f'{payload_key!r} has the wrong type')
    return payload


def _write_json(base_dir, username, filename, payload_key, payload):
    user_dir = get_user_data_dir(base_dir, username)
    try:
        os.makedirs(user_dir, mode=0o700, exist_ok=True)
    except PermissionError:
        raise ValueError(
            f'Cannot create data directory for user {username!r}: permission denied. '
            f'Check ownership of {base_dir!r}'
        )

    body = json.dumps(
        {'version': SCHEMA_VERSION, payload_key: payload}, indent=2
    ).encode()

    path = os.path.join(user_dir, filename)
    fd, tmp_path = tempfile.mkstemp(dir=user_dir)
    try:
        # os.fdopen + file.write loops until every byte is written (or
        # raises), unlike a bare os.write, which is permitted to return
        # having written fewer bytes than asked and cannot be relied on
        # for a single call over an arbitrary payload size.
        with os.fdopen(fd, 'wb') as f:
            f.write(body)
            f.flush()
            os.fchmod(f.fileno(), 0o600)
        os.rename(tmp_path, path)
    except OSError as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        # Every caller of write_hosts/write_settings only catches
        # ValueError; an uncaught OSError here would otherwise escape as
        # an unhandled 500 with no useful message for the client.
        raise ValueError(
            f'Could not write {filename} for user {username!r}: {exc}'
        )


def read_hosts(base_dir, username):
    return _read_json(base_dir, username, HOSTS_FILENAME, 'hosts', [])


def write_hosts(base_dir, username, hosts):
    validated = validate_hosts(hosts)
    _write_json(base_dir, username, HOSTS_FILENAME, 'hosts', validated)
    return validated


def read_settings(base_dir, username):
    return _read_json(base_dir, username, SETTINGS_FILENAME, 'settings', {})


def write_settings(base_dir, username, settings):
    validated = validate_settings(settings)
    _write_json(
        base_dir, username, SETTINGS_FILENAME, 'settings', validated)
    return validated
