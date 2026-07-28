# User-Editable Host List and Roaming Settings — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let each signed-in user maintain a private list of SSH hosts and a set of preferences, stored server-side so they roam across browsers and machines.

**Architecture:** A new `webssh/user_data.py` stores per-user JSON under `<userdatadir>/<username>/`, mirroring how `user_keys.py` already stores per-user SSH keys. Two JSON APIs read and write it. `IndexHandler` merges the user's hosts with the administrator allowlist at connect time, with administrator entries winning collisions. The UI is a settings tab inside the existing in-app tab bar, fed by a server-rendered HTML fragment.

**Tech Stack:** Python 3, Tornado, Paramiko, PyYAML, jQuery, xterm.js. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-07-27-user-editable-hosts-design.md`

## Global Constraints

- **No new dependencies.** Everything needed is already in `requirements.txt`.
- **Match existing code style.** The codebase uses `'{}'.format(x)` rather than f-strings, `super(ClassName, self).__init__(...)` rather than bare `super()`, and `u''` string literals in handler argument defaults. Follow it; do not modernize surrounding code.
- **JavaScript is ES5 + jQuery.** `webssh/static/js/main.js` uses `var`, no arrow functions, no `const`/`let`, no modules. Match it.
- **Tests run with pytest** but are written as `unittest.TestCase` (or `tornado.testing.AsyncHTTPTestCase` for handlers). Run with `.venv/bin/python -m pytest`.
- **Never persist secrets.** Passwords, TOTP codes, and key passphrases must never reach `user_data.py` or any stored JSON. Validation whitelists fields, so unknown keys are dropped rather than stored.
- **Backward compatibility is mandatory.** With `user_hosts` unset or false, every existing behavior must be byte-for-byte unchanged. The full existing suite must stay green after every task.
- **Feature gate:** active only when `user_hosts` is true AND a data directory resolves AND the request carries a username in the `userheader` header.
- **Internal host key field naming:** YAML and JSON input use `host_key`; the parsed/normalized dict uses `host_keys` (plural, always a list). This asymmetry already exists in `parse_allowed_hosts` — preserve it.

**Baseline:** the suite is green at 152 passed. Verify with `.venv/bin/python -m pytest -q` before starting. If you see ~53 failures mentioning paramiko and `known_hosts`, your `~/.ssh/known_hosts` contains a malformed line; that is an environment problem, not a regression.

---

### Task 1: Extract single-host parsing in settings.py

Administrator hosts and user hosts must be validated by identical code, so a user cannot submit a host key pin an administrator could not. Right now that logic is inlined in the `parse_allowed_hosts` loop. This task extracts it with no behavior change.

**Files:**
- Modify: `webssh/settings.py:286-323` (`parse_allowed_hosts`)
- Test: `tests/test_settings.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `parse_host_entry(entry)` in `webssh/settings.py`. Takes a dict, returns a new dict `{'name': str, 'hostname': str, 'port': int, 'host_keys': list[str]}`, raises `ValueError` on any invalid field. Tasks 2 and 4 both call it.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_settings.py`:

```python
class TestParseHostEntry(unittest.TestCase):

    def test_minimal_entry(self):
        from webssh.settings import parse_host_entry
        host = parse_host_entry({'hostname': 'example.com'})
        self.assertEqual(host, {
            'name': 'example.com',
            'hostname': 'example.com',
            'port': 22,
            'host_keys': [],
        })

    def test_full_entry_with_string_host_key(self):
        from webssh.settings import parse_host_entry
        key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefgh'
        host = parse_host_entry({
            'name': 'Prod', 'hostname': '10.0.1.5', 'port': 2222,
            'host_key': key,
        })
        self.assertEqual(host['name'], 'Prod')
        self.assertEqual(host['port'], 2222)
        self.assertEqual(host['host_keys'], [key])

    def test_missing_hostname(self):
        from webssh.settings import parse_host_entry
        with self.assertRaises(ValueError):
            parse_host_entry({'name': 'nope'})

    def test_not_a_mapping(self):
        from webssh.settings import parse_host_entry
        with self.assertRaises(ValueError):
            parse_host_entry('example.com')

    def test_invalid_port(self):
        from webssh.settings import parse_host_entry
        for port in [0, 70000, -1]:
            with self.assertRaises(ValueError):
                parse_host_entry({'hostname': 'a.com', 'port': port})

    def test_invalid_host_key_type(self):
        from webssh.settings import parse_host_entry
        with self.assertRaises(ValueError):
            parse_host_entry({
                'hostname': 'a.com', 'host_key': 'ssh-dss AAAAB3Nz'})

    def test_invalid_host_key_base64(self):
        from webssh.settings import parse_host_entry
        with self.assertRaises(ValueError):
            parse_host_entry({
                'hostname': 'a.com', 'host_key': 'ssh-ed25519 not!base64!'})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_settings.py::TestParseHostEntry -v`
Expected: FAIL with `ImportError: cannot import name 'parse_host_entry'`

- [ ] **Step 3: Extract the function**

In `webssh/settings.py`, add `parse_host_entry` immediately above `parse_allowed_hosts`. The body is lifted verbatim from the existing loop:

```python
def parse_host_entry(entry):
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
    try:
        port = int(entry.get('port', 22))
    except (TypeError, ValueError):
        raise ValueError(
            'Invalid port {!r} for host {!r}; must be 1-65535'.format(
                entry.get('port'), entry['hostname'])
        )
    if port < 1 or port > 65535:
        raise ValueError(
            'Invalid port {!r} for host {!r}; must be 1-65535'.format(
                port, entry['hostname'])
        )
    return {
        'name': entry.get('name', entry['hostname']),
        'hostname': entry['hostname'],
        'port': port,
        'host_keys': raw_keys,
    }
```

Then replace the loop body in `parse_allowed_hosts` so the whole function reads:

```python
def parse_allowed_hosts(data):
    if 'hosts' not in data:
        return []

    hosts = data['hosts']
    if not isinstance(hosts, list) or not hosts:
        raise ValueError(
            'Config file "hosts" must be a non-empty list'
        )

    return [parse_host_entry(entry) for entry in hosts]
```

Note the one deliberate improvement: the original `int(entry.get('port', 22))` raised an uncaught `TypeError`/`ValueError` on a non-numeric port such as `port: abc`. It is now wrapped to raise `ValueError` with a clear message, which is what every caller already expects.

- [ ] **Step 4: Run the new tests and the full suite**

Run: `.venv/bin/python -m pytest tests/test_settings.py::TestParseHostEntry -v`
Expected: PASS (7 tests)

Run: `.venv/bin/python -m pytest -q`
Expected: PASS, 159 passed. No existing test may fail — this is a pure refactor.

- [ ] **Step 5: Commit**

```bash
git add webssh/settings.py tests/test_settings.py
git commit -m "refactor: extract parse_host_entry from parse_allowed_hosts"
```

---

### Task 2: Per-user storage module

**Files:**
- Create: `webssh/user_data.py`
- Test: `tests/test_user_data.py`

**Interfaces:**
- Consumes: `parse_host_entry` from Task 1.
- Produces, all in `webssh.user_data`:
  - `SCHEMA_VERSION = 1`
  - `get_user_data_dir(base_dir, username)` → absolute path, raises `ValueError`
  - `read_hosts(base_dir, username)` → `list[dict]`, `[]` when missing or corrupt
  - `write_hosts(base_dir, username, hosts)` → `list[dict]` (the normalized list written)
  - `read_settings(base_dir, username)` → `dict`, `{}` when missing or corrupt
  - `write_settings(base_dir, username, settings)` → `dict` (the normalized dict written)
  - `validate_hosts(hosts)` → `list[dict]`, raises `ValueError`
  - `validate_settings(settings)` → `dict`, raises `ValueError`

A stored host dict has the four keys from `parse_host_entry` plus the two user-only keys `username` and `default_command`, which are always present as strings (empty string when unset).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_user_data.py`:

```python
import json
import os
import stat
import tempfile
import unittest

from webssh.user_data import (
    SCHEMA_VERSION, get_user_data_dir, read_hosts, write_hosts,
    read_settings, write_settings, validate_hosts, validate_settings
)


VALID_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefgh'


class TestGetUserDataDir(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()

    def test_valid_username(self):
        path = get_user_data_dir(self.base, 'alice')
        self.assertTrue(path.endswith(os.sep + 'alice'))

    def test_path_traversal_rejected(self):
        for name in ['../etc', 'foo/bar', '..', '.hidden', '']:
            with self.assertRaises(ValueError):
                get_user_data_dir(self.base, name)


class TestValidateHosts(unittest.TestCase):

    def test_normalizes_minimal_host(self):
        result = validate_hosts([{'hostname': 'nas.lan'}])
        self.assertEqual(result, [{
            'name': 'nas.lan', 'hostname': 'nas.lan', 'port': 22,
            'host_keys': [], 'username': '', 'default_command': '',
        }])

    def test_keeps_user_only_fields(self):
        result = validate_hosts([{
            'hostname': 'nas.lan', 'port': 2222, 'name': 'homelab',
            'host_key': VALID_KEY, 'username': 'ryan',
            'default_command': 'tmux attach',
        }])
        self.assertEqual(result[0]['username'], 'ryan')
        self.assertEqual(result[0]['default_command'], 'tmux attach')
        self.assertEqual(result[0]['host_keys'], [VALID_KEY])

    def test_drops_unknown_fields(self):
        result = validate_hosts([{'hostname': 'a.com', 'password': 'hunter2'}])
        self.assertNotIn('password', result[0])

    def test_rejects_non_list(self):
        with self.assertRaises(ValueError):
            validate_hosts({'hostname': 'a.com'})

    def test_rejects_bad_port(self):
        with self.assertRaises(ValueError):
            validate_hosts([{'hostname': 'a.com', 'port': 99999}])

    def test_rejects_bad_host_key(self):
        with self.assertRaises(ValueError):
            validate_hosts([{'hostname': 'a.com', 'host_key': 'ssh-dss AAAA'}])

    def test_rejects_non_string_user_fields(self):
        with self.assertRaises(ValueError):
            validate_hosts([{'hostname': 'a.com', 'username': 42}])

    def test_rejects_too_many_hosts(self):
        with self.assertRaises(ValueError):
            validate_hosts([{'hostname': 'h{}.com'.format(i)}
                            for i in range(201)])

    def test_empty_list_is_valid(self):
        self.assertEqual(validate_hosts([]), [])


class TestValidateSettings(unittest.TestCase):

    def test_accepts_known_settings(self):
        result = validate_settings({
            'font_size': 14, 'background': '#000000', 'foreground': '#ffffff',
            'cursor': '#00ff00', 'cursor_blink': True, 'encoding': 'utf-8',
            'term': 'xterm-256color', 'key_source': 'stored',
            'last_hostname': 'nas.lan', 'last_username': 'ryan',
            'last_port': 2222,
        })
        self.assertEqual(result['font_size'], 14)
        self.assertEqual(result['key_source'], 'stored')
        self.assertEqual(result['last_port'], 2222)

    def test_drops_secrets_and_unknown_keys(self):
        result = validate_settings({
            'password': 'hunter2', 'credential': 'x', 'totp': '123456',
            'passphrase': 'y', 'privatekey': 'z', 'font_size': 12,
        })
        self.assertEqual(result, {'font_size': 12})

    def test_rejects_non_mapping(self):
        with self.assertRaises(ValueError):
            validate_settings(['font_size', 12])

    def test_rejects_out_of_range_font_size(self):
        for size in [0, 5, 200]:
            with self.assertRaises(ValueError):
                validate_settings({'font_size': size})

    def test_rejects_bad_color(self):
        for color in ['javascript:alert(1)', '#12', 'red;x', 123]:
            with self.assertRaises(ValueError):
                validate_settings({'background': color})

    def test_accepts_named_and_hex_colors(self):
        for color in ['black', 'white', '#fff', '#00ff00']:
            self.assertEqual(
                validate_settings({'background': color})['background'], color)

    def test_rejects_bad_key_source(self):
        with self.assertRaises(ValueError):
            validate_settings({'key_source': 'somewhere-else'})

    def test_rejects_bad_encoding(self):
        with self.assertRaises(ValueError):
            validate_settings({'encoding': 'not-a-real-encoding'})


class TestRoundTrip(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()

    def test_hosts_round_trip(self):
        written = write_hosts(self.base, 'alice', [{'hostname': 'nas.lan'}])
        self.assertEqual(read_hosts(self.base, 'alice'), written)

    def test_settings_round_trip(self):
        written = write_settings(self.base, 'alice', {'font_size': 16})
        self.assertEqual(read_settings(self.base, 'alice'), written)
        self.assertEqual(written, {'font_size': 16})

    def test_read_missing_returns_empty(self):
        self.assertEqual(read_hosts(self.base, 'nobody'), [])
        self.assertEqual(read_settings(self.base, 'nobody'), {})

    def test_read_corrupt_returns_empty(self):
        user_dir = get_user_data_dir(self.base, 'alice')
        os.makedirs(user_dir, mode=0o700)
        with open(os.path.join(user_dir, 'hosts.json'), 'w') as f:
            f.write('{not json at all')
        self.assertEqual(read_hosts(self.base, 'alice'), [])

    def test_read_wrong_shape_returns_empty(self):
        user_dir = get_user_data_dir(self.base, 'alice')
        os.makedirs(user_dir, mode=0o700)
        with open(os.path.join(user_dir, 'hosts.json'), 'w') as f:
            json.dump({'version': 1, 'hosts': 'not-a-list'}, f)
        self.assertEqual(read_hosts(self.base, 'alice'), [])

    def test_written_file_has_version_and_mode(self):
        write_hosts(self.base, 'alice', [{'hostname': 'nas.lan'}])
        path = os.path.join(get_user_data_dir(self.base, 'alice'), 'hosts.json')
        with open(path) as f:
            raw = json.load(f)
        self.assertEqual(raw['version'], SCHEMA_VERSION)
        self.assertIsInstance(raw['hosts'], list)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o600)

    def test_invalid_write_leaves_previous_data(self):
        write_hosts(self.base, 'alice', [{'hostname': 'good.lan'}])
        with self.assertRaises(ValueError):
            write_hosts(self.base, 'alice', [{'hostname': 'bad', 'port': 0}])
        stored = read_hosts(self.base, 'alice')
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]['hostname'], 'good.lan')

    def test_write_leaves_no_temp_files(self):
        write_hosts(self.base, 'alice', [{'hostname': 'nas.lan'}])
        entries = os.listdir(get_user_data_dir(self.base, 'alice'))
        self.assertEqual(sorted(entries), ['hosts.json'])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_user_data.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'webssh.user_data'`

- [ ] **Step 3: Write the module**

Create `webssh/user_data.py`:

```python
import json
import logging
import os
import re
import tempfile

from webssh.settings import parse_host_entry
from webssh.user_keys import sanitize_username
from webssh.utils import is_valid_encoding


SCHEMA_VERSION = 1
MAX_HOSTS = 200
MAX_FIELD_LENGTH = 512

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
    real_base = os.path.realpath(base_dir)
    real_user = os.path.realpath(user_dir)
    if not real_user.startswith(real_base + os.sep):
        raise ValueError('Invalid username.')
    return real_user


def _check_string(value, name, allow_empty=True):
    if not isinstance(value, str):
        raise ValueError('{} must be a string'.format(name))
    if len(value) > MAX_FIELD_LENGTH:
        raise ValueError('{} is too long'.format(name))
    if not allow_empty and not value:
        raise ValueError('{} must not be empty'.format(name))
    return value


def validate_hosts(hosts):
    if not isinstance(hosts, list):
        raise ValueError('hosts must be a list')
    if len(hosts) > MAX_HOSTS:
        raise ValueError('Too many hosts; the limit is {}'.format(MAX_HOSTS))

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
        raise ValueError('settings must be a mapping')

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
                raise ValueError('Invalid color for {}'.format(name))
            result[name] = value

    if 'cursor_blink' in settings:
        value = settings['cursor_blink']
        if not isinstance(value, bool):
            raise ValueError('cursor_blink must be a boolean')
        result['cursor_blink'] = value

    if 'encoding' in settings:
        value = settings['encoding']
        if not isinstance(value, str) or not is_valid_encoding(value):
            raise ValueError('Invalid encoding {!r}'.format(value))
        result['encoding'] = value

    if 'term' in settings:
        value = settings['term']
        if not isinstance(value, str) or not TERM_RE.match(value):
            raise ValueError('Invalid term {!r}'.format(value))
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


def _read_json(base_dir, username, filename, payload_key, empty):
    user_dir = get_user_data_dir(base_dir, username)
    path = os.path.join(user_dir, filename)
    if not os.path.isfile(path):
        return empty
    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except (ValueError, OSError) as exc:
        logging.warning(
            'Ignoring unreadable {} for user {!r}: {}'.format(
                filename, username, exc)
        )
        return empty
    if not isinstance(data, dict):
        logging.warning(
            'Ignoring malformed {} for user {!r}'.format(filename, username))
        return empty
    payload = data.get(payload_key, empty)
    if not isinstance(payload, type(empty)):
        logging.warning(
            'Ignoring malformed {} for user {!r}'.format(filename, username))
        return empty
    return payload


def _write_json(base_dir, username, filename, payload_key, payload):
    user_dir = get_user_data_dir(base_dir, username)
    try:
        os.makedirs(user_dir, mode=0o700, exist_ok=True)
    except PermissionError:
        raise ValueError(
            'Cannot create data directory for user {!r}: permission denied. '
            'Check ownership of {!r}'.format(username, base_dir)
        )

    body = json.dumps(
        {'version': SCHEMA_VERSION, payload_key: payload}, indent=2
    ).encode()

    path = os.path.join(user_dir, filename)
    fd, tmp_path = tempfile.mkstemp(dir=user_dir)
    closed = False
    try:
        os.write(fd, body)
        os.fchmod(fd, 0o600)
        os.close(fd)
        closed = True
        os.rename(tmp_path, path)
    except Exception:
        os.unlink(tmp_path)
        raise
    finally:
        if not closed:
            try:
                os.close(fd)
            except OSError:
                pass


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
```

Note two ordering details that make the atomicity tests pass: validation runs before any file is touched, so a rejected write leaves prior data intact; and `os.rename` over the same filesystem is atomic, so a reader never sees a partial file.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_user_data.py -v`
Expected: PASS (all tests)

Run: `.venv/bin/python -m pytest -q`
Expected: PASS, no regressions.

- [ ] **Step 5: Commit**

```bash
git add webssh/user_data.py tests/test_user_data.py
git commit -m "feat: add per-user host and settings storage module"
```

---

### Task 3: Configuration plumbing

**Files:**
- Modify: `webssh/settings.py` — add options near line 61, add `check_user_data_dir` after `check_user_key_dir` (line 396), extend `apply_config_settings` (line 351)
- Modify: `webssh/main.py:171-197` (`main`)
- Test: `tests/test_settings.py`

**Interfaces:**
- Consumes: nothing from prior tasks.
- Produces:
  - Tornado options `user_hosts` (bool, default `False`) and `userdatadir` (str, default `''`)
  - `get_user_data_dir_setting(options)` → `str`; returns `options.userdatadir` if set, else `options.userkeydir`, else `''`
  - `check_user_data_dir(user_data_dir, tdstream='')` → creates the directory, raises `ValueError` on failure, logs the spoofable-header warning when `tdstream` is empty

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_settings.py`:

```python
class TestUserDataSettings(unittest.TestCase):

    def test_userdatadir_falls_back_to_userkeydir(self):
        from webssh.settings import get_user_data_dir_setting

        class Opts(object):
            userdatadir = ''
            userkeydir = '/var/lib/webssh/keys'

        self.assertEqual(get_user_data_dir_setting(Opts()),
                         '/var/lib/webssh/keys')

    def test_userdatadir_wins_when_set(self):
        from webssh.settings import get_user_data_dir_setting

        class Opts(object):
            userdatadir = '/var/lib/webssh/data'
            userkeydir = '/var/lib/webssh/keys'

        self.assertEqual(get_user_data_dir_setting(Opts()),
                         '/var/lib/webssh/data')

    def test_userdatadir_empty_when_neither_set(self):
        from webssh.settings import get_user_data_dir_setting

        class Opts(object):
            userdatadir = ''
            userkeydir = ''

        self.assertEqual(get_user_data_dir_setting(Opts()), '')

    def test_check_user_data_dir_creates_directory(self):
        import tempfile
        from webssh.settings import check_user_data_dir
        base = tempfile.mkdtemp()
        target = os.path.join(base, 'data')
        check_user_data_dir(target, tdstream='10.0.0.1')
        self.assertTrue(os.path.isdir(target))

    def test_check_user_data_dir_noop_when_empty(self):
        from webssh.settings import check_user_data_dir
        self.assertIsNone(check_user_data_dir(''))

    def test_check_user_data_dir_rejects_file(self):
        import tempfile
        from webssh.settings import check_user_data_dir
        fd, path = tempfile.mkstemp()
        os.close(fd)
        with self.assertRaises(ValueError):
            check_user_data_dir(path, tdstream='10.0.0.1')


class TestApplyUserHostsConfig(unittest.TestCase):

    def test_user_hosts_and_userdatadir_from_config(self):
        import tempfile
        import yaml
        from tornado.options import options as opts
        from webssh.settings import apply_config_settings

        fd, path = tempfile.mkstemp(suffix='.yaml')
        with os.fdopen(fd, 'w') as f:
            yaml.safe_dump({
                'user_hosts': True, 'userdatadir': '/tmp/webssh-data'}, f)

        old_config = opts.config
        old_flag = opts.user_hosts
        old_dir = opts.userdatadir
        try:
            opts.config = path
            apply_config_settings(opts)
            self.assertTrue(opts.user_hosts)
            self.assertEqual(opts.userdatadir, '/tmp/webssh-data')
        finally:
            opts.config = old_config
            opts.user_hosts = old_flag
            opts.userdatadir = old_dir
            os.unlink(path)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_settings.py::TestUserDataSettings tests/test_settings.py::TestApplyUserHostsConfig -v`
Expected: FAIL with `ImportError: cannot import name 'get_user_data_dir_setting'`

- [ ] **Step 3: Add the options and helpers**

In `webssh/settings.py`, directly after the `userheader` definition at line 61:

```python
define('userdatadir', default='',
       help='Directory for per-user hosts and settings '
            '(defaults to userkeydir)')
define('user_hosts', type=bool, default=False,
       help='Allow authenticated users to manage their own host list')
```

Add after `check_user_key_dir`:

```python
def get_user_data_dir_setting(options):
    return options.userdatadir or options.userkeydir or ''


def check_user_data_dir(user_data_dir, tdstream=''):
    if not user_data_dir:
        return
    if not tdstream:
        logging.warning(
            'SECURITY WARNING: user_hosts is enabled but no trusted_proxies '
            'configured. The user header can be spoofed by any client.'
        )
    try:
        os.makedirs(user_data_dir, mode=0o700, exist_ok=True)
    except PermissionError:
        raise ValueError(
            'Cannot create user data directory {!r}: permission denied. '
            'Create the directory manually or run with appropriate '
            'permissions.'.format(user_data_dir)
        )
    except (FileExistsError, NotADirectoryError):
        raise ValueError(
            'User data directory {!r} is not a directory'.format(user_data_dir)
        )
    if not os.path.isdir(user_data_dir):
        raise ValueError(
            'User data directory {!r} is not a directory'.format(user_data_dir)
        )
```

In `apply_config_settings`, after the `userheader` block at line 360:

```python
    if not options.userdatadir and 'userdatadir' in config:
        options.userdatadir = config['userdatadir']
    if not options.user_hosts and 'user_hosts' in config:
        options.user_hosts = bool(config['user_hosts'])
```

- [ ] **Step 4: Wire it into startup**

In `webssh/main.py`, extend the import from `webssh.settings` (lines 15-20) with `get_user_data_dir_setting` and `check_user_data_dir`, then in `main()` immediately after the existing `check_user_key_dir` call at line 178:

```python
    user_data_dir = get_user_data_dir_setting(options)
    if options.user_hosts:
        check_user_data_dir(user_data_dir, options.tdstream)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_settings.py -v`
Expected: PASS

Run: `.venv/bin/python -m pytest -q`
Expected: PASS, no regressions.

- [ ] **Step 6: Commit**

```bash
git add webssh/settings.py webssh/main.py tests/test_settings.py
git commit -m "feat: add user_hosts and userdatadir configuration options"
```

---

### Task 4: Host and settings APIs

**Files:**
- Modify: `webssh/handler.py` — add handlers after `UserKeyHandler` (line 711)
- Modify: `webssh/main.py:23-60` (`make_handlers`)
- Test: `tests/test_app.py`

**Interfaces:**
- Consumes: `webssh.user_data` (Task 2), `get_user_data_dir_setting` (Task 3).
- Produces:
  - `UserDataMixin` with `get_auth_username()` and `check_feature_enabled()`
  - `UserHostsHandler` at `/api/hosts` (GET, PUT)
  - `UserSettingsHandler` at `/api/settings` (GET, PUT)
  - `make_handlers` passes `user_hosts_enabled`, `user_data_dir`, and `allowed_hosts` to both.

Routes are registered unconditionally. Gating happens inside the handler so a disabled feature returns 403 rather than 404, which is what the spec requires and what the tests assert.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_app.py`:

Follow the `OtherTestBase.get_app` convention already in this file: set the
`options` attributes the handlers read, then call `make_handlers`. Do not reach
into `app.default_router` — the router internals differ between Tornado versions.

```python
class UserDataTestBase(TestAppBase):

    headers = {'Cookie': '_xsrf=yummy',
               'X-Authentik-Username': 'alice'}
    user_hosts = True

    def get_app(self):
        self.data_dir = tempfile.mkdtemp()
        options.debug = False
        options.xsrf = True
        options.policy = 'warning'
        options.hostfile = ''
        options.syshostfile = ''
        options.tdstream = ''
        options.origin = 'same'
        options.user_hosts = self.user_hosts
        options.userdatadir = self.data_dir
        options.userheader = 'X-Authentik-Username'
        self.addCleanup(self._restore_options)
        return make_app(make_handlers(self.io_loop, options),
                        get_app_settings(options))

    def _restore_options(self):
        options.user_hosts = False
        options.userdatadir = ''
        options.config = ''


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


class TestUserDataApiDisabled(UserDataTestBase):

    user_hosts = False

    def test_get_hosts_returns_403(self):
        response = self.fetch('/api/hosts', headers=self.headers)
        self.assertEqual(response.code, 403)

    def test_get_settings_returns_403(self):
        response = self.fetch('/api/settings', headers=self.headers)
        self.assertEqual(response.code, 403)
```

`tests/test_app.py` currently imports `json` but not `tempfile` or `unittest`.
Add both to the imports at the top of the file; `unittest` is needed by Task 5.

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_app.py::TestUserDataApi -v`
Expected: FAIL — the routes 404 because they do not exist yet.

- [ ] **Step 3: Write the handlers**

In `webssh/handler.py`, add `from webssh import user_data` alongside the existing `user_keys` import, then add after `UserKeyHandler`:

```python
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
        if not self.user_hosts_enabled or not self.user_data_dir:
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

    def get_json_body(self, key, default):
        try:
            data = json.loads(self.request.body.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            raise tornado.web.HTTPError(400, 'Malformed JSON body.')
        if not isinstance(data, dict):
            raise tornado.web.HTTPError(400, 'Body must be a JSON object.')
        return data.get(key, default)


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
        hosts = self.get_json_body('hosts', [])
        try:
            stored = user_data.write_hosts(self.user_data_dir, username, hosts)
        except ValueError as exc:
            raise tornado.web.HTTPError(400, str(exc))
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
        settings = self.get_json_body('settings', {})
        try:
            stored = user_data.write_settings(
                self.user_data_dir, username, settings)
        except ValueError as exc:
            raise tornado.web.HTTPError(400, str(exc))
        self.write({'settings': stored})
```

`json` is already imported at the top of `handler.py`; confirm with `grep -n '^import json' webssh/handler.py` and add it if missing.

- [ ] **Step 4: Register the routes**

In `webssh/main.py`, import `get_user_data_dir_setting` (already added in Task 3) and extend `make_handlers`. After the `user_header = options.userheader` line:

```python
    user_data_dir = get_user_data_dir_setting(options)
    user_hosts_enabled = bool(options.user_hosts and user_data_dir)

    user_data_kwargs = dict(
        loop=loop,
        user_data_dir=user_data_dir,
        user_header=user_header,
        user_hosts_enabled=user_hosts_enabled,
        allowed_hosts=allowed_hosts,
        live_config=live_config
    )
```

and extend the `handlers` list:

```python
    handlers = [
        (r'/', IndexHandler, index_kwargs),
        (r'/ws', WsockHandler, dict(loop=loop)),
        (r'/api/hosts', UserHostsHandler, user_data_kwargs),
        (r'/api/settings', UserSettingsHandler, user_data_kwargs),
    ]
```

Add `UserHostsHandler` and `UserSettingsHandler` to the `from webssh.handler import (...)` list at lines 11-13.

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_app.py::TestUserDataApi tests/test_app.py::TestUserDataApiDisabled -v`
Expected: PASS

Run: `.venv/bin/python -m pytest -q`
Expected: PASS, no regressions.

- [ ] **Step 6: Commit**

```bash
git add webssh/handler.py webssh/main.py tests/test_app.py
git commit -m "feat: add /api/hosts and /api/settings endpoints"
```

---

### Task 5: Merge user hosts at connect time

This is the security-critical task. Two invariants must hold: an administrator entry always wins a `hostname:port` collision, and with the feature disabled a user-supplied host is still rejected by the allowlist.

**Files:**
- Modify: `webssh/handler.py:344-359` (`IndexHandler.initialize`), `:423-440` (`check_allowed_hosts`, `load_configured_host_key`), `:599-625` (`get`)
- Modify: `webssh/main.py` — pass the two new kwargs into `index_kwargs`
- Test: `tests/test_app.py`

**Interfaces:**
- Consumes: `user_data.read_hosts` (Task 2), `user_hosts_enabled` / `user_data_dir` wiring (Tasks 3 and 4).
- Produces: `IndexHandler.get_user_hosts()` → `list[dict]` and `IndexHandler.get_effective_hosts()` → `list[dict]`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_app.py`:

```python
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
```

And an end-to-end pair asserting the allowlist gate. The administrator allowlist
is supplied the same way production does it — through a config file — because
`make_handlers` calls `get_allowed_hosts_setting(options)`, which reads
`options.config`:

```python
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
        options.config = self.config_path
        super(TestConnectWithUserHosts, self).setUp()
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
```

Note the shape: a shared base holds the fixture, and each concrete class
asserts its own behavior. No test inherits an assertion that does not apply to
it, and no test body is empty.

`tests/test_app.py` imports `json` but not `os`, so add `import os` too (Task 4
already added `tempfile` and `unittest`).

The `setUp` ordering matters: `options.config` must be set before
`super().setUp()`, because `AsyncHTTPTestCase.setUp` is what calls `get_app`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_app.py::TestEffectiveHosts -v`
Expected: FAIL with `AttributeError: type object 'IndexHandler' has no attribute 'get_effective_hosts'`

- [ ] **Step 3: Implement the merge**

In `IndexHandler.initialize`, extend the signature and body:

```python
    def initialize(self, loop, policy, host_keys_settings, allowed_hosts=None,
                   user_key_dir='', user_header='X-Authentik-Username',
                   user_data_dir='', user_hosts_enabled=False,
                   live_config=None):
```

and after the existing `self.user_header = user_header` line:

```python
        self.user_data_dir = user_data_dir
        self.user_hosts_enabled = user_hosts_enabled
```

Add the two new methods just above `check_allowed_hosts`:

```python
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
        admin = self.allowed_hosts
        seen = set((h['hostname'], h['port']) for h in admin)
        merged = list(admin)
        for host in self.get_user_hosts():
            if (host['hostname'], host['port']) not in seen:
                merged.append(host)
        return merged
```

Replace `check_allowed_hosts` and `load_configured_host_key`:

```python
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
```

Two subtleties, both deliberate:

- `check_allowed_hosts` keeps its `if not self.allowed_hosts: return` guard. When no administrator allowlist is configured the hostname field is free text, and adding personal hosts must not suddenly restrict the user to only those hosts.
- `load_configured_host_key` *drops* its equivalent guard. A personal host's key pin must load even when no administrator allowlist exists; with an empty effective list the loop is a harmless no-op.

- [ ] **Step 4: Pass the new kwargs**

In `webssh/main.py`, add to `index_kwargs`:

```python
        user_data_dir=user_data_dir,
        user_hosts_enabled=user_hosts_enabled,
```

- [ ] **Step 5: Expose hosts to the template**

In `IndexHandler.get`, before the `self.render(...)` call, add:

```python
        user_hosts = self.get_user_hosts()
        user_settings = {}
        if self.user_hosts_enabled and auth_username:
            try:
                user_settings = user_data.read_settings(
                    self.user_data_dir, auth_username)
            except ValueError:
                user_settings = {}
```

and extend the `render` call with:

```python
                    user_hosts_enabled=self.user_hosts_enabled,
                    user_hosts=user_hosts,
                    user_settings=user_settings,
```

Note: `self.allowed_hosts` is still what the template's existing host `<select>` iterates. Task 7 changes that to the merged list.

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_app.py -v`
Expected: PASS

Run: `.venv/bin/python -m pytest -q`
Expected: PASS, no regressions. Pay particular attention to any existing allowed-hosts test — those assert the disabled-feature behavior that must not change.

- [ ] **Step 7: Commit**

```bash
git add webssh/handler.py webssh/main.py tests/test_app.py
git commit -m "feat: merge user hosts with admin allowlist at connect time"
```

---

### Task 6: Settings pane endpoint and template

**Files:**
- Create: `webssh/templates/settings.html`
- Modify: `webssh/handler.py` — add `SettingsPaneHandler` after `UserSettingsHandler`
- Modify: `webssh/main.py` — register `/settings-pane`
- Modify: `webssh/static/css/main.css` — append settings styles
- Test: `tests/test_app.py`

**Interfaces:**
- Consumes: `UserDataMixin` (Task 4).
- Produces: `GET /settings-pane` → an HTML fragment (no `<html>`/`<body>`), 404 when the feature is disabled. The fragment's root element is `<div class="settings-pane">`, and it contains `#settings-hosts`, `#settings-terminal`, and `#settings-connection` sections plus a `#settings-save` button. Task 7 depends on these IDs.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_app.py`, inside `TestUserDataApi`:

```python
    def test_settings_pane_returns_fragment(self):
        response = self.fetch('/settings-pane', headers=self.headers)
        self.assertEqual(response.code, 200)
        self.assertIn(b'settings-pane', response.body)
        self.assertNotIn(b'<html', response.body)
```

and inside `TestUserDataApiDisabled`:

```python
    def test_settings_pane_returns_404(self):
        response = self.fetch('/settings-pane', headers=self.headers)
        self.assertEqual(response.code, 404)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_app.py::TestUserDataApi::test_settings_pane_returns_fragment -v`
Expected: FAIL with a 404.

- [ ] **Step 3: Write the handler**

In `webssh/handler.py`, after `UserSettingsHandler`:

```python
class SettingsPaneHandler(UserDataMixin, MixinHandler,
                          tornado.web.RequestHandler):

    def get(self):
        if not self.user_hosts_enabled or not self.user_data_dir:
            raise tornado.web.HTTPError(404)
        username = self.get_auth_username()
        self.render('settings.html',
                    auth_username=username,
                    admin_hosts=self.allowed_hosts)
```

Register in `webssh/main.py` alongside the API routes:

```python
        (r'/settings-pane', SettingsPaneHandler, user_data_kwargs),
```

and add `SettingsPaneHandler` to the handler import list.

- [ ] **Step 4: Write the template**

Create `webssh/templates/settings.html`. It renders only the static shell; host rows and current values are filled in by JavaScript in Task 7 from `/api/hosts` and the in-page `prefs` object.

```html
<div class="settings-pane">
  <div class="settings-header">
    <span class="settings-title">Settings</span>
    <span class="settings-user">{{ auth_username }}</span>
  </div>

  <div class="settings-tabs" role="tablist">
    <button type="button" class="settings-tab active" data-section="hosts" role="tab">Hosts</button>
    <button type="button" class="settings-tab" data-section="terminal" role="tab">Terminal</button>
    <button type="button" class="settings-tab" data-section="connection" role="tab">Connection</button>
  </div>

  <div class="settings-body">
    <section id="settings-hosts" class="settings-section active">
      {% if admin_hosts %}
      <div class="settings-subhead">Administrator hosts (read-only)</div>
      <table class="settings-table">
        <tbody>
          {% for host in admin_hosts %}
          <tr class="admin-host">
            <td>{{ host['name'] }}</td>
            <td>{{ host['hostname'] }}</td>
            <td>{{ host['port'] }}</td>
            <td><span class="host-badge">admin</span></td>
          </tr>
          {% end %}
        </tbody>
      </table>
      {% end %}

      <div class="settings-subhead">Your hosts</div>
      <table class="settings-table">
        <tbody id="user-host-rows"></tbody>
      </table>
      <button type="button" class="btn-generate" id="add-host-btn">+ Add host</button>
    </section>

    <section id="settings-terminal" class="settings-section">
      <div class="field-row">
        <div class="field-group">
          <span class="field-label">Font Size</span>
          <input class="field-input" type="number" id="set-font-size" min="6" max="40" placeholder="14">
        </div>
        <div class="field-group">
          <span class="field-label">Background</span>
          <input class="field-input" type="text" id="set-background" placeholder="black">
        </div>
      </div>
      <div class="field-row">
        <div class="field-group">
          <span class="field-label">Foreground</span>
          <input class="field-input" type="text" id="set-foreground" placeholder="white">
        </div>
        <div class="field-group">
          <span class="field-label">Cursor</span>
          <input class="field-input" type="text" id="set-cursor" placeholder="white">
        </div>
      </div>
      <div class="field-row single">
        <label class="settings-checkbox">
          <input type="checkbox" id="set-cursor-blink"> Cursor blink
        </label>
      </div>
    </section>

    <section id="settings-connection" class="settings-section">
      <div class="field-row">
        <div class="field-group">
          <span class="field-label">Encoding</span>
          <input class="field-input" type="text" id="set-encoding" placeholder="utf-8">
        </div>
        <div class="field-group">
          <span class="field-label">Terminal Type</span>
          <input class="field-input" type="text" id="set-term" placeholder="xterm-256color">
        </div>
      </div>
      <div class="field-row single">
        <div class="field-group">
          <span class="field-label">Preferred Key Source</span>
          <select class="field-input" id="set-key-source">
            <option value="upload">Upload Key</option>
            <option value="stored">Stored Key</option>
          </select>
        </div>
      </div>
    </section>
  </div>

  <div class="settings-footer">
    <span class="settings-status" id="settings-status"></span>
    <button type="button" class="btn-connect btn-primary" id="settings-save">Save</button>
  </div>
</div>

<template id="host-row-template">
  <tr class="user-host">
    <td><input class="field-input host-name" type="text" placeholder="Name"></td>
    <td><input class="field-input host-hostname" type="text" placeholder="hostname" required></td>
    <td><input class="field-input host-port" type="number" min="1" max="65535" placeholder="22"></td>
    <td><input class="field-input host-username" type="text" placeholder="login user"></td>
    <td><input class="field-input host-command" type="text" placeholder="default command"></td>
    <td><textarea class="field-input host-keys" rows="2" placeholder="ssh-ed25519 AAAA... (one per line)"></textarea></td>
    <td><button type="button" class="btn-reset btn-danger host-delete" title="Delete host">&times;</button></td>
  </tr>
</template>
```

- [ ] **Step 5: Add the styles**

Append to `webssh/static/css/main.css`. Reuse the existing color variables rather than inventing new ones — check the top of the file for the custom properties already defined and substitute the real names if these differ:

```css
.settings-pane {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
  color: inherit;
}

.settings-header {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.12);
}

.settings-title { font-weight: 600; letter-spacing: 0.04em; }
.settings-user { opacity: 0.7; font-size: 0.85em; }

.settings-tabs { display: flex; gap: 4px; padding: 8px 16px 0; }

.settings-tab {
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  padding: 6px 12px;
  color: inherit;
  opacity: 0.6;
  cursor: pointer;
}

.settings-tab.active { opacity: 1; border-bottom-color: currentColor; }

.settings-body { flex: 1; overflow-y: auto; padding: 16px; }
.settings-section { display: none; }
.settings-section.active { display: block; }

.settings-subhead {
  text-transform: uppercase;
  font-size: 0.75em;
  letter-spacing: 0.08em;
  opacity: 0.6;
  margin: 16px 0 8px;
}

.settings-table { width: 100%; border-collapse: collapse; }
.settings-table td { padding: 4px; vertical-align: top; }
.settings-table tr.admin-host td { opacity: 0.55; padding: 6px 4px; }

.host-badge {
  font-size: 0.7em;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  border: 1px solid currentColor;
  border-radius: 3px;
  padding: 1px 5px;
  opacity: 0.8;
}

.settings-checkbox { display: flex; align-items: center; gap: 8px; }

.settings-footer {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 12px;
  padding: 12px 16px;
  border-top: 1px solid rgba(255, 255, 255, 0.12);
}

.settings-status { font-size: 0.85em; opacity: 0.75; }
.settings-status.error { color: #ff6b6b; opacity: 1; }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_app.py -v`
Expected: PASS

Run: `.venv/bin/python -m pytest -q`
Expected: PASS, no regressions.

- [ ] **Step 7: Commit**

```bash
git add webssh/handler.py webssh/main.py webssh/templates/settings.html webssh/static/css/main.css tests/test_app.py
git commit -m "feat: add /settings-pane fragment endpoint and template"
```

---

### Task 7: Settings tab in the client

**Files:**
- Modify: `webssh/static/js/main.js:69-147` (`createTab`), `:149-193` (`activateTab`), `:195-243` (`closeTab`)
- Modify: `webssh/templates/index.html:26-29` (tab bar), `:51-59` (host select), `:178-182` (bootstrap globals)

**Interfaces:**
- Consumes: `GET /settings-pane`, `GET/PUT /api/hosts` (Tasks 4 and 6).
- Produces:
  - `tabManager.createTab(kind)` where `kind` is `'terminal'` (default) or `'settings'`
  - `tabManager.openSettings()` — focuses the existing settings tab or creates one
  - `refresh_host_list()` — refetches `/api/hosts` and rebuilds the `#hostname` select

- [ ] **Step 1: Add the gear control and globals to index.html**

In the tab bar block, add a gear button next to the new-tab button:

```html
    <div id="tab-bar">
      <div id="tab-list"></div>
      <button id="new-tab-btn" type="button" title="New connection" aria-label="Open new connection tab">+</button>
      {% if user_hosts_enabled %}
      <button id="settings-btn" type="button" title="Settings" aria-label="Open settings">&#9881;</button>
      {% end %}
    </div>
```

Change the host `<select>` block so it renders the merged list. Replace the `{% if allowed_hosts %}` condition and loop with:

```html
                {% if allowed_hosts or user_hosts %}
                <select class="field-input" id="hostname" name="hostname" required>
                  {% for host in allowed_hosts %}
                  <option value="{{ host['hostname'] }}" data-port="{{ host['port'] }}">{{ host['name'] }}</option>
                  {% end %}
                  {% for host in user_hosts %}
                  <option value="{{ host['hostname'] }}" data-port="{{ host['port'] }}" data-username="{{ host['username'] }}" data-command="{{ host['default_command'] }}">{{ host['name'] }}</option>
                  {% end %}
                </select>
                {% else %}
```

The port field's `readonly` attribute at line 84 must follow the same condition — change `{% if allowed_hosts %}readonly{% end %}` to `{% if allowed_hosts or user_hosts %}readonly{% end %}`.

Add to the globals script block:

```html
      var allowed_hosts_configured = {% if allowed_hosts or user_hosts %}true{% else %}false{% end %};
      var user_hosts_enabled = {% if user_hosts_enabled %}true{% else %}false{% end %};
      var user_settings = {% raw json_encode(user_settings) %};
```

- [ ] **Step 2: Teach tabManager about tab kinds**

In `main.js`, change the `createTab` signature and the tab object it builds:

```javascript
    createTab: function(kind) {
      kind = kind || 'terminal';
      var tabId = ++this.tabCounter;
      var container = document.createElement('div');
      container.className = 'terminal-pane';
      container.id = 'terminal-pane-' + tabId;
```

In the same function, set the initial label from the kind:

```javascript
      var label = document.createElement('span');
      label.className = 'tab-label';
      label.textContent = (kind === 'settings') ? 'Settings' : 'New Connection';
```

and add `kind` to the tab object literal, alongside `id` and `label`:

```javascript
      var tab = {
        id: tabId,
        kind: kind,
        label: (kind === 'settings') ? 'Settings' : 'New Connection',
```

- [ ] **Step 3: Branch activateTab on kind**

Replace the `if (tab.state === CONNECTED && tab.term) { ... } else { ... }` block in `activateTab` with:

```javascript
      if (tab.kind === 'settings') {
        form_container.hide();
      } else if (tab.state === CONNECTED && tab.term) {
        form_container.hide();
        // Fit after a brief delay so layout settles, then focus
        setTimeout(function() {
          if (tab.fitAddon) {
            tab.fitAddon.fit();
          }
          if (tab.term) {
            setTimeout(function() { tab.term.focus(); }, 50);
          }
        }, 10);
      } else {
        form_container.show();
      }
```

and the title block below it:

```javascript
      if (tab.kind === 'settings') {
        title_element.text = 'Settings';
      } else if (tab.state === CONNECTED && tab.title) {
        title_element.text = tab.title;
      } else {
        title_element.text = default_title;
      }
```

`bindWssh(tab)` is called unconditionally at the end of `activateTab`. Verify it tolerates `tab.term === null`; if it dereferences `tab.term`, guard the call with `if (tab.kind !== 'settings') { this.bindWssh(tab); }`.

- [ ] **Step 4: Make the last-closed tab a terminal tab**

In `closeTab`, the fallback at the end currently reads `this.createTab();`. It already defaults to a terminal tab now that `kind` defaults to `'terminal'`, but make it explicit:

```javascript
        } else {
          // No tabs left, create new one
          this.createTab('terminal');
        }
```

- [ ] **Step 5: Add openSettings and wire the gear button**

Add to `tabManager`, after `getActiveTab`:

```javascript
    openSettings: function() {
      var ids = this.getTabIds();
      for (var i = 0; i < ids.length; i++) {
        if (this.tabs[ids[i]].kind === 'settings') {
          this.activateTab(ids[i]);
          return;
        }
      }
      var tab = this.createTab('settings');
      var pane = $(tab.containerEl);
      pane.html('<div class="settings-loading">Loading settings...</div>');
      $.get('/settings-pane')
        .done(function(html) {
          pane.html(html);
          init_settings_pane(pane);
        })
        .fail(function() {
          pane.html('<div class="settings-loading">Failed to load settings.</div>');
        });
      return tab;
    },
```

Wire the button where the other DOM handlers are bound, near the `#new-tab-btn` handler:

```javascript
  $('#settings-btn').on('click', function() {
    tabManager.openSettings();
  });
```

- [ ] **Step 6: Implement the settings pane behavior**

Add these functions near the other utility functions:

```javascript
  function settings_status(pane, message, is_error) {
    var el = pane.find('#settings-status');
    el.text(message || '');
    el.toggleClass('error', !!is_error);
  }


  function add_host_row(pane, host) {
    host = host || {};
    var tpl = pane.find('#host-row-template')[0];
    var row = $(document.importNode(tpl.content, true));
    row.find('.host-name').val(host.name || '');
    row.find('.host-hostname').val(host.hostname || '');
    row.find('.host-port').val(host.port || '');
    row.find('.host-username').val(host.username || '');
    row.find('.host-command').val(host.default_command || '');
    row.find('.host-keys').val((host.host_keys || []).join('\n'));
    pane.find('#user-host-rows').append(row);
  }


  function collect_host_rows(pane) {
    var hosts = [];
    pane.find('#user-host-rows tr.user-host').each(function() {
      var row = $(this);
      var hostname = row.find('.host-hostname').val().trim();
      if (!hostname) return;
      var keys = row.find('.host-keys').val().split('\n');
      var cleaned = [];
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i].trim();
        if (k) cleaned.push(k);
      }
      var port = window.parseInt(row.find('.host-port').val(), 10);
      hosts.push({
        name: row.find('.host-name').val().trim() || hostname,
        hostname: hostname,
        port: port > 0 ? port : 22,
        host_key: cleaned,
        username: row.find('.host-username').val().trim(),
        default_command: row.find('.host-command').val().trim()
      });
    });
    return hosts;
  }


  function collect_settings(pane) {
    var settings = {};
    var size = window.parseInt(pane.find('#set-font-size').val(), 10);
    if (size > 0) settings.font_size = size;
    var pairs = {
      background: '#set-background', foreground: '#set-foreground',
      cursor: '#set-cursor', encoding: '#set-encoding', term: '#set-term'
    };
    for (var key in pairs) {
      var value = pane.find(pairs[key]).val().trim();
      if (value) settings[key] = value;
    }
    settings.cursor_blink = pane.find('#set-cursor-blink').is(':checked');
    settings.key_source = pane.find('#set-key-source').val();
    return settings;
  }


  function init_settings_pane(pane) {
    pane.find('.settings-tab').on('click', function() {
      var section = $(this).data('section');
      pane.find('.settings-tab').removeClass('active');
      $(this).addClass('active');
      pane.find('.settings-section').removeClass('active');
      pane.find('#settings-' + section).addClass('active');
    });

    pane.find('#add-host-btn').on('click', function() {
      add_host_row(pane, {});
    });

    pane.on('click', '.host-delete', function() {
      $(this).closest('tr').remove();
    });

    pane.find('#set-font-size').val(user_settings.font_size || '');
    pane.find('#set-background').val(user_settings.background || '');
    pane.find('#set-foreground').val(user_settings.foreground || '');
    pane.find('#set-cursor').val(user_settings.cursor || '');
    pane.find('#set-encoding').val(user_settings.encoding || '');
    pane.find('#set-term').val(user_settings.term || '');
    pane.find('#set-cursor-blink').prop('checked',
                                        user_settings.cursor_blink !== false);
    if (user_settings.key_source) {
      pane.find('#set-key-source').val(user_settings.key_source);
    }

    $.get('/api/hosts').done(function(data) {
      var hosts = data.user_hosts || [];
      for (var i = 0; i < hosts.length; i++) {
        add_host_row(pane, hosts[i]);
      }
    });

    pane.find('#settings-save').on('click', function() {
      settings_status(pane, 'Saving...');
      var hosts = collect_host_rows(pane);
      var settings = collect_settings(pane);
      $.ajax({
        url: '/api/hosts', type: 'PUT', contentType: 'application/json',
        headers: {'X-Xsrftoken': get_xsrf_token()},
        data: JSON.stringify({hosts: hosts})
      }).done(function() {
        return $.ajax({
          url: '/api/settings', type: 'PUT', contentType: 'application/json',
          headers: {'X-Xsrftoken': get_xsrf_token()},
          data: JSON.stringify({settings: settings})
        }).done(function(data) {
          user_settings = data.settings || {};
          settings_status(pane, 'Saved');
          refresh_host_list();
        }).fail(function(xhr) {
          settings_status(pane, save_error_text(xhr), true);
        });
      }).fail(function(xhr) {
        settings_status(pane, save_error_text(xhr), true);
      });
    });
  }


  function save_error_text(xhr) {
    if (xhr && xhr.status === 400) {
      return 'Rejected: check hostnames, ports, and host keys.';
    }
    return 'Save failed.';
  }


  function get_xsrf_token() {
    var match = document.cookie.match(/\b_xsrf=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : '';
  }


  function refresh_host_list() {
    if (!user_hosts_enabled) return;
    $.get('/api/hosts').done(function(data) {
      var select = $('#hostname');
      if (!select.is('select')) return;
      var current = select.val();
      select.empty();
      var groups = [data.admin_hosts || [], data.user_hosts || []];
      for (var g = 0; g < groups.length; g++) {
        for (var i = 0; i < groups[g].length; i++) {
          var host = groups[g][i];
          var option = $('<option>')
            .attr('value', host.hostname)
            .attr('data-port', host.port)
            .text(host.name);
          if (g === 1) {
            option.attr('data-username', host.username || '');
            option.attr('data-command', host.default_command || '');
          }
          select.append(option);
        }
      }
      if (current) select.val(current);
      select.trigger('change');
    });
  }
```

- [ ] **Step 7: Prefill username and command from the selected host**

Find the existing `#hostname` change handler (search for `data-port`) and extend it so a user host also prefills the login username and default command:

```javascript
    var option = $('#hostname option:selected');
    var host_username = option.attr('data-username');
    var host_command = option.attr('data-command');
    if (host_username) $('#username').val(host_username);
    if (host_command !== undefined) $('#default-command').val(host_command);
```

Place this after the existing port-setting logic so it does not disturb it.

- [ ] **Step 8: Manual verification**

Start the server with the feature on:

```bash
mkdir -p /tmp/webssh-data
.venv/bin/python run.py --port=8889 --user_hosts=true \
  --userdatadir=/tmp/webssh-data --userheader=X-Test-User --debug
```

The `userheader` cannot be sent by a browser directly, so verify the APIs with curl and the UI with a browser extension that injects the header, or temporarily hardcode a username for testing. Confirm each of these:

- [ ] The gear button appears in the tab bar.
- [ ] Clicking it opens a "Settings" tab; the connect form is hidden while it is active.
- [ ] Clicking the gear again focuses that same tab rather than opening a second one.
- [ ] Adding a host, saving, and switching to a terminal tab shows the new host in the hostname dropdown without a page reload.
- [ ] Connecting a terminal, then opening settings, then returning to the terminal tab leaves the session alive and scrolled where it was.
- [ ] Closing the last remaining tab yields a terminal tab, not a settings tab.
- [ ] Saving an invalid host (port `0`) shows the inline error and does not clear the form.

- [ ] **Step 9: Run the suite and commit**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS, no regressions.

```bash
git add webssh/static/js/main.js webssh/templates/index.html
git commit -m "feat: add in-app settings tab with host editor"
```

---

### Task 8: Roaming preferences

**Files:**
- Modify: `webssh/static/js/main.js:364-420` (`store_items`, `store_default_command`, `restore_default_command`, `restore_items`), plus the terminal construction block at `:703-720`

**Interfaces:**
- Consumes: `user_settings` global (Task 5 render, Task 7 template), `/api/settings` (Task 4), `refresh_host_list` and `get_xsrf_token` (Task 7).
- Produces: `prefs.get(name)`, `prefs.set(name, value)`, `prefs.flush()`.

- [ ] **Step 1: Add the prefs object**

Add near the other utility functions in `main.js`:

```javascript
  var prefs = {
    pending: null,
    timer: null,

    get: function(name) {
      if (user_hosts_enabled && user_settings[name] !== undefined) {
        return user_settings[name];
      }
      return window.localStorage.getItem(name);
    },

    set: function(name, value) {
      window.localStorage.setItem(name, value);
      if (!user_hosts_enabled) return;
      user_settings[name] = value;
      this.schedule();
    },

    schedule: function() {
      var self = this;
      if (this.timer) window.clearTimeout(this.timer);
      this.timer = window.setTimeout(function() { self.flush(); }, 1000);
    },

    flush: function() {
      if (!user_hosts_enabled) return;
      this.timer = null;
      $.ajax({
        url: '/api/settings', type: 'PUT', contentType: 'application/json',
        headers: {'X-Xsrftoken': get_xsrf_token()},
        data: JSON.stringify({settings: user_settings})
      });
    }
  };
```

Because `validate_settings` whitelists keys server-side, a stray `credential` or `totp` reaching `user_settings` would be dropped rather than stored. Do not rely on that alone — keep the client from putting them there in the first place, per Step 2.

- [ ] **Step 2: Route last-used values through prefs**

Replace `store_items` and `restore_items` so they persist only the three roaming fields and never the secrets:

```javascript
  var ROAMING_FIELDS = {
    hostname: 'last_hostname',
    username: 'last_username',
    port: 'last_port'
  };


  function store_items(names, data) {
    var i, name, value;

    for (i = 0; i < names.length; i++) {
      name = names[i];
      value = data.get(name);
      if (value) {
        window.localStorage.setItem(name, value);
        if (ROAMING_FIELDS[name]) {
          var stored = (name === 'port') ? window.parseInt(value, 10) : value;
          if (name !== 'port' || stored > 0) {
            user_settings[ROAMING_FIELDS[name]] = stored;
          }
        }
      }
    }
    prefs.schedule();
  }


  function restore_items(names) {
    var i, name, value;

    for (i = 0; i < names.length; i++) {
      name = names[i];
      value = null;
      if (user_hosts_enabled && ROAMING_FIELDS[name]) {
        var roamed = user_settings[ROAMING_FIELDS[name]];
        if (roamed !== undefined && roamed !== null && roamed !== '') {
          value = String(roamed);
        }
      }
      if (value === null) {
        value = window.localStorage.getItem(name);
      }
      if (value) {
        var el = $('#' + name);
        el.val(value);
        if (name === 'hostname' && el.is('select')) {
          el.trigger('change');
        }
      }
    }
  }
```

`form_keys` includes `credential` and `totp`, and `ROAMING_FIELDS` deliberately omits both, so neither is ever added to `user_settings`. The pre-existing `localStorage` behavior for those fields is unchanged.

- [ ] **Step 3: Move default commands onto host records**

Replace `store_default_command` and `restore_default_command`:

```javascript
  function find_user_host(hostname, port) {
    var match = null;
    $('#hostname option').each(function() {
      var option = $(this);
      // Only user hosts carry data-command; admin hosts never do.
      if (option.attr('data-command') === undefined) return;
      if (option.attr('value') !== hostname) return;
      if (String(option.attr('data-port')) !== String(port || 22)) return;
      match = option;
      return false;
    });
    return match;
  }


  function store_default_command(data) {
    var key = get_host_key(data);
    if (!key) return;
    var command = $('#default-command').val().trim();
    if (command) {
      window.localStorage.setItem(key, command);
    } else {
      window.localStorage.removeItem(key);
    }
    // Server-side hosts own their own default_command, edited in Settings.
  }


  function restore_default_command(hostname, port) {
    if (!hostname) return;
    var option = find_user_host(hostname, port);
    if (option) {
      $('#default-command').val(option.attr('data-command') || '');
      return;
    }
    var key = get_host_key({hostname: hostname, port: port});
    if (!key) return;
    var command = window.localStorage.getItem(key);
    $('#default-command').val(command || '');
  }
```

A saved host's `default_command` is authoritative and is edited in the settings pane. For free-text hosts, the old `localStorage` path still applies.

- [ ] **Step 4: One-time migration of localStorage commands**

Add and call this once during page initialization, after `refresh_host_list` is defined:

```javascript
  function migrate_local_commands() {
    if (!user_hosts_enabled) return;
    if (window.localStorage.getItem('webssh_migrated_commands')) return;
    var found = [];
    for (var i = 0; i < window.localStorage.length; i++) {
      var key = window.localStorage.key(i);
      if (key && key.indexOf('command:') === 0) {
        var parts = key.split(':');
        found.push({
          hostname: parts[1],
          port: window.parseInt(parts[2], 10) || 22,
          command: window.localStorage.getItem(key)
        });
      }
    }
    if (!found.length) {
      window.localStorage.setItem('webssh_migrated_commands', '1');
      return;
    }
    $.get('/api/hosts').done(function(data) {
      var hosts = data.user_hosts || [];
      var index = {};
      for (var i = 0; i < hosts.length; i++) {
        index[hosts[i].hostname + ':' + hosts[i].port] = hosts[i];
      }
      var changed = false;
      for (var j = 0; j < found.length; j++) {
        var match = index[found[j].hostname + ':' + found[j].port];
        if (match && !match.default_command) {
          match.default_command = found[j].command;
          changed = true;
        }
      }
      if (!changed) {
        window.localStorage.setItem('webssh_migrated_commands', '1');
        return;
      }
      var payload = [];
      for (var k = 0; k < hosts.length; k++) {
        payload.push({
          name: hosts[k].name, hostname: hosts[k].hostname,
          port: hosts[k].port, host_key: hosts[k].host_keys || [],
          username: hosts[k].username || '',
          default_command: hosts[k].default_command || ''
        });
      }
      $.ajax({
        url: '/api/hosts', type: 'PUT', contentType: 'application/json',
        headers: {'X-Xsrftoken': get_xsrf_token()},
        data: JSON.stringify({hosts: payload})
      }).done(function() {
        window.localStorage.setItem('webssh_migrated_commands', '1');
        refresh_host_list();
      });
    });
  }
```

The guard key means the migration runs at most once per browser, and it never overwrites a `default_command` the user has already set.

- [ ] **Step 5: Apply terminal preferences**

In the terminal construction block, make stored preferences the fallback beneath URL parameters, preserving the existing precedence where a URL parameter always wins:

```javascript
          termOptions = {
            cursorBlink: user_settings.cursor_blink !== false,
            theme: {
              background: url_opts_data.bgcolor || user_settings.background || 'black',
              foreground: url_opts_data.fontcolor || user_settings.foreground || 'white',
              cursor: url_opts_data.cursor || user_settings.cursor ||
                      url_opts_data.fontcolor || user_settings.foreground || 'white'
            }
          };
```

and extend the font size block below it:

```javascript
      var fontsize = window.parseInt(
        url_opts_data.fontsize || user_settings.font_size, 10);
      if (fontsize && fontsize > 0) {
        termOptions.fontSize = fontsize;
      }
```

Also apply the stored terminal type by setting the hidden `#term` input during initialization:

```javascript
  if (user_settings.term) {
    $('#term').val(user_settings.term);
  }
  if (user_settings.key_source === 'stored' && user_key_enabled) {
    $('#key_source_stored').prop('checked', true).trigger('change');
  }
```

- [ ] **Step 6: Manual verification**

Restart the server as in Task 7, then confirm:

- [ ] Connect to a host, reload the page: hostname, username, and port are restored.
- [ ] Change the font size in Settings, save, open a new connection: the new terminal uses that size.
- [ ] A URL with `?fontsize=20` still overrides the stored font size.
- [ ] Open the browser's dev tools, inspect `/api/settings`: the stored JSON contains no `credential`, `totp`, `password`, or `passphrase` key.
- [ ] With `user_hosts` disabled, everything still persists via `localStorage` exactly as before.
- [ ] Set a default command in `localStorage` for a host you have also saved server-side, reload twice: the command migrates onto the host record and the migration does not run again.

- [ ] **Step 7: Run the suite and commit**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS, no regressions.

```bash
git add webssh/static/js/main.js
git commit -m "feat: roam user preferences through server-side storage"
```

---

### Task 9: Documentation

**Files:**
- Modify: `config.yaml.example`
- Modify: `README.md`

**Interfaces:**
- Consumes: the config keys from Task 3.
- Produces: nothing code depends on.

- [ ] **Step 1: Document the config keys**

Append to `config.yaml.example`, after the `userheader` block:

```yaml
# User-managed hosts and settings (optional)
# When true, authenticated users can add their own hosts and manage terminal
# preferences from the in-app Settings tab. Their hosts and settings are stored
# server-side so they roam across browsers and machines.
#
# SECURITY: enabling this lets users connect to hosts outside the `hosts`
# allowlist above. Leave it false if the allowlist is meant to be a hard
# restriction. Personal hosts can pin their own host_key, which is required
# when policy is `reject`.
#
# Requires an authenticated username via userheader. Set trusted_proxies so the
# header cannot be spoofed.
# user_hosts: true

# Directory for per-user hosts and settings (optional)
# Defaults to userkeydir when unset, placing hosts.json and settings.json
# alongside each user's SSH key.
# userdatadir: /var/lib/webssh/user-data
```

- [ ] **Step 2: Document the feature in the README**

Add to the Features list:

```markdown
* Per-user host lists and preferences that roam across browsers and machines
```

And add a section after the Configuration section:

````markdown
### User-managed hosts

With `user_hosts: true`, each authenticated user gets a Settings tab where they
can add their own hosts and set terminal preferences. Both are stored on the
server under `userdatadir` (defaulting to `userkeydir`), so they follow the user
between browsers and machines.

```yaml
user_hosts: true
userdatadir: /var/lib/webssh/user-data
userheader: X-Authentik-Username
trusted_proxies:
  - 10.0.0.1
```

Administrator hosts from `hosts:` remain read-only and always take precedence: if
a user saves a host with the same hostname and port as an administrator entry,
the administrator's host key pin is the one used.

Enabling this means users can connect to hosts outside the `hosts:` allowlist. If
that allowlist is a security boundary rather than a convenience list, leave
`user_hosts` off.
````

- [ ] **Step 3: Verify and commit**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS, 0 failures.

```bash
git add config.yaml.example README.md
git commit -m "docs: document user_hosts and userdatadir"
```

---

## Verification Checklist

Before considering the feature complete:

- [ ] `.venv/bin/python -m pytest -q` passes with zero failures
- [ ] With `user_hosts` unset, a diff of behavior against `main` shows no change: the host dropdown, allowlist enforcement, and `localStorage` persistence all behave identically
- [ ] A user host cannot override an administrator host key pin (Task 5 test)
- [ ] Stored JSON contains no credentials (Task 2 and Task 8 checks)
- [ ] `hosts.json` and `settings.json` are mode `0600`
- [ ] The manual UI checks in Tasks 7 and 8 all pass
