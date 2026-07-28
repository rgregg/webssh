import json
import os
import stat
import tempfile
import unittest

from webssh.user_data import (
    SCHEMA_VERSION, get_user_data_dir, read_hosts, write_hosts,
    read_settings, write_settings, validate_hosts, validate_settings
)


VALID_KEY = ('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrAb7GEqLHlbAF9gMdvDZzd'
             'Knd2MlrZ2sAs5qF7XMRF')


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
