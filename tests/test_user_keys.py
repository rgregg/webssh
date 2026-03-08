import os
import stat
import tempfile
import unittest

from webssh.user_keys import (
    sanitize_username, get_user_key_dir, has_stored_key,
    read_public_key, read_private_key, generate_key_pair
)


class TestSanitizeUsername(unittest.TestCase):

    def test_valid_usernames(self):
        for name in ['alice', 'bob123', 'user.name', 'user-name', 'user_name',
                      'A.B-C_1']:
            self.assertEqual(sanitize_username(name), name)

    def test_empty_username(self):
        with self.assertRaises(ValueError):
            sanitize_username('')

    def test_none_username(self):
        with self.assertRaises(ValueError):
            sanitize_username(None)

    def test_path_traversal(self):
        for name in ['../etc', 'foo/bar']:
            with self.assertRaises(ValueError):
                sanitize_username(name)

    def test_special_chars(self):
        for name in ['user@host', 'user name', 'user;cmd', 'user$var']:
            with self.assertRaises(ValueError):
                sanitize_username(name)


class TestGetUserKeyDir(unittest.TestCase):

    def test_returns_correct_path(self):
        result = get_user_key_dir('/tmp/keys', 'alice')
        self.assertEqual(result, os.path.realpath('/tmp/keys/alice'))

    def test_rejects_dot_dot(self):
        with self.assertRaises(ValueError):
            get_user_key_dir('/tmp/keys', '..')

    def test_rejects_dot(self):
        with self.assertRaises(ValueError):
            get_user_key_dir('/tmp/keys', '.')


class TestKeyOperations(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_has_stored_key_false_when_missing(self):
        self.assertFalse(has_stored_key(self.tmpdir, 'alice'))

    def test_generate_and_has_stored_key(self):
        pub = generate_key_pair(self.tmpdir, 'alice')
        self.assertTrue(has_stored_key(self.tmpdir, 'alice'))
        self.assertIn('ssh-ed25519', pub)
        self.assertIn('alice', pub)

    def test_file_permissions(self):
        generate_key_pair(self.tmpdir, 'alice')
        user_dir = os.path.join(self.tmpdir, 'alice')
        priv_path = os.path.join(user_dir, 'id_ed25519')
        pub_path = os.path.join(user_dir, 'id_ed25519.pub')

        priv_mode = stat.S_IMODE(os.stat(priv_path).st_mode)
        pub_mode = stat.S_IMODE(os.stat(pub_path).st_mode)
        self.assertEqual(priv_mode, 0o600)
        self.assertEqual(pub_mode, 0o644)

    def test_read_public_key(self):
        pub = generate_key_pair(self.tmpdir, 'alice')
        read_pub = read_public_key(self.tmpdir, 'alice')
        self.assertEqual(read_pub, pub)

    def test_read_private_key(self):
        generate_key_pair(self.tmpdir, 'alice')
        priv = read_private_key(self.tmpdir, 'alice')
        self.assertIn('PRIVATE KEY', priv)

    def test_overwrite_existing_key(self):
        pub1 = generate_key_pair(self.tmpdir, 'alice')
        pub2 = generate_key_pair(self.tmpdir, 'alice')
        self.assertTrue(has_stored_key(self.tmpdir, 'alice'))
        # Keys should be different (new generation)
        self.assertNotEqual(pub1, pub2)
