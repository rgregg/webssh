import logging
import os
import tempfile
import unittest

import yaml
from tornado.options import options
from tornado.web import Application
from webssh import handler
from webssh.main import (
    app_listen, reload_config, check_user_hosts_configuration
)


class TestMain(unittest.TestCase):

    def test_app_listen(self):
        app = Application()
        app.listen = lambda x, y, **kwargs: 1

        handler.redirecting = None
        server_settings = dict()
        app_listen(app, 80, '127.0.0.1', server_settings)
        self.assertFalse(handler.redirecting)

        handler.redirecting = None
        server_settings = dict(ssl_options='enabled')
        app_listen(app, 80, '127.0.0.1', server_settings)
        self.assertTrue(handler.redirecting)


class TestCheckUserHostsConfiguration(unittest.TestCase):

    def test_disabled_does_nothing(self):
        with self.assertLogs(level='WARNING') as cm:
            logging.warning('sentinel')
            check_user_hosts_configuration(False, '')
        self.assertEqual(len(cm.output), 1)

    def test_enabled_without_data_dir_warns(self):
        with self.assertLogs(level='WARNING') as cm:
            check_user_hosts_configuration(True, '')
        self.assertTrue(any(
            'user_hosts is enabled but no userdatadir or userkeydir' in msg
            for msg in cm.output
        ))

    def test_enabled_with_data_dir_checks_directory(self):
        data_dir = tempfile.mkdtemp()
        try:
            # Should not raise, and should not log the "not configured"
            # warning when a data dir is present (a separate security
            # warning about missing trusted_proxies is expected instead).
            with self.assertLogs(level='WARNING') as cm:
                check_user_hosts_configuration(True, data_dir)
            self.assertFalse(any(
                'not configured' in msg for msg in cm.output
            ))
        finally:
            os.rmdir(data_dir)


class TestReloadConfig(unittest.TestCase):

    def _make_config(self, data):
        f = tempfile.NamedTemporaryFile(
            mode='w', suffix='.yaml', delete=False)
        yaml.dump(data, f)
        f.close()
        return f.name

    def _make_host_keys_settings(self):
        from paramiko import HostKeys
        return {
            'host_keys': HostKeys(),
            'system_host_keys': HostKeys(),
            'host_keys_filename': ''
        }

    def test_reload_updates_allowed_hosts(self):
        config = self._make_config({
            'hosts': [{'hostname': '10.0.0.1', 'name': 'server1'}]
        })
        live = {'allowed_hosts': [], 'policy': None}
        hks = self._make_host_keys_settings()
        try:
            reload_config(config, live, hks)
            self.assertEqual(len(live['allowed_hosts']), 1)
            self.assertEqual(live['allowed_hosts'][0]['hostname'], '10.0.0.1')
        finally:
            os.unlink(config)

    def test_reload_invalid_hosts_keeps_previous(self):
        config = self._make_config({
            'hosts': [{'not_hostname': 'bad'}]
        })
        live = {'allowed_hosts': [{'hostname': 'old'}]}
        hks = self._make_host_keys_settings()
        try:
            reload_config(config, live, hks)
            # Previous config preserved
            self.assertEqual(live['allowed_hosts'][0]['hostname'], 'old')
        finally:
            os.unlink(config)

    def test_reload_invalid_yaml_keeps_previous(self):
        f = tempfile.NamedTemporaryFile(
            mode='w', suffix='.yaml', delete=False)
        f.write(': invalid: yaml: [')
        f.close()
        live = {'allowed_hosts': [{'hostname': 'old'}]}
        hks = self._make_host_keys_settings()
        try:
            reload_config(f.name, live, hks)
            self.assertEqual(live['allowed_hosts'][0]['hostname'], 'old')
        finally:
            os.unlink(f.name)

    def test_reload_idle_timeout_valid(self):
        config = self._make_config({'idle_timeout': 600})
        live = {'allowed_hosts': []}
        hks = self._make_host_keys_settings()
        old = options.idletimeout
        try:
            reload_config(config, live, hks)
            self.assertEqual(options.idletimeout, 600)
        finally:
            options.idletimeout = old
            os.unlink(config)

    def test_reload_idle_timeout_negative_keeps_previous(self):
        config = self._make_config({'idle_timeout': -1})
        live = {'allowed_hosts': []}
        hks = self._make_host_keys_settings()
        old = options.idletimeout
        try:
            reload_config(config, live, hks)
            self.assertEqual(options.idletimeout, old)
        finally:
            os.unlink(config)

    def test_reload_idle_timeout_invalid_keeps_previous(self):
        config = self._make_config({'idle_timeout': 'not_a_number'})
        live = {'allowed_hosts': []}
        hks = self._make_host_keys_settings()
        old = options.idletimeout
        try:
            reload_config(config, live, hks)
            self.assertEqual(options.idletimeout, old)
        finally:
            os.unlink(config)

    def test_reload_atomic_on_policy_failure(self):
        """If policy validation fails, allowed_hosts should not update."""
        config = self._make_config({
            'hosts': [{'hostname': '10.0.0.2', 'name': 'new'}],
            'policy': 'invalid_policy'
        })
        live = {'allowed_hosts': [{'hostname': 'old'}], 'policy': None}
        hks = self._make_host_keys_settings()
        try:
            reload_config(config, live, hks)
            # Neither should update
            self.assertEqual(live['allowed_hosts'][0]['hostname'], 'old')
        finally:
            os.unlink(config)
