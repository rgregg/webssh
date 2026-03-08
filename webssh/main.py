import logging
import os
import os.path
import tornado.template
import tornado.web
import tornado.ioloop

from tornado.ioloop import PeriodicCallback
from tornado.options import options
from webssh import handler
from webssh.handler import (
    IndexHandler, WsockHandler, NotFoundHandler, UserKeyHandler
)
from webssh.policy import get_policy_class
from webssh.settings import (
    get_app_settings,  get_host_keys_settings, get_policy_setting,
    get_ssl_context, get_server_settings, check_encoding_setting,
    get_allowed_hosts_setting, check_user_key_dir, apply_config_settings,
    load_config_file, parse_allowed_hosts
)


def make_handlers(loop, options, live_config=None):
    host_keys_settings = get_host_keys_settings(options)
    policy = get_policy_setting(options, host_keys_settings)
    allowed_hosts = get_allowed_hosts_setting(options)

    if live_config is None:
        live_config = {}
    live_config['allowed_hosts'] = allowed_hosts
    live_config['policy'] = policy
    live_config['host_keys_settings'] = host_keys_settings

    user_key_dir = options.userkeydir
    user_header = options.userheader

    index_kwargs = dict(
        loop=loop, policy=policy,
        host_keys_settings=host_keys_settings,
        allowed_hosts=allowed_hosts,
        user_key_dir=user_key_dir,
        user_header=user_header,
        live_config=live_config
    )

    handlers = [
        (r'/', IndexHandler, index_kwargs),
        (r'/ws', WsockHandler, dict(loop=loop))
    ]

    if user_key_dir:
        handlers.append(
            (r'/user-key', UserKeyHandler, dict(
                loop=loop,
                user_key_dir=user_key_dir,
                user_header=user_header
            ))
        )

    return handlers


def make_app(handlers, settings):
    settings.update(default_handler_class=NotFoundHandler)
    return tornado.web.Application(handlers, **settings)


def app_listen(app, port, address, server_settings):
    app.listen(port, address, **server_settings)
    if not server_settings.get('ssl_options'):
        server_type = 'http'
    else:
        server_type = 'https'
        handler.redirecting = True if options.redirect else False
    logging.info(
        'Listening on {}:{} ({})'.format(address, port, server_type)
    )


DEFAULT_CONFIG_PATH = '/data/config.yaml'


def reload_config(config_path, live_config, host_keys_settings):
    """Reload allowed_hosts, policy, and idle_timeout from the config file.

    Validates all values before applying any changes so a partial failure
    does not leave live_config in an inconsistent state.
    """
    try:
        data = load_config_file(config_path)
    except Exception as exc:
        logging.error('Failed to reload config: {}'.format(exc))
        return

    # Stage all values before applying
    updates = {}

    try:
        updates['allowed_hosts'] = parse_allowed_hosts(data)
    except ValueError as exc:
        logging.error('Invalid hosts in config reload: {}'.format(exc))
        return

    if 'policy' in data:
        try:
            from webssh.policy import check_policy_setting
            policy_class = get_policy_class(data['policy'])
            check_policy_setting(policy_class, host_keys_settings)
            updates['policy'] = policy_class()
        except ValueError as exc:
            logging.error('Invalid policy in config reload: {}'.format(exc))
            return

    new_idle_timeout = None
    if 'idle_timeout' in data:
        try:
            new_idle_timeout = int(data['idle_timeout'])
        except (TypeError, ValueError):
            logging.error(
                'Invalid idle_timeout in config reload: {!r}'.format(
                    data['idle_timeout']))
            return
        if new_idle_timeout < 0:
            logging.error(
                'Invalid idle_timeout (must be >= 0): {}'.format(
                    new_idle_timeout))
            return

    # All validation passed — apply atomically
    for key, value in updates.items():
        live_config[key] = value

    if new_idle_timeout is not None:
        options.idletimeout = new_idle_timeout

    parts = []
    if 'allowed_hosts' in updates:
        parts.append('{} hosts'.format(len(updates['allowed_hosts'])))
    if 'policy' in updates:
        parts.append('policy={}'.format(data['policy']))
    if new_idle_timeout is not None:
        parts.append('idle_timeout={}'.format(new_idle_timeout))
    logging.info('Config reloaded: {}'.format(', '.join(parts)))


def start_config_watcher(config_path, live_config, host_keys_settings,
                         interval=5000):
    """Watch config file for changes and reload when modified."""
    state = {'mtime': 0}

    try:
        state['mtime'] = os.path.getmtime(config_path)
    except OSError:
        pass

    def check_config():
        try:
            mtime = os.path.getmtime(config_path)
        except OSError:
            return
        if mtime > state['mtime']:
            state['mtime'] = mtime
            logging.info('Config file changed, reloading...')
            reload_config(config_path, live_config, host_keys_settings)

    watcher = PeriodicCallback(check_config, interval)
    watcher.start()
    return watcher


def main():
    options.parse_command_line()
    if not options.config and os.path.isfile(DEFAULT_CONFIG_PATH):
        options.config = DEFAULT_CONFIG_PATH
        logging.info('Using default config file: {}'.format(DEFAULT_CONFIG_PATH))
    apply_config_settings(options)
    check_encoding_setting(options.encoding)
    check_user_key_dir(options.userkeydir, options.tdstream)
    loop = tornado.ioloop.IOLoop.current()
    live_config = {}
    app = make_app(make_handlers(loop, options, live_config),
                   get_app_settings(options))
    # Pre-compile the template so the first request doesn't pay the cost
    loader = tornado.template.Loader(app.settings['template_path'])
    loader.load('index.html')
    app.settings['template_loader'] = loader
    ssl_ctx = get_ssl_context(options)
    server_settings = get_server_settings(options)
    app_listen(app, options.port, options.address, server_settings)
    if ssl_ctx:
        server_settings.update(ssl_options=ssl_ctx)
        app_listen(app, options.sslport, options.ssladdress, server_settings)
    if options.config:
        start_config_watcher(
            options.config, live_config, live_config.get('host_keys_settings')
        )
    try:
        loop.start()
    except KeyboardInterrupt:
        logging.info('Exiting.')


if __name__ == '__main__':
    main()
