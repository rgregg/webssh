import logging
import os.path
import tornado.template
import tornado.web
import tornado.ioloop

from tornado.options import options
from webssh import handler
from webssh.handler import (
    IndexHandler, WsockHandler, NotFoundHandler, UserKeyHandler
)
from webssh.settings import (
    get_app_settings,  get_host_keys_settings, get_policy_setting,
    get_ssl_context, get_server_settings, check_encoding_setting,
    get_allowed_hosts_setting, check_user_key_dir, apply_config_settings
)


def make_handlers(loop, options):
    host_keys_settings = get_host_keys_settings(options)
    policy = get_policy_setting(options, host_keys_settings)
    allowed_hosts = get_allowed_hosts_setting(options)

    user_key_dir = options.userkeydir
    user_header = options.userheader

    index_kwargs = dict(
        loop=loop, policy=policy,
        host_keys_settings=host_keys_settings,
        allowed_hosts=allowed_hosts,
        user_key_dir=user_key_dir,
        user_header=user_header
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


def main():
    options.parse_command_line()
    if not options.config and os.path.isfile(DEFAULT_CONFIG_PATH):
        options.config = DEFAULT_CONFIG_PATH
        logging.info('Using default config file: {}'.format(DEFAULT_CONFIG_PATH))
    apply_config_settings(options)
    check_encoding_setting(options.encoding)
    check_user_key_dir(options.userkeydir, options.tdstream)
    loop = tornado.ioloop.IOLoop.current()
    app = make_app(make_handlers(loop, options), get_app_settings(options))
    # Pre-compile the template so the first request doesn't pay the cost
    loader = tornado.template.Loader(app.settings['template_path'])
    loader.load('index.html')
    ssl_ctx = get_ssl_context(options)
    server_settings = get_server_settings(options)
    app_listen(app, options.port, options.address, server_settings)
    if ssl_ctx:
        server_settings.update(ssl_options=ssl_ctx)
        app_listen(app, options.sslport, options.ssladdress, server_settings)
    loop.start()


if __name__ == '__main__':
    main()
