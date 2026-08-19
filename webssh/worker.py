import logging
try:
    import secrets
except ImportError:
    secrets = None
import tornado.websocket

from uuid import uuid4
from tornado.ioloop import IOLoop
from tornado.iostream import _ERRNO_CONNRESET
from tornado.util import errno_from_exception


BUF_SIZE = 32 * 1024
clients = {}  # {ip: {id: worker}}

# Workers whose websocket has attached, reachable by id for the duration of
# the session. Deliberately separate from `clients`: the websocket handler
# nulls the `clients` entry to make a worker id single-use for websocket
# authentication, and that property must not be weakened to make lookup
# convenient here.
live_workers = {}  # {id: worker}


def register_live_worker(worker):
    live_workers[worker.id] = worker


def unregister_live_worker(worker):
    live_workers.pop(worker.id, None)


# Short-lived, single-use credentials for the one transfer a browser cannot
# authenticate with a header: the download navigation. A ticket authorises
# one download of one path from one address for TICKET_TTL seconds, so a
# copy recovered from browser history is worthless.
TICKET_TTL = 60
MAX_TICKETS = 256

# A legitimate user holds a handful of tickets at once. Without a per-worker
# limit, one authenticated session (or a looping client) could mint enough
# tickets to exhaust MAX_TICKETS by itself, returning 503 to every other
# user's /transfer/ticket for up to TICKET_TTL seconds.
MAX_TICKETS_PER_WORKER = 8

# PATH_MAX on Linux. Rejected at mint rather than stored, so an oversized
# path never occupies a ticket slot in the first place.
MAX_TICKET_PATH_LENGTH = 4096

tickets = {}  # ticket -> {'worker_id', 'path', 'ip', 'expires'}


class TicketStoreFull(Exception):
    pass


class TicketPathTooLong(Exception):
    pass


def _sweep_tickets(now):
    for key in [k for k, v in tickets.items() if v['expires'] < now]:
        tickets.pop(key, None)


def mint_ticket(worker_id, path, ip, now):
    if len(path.encode('utf-8')) > MAX_TICKET_PATH_LENGTH:
        raise TicketPathTooLong()

    _sweep_tickets(now)
    if len(tickets) >= MAX_TICKETS:
        # Reaching the global cap after a sweep means something is looping,
        # so refuse rather than let the store grow without bound.
        raise TicketStoreFull()

    per_worker = sum(1 for v in tickets.values()
                     if v['worker_id'] == worker_id)
    if per_worker >= MAX_TICKETS_PER_WORKER:
        # Same refusal as the global cap: the caller cannot tell, from the
        # response, which limit it hit, and does not need to.
        raise TicketStoreFull()

    ticket = Worker.gen_id()
    tickets[ticket] = {
        'worker_id': worker_id,
        'path': path,
        'ip': ip,
        'expires': now + TICKET_TTL,
    }
    return ticket


def peek_ticket(ticket, ip, now):
    """Validate a ticket without spending it, returning its claim or None.

    Used to resolve the worker for the download concurrency check before
    the ticket is consumed, so a request the cap rejects leaves the ticket
    usable for a retry rather than burning a single-use credential on a
    429.

    Despite the name, this pops the ticket before comparing, exactly like
    consume_ticket: an address mismatch (or expiry) must still burn it, or
    an attacker holding a leaked ticket gets a free retry from every
    address they control within the TTL. The difference from consume_ticket
    is only what happens on success -- the claim is valid, so the ticket is
    restored to the store instead of staying popped, leaving it live for
    the real consume_ticket call once the caller decides to proceed. Do not
    "simplify" this to tickets.get(): that reopens the retry-from-anywhere
    hole this function exists to close.
    """
    claim = tickets.pop(ticket, None)
    if claim is None:
        return None
    if claim['expires'] < now or claim['ip'] != ip:
        return None
    tickets[ticket] = claim
    return {'worker_id': claim['worker_id'], 'path': claim['path']}


def consume_ticket(ticket, ip, now):
    """Redeem a ticket, returning its claim or None.

    The ticket is removed on every outcome where it existed, including an
    address mismatch: leaving it live would let someone who guessed one
    retry from every address they control.
    """
    claim = tickets.pop(ticket, None)
    if claim is None:
        return None
    if claim['expires'] < now or claim['ip'] != ip:
        return None
    return {'worker_id': claim['worker_id'], 'path': claim['path']}


def drop_tickets_for(worker_id):
    for key in [k for k, v in tickets.items() if v['worker_id'] == worker_id]:
        tickets.pop(key, None)


def clear_worker(worker, clients):
    ip = worker.src_addr[0]
    workers = clients.get(ip)
    assert worker.id in workers
    workers.pop(worker.id)

    if not workers:
        clients.pop(ip)
        if not clients:
            clients.clear()


def recycle_worker(worker):
    if worker.handler:
        return
    logging.warning('Recycling worker {}'.format(worker.id))
    worker.close(reason='worker recycled')


class Worker(object):
    def __init__(self, loop, ssh, chan, dst_addr):
        self.loop = loop
        self.ssh = ssh
        self.chan = chan
        self.dst_addr = dst_addr
        self.fd = chan.fileno()
        self.id = self.gen_id()
        self.data_to_dst = []
        self.handler = None
        self.mode = IOLoop.READ
        self.closed = False
        # Number of transfers in flight. A nonzero count suppresses the
        # idle disconnect, which otherwise only resets on websocket traffic.
        self.transfers = 0

    def begin_transfer(self):
        self.transfers += 1

    def end_transfer(self):
        """Release one transfer slot.

        Clamped at zero and logged if it would go negative. The counter is
        load-bearing twice over -- it caps concurrency and it suppresses the
        idle disconnect -- so an unbalanced release does not merely lose a
        slot, it leaves the session unable to ever time out. Both handlers
        release from `finally` blocks and disconnect callbacks that can
        overlap, so the invariant is easy to break quietly; this makes a
        break visible instead.
        """
        if self.transfers <= 0:
            logging.error(
                'Transfer counter underflow on worker {}; releasing a slot '
                'that was never taken'.format(self.id))
            self.transfers = 0
            return
        self.transfers -= 1

    def __call__(self, fd, events):
        if events & IOLoop.READ:
            self.on_read()
        if events & IOLoop.WRITE:
            self.on_write()
        if events & IOLoop.ERROR:
            self.close(reason='error event occurred')

    @classmethod
    def gen_id(cls):
        return secrets.token_urlsafe(nbytes=32) if secrets else uuid4().hex

    def set_handler(self, handler):
        if not self.handler:
            self.handler = handler

    def update_handler(self, mode):
        if self.mode != mode:
            self.loop.update_handler(self.fd, mode)
            self.mode = mode
        if mode == IOLoop.WRITE:
            self.loop.call_later(0.1, self, self.fd, IOLoop.WRITE)

    def on_read(self):
        logging.debug('worker {} on read'.format(self.id))
        try:
            data = self.chan.recv(BUF_SIZE)
        except (OSError, IOError) as e:
            logging.error(e)
            if self.chan.closed or errno_from_exception(e) in _ERRNO_CONNRESET:
                self.close(reason='chan error on reading')
        else:
            logging.debug('{!r} from {}:{}'.format(data, *self.dst_addr))
            if not data:
                self.close(reason='Remote server closed the connection.')
                return

            logging.debug('{!r} to {}:{}'.format(data, *self.handler.src_addr))
            try:
                self.handler.write_message(data, binary=True)
            except tornado.websocket.WebSocketClosedError:
                self.close(reason='websocket closed')

    def on_write(self):
        logging.debug('worker {} on write'.format(self.id))
        if not self.data_to_dst:
            return

        data = ''.join(self.data_to_dst)
        logging.debug('{!r} to {}:{}'.format(data, *self.dst_addr))

        try:
            sent = self.chan.send(data)
        except (OSError, IOError) as e:
            logging.error(e)
            if self.chan.closed or errno_from_exception(e) in _ERRNO_CONNRESET:
                self.close(reason='chan error on writing')
            else:
                self.update_handler(IOLoop.WRITE)
        else:
            self.data_to_dst = []
            data = data[sent:]
            if data:
                self.data_to_dst.append(data)
                self.update_handler(IOLoop.WRITE)
            else:
                self.update_handler(IOLoop.READ)

    def close(self, reason=None):
        if self.closed:
            return
        self.closed = True
        unregister_live_worker(self)
        drop_tickets_for(self.id)

        logging.info(
            'Closing worker {} with reason: {}'.format(self.id, reason)
        )
        if self.handler:
            self.loop.remove_handler(self.fd)
            self.handler.close(reason=reason)
        self.chan.close()
        self.ssh.close()
        logging.info('Connection to {}:{} lost'.format(*self.dst_addr))

        clear_worker(self, clients)
        logging.debug(clients)
