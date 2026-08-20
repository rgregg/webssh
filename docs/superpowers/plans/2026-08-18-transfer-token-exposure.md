# Worker Token Exposure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the session-long worker token from appearing in URLs, where it lands in the browser's download history and in server access logs.

**Architecture:** `list` and `upload` are XHR/`fetch`, so they carry the token in an `X-Worker-Id` header. `download` is a browser navigation and cannot set headers, so it redeems a single-use, IP-bound, 60-second ticket minted by a separate POST.

**Tech Stack:** Python 3.10+, Tornado, paramiko; browser JavaScript in ES5, tested with `node --test`.

**Spec:** `docs/superpowers/specs/2026-08-18-transfer-token-exposure-design.md`

## Global Constraints

- Python: **no f-strings** (use `.format()`), `super(ClassName, self)` form, compact parenthesised imports.
- JavaScript: **ES5 only** under `webssh/static/js/` — no `const`, `let`, arrow functions, template literals. Enforced by `scripts/check_es5.js`.
- **No new dependencies**, Python or npm.
- CI pins `ruff==0.15.6`; `ruff check .` must be clean.
- Ticket TTL is **60 seconds**; `MAX_TICKETS` is **256**; tickets are **single-use** and bound to **worker, path, and client IP**.
- Ticket failures return **404** with no detail identifying which check failed. A valid ticket whose session has ended returns **410**.
- **No backward compatibility for `?id=`** on the three transfer routes.
- `ws?id=` is deliberately unchanged.

**Baseline:** 338 Python tests and 67 JS tests pass at `9198dea` on branch `fix/transfer-token-exposure`.

**Verification commands:**
- Python: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
- JS: `node --test tests/js/*.test.js`
- ES5 gate: `node scripts/check_es5.js`
- Lint: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m ruff check .`

---

## File Structure

| File | Responsibility | Change |
| --- | --- | --- |
| `webssh/worker.py` | Worker registry | Add the ticket store and its mint/consume/sweep functions; drop a worker's tickets on close |
| `tests/test_app.py` | Python tests | Ticket lifecycle tests; header and query-string tests for all three routes |
| `webssh/handler.py` | HTTP handlers | Token from header in `TransferMixin`; new `TransferTicketHandler`; download redeems a ticket |
| `webssh/main.py` | Routes | Register `/transfer/ticket` |
| `webssh/static/js/file-transfer.js` | Pure client logic | URL builders lose `id`; add `ticket_url` |
| `tests/js/file-transfer.test.js` | JS tests | Cover the changed builders |
| `webssh/static/js/transfer-ui.js` | Picker/upload DOM wiring | Send `X-Worker-Id`; mint then redeem for download |

---

### Task 1: The ticket store

**Files:**
- Modify: `webssh/worker.py`
- Test: `tests/test_app.py`

**Interfaces:**
- Consumes: nothing.
- Produces, all in `webssh.worker`:
  - `TICKET_TTL = 60`
  - `MAX_TICKETS = 256`
  - `tickets` (dict)
  - `mint_ticket(worker_id, path, ip, now) -> str` — raises `TicketStoreFull` when full after sweeping
  - `consume_ticket(ticket, ip, now) -> dict or None` — returns `{'worker_id', 'path'}` on success, `None` on any failure, and removes the ticket either way when it existed
  - `drop_tickets_for(worker_id)`
  - `TicketStoreFull` (exception)

`now` is passed in rather than read inside, so expiry is testable without sleeping or patching the clock.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_app.py`:

```python
class TestTicketStore(unittest.TestCase):
    """A ticket replaces the session-long worker token in the download URL.
    Its whole value is that a copy recovered from browser history is
    already useless, so expiry, single use, and IP binding are the point."""

    def setUp(self):
        worker.tickets.clear()
        self.addCleanup(worker.tickets.clear)

    def test_a_minted_ticket_consumes_to_its_worker_and_path(self):
        t = worker.mint_ticket('wid', '/var/log/syslog', '10.0.0.5', now=1000)
        claim = worker.consume_ticket(t, '10.0.0.5', now=1001)
        self.assertEqual(claim['worker_id'], 'wid')
        self.assertEqual(claim['path'], '/var/log/syslog')

    def test_a_ticket_cannot_be_used_twice(self):
        t = worker.mint_ticket('wid', '/f', '10.0.0.5', now=1000)
        self.assertIsNotNone(worker.consume_ticket(t, '10.0.0.5', now=1001))
        self.assertIsNone(worker.consume_ticket(t, '10.0.0.5', now=1002))

    def test_an_expired_ticket_is_refused(self):
        t = worker.mint_ticket('wid', '/f', '10.0.0.5', now=1000)
        after = 1000 + worker.TICKET_TTL + 1
        self.assertIsNone(worker.consume_ticket(t, '10.0.0.5', now=after))

    def test_a_ticket_at_exactly_the_ttl_is_still_valid(self):
        t = worker.mint_ticket('wid', '/f', '10.0.0.5', now=1000)
        self.assertIsNotNone(
            worker.consume_ticket(t, '10.0.0.5', now=1000 + worker.TICKET_TTL))

    def test_a_ticket_from_another_ip_is_refused(self):
        t = worker.mint_ticket('wid', '/f', '10.0.0.5', now=1000)
        self.assertIsNone(worker.consume_ticket(t, '203.0.113.9', now=1001))

    def test_an_ip_mismatch_still_burns_the_ticket(self):
        # Otherwise an attacker who guessed a ticket could retry from
        # every address they control until one matched.
        t = worker.mint_ticket('wid', '/f', '10.0.0.5', now=1000)
        worker.consume_ticket(t, '203.0.113.9', now=1001)
        self.assertIsNone(worker.consume_ticket(t, '10.0.0.5', now=1002))

    def test_an_unknown_ticket_is_refused(self):
        self.assertIsNone(worker.consume_ticket('never-minted', '1.2.3.4',
                                                now=1000))

    def test_tickets_are_unguessable_and_distinct(self):
        a = worker.mint_ticket('wid', '/f', '10.0.0.5', now=1000)
        b = worker.mint_ticket('wid', '/f', '10.0.0.5', now=1000)
        self.assertNotEqual(a, b)
        self.assertGreaterEqual(len(a), 32)

    def test_minting_sweeps_expired_tickets(self):
        for i in range(10):
            worker.mint_ticket('wid', '/f{}'.format(i), '10.0.0.5', now=1000)
        self.assertEqual(len(worker.tickets), 10)
        worker.mint_ticket('wid', '/fresh', '10.0.0.5',
                           now=1000 + worker.TICKET_TTL + 1)
        # The ten stale ones are gone; only the fresh one remains.
        self.assertEqual(len(worker.tickets), 1)

    def test_minting_past_the_cap_raises_rather_than_growing(self):
        for i in range(worker.MAX_TICKETS):
            worker.mint_ticket('wid', '/f{}'.format(i), '10.0.0.5', now=1000)
        with self.assertRaises(worker.TicketStoreFull):
            worker.mint_ticket('wid', '/overflow', '10.0.0.5', now=1000)
        self.assertEqual(len(worker.tickets), worker.MAX_TICKETS)

    def test_dropping_a_workers_tickets_leaves_other_workers_alone(self):
        mine = worker.mint_ticket('wid', '/f', '10.0.0.5', now=1000)
        theirs = worker.mint_ticket('other', '/f', '10.0.0.5', now=1000)
        worker.drop_tickets_for('wid')
        self.assertIsNone(worker.consume_ticket(mine, '10.0.0.5', now=1001))
        self.assertIsNotNone(worker.consume_ticket(theirs, '10.0.0.5',
                                                   now=1001))

    def test_closing_a_worker_drops_its_tickets(self):
        # A ticket must not outlive the session it authorises.
        class FakeChan(object):
            def fileno(self):
                return 0

            def close(self):
                pass

        class FakeSSH(object):
            def close(self):
                pass

        w = worker.Worker(None, FakeSSH(), FakeChan(), ('1.2.3.4', 22))
        w.id = 'closing'
        w.src_addr = ('10.0.0.5', 1234)
        worker.clients['10.0.0.5'] = {'closing': None}
        self.addCleanup(worker.clients.clear)

        t = worker.mint_ticket(w.id, '/f', '10.0.0.5', now=1000)
        w.close(reason='test')
        self.assertIsNone(worker.consume_ticket(t, '10.0.0.5', now=1001))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k TicketStore`
Expected: FAIL — `AttributeError: module 'webssh.worker' has no attribute 'tickets'`

- [ ] **Step 3: Implement the store**

In `webssh/worker.py`, after the `unregister_live_worker` definition, add:

```python
# Short-lived, single-use credentials for the one transfer a browser cannot
# authenticate with a header: the download navigation. A ticket authorises
# one download of one path from one address for TICKET_TTL seconds, so a
# copy recovered from browser history is worthless.
TICKET_TTL = 60
MAX_TICKETS = 256

tickets = {}  # ticket -> {'worker_id', 'path', 'ip', 'expires'}


class TicketStoreFull(Exception):
    pass


def _sweep_tickets(now):
    for key in [k for k, v in tickets.items() if v['expires'] < now]:
        tickets.pop(key, None)


def mint_ticket(worker_id, path, ip, now):
    _sweep_tickets(now)
    if len(tickets) >= MAX_TICKETS:
        # A legitimate user holds a handful at once. Reaching the cap after
        # a sweep means something is looping, so refuse rather than let the
        # store grow without bound.
        raise TicketStoreFull()

    ticket = Worker.gen_id()
    tickets[ticket] = {
        'worker_id': worker_id,
        'path': path,
        'ip': ip,
        'expires': now + TICKET_TTL,
    }
    return ticket


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
```

`mint_ticket` uses `Worker.gen_id()`, the same 32-byte URL-safe generator that produces worker ids, so tickets inherit its entropy.

In `Worker.close`, immediately after the existing `unregister_live_worker(self)` line, add:

```python
        drop_tickets_for(self.id)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k TicketStore`
Expected: PASS, 12 tests

- [ ] **Step 5: Verify nothing regressed**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
Expected: PASS, 350 tests (338 baseline + 12)

- [ ] **Step 6: Lint and commit**

```bash
/home/ryan/github/rgregg/webssh/.venv/bin/python -m ruff check .
git add webssh/worker.py tests/test_app.py
git commit -m "feat: add single-use download tickets"
```

---

### Task 2: Token from a header, and the ticket endpoint

**Files:**
- Modify: `webssh/handler.py`
- Modify: `webssh/main.py`
- Test: `tests/test_app.py`

**Interfaces:**
- Consumes: `worker.mint_ticket`, `worker.consume_ticket`, `worker.TicketStoreFull`, `worker.TICKET_TTL` from Task 1.
- Produces: `TransferMixin.WORKER_ID_HEADER = 'X-Worker-Id'`, `TransferTicketHandler`, and a `get_live_worker()` that reads the header rather than the query string.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_app.py`:

```python
class TestTransferTokenHeader(TransferTestBase):
    """The worker token is a session-long credential. It must travel in a
    header, never a URL, so it cannot land in browser history or access
    logs."""

    def hdrs(self, extra=None):
        h = dict(self.headers)
        h['X-Worker-Id'] = 'tid'
        if extra:
            h.update(extra)
        return h

    def test_list_accepts_the_token_in_a_header(self):
        response = self.fetch('/transfer/list?path=/home/ryan',
                              headers=self.hdrs())
        self.assertEqual(response.code, 200)

    def test_list_rejects_the_token_in_the_query_string(self):
        # The point of the change: the old form must stop working, or the
        # leak survives wherever a caller kept using it.
        response = self.fetch('/transfer/list?id=tid&path=/home/ryan',
                              headers=self.headers)
        self.assertEqual(response.code, 404)

    def test_list_from_a_different_client_ip_is_still_404(self):
        self.worker.src_addr = ('203.0.113.7', 1234)
        response = self.fetch('/transfer/list?path=/home/ryan',
                              headers=self.hdrs())
        self.assertEqual(response.code, 404)

    def test_upload_accepts_the_token_in_a_header(self):
        response = self.fetch(
            '/transfer/upload?path=/home/ryan/hdr.txt&filename=hdr.txt',
            method='POST', body=b'x',
            headers=self.hdrs({'X-Xsrftoken': 'yummy',
                               'Content-Type': 'application/octet-stream'}))
        self.assertEqual(response.code, 200)

    def test_upload_rejects_the_token_in_the_query_string(self):
        response = self.fetch(
            '/transfer/upload?id=tid&path=/home/ryan/q.txt&filename=q.txt',
            method='POST', body=b'x',
            headers={'Cookie': '_xsrf=yummy', 'X-Xsrftoken': 'yummy',
                     'Content-Type': 'application/octet-stream'})
        self.assertEqual(response.code, 404)


class TestTransferTicketEndpoint(TransferTestBase):

    def hdrs(self):
        h = dict(self.headers)
        h['X-Worker-Id'] = 'tid'
        h['X-Xsrftoken'] = 'yummy'
        h['Content-Type'] = 'application/json'
        return h

    def mint(self, path='/home/ryan/a.txt', headers=None):
        return self.fetch('/transfer/ticket', method='POST',
                          body=json.dumps({'path': path}),
                          headers=headers if headers is not None
                          else self.hdrs())

    def test_minting_returns_a_ticket_and_its_lifetime(self):
        response = self.mint()
        self.assertEqual(response.code, 200)
        data = json.loads(to_str(response.body))
        self.assertTrue(data['ticket'])
        self.assertEqual(data['expires_in'], worker.TICKET_TTL)

    def test_the_response_does_not_echo_the_worker_token(self):
        # A ticket that carried the token would defeat its own purpose.
        body = to_str(self.mint().body)
        self.assertNotIn('tid', body)

    def test_minting_requires_the_xsrf_header(self):
        h = dict(self.headers)
        h['X-Worker-Id'] = 'tid'
        h['Content-Type'] = 'application/json'
        self.assertEqual(self.mint(headers=h).code, 403)

    def test_minting_for_an_unknown_worker_is_404(self):
        h = self.hdrs()
        h['X-Worker-Id'] = 'nope'
        self.assertEqual(self.mint(headers=h).code, 404)

    def test_minting_without_a_path_is_400(self):
        response = self.fetch('/transfer/ticket', method='POST',
                              body=json.dumps({}), headers=self.hdrs())
        self.assertEqual(response.code, 400)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k "TransferTokenHeader or TransferTicketEndpoint"`
Expected: FAIL — the header tests 404 because the token is still read from the query string, and `/transfer/ticket` is not routed.

- [ ] **Step 3: Read the token from a header**

In `webssh/handler.py`, replace the first three lines of `TransferMixin.get_live_worker` (currently `worker_id = self.get_argument('id', '')` and its guard) so the method begins:

```python
    WORKER_ID_HEADER = 'X-Worker-Id'

    def get_live_worker(self):
        # A header, never a query parameter: the token authorises the whole
        # session, and a URL copy would persist in browser history and in
        # access logs.
        worker_id = self.request.headers.get(self.WORKER_ID_HEADER, '')
        if not worker_id:
            raise tornado.web.HTTPError(404)
```

Leave the rest of the method — the `live_workers` lookup, the client-IP check, and the `closed` check — exactly as it is. Put `WORKER_ID_HEADER` with the other class attributes on `TransferMixin`, not inside the method.

- [ ] **Step 4: Add the ticket handler**

In `webssh/handler.py`, immediately after `TransferListHandler`, add:

```python
class TransferTicketHandler(TransferMixin, tornado.web.RequestHandler):
    """Mints the short-lived credential the download navigation redeems.

    A browser navigation cannot carry the X-Worker-Id header, so the
    download URL needs something it can hold in the clear. A ticket is
    that: one path, one address, one use, sixty seconds.
    """

    def post(self):
        live = self.get_live_worker()

        try:
            payload = json.loads(to_str(self.request.body or b'{}'))
        except ValueError:
            raise tornado.web.HTTPError(400, 'Invalid JSON')
        if not isinstance(payload, dict):
            raise tornado.web.HTTPError(400, 'Invalid JSON')

        path = payload.get('path') or ''
        if not path:
            raise tornado.web.HTTPError(400, 'Missing path')

        try:
            ticket = worker_module.mint_ticket(
                live.id, path, self.get_client_addr()[0], time.time())
        except worker_module.TicketStoreFull:
            logging.warning('Download ticket store full; refusing to mint')
            raise tornado.web.HTTPError(503, 'Too many pending downloads.')

        self.write({'ticket': ticket,
                    'expires_in': worker_module.TICKET_TTL})
```

Add `import time` to the imports, and import the worker module under an alias so it does not collide with the many local variables named `worker` in this file:

```python
from webssh import worker as worker_module
```

- [ ] **Step 5: Register the route**

In `webssh/main.py`, add alongside the other transfer routes:

```python
        (r'/transfer/ticket', TransferTicketHandler, transfer_kwargs),
```

and add `TransferTicketHandler` to the `from webssh.handler import (...)` block.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k "TransferTokenHeader or TransferTicketEndpoint"`
Expected: PASS, 10 tests

Existing transfer tests that still pass `?id=` will now fail. That is the intended breakage: update them to send the `X-Worker-Id` header instead. Do not reintroduce query-string support to keep them green.

- [ ] **Step 7: Verify nothing regressed**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
Expected: PASS. The count rises by the 10 new tests once the existing ones are migrated to the header.

- [ ] **Step 8: Lint and commit**

```bash
/home/ryan/github/rgregg/webssh/.venv/bin/python -m ruff check .
git add webssh/handler.py webssh/main.py tests/test_app.py
git commit -m "feat: carry the worker token in a header and mint download tickets"
```

---

### Task 3: Download redeems a ticket

**Files:**
- Modify: `webssh/handler.py` (`TransferDownloadHandler.get`)
- Test: `tests/test_app.py`

**Interfaces:**
- Consumes: `worker_module.consume_ticket`, `live_workers`.
- Produces: a download endpoint whose only credential is `?ticket=`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_app.py`:

```python
class TestTransferDownloadTicket(TransferTestBase):

    def mint(self, path='/home/ryan/a.txt'):
        h = dict(self.headers)
        h['X-Worker-Id'] = 'tid'
        h['X-Xsrftoken'] = 'yummy'
        h['Content-Type'] = 'application/json'
        response = self.fetch('/transfer/ticket', method='POST',
                              body=json.dumps({'path': path}), headers=h)
        return json.loads(to_str(response.body))['ticket']

    def test_a_ticket_downloads_the_file(self):
        response = self.fetch(
            '/transfer/download?ticket=' + self.mint(), headers=self.headers)
        self.assertEqual(response.code, 200)
        self.assertEqual(response.body, b'hello')

    def test_the_worker_token_no_longer_works_for_download(self):
        response = self.fetch(
            '/transfer/download?id=tid&path=/home/ryan/a.txt',
            headers=self.headers)
        self.assertEqual(response.code, 404)

    def test_a_ticket_cannot_be_replayed(self):
        ticket = self.mint()
        self.assertEqual(
            self.fetch('/transfer/download?ticket=' + ticket,
                       headers=self.headers).code, 200)
        self.assertEqual(
            self.fetch('/transfer/download?ticket=' + ticket,
                       headers=self.headers).code, 404)

    def test_an_unknown_ticket_is_404(self):
        response = self.fetch('/transfer/download?ticket=nonsense',
                              headers=self.headers)
        self.assertEqual(response.code, 404)

    def test_a_missing_ticket_is_404(self):
        self.assertEqual(
            self.fetch('/transfer/download', headers=self.headers).code, 404)

    def test_the_path_comes_from_the_ticket_not_the_query(self):
        # Otherwise a ticket for one file would authorise any file.
        ticket = self.mint('/home/ryan/a.txt')
        response = self.fetch(
            '/transfer/download?ticket=' + ticket + '&path=/etc/shadow',
            headers=self.headers)
        self.assertEqual(response.code, 200)
        self.assertEqual(response.body, b'hello')

    def test_a_ticket_is_useless_once_the_session_ends(self):
        # The ticket itself is still valid, so this is the one redemption
        # failure that reports 410 rather than 404.
        ticket = self.mint()
        self.worker.closed = True
        response = self.fetch('/transfer/download?ticket=' + ticket,
                              headers=self.headers)
        self.assertEqual(response.code, 410)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k TransferDownloadTicket`
Expected: FAIL — the download handler still expects `id` and `path`.

- [ ] **Step 3: Redeem the ticket**

In `TransferDownloadHandler.get`, replace the first two lines:

```python
        worker = self.get_live_worker()
        path = self.get_path()
```

with:

```python
        # A browser navigation cannot carry the X-Worker-Id header, so this
        # route authenticates with a single-use ticket instead. Both the
        # worker and the path come from the ticket: a ticket for one file
        # must not authorise another.
        claim = worker_module.consume_ticket(
            self.get_argument('ticket', ''),
            self.get_client_addr()[0], time.time())
        if claim is None:
            raise tornado.web.HTTPError(404)

        worker = live_workers.get(claim['worker_id'])
        if worker is None:
            raise tornado.web.HTTPError(404)
        if worker.closed:
            raise tornado.web.HTTPError(410, 'The terminal session ended.')

        path = claim['path']
```

The rest of the method — the concurrency cap, `content_disposition`, the streaming loop, and the `finally` — is unchanged.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k TransferDownloadTicket`
Expected: PASS, 7 tests

Existing download tests that pass `?id=&path=` will now fail. Migrate them to mint a ticket first.

- [ ] **Step 5: Verify nothing regressed**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
Expected: PASS

- [ ] **Step 6: Lint and commit**

```bash
/home/ryan/github/rgregg/webssh/.venv/bin/python -m ruff check .
git add webssh/handler.py tests/test_app.py
git commit -m "feat: authenticate downloads with a single-use ticket"
```

---

### Task 4: Client

**Files:**
- Modify: `webssh/static/js/file-transfer.js`
- Modify: `tests/js/file-transfer.test.js`
- Modify: `webssh/static/js/transfer-ui.js`

**Interfaces:**
- Consumes: the endpoints from Tasks 2 and 3.
- Produces: `upload_url(path, filename, overwrite)`, `download_url(ticket)`, both without a worker id. `webssh_transfer_ui` keeps its existing exports.

- [ ] **Step 1: Write the failing JS tests**

In `tests/js/file-transfer.test.js`, replace the three existing tests named `upload_url encodes every component`, `upload_url sets overwrite only when asked`, and `download_url encodes the path` with:

```javascript
test('upload_url no longer carries the worker token', function () {
  // The token authorises the whole session; a URL copy would persist in
  // access logs. It travels in the X-Worker-Id header instead.
  var url = ft.upload_url('/tmp/a b', 'a b.txt', false);
  assert.strictEqual(url.indexOf('id='), -1);
  assert.ok(url.indexOf('path=%2Ftmp%2Fa%20b') !== -1);
  assert.ok(url.indexOf('filename=a%20b.txt') !== -1);
  assert.strictEqual(url.indexOf('overwrite=true'), -1);
});

test('upload_url sets overwrite only when asked', function () {
  assert.ok(ft.upload_url('/t', 'f', true).indexOf('overwrite=true') !== -1);
});

test('download_url carries only the ticket', function () {
  var url = ft.download_url('tick et/+value');
  assert.ok(url.indexOf('/transfer/download?') === 0);
  assert.ok(url.indexOf('ticket=tick%20et%2F%2Bvalue') !== -1);
  assert.strictEqual(url.indexOf('id='), -1);
  assert.strictEqual(url.indexOf('path='), -1);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test tests/js/file-transfer.test.js`
Expected: FAIL — the builders still take an id and still put it in the URL.

- [ ] **Step 3: Update the builders**

In `webssh/static/js/file-transfer.js`, replace `upload_url` and `download_url` with:

```javascript
  // Neither builder takes a worker id: the token travels in the
  // X-Worker-Id header for upload, and the download is authorised by a
  // single-use ticket instead.
  function upload_url(path, filename, overwrite) {
    var url = '/transfer/upload?path=' + encodeURIComponent(path) +
      '&filename=' + encodeURIComponent(filename);
    if (overwrite) {
      url = url + '&overwrite=true';
    }
    return url;
  }

  function download_url(ticket) {
    return '/transfer/download?ticket=' + encodeURIComponent(ticket);
  }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test tests/js/*.test.js`
Expected: PASS, 67 tests

- [ ] **Step 5: Send the header from the UI**

In `webssh/static/js/transfer-ui.js`, make three changes.

The upload `fetch` (around line 116) becomes:

```javascript
    fetch(webssh_transfer.upload_url(path, file.name, overwrite), {
      method: 'POST',
      body: file,
      headers: {'X-Xsrftoken': xsrf(), 'X-Worker-Id': worker_id},
      signal: controller.signal
    }).then(function (response) {
```

The listing call (around line 227) becomes:

```javascript
      $.ajax({
        url: '/transfer/list',
        dataType: 'json',
        data: {path: dir, filter: filter || ''},
        headers: {'X-Worker-Id': worker_id}
      })
```

`$.getJSON` cannot set headers, so this switches to `$.ajax`; it returns the same promise interface, so the existing `.done(...)` and `.fail(...)` chain is unchanged.

The Download button handler (around line 300) becomes:

```javascript
    dialog.find('.picker-download').off('click').on('click', function () {
      var path = input.val();
      if (state.timer) {
        clearTimeout(state.timer);
        state.timer = null;
      }
      if (!path) {
        dialog.removeClass('visible');
        return;
      }
      // Mint a single-use ticket, then navigate to it. The worker token
      // stays out of the URL, so the browser's download history records a
      // credential that is already spent.
      $.ajax({
        url: '/transfer/ticket',
        type: 'POST',
        contentType: 'application/json',
        dataType: 'json',
        data: JSON.stringify({path: path}),
        headers: {'X-Worker-Id': worker_id, 'X-Xsrftoken': xsrf()}
      }).done(function (data) {
        window.location = webssh_transfer.download_url(data.ticket);
        dialog.removeClass('visible');
      }).fail(function (xhr) {
        // Report rather than failing silently: a dead button with no
        // explanation is worse than an error.
        list.find('.picker-note.is-error').remove();
        list.append(note('Could not start download (' + xhr.status + ')')
          .addClass('is-error'));
      });
    });
```

Note this handler now closes the dialog only on success, so a failed mint leaves the picker open with its error visible.

- [ ] **Step 6: Verify**

```bash
node --test tests/js/*.test.js
node scripts/check_es5.js
/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q
grep -n "id=" webssh/static/js/file-transfer.js
```
Expected: JS and Python suites pass, ES5 clean, and the grep shows no `id=` in any transfer URL.

- [ ] **Step 7: Commit**

```bash
git add webssh/static/js/file-transfer.js webssh/static/js/transfer-ui.js \
        tests/js/file-transfer.test.js
git commit -m "feat: send the worker token as a header and download by ticket"
```

---

### Task 5: Documentation

**Files:**
- Modify: `docs/superpowers/specs/2026-08-10-file-transfer-design.md`
- Modify: `README.md`

- [ ] **Step 1: Correct the original design doc**

In `docs/superpowers/specs/2026-08-10-file-transfer-design.md`, replace the handler table rows with:

```
| `/transfer/ticket` | POST | Mint a single-use download ticket |
| `/transfer/list` | GET | List one directory, for the download picker |
| `/transfer/download` | GET | Stream a remote file, authorised by a ticket |
| `/transfer/upload` | POST | Stream a request body to a remote file |
```

and add immediately below that table:

```
`list` and `upload` carry the worker token in an `X-Worker-Id` header.
`download` is a browser navigation and cannot send headers, so it redeems a
single-use ticket minted by `POST /transfer/ticket`. The token never appears
in a URL; see `2026-08-18-transfer-token-exposure-design.md` for why.
```

- [ ] **Step 2: Note the behaviour in the README**

In the "File transfer" section of `README.md`, after the paragraph about the download picker, add:

```markdown
Downloads are authorised by a single-use ticket that expires after a minute
and is tied to your address, so the link in your browser's download history
cannot be reused.
```

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-08-10-file-transfer-design.md README.md
git commit -m "docs: describe header auth and download tickets"
```

---

## Verification Checklist

- [ ] `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q` passes
- [ ] `node --test tests/js/*.test.js` passes with 67 tests
- [ ] `node scripts/check_es5.js` clean
- [ ] `ruff check .` clean
- [ ] No `?id=` appears in any transfer URL, in JS or in tests
- [ ] A request with the token in the query string is rejected on all three routes
- [ ] A ticket cannot be replayed, used past its TTL, or used from another address
- [ ] The download path comes from the ticket, not the query string
- [ ] `Worker.close()` drops that worker's tickets
