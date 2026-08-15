# File Transfer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user drag a file onto a WebSSH terminal to upload it to the connected host, and download a file back, over the SSH connection the terminal already authenticated.

**Architecture:** SSH multiplexes channels, so `worker.ssh.open_sftp()` gives a file-transfer channel on the existing authenticated connection — no second login. A new `webssh/transfer.py` holds all SFTP mechanics with no web knowledge. Three Tornado handlers stream bytes to and from it. A new `live_workers` registry makes an attached worker reachable by ID, which it currently is not.

**Tech Stack:** Python 3.10+, Tornado, paramiko; browser JavaScript in ES5, tested with `node --test` and no npm packages.

**Spec:** `docs/superpowers/specs/2026-08-10-file-transfer-design.md`

## Global Constraints

- Python style matches the surrounding modules: **no f-strings** (use `.format()`), `super(ClassName, self)` form, compact parenthesised import blocks.
- JavaScript is **ES5 only**: no `const`, `let`, arrow functions, or template literals. CI lints this.
- **No new dependencies**, Python or npm. `package.json` must keep no `dependencies` and no `devDependencies`.
- CI pins `ruff==0.15.6`. Do not modernise unrelated code; run `ruff check .` before every commit.
- Transfer chunk size is **256 KB**, deliberately not `worker.BUF_SIZE` (32 KB, tuned for terminal latency).
- Directory listings cap at **1000 entries**.
- Remote SFTP errors are surfaced to the client **verbatim**. This is the opposite of the `handler.py:145` rule for server-state errors, and is deliberate — see the spec. Do not "harden" them into generic 500s.
- Paths are **never** sanitized or jailed. The SSH user's own permissions are the boundary.
- New test classes that mutate `tornado.options` must use `override_options` from `tests/test_app.py`, never hand-rolled restoration.
- Run the full suite with `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q` and the JS suite with `node --test tests/js/*.test.js`.

**Baseline:** 239 Python tests pass on `main` at `2999509`. Work happens on branch `feature/file-transfer`.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `webssh/transfer.py` (new) | All SFTP mechanics. No Tornado, no HTTP. |
| `tests/test_transfer.py` (new) | Unit tests for the above against a stub SFTP client. |
| `webssh/worker.py` (modify) | `live_workers` registry; per-worker transfer counter. |
| `webssh/handler.py` (modify) | Three transfer handlers plus a shared resolution mixin. |
| `webssh/main.py` (modify) | Three new routes. |
| `webssh/static/js/file-transfer.js` (new) | Pure client logic: OSC 7 parsing, path resolution, byte formatting. |
| `tests/js/file-transfer.test.js` (new) | `node --test` coverage for the above. |
| `webssh/static/js/transfer-ui.js` (new) | Drop zone, progress tray, picker dialog. Kept out of `main.js`, already 2007 lines. |
| `webssh/templates/index.html` (modify) | Script tags, drop overlay, progress tray markup. |
| `webssh/static/css/main.css` (modify) | Styles for overlay, tray, picker. |
| `webssh/settings.py` (modify) | `shell_integration` option. |
| `README.md` (modify) | Document the feature and the option. |

---

### Task 1: SFTP error mapping and the `Download` reader

**Files:**
- Create: `webssh/transfer.py`
- Test: `tests/test_transfer.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `CHUNK_SIZE`, `MAX_LIST_ENTRIES`, `TransferError(status, message)`, `error_from_oserror(exc, path)`, `Download(sftp, path)` with `.open() -> int`, `.read() -> bytes`, `.close()`, `.cancel()`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_transfer.py`:

```python
import errno
import stat
import unittest

from webssh import transfer


class FakeAttr(object):

    def __init__(self, filename, size=0, isdir=False, mtime=0):
        self.filename = filename
        self.st_size = size
        self.st_mtime = mtime
        self.st_mode = (stat.S_IFDIR | 0o755) if isdir else (stat.S_IFREG | 0o644)


class FakeFile(object):

    def __init__(self, data=b'', parent=None, path=None):
        self.data = data
        self.pos = 0
        self.closed = False
        self.prefetched = False
        self.parent = parent
        self.path = path

    def prefetch(self):
        self.prefetched = True

    def read(self, size):
        chunk = self.data[self.pos:self.pos + size]
        self.pos += len(chunk)
        return chunk

    def write(self, data):
        self.data += data

    def close(self):
        self.closed = True


class FakeSFTP(object):
    """Stands in for paramiko's SFTPClient. Only the calls transfer.py makes."""

    def __init__(self, files=None, dirs=None):
        self.files = dict(files or {})
        self.dirs = dict(dirs or {})
        self.removed = []
        self.closed = False

    def stat(self, path):
        if path in self.dirs:
            return FakeAttr(path, isdir=True)
        if path in self.files:
            return FakeAttr(path, size=len(self.files[path]))
        raise IOError(errno.ENOENT, 'No such file')

    def open(self, path, mode='r', bufsize=-1):
        if 'r' in mode:
            if path not in self.files:
                raise IOError(errno.ENOENT, 'No such file')
            return FakeFile(self.files[path], self, path)
        handle = FakeFile(b'', self, path)
        self.files[path] = b''
        return handle

    def listdir_attr(self, path):
        if path not in self.dirs:
            raise IOError(errno.ENOENT, 'No such file')
        return list(self.dirs[path])

    def remove(self, path):
        self.removed.append(path)
        self.files.pop(path, None)

    def close(self):
        self.closed = True


class TestErrorMapping(unittest.TestCase):

    def test_permission_denied_maps_to_403_and_keeps_the_message(self):
        exc = IOError(errno.EACCES, 'Permission denied')
        err = transfer.error_from_oserror(exc, '/etc/shadow')
        self.assertEqual(err.status, 403)
        self.assertIn('Permission denied', err.message)

    def test_missing_file_maps_to_404(self):
        exc = IOError(errno.ENOENT, 'No such file')
        self.assertEqual(transfer.error_from_oserror(exc, '/nope').status, 404)

    def test_no_space_maps_to_507(self):
        exc = IOError(errno.ENOSPC, 'No space left on device')
        err = transfer.error_from_oserror(exc, '/tmp/big')
        self.assertEqual(err.status, 507)
        self.assertIn('No space left', err.message)

    def test_unknown_errno_maps_to_400_rather_than_500(self):
        # A remote filesystem error is the user's own business; it should
        # never be reported as a WebSSH server fault.
        exc = IOError(errno.EIO, 'Input/output error')
        self.assertEqual(transfer.error_from_oserror(exc, '/x').status, 400)


class TestDownload(unittest.TestCase):

    def test_reads_the_whole_file_in_chunks(self):
        payload = b'x' * (transfer.CHUNK_SIZE + 17)
        sftp = FakeSFTP(files={'/tmp/a': payload})
        dl = transfer.Download(sftp, '/tmp/a')

        self.assertEqual(dl.open(), len(payload))
        chunks = []
        while True:
            chunk = dl.read()
            if not chunk:
                break
            chunks.append(chunk)
        dl.close()

        self.assertEqual(b''.join(chunks), payload)
        self.assertEqual(len(chunks[0]), transfer.CHUNK_SIZE)

    def test_calls_prefetch_because_it_dominates_throughput(self):
        sftp = FakeSFTP(files={'/tmp/a': b'abc'})
        dl = transfer.Download(sftp, '/tmp/a')
        dl.open()
        self.assertTrue(dl.handle.prefetched)

    def test_opening_a_directory_is_a_400_not_a_stream_of_junk(self):
        sftp = FakeSFTP(dirs={'/tmp': []})
        dl = transfer.Download(sftp, '/tmp')
        with self.assertRaises(transfer.TransferError) as caught:
            dl.open()
        self.assertEqual(caught.exception.status, 400)

    def test_missing_file_raises_404(self):
        dl = transfer.Download(FakeSFTP(), '/tmp/missing')
        with self.assertRaises(transfer.TransferError) as caught:
            dl.open()
        self.assertEqual(caught.exception.status, 404)

    def test_cancel_stops_further_reads(self):
        sftp = FakeSFTP(files={'/tmp/a': b'y' * (transfer.CHUNK_SIZE * 3)})
        dl = transfer.Download(sftp, '/tmp/a')
        dl.open()
        self.assertTrue(dl.read())
        dl.cancel()
        self.assertEqual(dl.read(), b'')
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_transfer.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'webssh.transfer'`

- [ ] **Step 3: Create the module**

Create `webssh/transfer.py`:

```python
import errno
import logging
import posixpath
import stat


CHUNK_SIZE = 256 * 1024
MAX_LIST_ENTRIES = 1000


class TransferError(Exception):
    """A failure that is safe to report to the client verbatim.

    These describe the user's own remote filesystem, reached with their own
    credentials, so the message carries no WebSSH server state. That is why
    it is passed through rather than replaced with a generic 500.
    """

    def __init__(self, status, message):
        super(TransferError, self).__init__(message)
        self.status = status
        self.message = message


ERRNO_STATUS = {
    errno.EACCES: 403,
    errno.EPERM: 403,
    errno.ENOENT: 404,
    errno.EISDIR: 400,
    errno.ENOTDIR: 400,
    errno.ENOSPC: 507,
    errno.EDQUOT: 507,
}


def error_from_oserror(exc, path):
    code = getattr(exc, 'errno', None)
    status = ERRNO_STATUS.get(code, 400)
    message = getattr(exc, 'strerror', None) or str(exc) or 'Transfer failed'
    return TransferError(status, '{}: {}'.format(message, path))


def open_sftp(ssh):
    try:
        return ssh.open_sftp()
    except Exception as exc:
        logging.warning('Could not open SFTP channel: {}'.format(exc))
        raise TransferError(410, 'The terminal session ended.')


def is_dir(attr):
    return stat.S_ISDIR(attr.st_mode)


class Download(object):
    """Sequential reader for one remote file.

    Each method is called from a thread-pool worker, never the IOLoop,
    because paramiko's SFTP calls block.
    """

    def __init__(self, sftp, path):
        self.sftp = sftp
        self.path = path
        self.handle = None
        self.cancelled = False

    def open(self):
        try:
            attr = self.sftp.stat(self.path)
        except (OSError, IOError) as exc:
            raise error_from_oserror(exc, self.path)

        if is_dir(attr):
            raise TransferError(
                400, 'Not a regular file: {}'.format(self.path))

        try:
            self.handle = self.sftp.open(self.path, 'rb')
        except (OSError, IOError) as exc:
            raise error_from_oserror(exc, self.path)

        # Sequential reads are several times faster with prefetch on, and
        # this is the single largest throughput lever available.
        try:
            self.handle.prefetch()
        except Exception:
            pass

        return attr.st_size

    def read(self):
        if self.cancelled or self.handle is None:
            return b''
        try:
            return self.handle.read(CHUNK_SIZE)
        except (OSError, IOError) as exc:
            raise error_from_oserror(exc, self.path)

    def cancel(self):
        self.cancelled = True

    def close(self):
        if self.handle is not None:
            try:
                self.handle.close()
            except Exception:
                pass
            self.handle = None
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_transfer.py -q`
Expected: PASS, 9 tests

- [ ] **Step 5: Lint and commit**

```bash
/home/ryan/github/rgregg/webssh/.venv/bin/python -m ruff check .
git add webssh/transfer.py tests/test_transfer.py
git commit -m "feat: add SFTP download reader and error mapping"
```

---

### Task 2: The `Upload` writer

**Files:**
- Modify: `webssh/transfer.py`
- Test: `tests/test_transfer.py`

**Interfaces:**
- Consumes: `TransferError`, `error_from_oserror`, `is_dir` from Task 1.
- Produces: `Upload(sftp, path, filename, overwrite=False)` with `.open() -> str` (returns the final resolved path), `.write(data)`, `.close()`, `.abort()`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_transfer.py`:

```python
class TestUpload(unittest.TestCase):

    def test_writes_the_payload_to_the_named_path(self):
        sftp = FakeSFTP()
        up = transfer.Upload(sftp, '/home/ryan/out.txt', 'out.txt')
        self.assertEqual(up.open(), '/home/ryan/out.txt')
        up.write(b'hello ')
        up.write(b'world')
        up.close()
        self.assertEqual(sftp.files['/home/ryan/out.txt'], b'hello world')

    def test_directory_destination_gets_the_source_filename_appended(self):
        sftp = FakeSFTP(dirs={'/home/ryan': []})
        up = transfer.Upload(sftp, '/home/ryan', 'report.pdf')
        self.assertEqual(up.open(), '/home/ryan/report.pdf')

    def test_existing_destination_raises_409_before_any_write(self):
        # The whole point is to refuse before truncating the remote file.
        sftp = FakeSFTP(files={'/home/ryan/out.txt': b'original'})
        up = transfer.Upload(sftp, '/home/ryan/out.txt', 'out.txt')
        with self.assertRaises(transfer.TransferError) as caught:
            up.open()
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(sftp.files['/home/ryan/out.txt'], b'original')

    def test_overwrite_true_replaces_the_file(self):
        sftp = FakeSFTP(files={'/home/ryan/out.txt': b'original'})
        up = transfer.Upload(sftp, '/home/ryan/out.txt', 'out.txt',
                             overwrite=True)
        up.open()
        up.write(b'new')
        up.close()
        self.assertEqual(sftp.files['/home/ryan/out.txt'], b'new')

    def test_abort_removes_the_partial_file(self):
        # A truncated file under the real name is worse than no file.
        sftp = FakeSFTP()
        up = transfer.Upload(sftp, '/home/ryan/big.iso', 'big.iso')
        up.open()
        up.write(b'partial')
        up.abort()
        self.assertIn('/home/ryan/big.iso', sftp.removed)

    def test_abort_before_open_removes_nothing(self):
        sftp = FakeSFTP()
        up = transfer.Upload(sftp, '/home/ryan/big.iso', 'big.iso')
        up.abort()
        self.assertEqual(sftp.removed, [])

    def test_permission_denied_on_open_maps_to_403(self):
        class Denying(FakeSFTP):
            def open(self, path, mode='r', bufsize=-1):
                raise IOError(errno.EACCES, 'Permission denied')

        up = transfer.Upload(Denying(), '/root/x', 'x')
        with self.assertRaises(transfer.TransferError) as caught:
            up.open()
        self.assertEqual(caught.exception.status, 403)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_transfer.py -q -k Upload`
Expected: FAIL — `AttributeError: module 'webssh.transfer' has no attribute 'Upload'`

- [ ] **Step 3: Implement it**

Append to `webssh/transfer.py`:

```python
class Upload(object):
    """Sequential writer for one remote file.

    ``open`` resolves the destination and refuses an existing file unless
    ``overwrite`` was set, so the caller can turn that into a 409 and ask
    the user before anything is truncated.
    """

    def __init__(self, sftp, path, filename, overwrite=False):
        self.sftp = sftp
        self.path = path
        self.filename = filename
        self.overwrite = overwrite
        self.handle = None
        self.final_path = None
        self.bytes_written = 0

    def _resolve(self):
        try:
            attr = self.sftp.stat(self.path)
        except (OSError, IOError) as exc:
            if getattr(exc, 'errno', None) == errno.ENOENT:
                return self.path, False
            raise error_from_oserror(exc, self.path)

        if is_dir(attr):
            return posixpath.join(self.path, self.filename), None
        return self.path, True

    def open(self):
        target, exists = self._resolve()

        if exists is None:
            # Destination was a directory; re-stat the joined path.
            try:
                self.sftp.stat(target)
                exists = True
            except (OSError, IOError) as exc:
                if getattr(exc, 'errno', None) != errno.ENOENT:
                    raise error_from_oserror(exc, target)
                exists = False

        if exists and not self.overwrite:
            raise TransferError(409, 'File exists: {}'.format(target))

        try:
            self.handle = self.sftp.open(target, 'wb')
        except (OSError, IOError) as exc:
            raise error_from_oserror(exc, target)

        self.final_path = target
        return target

    def write(self, data):
        if self.handle is None:
            raise TransferError(400, 'Upload was not opened')
        try:
            self.handle.write(data)
        except (OSError, IOError) as exc:
            raise error_from_oserror(exc, self.final_path)
        self.bytes_written += len(data)

    def close(self):
        if self.handle is not None:
            try:
                self.handle.close()
            except Exception:
                pass
            self.handle = None

    def abort(self):
        """Close and delete the partial file. Never raises."""
        self.close()
        if self.final_path is None:
            return
        try:
            self.sftp.remove(self.final_path)
        except Exception as exc:
            logging.warning('Could not remove partial upload {}: {}'.format(
                self.final_path, exc))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_transfer.py -q`
Expected: PASS, 16 tests

- [ ] **Step 5: Lint and commit**

```bash
/home/ryan/github/rgregg/webssh/.venv/bin/python -m ruff check .
git add webssh/transfer.py tests/test_transfer.py
git commit -m "feat: add SFTP upload writer with overwrite refusal"
```

---

### Task 3: Directory listing

**Files:**
- Modify: `webssh/transfer.py`
- Test: `tests/test_transfer.py`

**Interfaces:**
- Consumes: `MAX_LIST_ENTRIES`, `TransferError`, `error_from_oserror`, `is_dir`.
- Produces: `list_directory(sftp, path) -> {'path': str, 'entries': [{'name', 'size', 'is_dir', 'mtime'}], 'truncated': bool}`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_transfer.py`:

```python
class TestListDirectory(unittest.TestCase):

    def test_lists_files_and_directories_with_metadata(self):
        sftp = FakeSFTP(dirs={'/var/log': [
            FakeAttr('syslog', size=2100, mtime=111),
            FakeAttr('nginx', isdir=True, mtime=222),
        ]})
        result = transfer.list_directory(sftp, '/var/log')

        self.assertEqual(result['path'], '/var/log')
        self.assertFalse(result['truncated'])
        by_name = dict((e['name'], e) for e in result['entries'])
        self.assertEqual(by_name['syslog']['size'], 2100)
        self.assertFalse(by_name['syslog']['is_dir'])
        self.assertTrue(by_name['nginx']['is_dir'])
        self.assertEqual(by_name['nginx']['mtime'], 222)

    def test_sorts_directories_first_then_by_name(self):
        sftp = FakeSFTP(dirs={'/d': [
            FakeAttr('b.txt'),
            FakeAttr('a.txt'),
            FakeAttr('zdir', isdir=True),
        ]})
        names = [e['name'] for e in transfer.list_directory(sftp, '/d')['entries']]
        self.assertEqual(names, ['zdir', 'a.txt', 'b.txt'])

    def test_caps_long_listings_and_reports_truncation(self):
        # /usr/bin must not produce a multi-megabyte JSON response.
        entries = [FakeAttr('f{}'.format(i)) for i in range(transfer.MAX_LIST_ENTRIES + 50)]
        sftp = FakeSFTP(dirs={'/usr/bin': entries})
        result = transfer.list_directory(sftp, '/usr/bin')
        self.assertEqual(len(result['entries']), transfer.MAX_LIST_ENTRIES)
        self.assertTrue(result['truncated'])

    def test_missing_directory_raises_404(self):
        with self.assertRaises(transfer.TransferError) as caught:
            transfer.list_directory(FakeSFTP(), '/nope')
        self.assertEqual(caught.exception.status, 404)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_transfer.py -q -k ListDirectory`
Expected: FAIL — `AttributeError: module 'webssh.transfer' has no attribute 'list_directory'`

- [ ] **Step 3: Implement it**

Append to `webssh/transfer.py`:

```python
def list_directory(sftp, path):
    try:
        attrs = sftp.listdir_attr(path)
    except (OSError, IOError) as exc:
        raise error_from_oserror(exc, path)

    entries = []
    for attr in attrs:
        entries.append({
            'name': attr.filename,
            'size': getattr(attr, 'st_size', 0) or 0,
            'is_dir': is_dir(attr),
            'mtime': getattr(attr, 'st_mtime', 0) or 0,
        })

    entries.sort(key=lambda e: (not e['is_dir'], e['name']))

    truncated = len(entries) > MAX_LIST_ENTRIES
    return {
        'path': path,
        'entries': entries[:MAX_LIST_ENTRIES],
        'truncated': truncated,
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_transfer.py -q`
Expected: PASS, 20 tests

- [ ] **Step 5: Lint and commit**

```bash
/home/ryan/github/rgregg/webssh/.venv/bin/python -m ruff check .
git add webssh/transfer.py tests/test_transfer.py
git commit -m "feat: add SFTP directory listing with entry cap"
```

---

### Task 4: The live-worker registry

**Files:**
- Modify: `webssh/worker.py:15` (module globals), `webssh/worker.py:38-48` (`Worker.__init__`), `webssh/worker.py:118-134` (`Worker.close`)
- Modify: `webssh/handler.py:934-941` (`WsockHandler.open`)
- Test: `tests/test_app.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `worker.live_workers` (dict of `{worker_id: Worker}`), `Worker.transfers` (int counter), `register_live_worker(worker)`, `unregister_live_worker(worker)`.

**Why a second structure:** `handler.py:936` sets `workers[worker_id] = None` after the WebSocket claims a worker, which is what makes a worker ID single-use for WebSocket authentication. Reusing `clients` for transfer lookup would mean not nulling it, letting a leaked ID open a second terminal on the same session. `live_workers` is therefore separate.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_app.py`, after the `TestUserHostKeyIsolation` class:

```python
class TestLiveWorkerRegistry(unittest.TestCase):

    def make_worker(self, worker_id='wid'):
        class FakeChan(object):
            def fileno(self):
                return 0

            def close(self):
                pass

        class FakeSSH(object):
            def close(self):
                pass

        w = worker.Worker(None, FakeSSH(), FakeChan(), ('1.2.3.4', 22))
        w.id = worker_id
        w.src_addr = ('9.9.9.9', 1234)
        return w

    def tearDown(self):
        worker.live_workers.clear()
        worker.clients.clear()

    def test_registering_makes_a_worker_reachable_by_id(self):
        w = self.make_worker()
        worker.register_live_worker(w)
        self.assertIs(worker.live_workers.get('wid'), w)

    def test_unregistering_removes_it(self):
        w = self.make_worker()
        worker.register_live_worker(w)
        worker.unregister_live_worker(w)
        self.assertIsNone(worker.live_workers.get('wid'))

    def test_unregistering_an_absent_worker_is_harmless(self):
        # close() may run without the websocket ever having attached.
        worker.unregister_live_worker(self.make_worker())

    def test_a_new_worker_starts_with_no_transfers(self):
        self.assertEqual(self.make_worker().transfers, 0)

    def test_close_unregisters_so_a_dead_id_cannot_be_reached(self):
        w = self.make_worker()
        worker.clients['9.9.9.9'] = {'wid': None}
        worker.register_live_worker(w)
        w.close(reason='test')
        self.assertIsNone(worker.live_workers.get('wid'))
```

Add `from webssh import worker` to the imports at the top of `tests/test_app.py` if not already present.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k LiveWorkerRegistry`
Expected: FAIL — `AttributeError: module 'webssh.worker' has no attribute 'live_workers'`

- [ ] **Step 3: Implement the registry**

In `webssh/worker.py`, change line 15 from:

```python
clients = {}  # {ip: {id: worker}}
```

to:

```python
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
```

In `Worker.__init__`, after `self.closed = False`, add:

```python
        # Number of transfers in flight. A nonzero count suppresses the
        # idle disconnect, which otherwise only resets on websocket traffic.
        self.transfers = 0
```

In `Worker.close`, immediately after `self.closed = True`, add:

```python
        unregister_live_worker(self)
```

- [ ] **Step 4: Wire the websocket handler**

In `webssh/handler.py`, inside `WsockHandler.open`, change the success branch (currently lines 935-941) from:

```python
            if worker:
                workers[worker_id] = None
                self.set_nodelay(True)
                worker.set_handler(self)
                self.worker_ref = weakref.ref(worker)
                self.loop.add_handler(worker.fd, worker, IOLoop.READ)
                self._reset_idle_timeout()
```

to:

```python
            if worker:
                workers[worker_id] = None
                register_live_worker(worker)
                self.set_nodelay(True)
                worker.set_handler(self)
                self.worker_ref = weakref.ref(worker)
                self.loop.add_handler(worker.fd, worker, IOLoop.READ)
                self._reset_idle_timeout()
```

Update the worker import near the top of `handler.py` to include the new names:

```python
from webssh.worker import Worker, recycle_worker, clients, live_workers, register_live_worker  # noqa
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k LiveWorkerRegistry`
Expected: PASS, 5 tests

- [ ] **Step 6: Verify nothing regressed**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
Expected: PASS, 264 tests (239 baseline + 20 transfer + 5 registry)

- [ ] **Step 7: Lint and commit**

```bash
/home/ryan/github/rgregg/webssh/.venv/bin/python -m ruff check .
git add webssh/worker.py webssh/handler.py tests/test_app.py
git commit -m "feat: track live workers so transfers can find a session"
```

---

### Task 5: Transfer handler base and `/transfer/list`

**Files:**
- Modify: `webssh/handler.py` (new classes at the end, before `WsockHandler`)
- Modify: `webssh/main.py` (route table)
- Test: `tests/test_app.py`

**Interfaces:**
- Consumes: `live_workers`, `Worker.transfers`, `transfer.list_directory`, `transfer.TransferError`, `transfer.open_sftp`.
- Produces: `TransferMixin.get_live_worker()`, `TransferMixin.MAX_CONCURRENT_TRANSFERS = 3`, `TransferListHandler`.

**Security note:** `get_live_worker` checks the worker ID *and* that the request's client IP matches `worker.src_addr[0]`. A transfer must be no more reachable than the terminal it belongs to. The test for a valid ID from a different IP is the one that pins this.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_app.py`:

```python
class TransferTestBase(TestAppBase):
    """Handler-level transfer tests with SFTP mocked at the open_sftp seam.

    tests/sshserver.py implements no SFTP subsystem, and writing one just to
    test our code would mean trusting a fake server. Patching open_sftp tests
    the code we actually control.
    """

    headers = {'Cookie': '_xsrf=yummy'}

    def get_app(self):
        self.override_options(
            debug=False, xsrf=True, policy='warning', hostfile='',
            syshostfile='', tdstream='', origin='same', maxconn=20,
        )
        return make_app(make_handlers(self.io_loop, options),
                        get_app_settings(options))

    def setUp(self):
        super(TransferTestBase, self).setUp()
        worker.live_workers.clear()
        self.addCleanup(worker.live_workers.clear)
        self.sftp = FakeSFTP(files={'/home/ryan/a.txt': b'hello'},
                             dirs={'/home/ryan': [FakeAttr('a.txt', size=5)]})
        self.worker = self.make_live_worker()

    def make_live_worker(self, worker_id='tid', client_ip='127.0.0.1'):
        test_sftp = self.sftp

        class FakeChan(object):
            def fileno(self):
                return 0

            def close(self):
                pass

        class FakeSSH(object):
            def open_sftp(self):
                return test_sftp

            def close(self):
                pass

        w = worker.Worker(self.io_loop, FakeSSH(), FakeChan(),
                          ('10.0.0.1', 22))
        w.id = worker_id
        w.src_addr = (client_ip, 1234)
        worker.live_workers[worker_id] = w
        return w


class TestTransferList(TransferTestBase):

    def test_lists_the_requested_directory(self):
        response = self.fetch('/transfer/list?id=tid&path=/home/ryan',
                              headers=self.headers)
        self.assertEqual(response.code, 200)
        data = json.loads(to_str(response.body))
        self.assertEqual(data['path'], '/home/ryan')
        self.assertEqual(data['entries'][0]['name'], 'a.txt')
        self.assertFalse(data['truncated'])

    def test_unknown_worker_id_is_404(self):
        response = self.fetch('/transfer/list?id=nope&path=/home/ryan',
                              headers=self.headers)
        self.assertEqual(response.code, 404)

    def test_valid_id_from_a_different_client_ip_is_404(self):
        # The security property the transfer endpoints rest on: a leaked
        # worker id is useless from anywhere but the session's own address.
        self.worker.src_addr = ('203.0.113.7', 1234)
        response = self.fetch('/transfer/list?id=tid&path=/home/ryan',
                              headers=self.headers)
        self.assertEqual(response.code, 404)

    def test_missing_directory_is_404_with_the_remote_message(self):
        response = self.fetch('/transfer/list?id=tid&path=/nope',
                              headers=self.headers)
        self.assertEqual(response.code, 404)

    def test_closed_worker_is_410(self):
        self.worker.closed = True
        response = self.fetch('/transfer/list?id=tid&path=/home/ryan',
                              headers=self.headers)
        self.assertEqual(response.code, 410)
```

Add to the imports at the top of `tests/test_app.py`:

```python
from tests.test_transfer import FakeSFTP, FakeAttr
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k TransferList`
Expected: FAIL — 404 on every route, because `/transfer/list` is not registered

- [ ] **Step 3: Implement the mixin and handler**

Add to `webssh/handler.py`, before `class WsockHandler`:

```python
class TransferMixin(MixinHandler):
    """Shared resolution for the file-transfer endpoints.

    A transfer is reachable exactly where its terminal is: the same 32-byte
    worker token, and the same client-IP check the websocket applies.
    """

    executor = ThreadPoolExecutor(max_workers=cpu_count() * 2)

    MAX_CONCURRENT_TRANSFERS = 3

    def get_live_worker(self):
        worker_id = self.get_argument('id', '')
        if not worker_id:
            raise tornado.web.HTTPError(404)

        worker = live_workers.get(worker_id)
        if worker is None:
            raise tornado.web.HTTPError(404)

        ip = self.get_client_addr()[0]
        if worker.src_addr[0] != ip:
            logging.warning(
                'Transfer request for worker {} from {}, which does not own '
                'it'.format(worker_id, ip))
            raise tornado.web.HTTPError(404)

        if worker.closed:
            raise tornado.web.HTTPError(410, 'The terminal session ended.')

        return worker

    def get_path(self):
        path = self.get_argument('path', '')
        if not path:
            raise tornado.web.HTTPError(400, 'Missing path')
        return path

    def transfer_error(self, exc):
        """Remote filesystem errors describe the user's own machine and are
        reported verbatim. Contrast handler.py's rule for server state."""
        raise tornado.web.HTTPError(exc.status, exc.message)

    def write_error(self, status_code, **kwargs):
        reason = self._reason
        exc_info = kwargs.get('exc_info')
        if exc_info and isinstance(exc_info[1], tornado.web.HTTPError):
            reason = exc_info[1].log_message or reason
        self.set_header('Content-Type', 'application/json')
        self.finish({'status': reason})


class TransferListHandler(TransferMixin, tornado.web.RequestHandler):

    @tornado.gen.coroutine
    def get(self):
        worker = self.get_live_worker()
        path = self.get_path()

        try:
            result = yield self.executor.submit(self._list, worker, path)
        except transfer.TransferError as exc:
            self.transfer_error(exc)

        self.write(result)

    def _list(self, worker, path):
        sftp = transfer.open_sftp(worker.ssh)
        try:
            return transfer.list_directory(sftp, path)
        finally:
            sftp.close()
```

Add near the top of `handler.py`:

```python
from webssh import transfer
```

- [ ] **Step 4: Register the route**

In `webssh/main.py`, inside `make_handlers`, add a `transfer_kwargs` dict after `user_data_kwargs` is built:

```python
    transfer_kwargs = dict(loop=loop)
```

and add these three entries to the returned handler list, immediately before the `/ws` route (the upload and download routes are used by later tasks; register all three now so the table is edited once):

```python
        (r'/transfer/list', TransferListHandler, transfer_kwargs),
        (r'/transfer/download', TransferDownloadHandler, transfer_kwargs),
        (r'/transfer/upload', TransferUploadHandler, transfer_kwargs),
```

Add the three names to the `from webssh.handler import (...)` block.

Because `TransferDownloadHandler` and `TransferUploadHandler` do not exist yet, add these two placeholder classes to `handler.py` directly after `TransferListHandler`; Tasks 6 and 7 replace their bodies:

```python
class TransferDownloadHandler(TransferMixin, tornado.web.RequestHandler):

    def get(self):
        raise tornado.web.HTTPError(501)


class TransferUploadHandler(TransferMixin, tornado.web.RequestHandler):

    def post(self):
        raise tornado.web.HTTPError(501)
```

Add an `initialize` to `TransferMixin` so the `loop` kwarg is accepted:

```python
    def initialize(self, loop):
        super(TransferMixin, self).initialize()
        self.loop = loop
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k TransferList`
Expected: PASS, 5 tests

- [ ] **Step 6: Verify nothing regressed**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
Expected: PASS, 269 tests

- [ ] **Step 7: Lint and commit**

```bash
/home/ryan/github/rgregg/webssh/.venv/bin/python -m ruff check .
git add webssh/handler.py webssh/main.py tests/test_app.py
git commit -m "feat: add transfer endpoint base and directory listing route"
```

---

### Task 6: `/transfer/download`

**Files:**
- Modify: `webssh/handler.py` (`TransferDownloadHandler`)
- Test: `tests/test_app.py`

**Interfaces:**
- Consumes: `TransferMixin`, `transfer.Download`, `transfer.open_sftp`.
- Produces: `TransferDownloadHandler`, `content_disposition(filename) -> str`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_app.py`:

```python
class TestContentDisposition(unittest.TestCase):

    def test_ascii_filename_uses_the_plain_form(self):
        value = handler.content_disposition('report.pdf')
        self.assertIn('filename="report.pdf"', value)

    def test_non_ascii_filename_gets_rfc5987_encoding(self):
        value = handler.content_disposition('отчёт.pdf')
        self.assertIn("filename*=UTF-8''", value)
        # An ASCII fallback must still be present for older clients.
        self.assertIn('filename="', value)

    def test_quotes_are_escaped_not_passed_through(self):
        value = handler.content_disposition('we"ird.txt')
        self.assertNotIn('we"ird', value)

    def test_newline_in_filename_is_rejected(self):
        # Header injection vector: a remote filename is attacker-controlled
        # if the user can be induced to download from a hostile host.
        with self.assertRaises(ValueError):
            handler.content_disposition('evil\r\nSet-Cookie: x=1')


class TestTransferDownload(TransferTestBase):

    def test_streams_the_file_with_an_attachment_header(self):
        response = self.fetch('/transfer/download?id=tid&path=/home/ryan/a.txt',
                              headers=self.headers)
        self.assertEqual(response.code, 200)
        self.assertEqual(response.body, b'hello')
        disposition = response.headers['Content-Disposition']
        self.assertIn('attachment', disposition)
        self.assertIn('a.txt', disposition)

    def test_missing_file_is_404(self):
        response = self.fetch('/transfer/download?id=tid&path=/home/ryan/no.txt',
                              headers=self.headers)
        self.assertEqual(response.code, 404)

    def test_directory_is_400(self):
        response = self.fetch('/transfer/download?id=tid&path=/home/ryan',
                              headers=self.headers)
        self.assertEqual(response.code, 400)

    def test_wrong_client_ip_is_404(self):
        self.worker.src_addr = ('203.0.113.7', 1234)
        response = self.fetch('/transfer/download?id=tid&path=/home/ryan/a.txt',
                              headers=self.headers)
        self.assertEqual(response.code, 404)

    def test_transfer_counter_is_released_after_the_download(self):
        self.fetch('/transfer/download?id=tid&path=/home/ryan/a.txt',
                   headers=self.headers)
        self.assertEqual(self.worker.transfers, 0)

    def test_concurrency_cap_returns_429(self):
        self.worker.transfers = handler.TransferMixin.MAX_CONCURRENT_TRANSFERS
        response = self.fetch('/transfer/download?id=tid&path=/home/ryan/a.txt',
                              headers=self.headers)
        self.assertEqual(response.code, 429)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k "ContentDisposition or TransferDownload"`
Expected: FAIL — `AttributeError: module 'webssh.handler' has no attribute 'content_disposition'`, and 501 from the placeholder

- [ ] **Step 3: Implement it**

Add to `webssh/handler.py`, above `TransferMixin`:

```python
def content_disposition(filename):
    """Build an attachment header that survives a non-ASCII filename.

    Remote filenames are attacker-controlled if a user can be induced to
    download from a hostile host, so CR and LF are rejected outright rather
    than encoded.
    """
    if '\r' in filename or '\n' in filename:
        raise ValueError('Invalid filename')

    fallback = filename.encode('ascii', 'replace').decode('ascii')
    fallback = fallback.replace('\\', '_').replace('"', '_')
    quoted = quote(filename.encode('utf-8'), safe='')
    return "attachment; filename=\"{}\"; filename*=UTF-8''{}".format(
        fallback, quoted)
```

Add `from urllib.parse import quote` to the imports.

Replace the `TransferDownloadHandler` placeholder with:

```python
class TransferDownloadHandler(TransferMixin, tornado.web.RequestHandler):

    _download = None

    @tornado.gen.coroutine
    def get(self):
        worker = self.get_live_worker()
        path = self.get_path()

        if worker.transfers >= self.MAX_CONCURRENT_TRANSFERS:
            raise tornado.web.HTTPError(429, 'Too many transfers in progress.')

        try:
            disposition = content_disposition(posixpath.basename(path))
        except ValueError:
            raise tornado.web.HTTPError(400, 'Invalid filename')

        sftp = None
        worker.transfers += 1
        try:
            sftp = yield self.executor.submit(transfer.open_sftp, worker.ssh)
            self._download = transfer.Download(sftp, path)
            size = yield self.executor.submit(self._download.open)

            self.set_header('Content-Type', 'application/octet-stream')
            self.set_header('Content-Length', str(size))
            self.set_header('Content-Disposition', disposition)

            while True:
                chunk = yield self.executor.submit(self._download.read)
                if not chunk:
                    break
                self.write(chunk)
                # The flush is the backpressure point against a slow browser.
                yield self.flush()
        except transfer.TransferError as exc:
            self.transfer_error(exc)
        finally:
            worker.transfers -= 1
            if self._download is not None:
                yield self.executor.submit(self._download.close)
                self._download = None
            if sftp is not None:
                yield self.executor.submit(sftp.close)

    def on_connection_close(self):
        # Cancellation is connection teardown, not a message. Download.read
        # returns b'' once cancelled, which ends the chunk loop.
        if self._download is not None:
            self._download.cancel()
        super(TransferDownloadHandler, self).on_connection_close()
```

Add `import posixpath` to the imports.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k "ContentDisposition or TransferDownload"`
Expected: PASS, 10 tests

- [ ] **Step 5: Verify nothing regressed**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
Expected: PASS, 279 tests

- [ ] **Step 6: Lint and commit**

```bash
/home/ryan/github/rgregg/webssh/.venv/bin/python -m ruff check .
git add webssh/handler.py tests/test_app.py
git commit -m "feat: stream remote files to the browser"
```

---

### Task 7: `/transfer/upload`

**Files:**
- Modify: `webssh/handler.py` (`TransferUploadHandler`)
- Modify: `webssh/settings.py` (`max_upload_size`)
- Test: `tests/test_app.py`

**Interfaces:**
- Consumes: `TransferMixin`, `transfer.Upload`, `transfer.open_sftp`.
- Produces: `TransferUploadHandler`, `settings.max_upload_size`.

**Two Tornado details that will silently break this if missed:**
1. The app sets `max_body_size=1MB` (`settings.py:74`), sized for private-key uploads. A streaming handler must raise its own limit with `self.request.connection.set_max_body_size(...)` in `prepare()`, or every upload over 1 MB is refused.
2. With `@stream_request_body`, the body is not parsed, so the XSRF token cannot come from form arguments. The client sends it in the `X-Xsrftoken` header, as `user-hosts.js` already does for `/api/hosts`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_app.py`:

```python
class TestTransferUpload(TransferTestBase):

    def upload(self, query, body, headers=None):
        hdrs = dict(headers if headers is not None else self.headers)
        hdrs['X-Xsrftoken'] = 'yummy'
        hdrs['Content-Type'] = 'application/octet-stream'
        return self.fetch('/transfer/upload?' + query, method='POST',
                          body=body, headers=hdrs)

    def test_writes_the_body_to_the_destination(self):
        response = self.upload(
            'id=tid&path=/home/ryan/new.txt&filename=new.txt', b'payload')
        self.assertEqual(response.code, 200)
        data = json.loads(to_str(response.body))
        self.assertEqual(data['path'], '/home/ryan/new.txt')
        self.assertEqual(data['bytes'], 7)
        self.assertEqual(self.sftp.files['/home/ryan/new.txt'], b'payload')

    def test_existing_destination_is_409_and_leaves_the_file_alone(self):
        response = self.upload(
            'id=tid&path=/home/ryan/a.txt&filename=a.txt', b'clobber')
        self.assertEqual(response.code, 409)
        self.assertEqual(self.sftp.files['/home/ryan/a.txt'], b'hello')

    def test_reissuing_with_overwrite_succeeds(self):
        response = self.upload(
            'id=tid&path=/home/ryan/a.txt&filename=a.txt&overwrite=true',
            b'clobber')
        self.assertEqual(response.code, 200)
        self.assertEqual(self.sftp.files['/home/ryan/a.txt'], b'clobber')

    def test_directory_destination_appends_the_filename(self):
        response = self.upload(
            'id=tid&path=/home/ryan&filename=fresh.txt', b'x')
        self.assertEqual(response.code, 200)
        data = json.loads(to_str(response.body))
        self.assertEqual(data['path'], '/home/ryan/fresh.txt')

    def test_wrong_client_ip_is_404(self):
        self.worker.src_addr = ('203.0.113.7', 1234)
        response = self.upload(
            'id=tid&path=/home/ryan/new.txt&filename=new.txt', b'x')
        self.assertEqual(response.code, 404)

    def test_missing_xsrf_header_is_rejected(self):
        response = self.fetch(
            '/transfer/upload?id=tid&path=/home/ryan/new.txt&filename=new.txt',
            method='POST', body=b'x', headers=self.headers)
        self.assertEqual(response.code, 403)

    def test_transfer_counter_is_released_after_the_upload(self):
        self.upload('id=tid&path=/home/ryan/new.txt&filename=new.txt', b'x')
        self.assertEqual(self.worker.transfers, 0)

    def test_concurrency_cap_returns_429(self):
        self.worker.transfers = handler.TransferMixin.MAX_CONCURRENT_TRANSFERS
        response = self.upload(
            'id=tid&path=/home/ryan/new.txt&filename=new.txt', b'x')
        self.assertEqual(response.code, 429)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k TransferUpload`
Expected: FAIL — 501 from the placeholder handler

- [ ] **Step 3: Add the size limit setting**

In `webssh/settings.py`, below `max_body_size = 1 * 1024 * 1024` (line 74), add:

```python
# Uploads stream to SFTP and never sit in memory, so this is a policy
# ceiling rather than a memory constraint. It is applied per-connection in
# the upload handler; the global max_body_size stays small for the ordinary
# form posts it was sized for.
max_upload_size = 512 * 1024 * 1024
```

- [ ] **Step 4: Implement the handler**

Replace the `TransferUploadHandler` placeholder in `webssh/handler.py` with:

```python
@tornado.web.stream_request_body
class TransferUploadHandler(TransferMixin, tornado.web.RequestHandler):

    def prepare(self):
        # The app-wide max_body_size is sized for form posts. Without this,
        # any upload over 1 MB is refused before the handler ever runs.
        self.request.connection.set_max_body_size(max_upload_size)

        self.worker = self.get_live_worker()
        if self.worker.transfers >= self.MAX_CONCURRENT_TRANSFERS:
            raise tornado.web.HTTPError(429, 'Too many transfers in progress.')

        path = self.get_path()
        filename = self.get_argument('filename', '') or posixpath.basename(path)
        overwrite = self.get_argument('overwrite', '') == 'true'

        self.sftp = transfer.open_sftp(self.worker.ssh)
        self.upload = transfer.Upload(self.sftp, path, filename,
                                      overwrite=overwrite)
        try:
            self.upload.open()
        except transfer.TransferError as exc:
            self._cleanup(abort=False)
            self.transfer_error(exc)

        self.worker.transfers += 1
        self.counted = True

    def data_received(self, chunk):
        # Returning the Future is what makes backpressure real: Tornado stops
        # reading the socket until the SFTP write lands, so a slow host
        # throttles the browser instead of growing server memory.
        return self.executor.submit(self.upload.write, chunk)

    @tornado.gen.coroutine
    def post(self):
        yield self.executor.submit(self.upload.close)
        result = {'path': self.upload.final_path,
                  'bytes': self.upload.bytes_written}
        self._cleanup(abort=False)
        self.write(result)

    def on_connection_close(self):
        # A cancelled upload leaves a truncated file under the real name
        # unless it is removed.
        self._cleanup(abort=True)
        super(TransferUploadHandler, self).on_connection_close()

    def _cleanup(self, abort):
        if getattr(self, 'counted', False):
            self.worker.transfers -= 1
            self.counted = False
        upload = getattr(self, 'upload', None)
        if upload is not None:
            if abort:
                upload.abort()
            else:
                upload.close()
            self.upload = None
        sftp = getattr(self, 'sftp', None)
        if sftp is not None:
            try:
                sftp.close()
            except Exception:
                pass
            self.sftp = None
```

Add `max_upload_size` to the `from webssh.settings import (...)` block in `handler.py`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k TransferUpload`
Expected: PASS, 8 tests

- [ ] **Step 6: Verify nothing regressed**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
Expected: PASS, 287 tests

- [ ] **Step 7: Lint and commit**

```bash
/home/ryan/github/rgregg/webssh/.venv/bin/python -m ruff check .
git add webssh/handler.py webssh/settings.py tests/test_app.py
git commit -m "feat: stream browser uploads to the remote host"
```

---

### Task 8: Idle-timeout suppression during transfers

**Files:**
- Modify: `webssh/handler.py:955-959` (`WsockHandler._idle_disconnect`)
- Test: `tests/test_app.py`

**Interfaces:**
- Consumes: `Worker.transfers`.
- Produces: no new names.

**Why:** `_reset_idle_timeout` only runs on WebSocket messages. A ten-minute download with no typing would let the idle timer close the terminal — and the SSH connection — out from under the transfer.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_app.py`:

```python
class TestIdleTimeoutDuringTransfer(unittest.TestCase):

    class FakeWorker(object):
        def __init__(self, transfers):
            self.transfers = transfers
            self.closed_reason = None

        def close(self, reason=None):
            self.closed_reason = reason

    def make_handler(self, worker_obj):
        ws = handler.WsockHandler.__new__(handler.WsockHandler)
        ws.src_addr = ('127.0.0.1', 1234)
        ws.worker_ref = lambda: worker_obj
        ws._idle_timeout = None
        ws.loop = None
        return ws

    def test_idle_disconnect_closes_when_no_transfer_is_running(self):
        w = self.FakeWorker(transfers=0)
        self.make_handler(w)._idle_disconnect()
        self.assertEqual(w.closed_reason, 'Idle timeout.')

    def test_idle_disconnect_is_deferred_while_a_transfer_runs(self):
        # Closing here would kill the SSH connection the transfer rides on.
        w = self.FakeWorker(transfers=1)
        ws = self.make_handler(w)
        ws._reset_idle_timeout = lambda: None
        ws._idle_disconnect()
        self.assertIsNone(w.closed_reason)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k IdleTimeoutDuringTransfer`
Expected: FAIL on the second test — the worker is closed despite an active transfer

- [ ] **Step 3: Implement it**

In `webssh/handler.py`, replace `WsockHandler._idle_disconnect` (currently lines 955-959):

```python
    def _idle_disconnect(self):
        worker = self.worker_ref() if self.worker_ref else None
        if worker and worker.transfers:
            # A transfer is in flight on this connection. Closing now would
            # kill the SSH session it rides on, so re-arm instead.
            logging.debug('Idle timeout deferred: transfer in progress')
            self._reset_idle_timeout()
            return

        logging.info('Idle timeout for {}:{}'.format(*self.src_addr))
        if worker:
            worker.close(reason='Idle timeout.')
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k IdleTimeoutDuringTransfer`
Expected: PASS, 2 tests

- [ ] **Step 5: Verify nothing regressed**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
Expected: PASS, 289 tests

- [ ] **Step 6: Lint and commit**

```bash
/home/ryan/github/rgregg/webssh/.venv/bin/python -m ruff check .
git add webssh/handler.py tests/test_app.py
git commit -m "fix: do not idle-disconnect a session mid-transfer"
```

---

### Task 9: Client-side pure logic

**Files:**
- Create: `webssh/static/js/file-transfer.js`
- Create: `tests/js/file-transfer.test.js`

**Interfaces:**
- Consumes: nothing.
- Produces: global `webssh_transfer` with `parse_osc7(payload)`, `resolve_path(cwd, input)`, `format_bytes(n)`, `upload_url(id, path, filename, overwrite)`, `download_url(id, path)`.

**Style:** ES5 only, module pattern and `module.exports` tail exactly as `user-hosts.js` does, so `node --test` can require it.

- [ ] **Step 1: Write the failing tests**

Create `tests/js/file-transfer.test.js`:

```javascript
'use strict';

var test = require('node:test');
var assert = require('node:assert');
var ft = require('../../webssh/static/js/file-transfer.js');

test('parse_osc7 extracts the path from a file URI', function () {
  assert.strictEqual(ft.parse_osc7('file://myhost/var/log'), '/var/log');
  assert.strictEqual(ft.parse_osc7('file:///var/log'), '/var/log');
});

test('parse_osc7 percent-decodes escaped characters', function () {
  assert.strictEqual(ft.parse_osc7('file://h/tmp/a%20b'), '/tmp/a b');
  assert.strictEqual(ft.parse_osc7('file://h/tmp/%C3%A9'), '/tmp/\u00e9');
});

test('parse_osc7 returns null for anything it does not understand', function () {
  // A malformed sequence must leave the last known directory alone rather
  // than silently retargeting uploads to a bogus path.
  assert.strictEqual(ft.parse_osc7(''), null);
  assert.strictEqual(ft.parse_osc7('http://h/var'), null);
  assert.strictEqual(ft.parse_osc7('file://h'), null);
  assert.strictEqual(ft.parse_osc7('nonsense'), null);
});

test('parse_osc7 survives a bad percent escape instead of throwing', function () {
  assert.strictEqual(ft.parse_osc7('file://h/tmp/%ZZ'), null);
});

test('resolve_path returns absolute input unchanged', function () {
  assert.strictEqual(ft.resolve_path('/var/log', '/etc/passwd'), '/etc/passwd');
});

test('resolve_path joins a relative name onto the current directory', function () {
  assert.strictEqual(ft.resolve_path('/var/log', 'syslog'), '/var/log/syslog');
  assert.strictEqual(ft.resolve_path('/var/log/', 'syslog'), '/var/log/syslog');
});

test('resolve_path falls back to the name when no directory is known', function () {
  assert.strictEqual(ft.resolve_path(null, 'syslog'), 'syslog');
  assert.strictEqual(ft.resolve_path('', 'syslog'), 'syslog');
});

test('format_bytes produces short human units', function () {
  assert.strictEqual(ft.format_bytes(0), '0 B');
  assert.strictEqual(ft.format_bytes(512), '512 B');
  assert.strictEqual(ft.format_bytes(1024), '1.0 KB');
  assert.strictEqual(ft.format_bytes(1536), '1.5 KB');
  assert.strictEqual(ft.format_bytes(1048576), '1.0 MB');
  assert.strictEqual(ft.format_bytes(3221225472), '3.0 GB');
});

test('upload_url encodes every component', function () {
  var url = ft.upload_url('wid', '/tmp/a b', 'a b.txt', false);
  assert.ok(url.indexOf('id=wid') !== -1);
  assert.ok(url.indexOf('path=%2Ftmp%2Fa%20b') !== -1);
  assert.ok(url.indexOf('filename=a%20b.txt') !== -1);
  assert.strictEqual(url.indexOf('overwrite=true'), -1);
});

test('upload_url sets overwrite only when asked', function () {
  assert.ok(ft.upload_url('w', '/t', 'f', true).indexOf('overwrite=true') !== -1);
});

test('download_url encodes the path', function () {
  var url = ft.download_url('wid', '/tmp/a b');
  assert.ok(url.indexOf('/transfer/download?') === 0);
  assert.ok(url.indexOf('path=%2Ftmp%2Fa%20b') !== -1);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test tests/js/file-transfer.test.js`
Expected: FAIL — `Cannot find module '.../file-transfer.js'`

- [ ] **Step 3: Create the module**

Create `webssh/static/js/file-transfer.js`:

```javascript
/*jslint browser:true */
/*
 * Pure decision logic for browser/host file transfer.
 *
 * No DOM access and no jQuery, so this file is unit-testable under
 * `node --test` with no browser and no packages. transfer-ui.js does the
 * DOM work and calls in here for decisions.
 */

var webssh_transfer = (function () {
  'use strict';

  // Parses the payload of an OSC 7 sequence, which shells emit as
  // file://<host>/<path> to report their working directory. Returns null
  // for anything unrecognised so the caller keeps its last known good
  // directory rather than retargeting uploads at a bogus path.
  function parse_osc7(payload) {
    var text = (payload === undefined || payload === null) ? '' : String(payload);
    if (text.indexOf('file://') !== 0) {
      return null;
    }
    var rest = text.slice(7);
    var slash = rest.indexOf('/');
    if (slash === -1) {
      return null;
    }
    var raw = rest.slice(slash);
    if (!raw) {
      return null;
    }
    try {
      return decodeURIComponent(raw);
    } catch (e) {
      // Malformed percent escape. Treat as unknown rather than throwing
      // inside the terminal's parser callback.
      return null;
    }
  }

  function resolve_path(cwd, input) {
    var name = (input === undefined || input === null) ? '' : String(input);
    if (name.charAt(0) === '/') {
      return name;
    }
    var dir = (cwd === undefined || cwd === null) ? '' : String(cwd);
    if (!dir) {
      return name;
    }
    if (dir.charAt(dir.length - 1) === '/') {
      return dir + name;
    }
    return dir + '/' + name;
  }

  var UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

  function format_bytes(n) {
    var value = Number(n) || 0;
    var unit = 0;
    while (value >= 1024 && unit < UNITS.length - 1) {
      value = value / 1024;
      unit = unit + 1;
    }
    if (unit === 0) {
      return String(Math.round(value)) + ' B';
    }
    return value.toFixed(1) + ' ' + UNITS[unit];
  }

  function upload_url(id, path, filename, overwrite) {
    var url = '/transfer/upload?id=' + encodeURIComponent(id) +
      '&path=' + encodeURIComponent(path) +
      '&filename=' + encodeURIComponent(filename);
    if (overwrite) {
      url = url + '&overwrite=true';
    }
    return url;
  }

  function download_url(id, path) {
    return '/transfer/download?id=' + encodeURIComponent(id) +
      '&path=' + encodeURIComponent(path);
  }

  return {
    parse_osc7: parse_osc7,
    resolve_path: resolve_path,
    format_bytes: format_bytes,
    upload_url: upload_url,
    download_url: download_url
  };
}());

if (typeof module !== 'undefined' && module.exports) {
  module.exports = webssh_transfer;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test tests/js/*.test.js`
Expected: PASS, all tests across both files

- [ ] **Step 5: Commit**

```bash
git add webssh/static/js/file-transfer.js tests/js/file-transfer.test.js
git commit -m "feat: add pure client logic for file transfer"
```

---

### Task 10: Browser UI — drop zone, progress tray, picker

**Files:**
- Create: `webssh/static/js/transfer-ui.js`
- Modify: `webssh/templates/index.html`
- Modify: `webssh/static/css/main.css`
- Modify: `webssh/static/js/main.js` (OSC 7 handler registration; terminal creation site)

**Interfaces:**
- Consumes: `webssh_transfer.*` from Task 9; the worker `id` already held per tab in `main.js`.
- Produces: global `webssh_transfer_ui` with `set_cwd(tab_id, path)`, `get_cwd(tab_id)`, `start_upload(tab_id, worker_id, file)`, `open_picker(tab_id, worker_id)`, `bind_drop(el, tab_id, worker_id)`, `cancel_for_tab(tab_id)`.

**Note on scope:** this task has no automated tests — it is DOM wiring, and the logic it depends on is covered in Task 9. Verify by hand per the manual matrix in Task 11.

**Before editing `main.js`, find the three attachment points** rather than guessing at names:

```bash
grep -n "new Terminal(" webssh/static/js/main.js
grep -n "settings-btn" webssh/static/js/main.js
grep -n "createTab\|activateTab\|closeTab" webssh/static/js/main.js
```

The first gives the terminal construction site, the second shows how an existing tab-bar button resolves the active tab and its worker id (mirror that exactly), and the third gives the tab lifecycle functions used in Step 5. Use the identifiers already in that file; do not introduce new ones.

- [ ] **Step 1: Register the OSC 7 handler in main.js**

In `main.js`, at the site where a terminal is constructed and opened (from the `new Terminal(` grep above), after the terminal is created, add:

```javascript
      term.parser.registerOscHandler(7, function (payload) {
        var dir = webssh_transfer.parse_osc7(payload);
        if (dir) {
          webssh_transfer_ui.set_cwd(tab_id, dir);
        }
        // Returning false lets any other handler see the sequence too.
        return false;
      });
```

Use whatever the surrounding code calls the tab identifier and terminal variable; do not rename them.

- [ ] **Step 2: Create the UI module**

Create `webssh/static/js/transfer-ui.js`:

```javascript
/*jslint browser:true */
/*
 * DOM wiring for file transfer: drop target, progress tray, download
 * picker. All decisions live in file-transfer.js; this file moves elements
 * and issues requests.
 */

var webssh_transfer_ui = (function () {
  'use strict';

  var cwd_by_tab = {};
  var active = {};
  var seq = 0;

  function xsrf() {
    return $('input[name="_xsrf"]').val() || '';
  }

  function set_cwd(tab_id, path) {
    cwd_by_tab[tab_id] = path;
  }

  function get_cwd(tab_id) {
    return cwd_by_tab[tab_id] || null;
  }

  function tray() {
    return $('#transfer-tray');
  }

  function add_row(label) {
    seq = seq + 1;
    var id = 'xfer-' + seq;
    var row = $('<div class="transfer-row" id="' + id + '"></div>');
    row.append($('<span class="transfer-label"></span>').text(label));
    row.append($('<span class="transfer-status">0%</span>'));
    row.append($('<button type="button" class="transfer-cancel">x</button>'));
    tray().append(row).addClass('visible');
    return row;
  }

  function finish_row(row, text) {
    row.find('.transfer-status').text(text);
    row.find('.transfer-cancel').remove();
    setTimeout(function () {
      row.fadeOut(400, function () {
        row.remove();
        if (!tray().children().length) {
          tray().removeClass('visible');
        }
      });
    }, 4000);
  }

  function track(tab_id, controller) {
    if (!active[tab_id]) {
      active[tab_id] = [];
    }
    active[tab_id].push(controller);
  }

  // Transfers are scoped to the session that owns them: closing the tab
  // aborts them rather than leaving a background transfer running against
  // a terminal the user believes is gone.
  function cancel_for_tab(tab_id) {
    var list = active[tab_id] || [];
    for (var i = 0; i < list.length; i++) {
      try {
        list[i].abort();
      } catch (e) {
        // Already settled; nothing to do.
      }
    }
    delete active[tab_id];
    delete cwd_by_tab[tab_id];
  }

  function send_upload(tab_id, worker_id, file, path, overwrite, row) {
    var controller = new AbortController();
    track(tab_id, controller);
    row.find('.transfer-cancel').on('click', function () {
      controller.abort();
    });

    fetch(webssh_transfer.upload_url(worker_id, path, file.name, overwrite), {
      method: 'POST',
      body: file,
      headers: {'X-Xsrftoken': xsrf()},
      signal: controller.signal
    }).then(function (response) {
      if (response.status === 409) {
        if (window.confirm(file.name + ' already exists. Overwrite?')) {
          send_upload(tab_id, worker_id, file, path, true, row);
          return null;
        }
        finish_row(row, 'cancelled');
        return null;
      }
      if (!response.ok) {
        return response.json().then(function (data) {
          finish_row(row, data.status || ('failed (' + response.status + ')'));
        }, function () {
          finish_row(row, 'failed (' + response.status + ')');
        });
      }
      return response.json().then(function (data) {
        finish_row(row, 'uploaded ' + webssh_transfer.format_bytes(data.bytes));
      });
    }).catch(function (err) {
      finish_row(row, err && err.name === 'AbortError' ? 'cancelled' : 'failed');
    });
  }

  function start_upload(tab_id, worker_id, file) {
    var dir = get_cwd(tab_id);
    var path;
    if (dir) {
      path = webssh_transfer.resolve_path(dir, file.name);
    } else {
      path = window.prompt('Upload ' + file.name + ' to:', '');
      if (!path) {
        return;
      }
    }
    var row = add_row('\u2191 ' + file.name);
    send_upload(tab_id, worker_id, file, path, false, row);
  }

  function open_picker(tab_id, worker_id) {
    var dir = get_cwd(tab_id) || '.';
    var dialog = $('#transfer-picker');
    var list = dialog.find('.picker-list').empty();
    var input = dialog.find('.picker-path').val(dir);

    $.getJSON('/transfer/list', {id: worker_id, path: dir})
      .done(function (data) {
        input.val(data.path);
        $.each(data.entries, function (i, entry) {
          var item = $('<div class="picker-item"></div>');
          item.toggleClass('is-dir', entry.is_dir);
          item.text(entry.name + (entry.is_dir ? '/' : ' \u2014 ' +
            webssh_transfer.format_bytes(entry.size)));
          if (!entry.is_dir) {
            // Directories are shown for orientation but are not selectable:
            // navigation is what would turn this into a file browser.
            item.on('click', function () {
              input.val(webssh_transfer.resolve_path(data.path, entry.name));
            });
          }
          list.append(item);
        });
        if (data.truncated) {
          list.append($('<div class="picker-note"></div>')
            .text('Listing truncated.'));
        }
      })
      .fail(function (xhr) {
        list.append($('<div class="picker-note"></div>')
          .text('Could not list directory (' + xhr.status + ')'));
      });

    dialog.addClass('visible');
    dialog.find('.picker-download').off('click').on('click', function () {
      var path = input.val();
      if (path) {
        window.location = webssh_transfer.download_url(worker_id, path);
      }
      dialog.removeClass('visible');
    });
    dialog.find('.picker-cancel').off('click').on('click', function () {
      dialog.removeClass('visible');
    });
  }

  function bind_drop(el, tab_id, worker_id) {
    var overlay = $('#transfer-drop-overlay');
    el.on('dragover', function (e) {
      e.preventDefault();
      overlay.addClass('visible');
    });
    el.on('dragleave drop', function () {
      overlay.removeClass('visible');
    });
    el.on('drop', function (e) {
      e.preventDefault();
      var files = e.originalEvent.dataTransfer.files;
      for (var i = 0; i < files.length; i++) {
        start_upload(tab_id, worker_id, files[i]);
      }
    });
  }

  return {
    set_cwd: set_cwd,
    get_cwd: get_cwd,
    start_upload: start_upload,
    open_picker: open_picker,
    bind_drop: bind_drop,
    cancel_for_tab: cancel_for_tab
  };
}());
```

- [ ] **Step 3: Add the markup**

In `webssh/templates/index.html`, add before `</body>`:

```html
    <div id="transfer-drop-overlay"><div class="drop-message">Drop to upload</div></div>
    <div id="transfer-tray"></div>
    <div id="transfer-picker">
      <div class="picker-box">
        <input type="text" class="picker-path" spellcheck="false">
        <div class="picker-list"></div>
        <div class="picker-actions">
          <button type="button" class="picker-cancel">Cancel</button>
          <button type="button" class="picker-download">Download</button>
        </div>
      </div>
    </div>
```

Add the two script tags **before** `main.js` (which depends on both):

```html
    <script src="static/js/file-transfer.js"></script>
    <script src="static/js/transfer-ui.js"></script>
```

Add a download button to the tab bar, beside the existing gear:

```html
      <button id="download-btn" type="button" title="Download file" aria-label="Download a file from the host">&#8595;</button>
```

- [ ] **Step 4: Style it**

Append to `webssh/static/css/main.css`, matching the existing dark tokens:

```css
/* --- File Transfer --- */
#download-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  padding: 0;
  border: none;
  background: none;
  color: var(--accent);
  font-family: var(--font-mono);
  font-size: 22px;
  line-height: 1;
  cursor: pointer;
  flex-shrink: 0;
  transition: background 0.1s;
}

#download-btn:hover { background: var(--accent-dim); }

#transfer-drop-overlay {
  display: none;
  position: absolute;
  inset: 0;
  z-index: 50;
  align-items: center;
  justify-content: center;
  background: rgba(0, 0, 0, 0.6);
  border: 2px dashed var(--accent);
  pointer-events: none;
}

#transfer-drop-overlay.visible { display: flex; }

.drop-message {
  font-family: var(--font-mono);
  font-size: 16px;
  color: var(--accent);
}

#transfer-tray {
  display: none;
  position: absolute;
  right: 12px;
  bottom: 12px;
  z-index: 60;
  width: 320px;
  max-width: calc(100% - 24px);
}

#transfer-tray.visible { display: block; }

.transfer-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  margin-top: 6px;
  background: var(--bg-elevated);
  border: 1px solid var(--border-subtle);
  border-radius: 6px;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-secondary);
}

.transfer-label {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.transfer-cancel {
  border: none;
  background: none;
  color: var(--text-muted);
  cursor: pointer;
  font-size: 14px;
}

.transfer-cancel:hover { color: var(--accent); }

#transfer-picker {
  display: none;
  position: absolute;
  inset: 0;
  z-index: 70;
  align-items: center;
  justify-content: center;
  background: rgba(0, 0, 0, 0.5);
}

#transfer-picker.visible { display: flex; }

.picker-box {
  width: 480px;
  max-width: calc(100% - 32px);
  padding: 14px;
  background: var(--bg-elevated);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
}

.picker-path {
  width: 100%;
  padding: 8px;
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: 6px;
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: 13px;
}

.picker-list {
  max-height: 300px;
  margin: 10px 0;
  overflow-y: auto;
  font-family: var(--font-mono);
  font-size: 12px;
}

.picker-item {
  padding: 5px 6px;
  color: var(--text-secondary);
  cursor: pointer;
  border-radius: 4px;
}

.picker-item:hover { background: var(--accent-dim); color: var(--accent); }

.picker-item.is-dir { color: var(--text-muted); cursor: default; }

.picker-item.is-dir:hover { background: none; color: var(--text-muted); }

.picker-note { padding: 6px; color: var(--text-muted); font-size: 11px; }

.picker-actions { display: flex; justify-content: flex-end; gap: 8px; }
```

- [ ] **Step 5: Wire the drop target and download button in main.js**

Where a terminal container element is created for a tab, call:

```javascript
      webssh_transfer_ui.bind_drop(container, tab_id, worker_id);
```

And beside the existing `$('#settings-btn').on('click', ...)` handler, add a `#download-btn` handler that resolves the active tab and its worker id **the same way that handler does**, then calls:

```javascript
    webssh_transfer_ui.open_picker(tab_id, worker_id);
```

In the tab-closing function found by the `closeTab` grep, add before the tab is torn down:

```javascript
      webssh_transfer_ui.cancel_for_tab(tab_id);
```

This is what makes "closing the tab cancels its transfers" true. Without it, an aborted session leaves a fetch running against a worker that is being closed underneath it.

- [ ] **Step 6: Verify nothing regressed**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q && node --test tests/js/*.test.js`
Expected: PASS on both

Confirm no ES5 violations were introduced:

```bash
grep -nE "\b(const|let)\b|=>|\`" webssh/static/js/transfer-ui.js webssh/static/js/file-transfer.js
```
Expected: no output

- [ ] **Step 7: Commit**

```bash
git add webssh/static/js/transfer-ui.js webssh/templates/index.html \
        webssh/static/css/main.css webssh/static/js/main.js
git commit -m "feat: add drop-to-upload, progress tray, and download picker"
```

---

### Task 11: Shell integration, config flag, and documentation

**Files:**
- Modify: `webssh/settings.py` (option definition and config application)
- Modify: `webssh/handler.py` (write the snippet after the shell starts)
- Modify: `config.yaml.example`, `README.md`
- Test: `tests/test_app.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `options.shell_integration`, `handler.SHELL_INTEGRATION_SNIPPET`.

**Honest framing:** this is the least robust part of the feature. It branches on shell family, is briefly visible before the screen clears it, and prints junk on an unexpected shell. It defaults to on because the payoff is the whole "drop lands where you are" experience, and the path-box fallback always exists. The flag is how a deployment opts out.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_app.py`:

```python
class TestShellIntegrationSnippet(unittest.TestCase):

    def test_snippet_handles_both_bash_and_zsh(self):
        snippet = handler.SHELL_INTEGRATION_SNIPPET
        self.assertIn('ZSH_VERSION', snippet)
        self.assertIn('PROMPT_COMMAND', snippet)
        self.assertIn('precmd', snippet)

    def test_snippet_emits_an_osc7_sequence(self):
        self.assertIn('\\033]7;file://', handler.SHELL_INTEGRATION_SNIPPET)

    def test_snippet_is_a_single_line_so_it_cannot_half_execute(self):
        # A partially delivered multi-line snippet would leave the shell in
        # a continuation prompt, wedging the session.
        body = handler.SHELL_INTEGRATION_SNIPPET.rstrip('\n')
        self.assertNotIn('\n', body)

    def test_snippet_ends_with_exactly_one_newline(self):
        snippet = handler.SHELL_INTEGRATION_SNIPPET
        self.assertTrue(snippet.endswith('\n'))
        self.assertFalse(snippet.endswith('\n\n'))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k ShellIntegration`
Expected: FAIL — `AttributeError: module 'webssh.handler' has no attribute 'SHELL_INTEGRATION_SNIPPET'`

- [ ] **Step 3: Define the option**

In `webssh/settings.py`, beside the other `define` calls (near line 66):

```python
define('shell_integration', type=bool, default=True,
       help='Ask the remote shell to report its working directory via OSC 7, '
            'so dropped files land in the directory you are in')
```

In `apply_config_settings`, beside the `user_hosts` handling:

```python
    if options.shell_integration and 'shell_integration' in config:
        options.shell_integration = bool(config['shell_integration'])
```

- [ ] **Step 4: Implement the injection**

Add to `webssh/handler.py`, near the other module constants:

```python
# Asks the shell to report its working directory on every prompt. Written
# once when the shell starts, then scrubbed from the screen and from bash
# history. Kept to a single line: a partially delivered multi-line snippet
# would strand the shell at a continuation prompt.
SHELL_INTEGRATION_SNIPPET = (
    ' if [ -n "$ZSH_VERSION" ]; then '
    'precmd() { printf "\\033]7;file://%s%s\\033\\\\" "$HOST" "$PWD"; }; '
    'elif [ -n "$BASH_VERSION" ]; then '
    'PROMPT_COMMAND=\'printf "\\033]7;file://%s%s\\033\\\\" "$HOSTNAME" "$PWD"\'; '
    'fi; clear; history -d $((HISTCMD-1)) 2>/dev/null || true\n'
)
```

In `IndexHandler.ssh_connect`, immediately after the shell channel is invoked and the `Worker` is constructed (around line 632), add:

```python
        if options.shell_integration:
            try:
                chan.send(SHELL_INTEGRATION_SNIPPET)
            except (OSError, IOError) as exc:
                # Never let this cost the user their session: the path box
                # is always available as a fallback.
                logging.warning(
                    'Shell integration not sent: {}'.format(exc))
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest tests/test_app.py -q -k ShellIntegration`
Expected: PASS, 4 tests

- [ ] **Step 6: Document it**

Add to `config.yaml.example`:

```yaml
# Ask the remote shell to report its working directory (OSC 7) so files
# dropped on the terminal land in the directory you are in. When off, or on
# a shell that does not cooperate, WebSSH asks for the destination instead.
# shell_integration: true
```

Add a section to `README.md` after the user-hosts documentation:

```markdown
### File transfer

Drag a file onto a connected terminal to upload it; use the download button
in the tab bar to fetch a file back. Transfers run over SFTP on the SSH
connection the terminal already authenticated, so they need no extra
credentials and carry exactly the permissions of the SSH user you connected
as.

Uploads land in the directory the shell is currently in, which WebSSH learns
from an OSC 7 sequence. Set `shell_integration: false` to disable that; the
destination is then requested with a prompt. Uploads never overwrite an
existing file without asking.

Transfers are capped at three at a time per session, and are cancelled if the
terminal tab is closed.
```

- [ ] **Step 7: Full verification**

```bash
/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q
node --test tests/js/*.test.js
/home/ryan/github/rgregg/webssh/.venv/bin/python -m ruff check .
```
Expected: 293 Python tests pass, JS tests pass, lint clean

- [ ] **Step 8: Commit**

```bash
git add webssh/settings.py webssh/handler.py config.yaml.example README.md \
        tests/test_app.py
git commit -m "feat: report the shell working directory for drop targets"
```

---

## Manual verification

Automated tests cannot judge the shell injection or real throughput. Deploy the branch image to the dev stack at `/opt/stacks/webssh-dev` (CI publishes `ghcr.io/rgregg/webssh:dev-feature-file-transfer` on the PR build) and check:

- [ ] **bash**: `cd /var/log`, drop a file — it lands in `/var/log`, and the injection is not visibly disruptive at session start
- [ ] **zsh**: same
- [ ] **dash or another unexpected shell**: degrades to the path box; any junk printed is a single line and does not wedge the prompt
- [ ] **`su` to another user**: directory tracking stops, path box takes over, nothing breaks
- [ ] **`shell_integration: false`**: no injection at all, path box used for every drop
- [ ] **~300 MB upload**: progress advances, cancel works, the partial file is removed from the host, and `docker stats` shows the WebSSH container's memory staying flat
- [ ] **~300 MB download**: streams to disk, cancel works, memory flat
- [ ] **Idle during a long transfer**: the terminal is not disconnected mid-transfer
- [ ] **Overwrite**: dropping a file whose name already exists prompts once, and Cancel leaves the original intact
- [ ] **Tab close during a transfer**: closing the terminal tab aborts the transfer, and no partial file is left on the host
- [ ] **Concurrency**: dropping four files at once transfers three and reports the fourth as rejected rather than failing silently

## Verification Checklist

- [ ] `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q` passes with 293 tests
- [ ] `node --test tests/js/*.test.js` passes
- [ ] `ruff check .` is clean under the pinned `ruff==0.15.6`
- [ ] `package.json` still has no `dependencies` and no `devDependencies`
- [ ] No file under `webssh/static/js/` uses `const`, `let`, arrow functions, or template literals
- [ ] `file-transfer.js` contains no DOM access and no jQuery reference
- [ ] `file-transfer.js` and `transfer-ui.js` are loaded before `main.js` in `index.html`
- [ ] A valid worker ID from a different client IP returns 404 on all three transfer routes
- [ ] Uploads over 1 MB succeed, proving `set_max_body_size` is in effect
- [ ] A cancelled upload leaves no partial file on the host
