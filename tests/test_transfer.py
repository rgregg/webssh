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
