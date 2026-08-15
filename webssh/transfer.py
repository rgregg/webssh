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
        # this is the single largest throughput lever available. A failure
        # here costs speed, not correctness, so it must not fail the
        # transfer -- but it should not vanish either, since a silently
        # unprefetched download is several times slower for no visible
        # reason.
        try:
            self.handle.prefetch()
        except Exception as exc:
            logging.warning(
                'Prefetch unavailable for {}, download will be slower: '
                '{}'.format(self.path, exc))

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
            except Exception as exc:
                # Not actionable for the caller -- the request is already
                # finishing or unwinding -- but a burst of these points at
                # a sick connection, so leave a trace rather than nothing.
                logging.debug(
                    'Ignoring error closing {}: {}'.format(self.path, exc))
            self.handle = None


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
            except Exception as exc:
                # Not actionable for the caller -- the request is already
                # finishing or unwinding -- but a burst of these points at
                # a sick connection, so leave a trace rather than nothing.
                logging.debug(
                    'Ignoring error closing {}: {}'.format(self.path, exc))
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


def matches_filter(name, needle):
    """Case-insensitive substring match. An empty needle matches everything."""
    if not needle:
        return True
    return needle.lower() in name.lower()


def list_directory(sftp, path, name_filter=''):
    """List one directory, optionally keeping only matching names.

    The filter is applied *before* the cap, which is the whole reason it
    lives on the server: capping first would slice the first
    MAX_LIST_ENTRIES names alphabetically, so a match sorting past that
    point could never be found no matter what the user typed.

    Note that the cap bounds the response, not the work: listdir_attr still
    reads the entire directory over SFTP.
    """
    try:
        attrs = sftp.listdir_attr(path)
    except (OSError, IOError) as exc:
        raise error_from_oserror(exc, path)

    needle = (name_filter or '').strip()

    entries = []
    for attr in attrs:
        if not matches_filter(attr.filename, needle):
            continue
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
        'filter': needle,
    }
