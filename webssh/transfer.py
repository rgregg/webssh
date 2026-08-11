import errno
import logging
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
