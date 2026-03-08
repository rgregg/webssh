import io
import os
import re
import logging
import tempfile

import paramiko
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


USERNAME_RE = re.compile(r'^[a-zA-Z0-9._-]+$')


def sanitize_username(username):
    if not username or not USERNAME_RE.match(username):
        raise ValueError('Invalid username.')
    if username in ('.', '..') or username.startswith('.'):
        raise ValueError('Invalid username.')
    return username


def get_user_key_dir(base_dir, username):
    sanitize_username(username)
    user_dir = os.path.join(base_dir, username)
    real_base = os.path.realpath(base_dir)
    real_user = os.path.realpath(user_dir)
    if not real_user.startswith(real_base + os.sep):
        raise ValueError('Invalid username.')
    return real_user


def has_stored_key(base_dir, username):
    user_dir = get_user_key_dir(base_dir, username)
    priv = os.path.join(user_dir, 'id_ed25519')
    pub = os.path.join(user_dir, 'id_ed25519.pub')
    return os.path.isfile(priv) and os.path.isfile(pub)


def read_public_key(base_dir, username):
    user_dir = get_user_key_dir(base_dir, username)
    pub_path = os.path.join(user_dir, 'id_ed25519.pub')
    with open(pub_path, 'r') as f:
        return f.read().strip()


def read_private_key(base_dir, username):
    user_dir = get_user_key_dir(base_dir, username)
    priv_path = os.path.join(user_dir, 'id_ed25519')
    with open(priv_path, 'r') as f:
        return f.read()


def generate_key_pair(base_dir, username):
    user_dir = get_user_key_dir(base_dir, username)
    try:
        os.makedirs(user_dir, mode=0o700, exist_ok=True)
    except PermissionError:
        raise ValueError(
            'Cannot create key directory for user {!r}: permission denied. '
            'Check ownership of {!r}'.format(username, base_dir)
        )

    priv_path = os.path.join(user_dir, 'id_ed25519')
    pub_path = os.path.join(user_dir, 'id_ed25519.pub')

    crypto_key = Ed25519PrivateKey.generate()
    pem = crypto_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()
    )

    # Load into paramiko to get public key components
    key = paramiko.Ed25519Key.from_private_key(io.StringIO(pem.decode()))
    pub_key_str = '{} {} {}@webssh-client'.format(
        key.get_name(), key.get_base64(), username
    )

    # Write private key atomically with correct permissions from the start
    fd, tmp_priv = tempfile.mkstemp(dir=user_dir)
    closed = False
    try:
        os.write(fd, pem)
        os.fchmod(fd, 0o600)
        os.close(fd)
        closed = True
        os.rename(tmp_priv, priv_path)
    except Exception:
        os.unlink(tmp_priv)
        raise
    finally:
        if not closed:
            try:
                os.close(fd)
            except OSError:
                pass

    # Write public key atomically
    fd, tmp_pub = tempfile.mkstemp(dir=user_dir)
    closed = False
    try:
        os.write(fd, (pub_key_str + '\n').encode())
        os.fchmod(fd, 0o644)
        os.close(fd)
        closed = True
        os.rename(tmp_pub, pub_path)
    except Exception:
        os.unlink(tmp_pub)
        raise
    finally:
        if not closed:
            try:
                os.close(fd)
            except OSError:
                pass

    logging.info('Generated SSH key pair for user {!r}'.format(username))
    return pub_key_str
