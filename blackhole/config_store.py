"""Linux operator-side transactions and private configuration revisions."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import uuid

from .subctl import validate_directory

REVISION = re.compile(r'[0-9a-f]{32}')
MAX_CONFIG_BYTES = 4 * 1024 * 1024


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError('configuration must be a private regular file owned by operator')
        with os.fdopen(fd, 'rb') as stream:
            fd = -1
            data = stream.read(MAX_CONFIG_BYTES + 1)
        if len(data) > MAX_CONFIG_BYTES:
            raise ValueError('configuration too large')
        return data
    finally:
        if fd >= 0:
            os.close(fd)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def locked(path, timeout=10):
    """Serialize the entire read/modify/write cycle. Never remove the lock file."""
    path = Path(path)
    validate_directory(path.parent)
    lock = path.parent / ('.' + path.name + '.lock')
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError('unsafe configuration lock')
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError('configuration busy') from None
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


def revisions_dir(path):
    path = Path(path)
    directory = path.parent / ('.' + path.name + '.backups')
    try:
        directory.mkdir(mode=0o700)
        sync_directory(path.parent)
    except FileExistsError:
        pass
    validate_directory(directory)
    return directory


def snapshot(path):
    """Call under locked(path). Preserve exact current bytes, including corruption."""
    data = read_private(path)
    directory = revisions_dir(path)
    revision = uuid.uuid4().hex
    fd = os.open(directory / (revision + '.json'),
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        sync_directory(directory)
    finally:
        if fd >= 0:
            os.close(fd)
    return revision


def revision_path(path, revision):
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        raise ValueError('invalid revision')
    return revisions_dir(path) / (revision + '.json')


def list_revisions(path):
    directory = revisions_dir(path)
    result = []
    for p in directory.iterdir():
        if p.suffix == '.json' and REVISION.fullmatch(p.stem):
            read_private(p)
            result.append(p.stem)
    return sorted(result)


def publish(path, data, xray):
    """Call under locked(path): validate candidate, snapshot old, replace, fsync."""
    path = Path(path)
    from . import devices
    if devices.initialized(path):
        import json
        devices.assert_config(json.loads(data), devices.load(path))
    if not isinstance(data, bytes) or len(data) > MAX_CONFIG_BYTES:
        raise ValueError('invalid configuration bytes')
    if os.path.lexists(path):
        read_private(path)
    fd, candidate = tempfile.mkstemp(prefix='.blackhole-', suffix='.json', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        checked = subprocess.run([xray, 'run', '-test', '-config', candidate],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 timeout=30, check=False)
        if checked.returncode:
            raise ValueError('Xray rejected configuration')
        if os.path.lexists(path):
            snapshot(path)
        os.replace(candidate, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)
