"""Local-only subscription management. Run within a trusted private directory."""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
from . import subscription


def private_file(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            raise ValueError('input file must be owned by the current user and inaccessible to group/others')
        with os.fdopen(fd, 'r', encoding='utf-8') as f:
            fd = -1
            data = f.read(100001)
        if len(data) > 100000:
            raise ValueError('input file too large')
        return data
    finally:
        if fd >= 0: os.close(fd)


def validate_directory(path):
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('directory must be owned by current user with no group/other permissions')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Experimental local subscription administration')
    parser.add_argument('--db', required=True, help='SQLite file in a private directory')
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('issue'); p.add_argument('--profiles-file', required=True); p.add_argument('--token-file', required=True)
    p = sub.add_parser('update'); p.add_argument('--profiles-file', required=True); p.add_argument('--token-file', required=True)
    p = sub.add_parser('revoke'); p.add_argument('--token-file', required=True)
    args = parser.parse_args(argv)
    try:
        path = Path(args.db)
        validate_directory(path.parent)
        if os.path.lexists(path):
            info = os.stat(path, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError('database must be a private regular file owned by current user')
        else:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            os.close(fd)
        profiles = None
        if args.action != 'revoke':
            profiles = json.loads(private_file(args.profiles_file))
            subscription.validate_profiles(profiles)
        with closing(subscription.connect(path)) as db:
            if args.action == 'issue':
                validate_directory(Path(args.token_file).parent)
                # Reserve destination before changing the database; never overwrite tokens.
                fd = os.open(args.token_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
                token = None
                try:
                    token = subscription.issue(db, profiles)
                    with os.fdopen(fd, 'w', encoding='ascii') as out:
                        fd = -1
                        out.write(token + '\n'); out.flush(); os.fsync(out.fileno())
                except BaseException:
                    if fd >= 0: os.close(fd)
                    if token is not None: subscription.revoke(db, token)
                    os.unlink(args.token_file)
                    raise
                print('Subscription issued; token saved to private file')
            else:
                token = private_file(args.token_file).strip()
                if args.action == 'update':
                    subscription.update(db, token, profiles)
                    print('Subscription updated')
                else:
                    if not subscription.revoke(db, token): raise ValueError('subscription not found')
                    print('Subscription revoked; revoke VLESS access separately')
        return 0
    except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
        # Avoid printing arbitrary file content or SQLite details containing secrets.
        print('error: operation failed; check private paths, inputs and permissions', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
