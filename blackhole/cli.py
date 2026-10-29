"""Manage a private Xray VLESS/REALITY configuration for a test server."""
import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path


def validate_name(value):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', value):
        raise ValueError('client name must contain 1–64 letters, numbers, _, . or -')
    return value


def check_domain(value):
    if len(value) > 253 or not all(re.fullmatch(r'(?!-)[a-zA-Z0-9-]{1,63}(?<!-)', p) for p in value.split('.')) or '.' not in value:
        raise ValueError('target must be a DNS hostname without port')
    return value.lower()


def build_config(target, key, short_id, port):
    target = check_domain(target)
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}', key):
        raise ValueError('invalid X25519 private key format')
    if not re.fullmatch(r'[0-9a-f]{16}', short_id):
        raise ValueError('short id must be 16 lowercase hex digits')
    if not 1 <= port <= 65535:
        raise ValueError('port must be in 1..65535')
    return {'log': {'loglevel':'warning'}, 'inbounds':[{'tag':'vless-reality','listen':'0.0.0.0','port':port,'protocol':'vless', 'settings':{'clients':[], 'decryption':'none'}, 'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'show':False,'target':target+':443','serverNames':[target],'privateKey':key,'shortIds':[short_id]}}}], 'outbounds':[{'protocol':'freedom','tag':'direct'}]}


def clients(config):
    inbounds = config.get('inbounds', [])
    matches = [i for i in inbounds if i.get('tag') == 'vless-reality' and i.get('protocol') == 'vless']
    if len(matches) != 1 or not isinstance(matches[0].get('settings', {}).get('clients'), list):
        raise ValueError('expected one managed VLESS inbound with clients')
    return matches[0]['settings']['clients']


def save_validated(path, config, xray):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('config path must not be a symlink')
    parent = path.parent
    if not parent.is_dir():
        raise ValueError('config directory must already exist')
    fd, tmp = tempfile.mkstemp(prefix='.blackhole-', dir=parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            os.fchmod(out.fileno(), 0o600)
            json.dump(config, out, indent=2)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        # Do not echo Xray output: it may expose configuration details.
        result = subprocess.run([xray, 'run', '-test', '-config', tmp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
        if result.returncode:
            raise ValueError('Xray rejected the candidate configuration; existing file unchanged')
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_config(path):
    if Path(path).is_symlink():
        raise ValueError('config path must not be a symlink')
    with open(path, encoding='utf-8') as f:
        config = json.load(f)
    clients(config)
    return config


def main(argv=None):
    parser = argparse.ArgumentParser(description='Experimental local Xray configuration manager')
    parser.add_argument('--config', required=True, help='private JSON configuration path')
    parser.add_argument('--xray', default='xray', help='path to trusted Xray binary')
    sub = parser.add_subparsers(dest='action', required=True)
    init = sub.add_parser('init')
    init.add_argument('--target', required=True, help='REALITY target hostname, port 443')
    init.add_argument('--private-key-file', required=True, help='file containing X25519 private key')
    init.add_argument('--port', type=int, default=443)
    add = sub.add_parser('add-client'); add.add_argument('name')
    remove = sub.add_parser('revoke-client'); remove.add_argument('name')
    sub.add_parser('list-clients')
    sub.add_parser('validate')
    args = parser.parse_args(argv)
    try:
        if args.action == 'init':
            if os.path.lexists(args.config):
                raise ValueError('config already exists; refusing to overwrite')
            key = Path(args.private_key_file).read_text(encoding='utf-8').strip()
            config = build_config(args.target, key, secrets.token_hex(8), args.port)
        else:
            config = load_config(args.config)
        if args.action == 'list-clients':
            for c in clients(config): print(c.get('email', ''))
            return 0
        if args.action == 'add-client':
            name = validate_name(args.name)
            if any(c.get('email') == name for c in clients(config)):
                raise ValueError('client name already exists')
            clients(config).append({'id':str(uuid.uuid4()), 'email':name, 'flow':'xtls-rprx-vision'})
        elif args.action == 'revoke-client':
            name = validate_name(args.name)
            before = len(clients(config))
            clients(config)[:] = [c for c in clients(config) if c.get('email') != name]
            if len(clients(config)) == before:
                raise ValueError('client not found')
        if args.action == 'validate':
            result = subprocess.run([args.xray, 'run', '-test', '-config', args.config], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
            if result.returncode: raise ValueError('Xray rejected configuration')
            print('Configuration accepted by Xray')
        else:
            save_validated(args.config, config, args.xray)
            print('Configuration validated and saved; restart Xray separately')
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print('error: '+str(exc), file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
