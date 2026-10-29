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


def build_config(target, key, short_id, port, fallback_port=8443, xhttp_path='/blackhole'):
    target = check_domain(target)
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}', key):
        raise ValueError('invalid X25519 private key format')
    if not re.fullmatch(r'[0-9a-f]{16}', short_id):
        raise ValueError('short id must be 16 lowercase hex digits')
    if not 1 <= port <= 65535 or not 1 <= fallback_port <= 65535 or port == fallback_port:
        raise ValueError('ports must be distinct and in 1..65535')
    if not re.fullmatch(r'/[A-Za-z0-9/_-]{1,100}', xhttp_path):
        raise ValueError('invalid XHTTP path')
    def inbound(tag, listen_port, network):
        stream = {'network': network, 'security': 'reality', 'realitySettings': {'show': False, 'target':target+':443', 'serverNames':[target], 'privateKey':key, 'shortIds':[short_id]}}
        if network == 'xhttp': stream['xhttpSettings'] = {'mode':'stream-one', 'path':xhttp_path}
        return {'tag':tag, 'listen':'0.0.0.0', 'port':listen_port, 'protocol':'vless', 'settings':{'clients':[], 'decryption':'none'}, 'streamSettings':stream}
    return {'log':{'access':'none', 'error':'none', 'loglevel':'none', 'dnsLog':False}, 'inbounds':[inbound('vless-xhttp',port,'xhttp'), inbound('vless-reality',fallback_port,'tcp')], 'outbounds':[{'protocol':'freedom','tag':'direct'}]}


def client_groups(config):
    inbounds = config.get('inbounds', [])
    matches = [i for i in inbounds if i.get('tag') in ('vless-reality','vless-xhttp') and i.get('protocol') == 'vless']
    tags = [i.get('tag') for i in matches]
    if tags.count('vless-reality') != 1 or tags.count('vless-xhttp') > 1 or any(not isinstance(i.get('settings', {}).get('clients'), list) for i in matches):
        raise ValueError('invalid managed VLESS inbounds')
    return {i['tag']:i['settings']['clients'] for i in matches}


def clients(config):
    return client_groups(config)['vless-reality']


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
    init.add_argument('--fallback-port', type=int, default=8443)
    init.add_argument('--xhttp-path', default='/blackhole')
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
            config = build_config(args.target, key, secrets.token_hex(8), args.port, args.fallback_port, args.xhttp_path)
        else:
            config = load_config(args.config)
        if args.action == 'list-clients':
            for c in clients(config): print(c.get('email', ''))
            return 0
        if args.action == 'add-client':
            name = validate_name(args.name)
            if any(c.get('email') == name for group in client_groups(config).values() for c in group):
                raise ValueError('client name already exists')
            client_id = str(uuid.uuid4())
            for tag, group in client_groups(config).items():
                entry = {'id':client_id, 'email':name}
                if tag == 'vless-reality': entry['flow'] = 'xtls-rprx-vision'
                group.append(entry)
        elif args.action == 'revoke-client':
            name = validate_name(args.name)
            groups = client_groups(config)
            before = sum(len(group) for group in groups.values())
            for group in groups.values(): group[:] = [c for c in group if c.get('email') != name]
            if sum(len(group) for group in groups.values()) == before:
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
