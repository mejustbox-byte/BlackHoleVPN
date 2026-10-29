"""Export private, standalone Xray SOCKS clients; never print credentials."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit, parse_qs

from .profiles import make_profiles
from .finalmask import add_tlshello_fragment
from .subctl import private_file, validate_directory


def make_client_config(config, name, address, public_key, *, transport='xhttp',
                       listen_port=10808, fingerprint='firefox', fragment=False,
                       lengths=('10-20',), delays=('10-20',), max_split='3-6'):
    """Build one loopback SOCKS client with a sole VLESS outbound, no direct route."""
    if transport not in ('xhttp', 'tcp'):
        raise ValueError('unsupported transport')
    if type(listen_port) is not int or not 1 <= listen_port <= 65535:
        raise ValueError('invalid local port')
    if type(fragment) is not bool:
        raise ValueError('fragment must be boolean')
    uri = make_profiles(config, name, address, public_key, fingerprint)[0 if transport == 'xhttp' else 1]
    parsed = urlsplit(uri)
    args = {key: values[0] for key, values in parse_qs(parsed.query).items()}
    user = {'id': parsed.username, 'encryption': 'none'}
    stream = {'network': transport, 'security': 'reality', 'realitySettings': {
        'serverName': args['sni'], 'fingerprint': args['fp'],
        'password': args['pbk'], 'shortId': args['sid'], 'show': False}}
    if transport == 'xhttp':
        stream['xhttpSettings'] = {'mode': args['mode'], 'path': args['path']}
    else:
        user['flow'] = args['flow']
    outbound = {'tag': 'vpn', 'protocol': 'vless', 'settings': {
        'vnext': [{'address': parsed.hostname, 'port': parsed.port, 'users': [user]}]},
        'streamSettings': stream}
    if fragment:
        outbound = add_tlshello_fragment(outbound, lengths, delays, max_split)
    return {'log': {'access': 'none', 'error': 'none', 'loglevel': 'none', 'dnsLog': False},
            'inbounds': [{'tag': 'local-socks', 'listen': '127.0.0.1', 'port': listen_port,
                          'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}],
            'outbounds': [outbound]}


def write_validated(path, config, xray):
    """Validate before publishing a new 0600 file; never replace an existing path."""
    path = Path(path)
    validate_directory(path.parent)
    fd, candidate = tempfile.mkstemp(prefix='.client-', suffix='.json', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            os.fchmod(out.fileno(), 0o600)
            json.dump(config, out, indent=2)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        result = subprocess.run([xray, 'run', '-test', '-config', candidate],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=30, check=False)
        if result.returncode:
            raise ValueError('client validation failed')
        # Atomic no-clobber publication, including existing symlinks.
        os.link(candidate, path)
    finally:
        os.unlink(candidate)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Export an experimental private Xray JSON client')
    parser.add_argument('--config', required=True, help='private managed server JSON')
    parser.add_argument('--name', required=True, help='existing client name')
    parser.add_argument('--address', required=True, help='server hostname or IP')
    parser.add_argument('--public-key-file', required=True, help='private file containing REALITY public key/password')
    parser.add_argument('--transport', choices=('xhttp', 'tcp'), required=True)
    parser.add_argument('--output', required=True, help='new file in a private directory')
    parser.add_argument('--listen-port', type=int, default=10808)
    parser.add_argument('--fingerprint', default='firefox')
    parser.add_argument('--fragment', action='store_true', help='opt in to FinalMask tlshello')
    parser.add_argument('--fragment-length', action='append', help='repeat for multiple byte ranges')
    parser.add_argument('--fragment-delay', action='append', help='repeat for multiple millisecond ranges')
    parser.add_argument('--fragment-max-split', default=None)
    parser.add_argument('--xray', default='xray')
    args = parser.parse_args(argv)
    try:
        if not args.fragment and any(v is not None for v in
                (args.fragment_length, args.fragment_delay, args.fragment_max_split)):
            raise ValueError('fragment parameters require explicit opt-in')
        config = make_client_config(json.loads(private_file(args.config)), args.name,
            args.address, private_file(args.public_key_file).strip(), transport=args.transport,
            listen_port=args.listen_port, fingerprint=args.fingerprint, fragment=args.fragment,
            lengths=args.fragment_length or ('10-20',), delays=args.fragment_delay or ('10-20',),
            max_split=args.fragment_max_split or '3-6')
        write_validated(args.output, config, args.xray)
        print('Client JSON validated and saved to private file')
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError):
        print('error: export failed; check private inputs, destination and Xray compatibility', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
