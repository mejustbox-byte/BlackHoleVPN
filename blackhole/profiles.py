"""Build experimental VLESS URIs from a locally managed dual inbound config."""
import re
import ipaddress
from urllib.parse import urlencode, quote
from .cli import client_groups, check_domain


def make_profiles(config, name, address, public_key, fingerprint='firefox'):
    try:
        ip = ipaddress.ip_address(address)
        address = '[' + str(ip) + ']' if ip.version == 6 else str(ip)
    except ValueError:
        address = check_domain(address)
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}', public_key):
        raise ValueError('invalid REALITY public key')
    if fingerprint not in ('firefox','chrome','edge','safari','ios','android','random','randomized'):
        raise ValueError('unsupported fingerprint')
    groups = client_groups(config)
    if 'vless-xhttp' not in groups:
        raise ValueError('XHTTP inbound is not configured')
    result=[]
    for tag, label in [('vless-xhttp','BlackHole primary XHTTP'),('vless-reality','BlackHole fallback Vision')]:
        inbound = next(i for i in config['inbounds'] if i.get('tag') == tag)
        matches = [c for c in groups[tag] if c.get('email') == name]
        if len(matches) != 1: raise ValueError('client must exist once in each inbound')
        reality = inbound['streamSettings']['realitySettings']
        args = {'security':'reality','sni':reality['serverNames'][0], 'fp':fingerprint, 'pbk':public_key, 'sid':reality['shortIds'][0]}
        if tag == 'vless-xhttp':
            settings=inbound['streamSettings']['xhttpSettings']
            args.update({'type':'xhttp','mode':settings['mode'],'path':settings['path']})
        else:
            args.update({'type':'tcp','flow':'xtls-rprx-vision'})
        result.append('vless://'+matches[0]['id']+'@'+address+':'+str(inbound['port'])+'?'+urlencode(args)+'#'+quote(label))
    return result
