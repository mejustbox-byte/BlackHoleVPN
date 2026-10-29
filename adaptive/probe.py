"""Opt-in, HTTPS HEAD probes through explicitly configured loopback HTTP proxies."""
import http.client
import ipaddress
import math
import socket
import ssl
import time
from urllib.parse import urlsplit
from adaptive.behavior import Analyzer


def validate_target(url):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise ValueError('invalid probe URL')
    try:
        u = urlsplit(url)
        port = u.port or 443
        if u.scheme != 'https' or not u.hostname or u.username is not None or u.password is not None or u.query or u.fragment or not 1 <= port <= 65535:
            raise ValueError('invalid probe URL')
        if u.hostname in ('localhost',) or u.hostname.endswith('.localhost'):
            raise ValueError('loopback destination is not allowed')
        try:
            ipaddress.ip_address(u.hostname)
        except ValueError:
            pass
        else:
            raise ValueError('probe target must be a DNS hostname')
    except ValueError:
        raise ValueError('target must be an HTTPS URL without credentials, query, fragment or IP address') from None
    return u.hostname, port, u.path or '/'


def validate_proxy(host, port):
    if host not in ('127.0.0.1', '::1') or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('proxy must be an explicit loopback IP and port')


def probe(target, proxy_host, proxy_port, timeout=5):
    """HEAD over HTTP CONNECT + validated TLS. Returns only status and latency."""
    host, port, path = validate_target(target)
    validate_proxy(proxy_host, proxy_port)
    if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError('timeout must be in (0, 30]')
    started = time.monotonic()
    connection = http.client.HTTPSConnection(proxy_host, proxy_port, timeout=timeout, context=ssl.create_default_context())
    try:
        connection.set_tunnel(host, port)
        connection.request('HEAD', path, headers={'Cache-Control':'no-store', 'Connection':'close'})
        response = connection.getresponse()
        ok = response.status == 204
        response.close()
        return {'ok':ok, 'latency_ms':(time.monotonic()-started)*1000 if ok else None}
    except (OSError, ssl.SSLError, http.client.HTTPException, socket.timeout):
        return {'ok':False, 'latency_ms':None}
    finally:
        connection.close()


def measure_round(analyzer, target, proxies, timeout=5):
    """Sample each supplied local proxy exactly once, with no direct fallback."""
    if not isinstance(analyzer, Analyzer) or not isinstance(proxies, dict) or set(proxies) != set(analyzer._samples):
        raise ValueError('one proxy must be supplied for each analyzer route')
    validate_target(target)
    for value in proxies.values():
        if not isinstance(value, (tuple,list)) or len(value) != 2: raise ValueError('invalid proxy')
        validate_proxy(value[0], value[1])
    for name, (host, port) in proxies.items():
        sample = probe(target, host, port, timeout)
        analyzer.observe(name, sample['ok'], sample['latency_ms'])
