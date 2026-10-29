"""Node-local device authority, independent of restorable Xray snapshots.

Call mutating functions under config_store.locked(config_path).
"""
import copy
import json
import os
from pathlib import Path
import re
import tempfile
import uuid

from . import config_store as store


def paths(config):
    p = Path(config)
    return (p.parent / ('.' + p.name + '.devices.json'),
            p.parent / ('.' + p.name + '.devices-required'))


def initialized(config):
    return any(os.path.lexists(p) for p in paths(config))


def checked(state):
    if not isinstance(state, dict) or state.get('version') != 1 or not isinstance(state.get('devices'), list):
        raise ValueError('invalid device registry')
    ids, uuids, active_names = set(), set(), set()
    for d in state['devices']:
        if not isinstance(d, dict) or set(d) != {'device_id', 'name', 'uuid', 'status'}:
            raise ValueError('invalid device record')
        if not isinstance(d['device_id'], str) or not re.fullmatch(r'[0-9a-f]{32}', d['device_id']):
            raise ValueError('invalid device id')
        if not isinstance(d['name'], str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', d['name']):
            raise ValueError('invalid device name')
        if not isinstance(d['uuid'], str) or str(uuid.UUID(d['uuid'])) != d['uuid']:
            raise ValueError('invalid device UUID')
        if d['status'] not in ('active', 'revoked') or d['device_id'] in ids or d['uuid'] in uuids:
            raise ValueError('duplicate or invalid device')
        ids.add(d['device_id']); uuids.add(d['uuid'])
        if d['status'] == 'active':
            if d['name'] in active_names: raise ValueError('duplicate active device name')
            active_names.add(d['name'])
    return state


def load(config):
    registry, marker = paths(config)
    if store.read_private(marker) != b'device-registry-v1\n':
        raise ValueError('missing device registry marker')
    return checked(json.loads(store.read_private(registry)))


def write(config, state):
    checked(state)
    registry, marker = paths(config)
    if store.read_private(marker) != b'device-registry-v1\n':
        raise ValueError('invalid registry marker')
    if os.path.lexists(registry): store.read_private(registry)
    data = (json.dumps(state, indent=2) + '\n').encode()
    if len(data) > store.MAX_CONFIG_BYTES: raise ValueError('registry too large')
    fd, candidate = tempfile.mkstemp(prefix='.devices-', suffix='.json', dir=registry.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), 0o600); f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(candidate, registry)
        store.sync_directory(registry.parent)
    finally:
        if os.path.exists(candidate): os.unlink(candidate)


def bootstrap(config, current):
    """Explicit one-time migration; never reset an existing/missing marked registry."""
    from .cli import client_groups
    if initialized(config): raise ValueError('registry already initialized or recovery required')
    groups = client_groups(current)
    reference = None
    for group in groups.values():
        pairs = [(c.get('email'), c.get('id')) for c in group]
        if len(set(pairs)) != len(pairs): raise ValueError('duplicate client')
        if reference is None: reference = set(pairs)
        elif set(pairs) != reference: raise ValueError('inconsistent managed clients')
    state = {'version': 1, 'devices': [
        {'device_id': uuid.uuid4().hex, 'name': name, 'uuid': identity, 'status': 'active'}
        for name, identity in sorted(reference or ())]}
    checked(state)
    assert_config(current, state)
    _, marker = paths(config)
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(b'device-registry-v1\n'); f.flush(); os.fsync(f.fileno())
    store.sync_directory(marker.parent)
    write(config, state)
    return state


def allocate(state, name):
    # Reuse an already registered active UUID after interrupted config publication.
    for d in state['devices']:
        if d['name'] == name and d['status'] == 'active': return d
    identity = str(uuid.uuid4())
    while any(d['uuid'] == identity for d in state['devices']): identity = str(uuid.uuid4())
    d = {'device_id': uuid.uuid4().hex, 'name': name, 'uuid': identity, 'status': 'active'}
    state['devices'].append(d)
    return d


def revoke(state, name):
    found = False
    for d in state['devices']:
        if d['name'] == name:
            d['status'] = 'revoked'; found = True
    if not found: raise ValueError('device not registered')


def reconcile(config, state):
    """Rebuild managed client lists from authority, preserving other server settings."""
    from .cli import client_groups
    checked(state)
    result = copy.deepcopy(config)
    groups = client_groups(result)
    for inbound in result['inbounds']:
        managed = inbound.get('protocol') == 'vless' and inbound.get('tag') in groups
        if not managed and (inbound.get('protocol') == 'vless'
                or isinstance(inbound.get('settings'), dict) and 'clients' in inbound['settings']):
            raise ValueError('unmanaged client-bearing inbound is not supported')
    for tag, group in groups.items():
        group[:] = [dict({'id': d['uuid'], 'email': d['name']},
                        **({'flow': 'xtls-rprx-vision'} if tag == 'vless-reality' else {}))
                    for d in state['devices'] if d['status'] == 'active']
    return result


def assert_config(config, state):
    from .cli import client_groups
    expected = client_groups(reconcile(config, state))
    actual = client_groups(config)
    for tag in expected:
        if sorted(json.dumps(c, sort_keys=True) for c in actual[tag]) != sorted(json.dumps(c, sort_keys=True) for c in expected[tag]):
            raise ValueError('configuration disagrees with device authority; reconcile required')
