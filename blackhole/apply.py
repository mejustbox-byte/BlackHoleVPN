"""Privileged local apply for one explicitly bound systemd Xray instance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time

from adaptive.probe import validate_target
from . import config_store as store, devices
from .cli import load_config
from .export import make_client_config
from .subctl import private_file

SYSTEMCTL = '/usr/bin/systemctl'
CURL = '/usr/bin/curl'


def atomic(path, data):
    if os.path.lexists(path): store.read_private(path)
    fd, temporary = tempfile.mkstemp(prefix='.apply-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), 0o600); f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(temporary, path); store.sync_directory(path.parent)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def encode(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def paths(config):
    p = Path(config)
    return p.parent / ('.' + p.name + '.last-good.json'), p.parent / ('.' + p.name + '.apply-state.json')


def policy(path):
    p = json.loads(private_file(path))
    fields = {'config','unit','xray','public_key_file','probe_device','url','sha256'}
    if not isinstance(p, dict) or set(p) != fields: raise ValueError('invalid policy')
    for name in ('config','xray','public_key_file'):
        if not isinstance(p[name],str) or not Path(p[name]).is_absolute() or not re.fullmatch(r'/[A-Za-z0-9_./-]+',p[name]): raise ValueError('absolute paths required')
    if not isinstance(p['unit'],str) or not re.fullmatch(r'blackholevpn-[a-z0-9][a-z0-9_-]*\.service',p['unit']):
        raise ValueError('invalid dedicated unit')
    if not isinstance(p['probe_device'],str): raise ValueError('invalid probe device')
    if not isinstance(p['sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',p['sha256']): raise ValueError('invalid digest')
    validate_target(p['url'])
    info=os.stat(p['xray'],follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or not os.access(p['xray'],os.X_OK): raise ValueError('invalid Xray binary')
    return p


def configured(p):
    r=subprocess.run([SYSTEMCTL,'show',p['unit'],'-p','ExecStart','--value'],
                     capture_output=True,text=True,timeout=5,check=False)
    matches=re.findall(r'argv\[\]=([^;]+);',r.stdout)
    expected=' '.join([p['xray'],'run','-config',p['config']])
    binaries=re.findall(r'path=([^;]+);',r.stdout)
    return (r.returncode==0 and len(matches)==1 and matches[0].strip()==expected
            and len(binaries)==1 and binaries[0].strip()==p['xray'])


def command(p, action):
    if action in ('restart','stop') and not configured(p): return False
    return subprocess.run([SYSTEMCTL,action,p['unit']],stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL,timeout=25,check=False).returncode == 0


def bound(p):
    r=subprocess.run([SYSTEMCTL,'show',p['unit'],'-p','MainPID','--value'],
                     capture_output=True,text=True,timeout=5,check=False)
    if r.returncode or not r.stdout.strip().isdigit(): return False
    pid=int(r.stdout.strip())
    if pid <= 0: return False
    try:
        args=Path('/proc',str(pid),'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        expected=[p['xray'],'run','-config',p['config']]
        return (args == [os.fsencode(a) for a in expected]
                and os.path.realpath('/proc/'+str(pid)+'/exe')==os.path.realpath(p['xray']))
    except OSError: return False


def validate(p, config):
    with tempfile.TemporaryDirectory(prefix='.apply-check-',dir=Path(p['config']).parent) as t:
        f=Path(t)/'server.json';f.write_bytes(encode(config));f.chmod(0o600)
        r=subprocess.run([p['xray'],'run','-test','-config',str(f)],stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,timeout=30,check=False)
        if r.returncode: raise ValueError('configuration invalid')


def wait_running(p, timeout=5):
    # Type=simple restart can finish before exec/proc identity is observable.
    deadline=time.monotonic()+timeout
    while True:
        if command(p,'is-active') and bound(p): return True
        if time.monotonic()>=deadline: return False
        time.sleep(.1)


def healthy(p, config):
    """Fresh sole-VLESS clients, two HTTPS GETs, TLS + body digest, no direct retry."""
    if not wait_running(p): return False
    key=private_file(p['public_key_file']).strip()
    for transport in ('xhttp','tcp'):
        process=None
        try:
            with tempfile.TemporaryDirectory(prefix='.apply-probe-',dir=Path(p['config']).parent) as t:
                root=Path(t)
                with socket.socket() as s: s.bind(('127.0.0.1',0));port=s.getsockname()[1]
                c=make_client_config(config,p['probe_device'],'127.0.0.1',key,
                                     transport=transport,listen_port=port)
                f=root/'client.json';f.write_bytes(encode(c));f.chmod(0o600)
                process=subprocess.Popen([p['xray'],'run','-config',str(f)],
                                         stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                deadline=time.monotonic()+3
                while True:
                    if process.poll() is not None: return False
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.2): break
                    except OSError:
                        if time.monotonic()>=deadline: return False
                        time.sleep(.05)
                body=root/'body'
                env={k:v for k,v in os.environ.items() if 'proxy' not in k.lower()}
                passed=False
                for attempt in range(2):
                    body.unlink(missing_ok=True)
                    r=subprocess.run([CURL,'--silent','--fail','--connect-timeout','8','--max-time','20',
                        '--max-filesize','65536','--proxy',f'socks5h://127.0.0.1:{port}',
                        '--noproxy','','--output',str(body),'--write-out','%{http_code}',p['url']],
                        env=env,capture_output=True,timeout=22,check=False)
                    if process.poll() is not None: return False
                    if (r.returncode==0 and r.stdout==b'200' and body.is_file()
                            and body.stat().st_size<=65536
                            and hashlib.sha256(body.read_bytes()).hexdigest()==p['sha256']):
                        passed=True;break
                    if attempt==0: time.sleep(.2)
                if not passed: return False
        except (OSError,ValueError,KeyError,subprocess.SubprocessError):
            return False
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
    return command(p,'is-active') and bound(p)


def state(config, phase):
    atomic(paths(config)[1],encode({'version':1,'phase':phase}))


def read_state(config):
    value=json.loads(store.read_private(paths(config)[1]))
    if (not isinstance(value,dict) or set(value)!={'version','phase'}
            or type(value['version']) is not int or value['version']!=1
            or value['phase'] not in ('healthy','applying','recovering','rolled_back','rollback_failed')):
        raise ValueError('invalid apply state')
    return value


def baseline(p):
    raw=json.loads(store.read_private(paths(p['config'])[0]))
    return devices.reconcile(raw,devices.load(p['config']))


def rollback(p, old):
    try:
        # Reload authority even on rollback: an old known-good UUID is not permission.
        old=devices.reconcile(old,devices.load(p['config']))
        state(p['config'],'recovering')
        store.publish(p['config'],encode(old),p['xray'])
        if not command(p,'restart') or not healthy(p,old): raise ValueError('recovery unhealthy')
        atomic(paths(p['config'])[0],encode(old))
        state(p['config'],'rolled_back')
        return 'rolled_back'
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        # Prevent a failed recovery from leaving a potentially stale instance serving.
        try: command(p,'stop')
        except (OSError,subprocess.SubprocessError): pass
        try: state(p['config'],'rollback_failed')
        except OSError: pass
        return 'rollback_failed'


def operate(p, action, candidate=None):
    if action not in ('adopt','apply','recover','status'): raise ValueError('invalid action')
    config=p['config'];good,journal=paths(config)
    with store.locked(config):
        authority=devices.load(config)
        if action=='status':
            return read_state(config)['phase']
        if not configured(p): raise ValueError('configured service binding mismatch')
        if action=='adopt':
            if os.path.lexists(good) or os.path.lexists(journal): raise ValueError('already adopted')
            current=load_config(config);devices.assert_config(current,authority)
            validate(p,current)
            if not healthy(p,current): raise ValueError('cannot adopt unhealthy instance')
            atomic(good,encode(current));state(config,'healthy')
            return 'healthy'
        old=baseline(p);validate(p,old)
        if action=='recover': return rollback(p,old)
        s=read_state(config)
        if s.get('phase') not in ('healthy','rolled_back'): raise ValueError('explicit recovery required')
        if not bound(p): raise ValueError('service binding mismatch')
        new=devices.reconcile(json.loads(store.read_private(candidate)),authority)
        validate(p,new)  # Reject syntax/authority errors before touching runtime.
        state(config,'applying')
        try:
            store.publish(config,encode(new),p['xray'])
            if not command(p,'restart') or not healthy(p,new): raise ValueError('candidate unhealthy')
            atomic(good,encode(new));state(config,'healthy')
            return 'healthy'
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
            return rollback(p,old)


def main(argv=None):
    parser=argparse.ArgumentParser(description='Apply to one explicitly bound local Xray service')
    parser.add_argument('--policy',required=True,help='private operator-owned policy')
    parser.add_argument('action',choices=('adopt','apply','recover','status'))
    parser.add_argument('--candidate',help='private server JSON required for apply')
    args=parser.parse_args(argv)
    try:
        if (args.action=='apply') != (args.candidate is not None): raise ValueError('candidate required only for apply')
        result=operate(policy(args.policy),args.action,args.candidate)
        print(result)
        if args.action=='status': return 0
        return 0 if result=='healthy' else 3 if result=='rolled_back' else 4
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print('error: apply operation failed; inspect private policy, authority and recovery state',file=sys.stderr)
        return 2


if __name__=='__main__': sys.exit(main())
