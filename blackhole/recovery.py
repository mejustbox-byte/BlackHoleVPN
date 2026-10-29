"""Systemd pre-start gate and local crash-recovery supervisor (Linux)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from . import apply, config_store as store, devices


def ticket_path(config):
    p=Path(config)
    return p.parent / ('.'+p.name+'.start-ticket.json')


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def process_start(pid):
    # comm may contain spaces or parentheses: fields after the last ')' start at field 3.
    return Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]


def lock_owner(config):
    p=Path(config);lock=p.parent/('.'+p.name+'.lock')
    store.read_private(lock)
    info=os.stat(lock,follow_symlinks=False)
    for line in Path('/proc/locks').read_text().splitlines():
        fields=line.split()
        if '->' in fields or 'FLOCK' not in fields: continue
        index=fields.index('FLOCK')
        if len(fields)<index+5: continue
        if fields[index+1:index+3]!=['ADVISORY','WRITE']: continue
        major,minor,inode=fields[index+4].split(':')
        if (int(major,16),int(minor,16),int(inode))==(os.major(info.st_dev),os.minor(info.st_dev),info.st_ino):
            return int(fields[index+3])
    return None


def digest(data):
    return hashlib.sha256(data).hexdigest()


def issue_ticket(p):
    if lock_owner(p['config'])!=os.getpid(): raise ValueError('restart requires owned config lock')
    registry,_=devices.paths(p['config'])
    value={'version':1,'pid':os.getpid(),'start':process_start(os.getpid()),'boot':boot_id(),
           'config':digest(store.read_private(p['config'])),
           'registry':digest(store.read_private(registry))}
    apply.atomic(ticket_path(p['config']),apply.encode(value))


def clear_ticket(p):
    path=ticket_path(p['config'])
    if not os.path.lexists(path): return
    value=json.loads(store.read_private(path))
    if not isinstance(value,dict) or value.get('pid')!=os.getpid(): raise ValueError('ticket ownership mismatch')
    path.unlink();store.sync_directory(path.parent)


def delegated(p):
    value=json.loads(store.read_private(ticket_path(p['config'])))
    fields={'version','pid','start','boot','config','registry'}
    if (not isinstance(value,dict) or set(value)!=fields or type(value['version']) is not int or value['version']!=1
            or type(value['pid']) is not int or value['pid']<=0): return False
    if (value['boot']!=boot_id() or value['start']!=process_start(value['pid'])
            or lock_owner(p['config'])!=value['pid']): return False
    registry,_=devices.paths(p['config'])
    current=store.read_private(p['config']);registered=store.read_private(registry)
    if value['config']!=digest(current) or value['registry']!=digest(registered): return False
    config=json.loads(current)
    devices.assert_config(config,devices.load(p['config']))
    apply.validate(p,config)
    return True


def prepare(p):
    """ExecStartPre: no systemctl restart and no health request to a stopped server."""
    if not apply.configured(p): raise ValueError('service binding mismatch')
    try:
        with store.locked(p['config'],timeout=0):
            # Ignore even a valid-looking ticket when no controller owns the lock.
            old=apply.baseline(p)
            store.publish(p['config'],apply.encode(old),p['xray'])
            apply.state(p['config'],'recovering')
            return 'prepared'
    except TimeoutError:
        # apply holds the lock while systemctl waits for ExecStartPre. Only this
        # exact, live controller-owned generation may pass without acquiring it.
        if delegated(p): return 'delegated'
        raise ValueError('busy without valid restart delegation') from None


def fingerprint(p):
    registry,_=devices.paths(p['config'])
    pid=subprocess.run([apply.SYSTEMCTL,'show',p['unit'],'-p','MainPID','--value'],
                       capture_output=True,timeout=5,check=False)
    if pid.returncode: raise ValueError('cannot observe service')
    return (digest(store.read_private(p['config'])),digest(store.read_private(registry)),
            digest(store.read_private(apply.paths(p['config'])[1])),pid.stdout.strip())


def failure(p):
    try: apply.command(p,'stop')
    except (OSError,ValueError,subprocess.SubprocessError): pass
    try: apply.state(p['config'],'rollback_failed')
    except (OSError,ValueError): pass
    return 'recovery_failed',None


def cycle(p, previous=None):
    """Return (fixed status, verified fingerprint). Never wait on an active apply."""
    try:
        with store.locked(p['config'],timeout=0):
            try:
                authority=devices.load(p['config'])
                if not apply.configured(p): raise ValueError('service binding mismatch')
                try: phase=apply.read_state(p['config'])['phase']
                except (OSError,ValueError): phase='unknown'
                try: observed=fingerprint(p) if phase!='unknown' else None
                except (OSError,ValueError): observed=None
                if (previous is not None and observed==previous
                        and apply.command(p,'is-active') and apply.bound(p)):
                    return 'healthy',previous
                old=apply.baseline(p)
                raw_good=json.loads(store.read_private(apply.paths(p['config'])[0]))
                try: current=json.loads(store.read_private(p['config']))
                except (OSError,ValueError): current=None
                if phase in ('healthy','rolled_back') and current==raw_good==old:
                    if apply.healthy(p,current): return 'healthy',fingerprint(p)
                result=apply.rollback(p,old)
                return (result,fingerprint(p) if result=='rolled_back' else None)
            except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
                return failure(p)
    except TimeoutError:
        return 'busy',previous
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        return failure(p)


def watch_state_path(config):
    p=Path(config)
    return p.parent/('.'+p.name+'.watch-state.json')


def watch(p, interval=5):
    previous=None;delay=interval;last=None
    while True:
        result,previous=cycle(p,previous)
        if result!=last:
            apply.atomic(watch_state_path(p['config']),apply.encode({'version':1,'pid':os.getpid(),'boot':boot_id(),'status':result}))
            print(result,flush=True);last=result
        delay=min(60,max(interval,delay*2)) if result in ('rollback_failed','recovery_failed') else interval
        time.sleep(delay)


def main(argv=None):
    parser=argparse.ArgumentParser(description='Local Xray startup guard and crash-recovery watcher')
    parser.add_argument('--policy',required=True)
    parser.add_argument('action',choices=('prepare','once','watch'))
    parser.add_argument('--interval',type=int,default=5)
    args=parser.parse_args(argv)
    try:
        if not 1<=args.interval<=60: raise ValueError('invalid interval')
        p=apply.policy(args.policy)
        if args.action=='watch': watch(p,args.interval);return 0
        result=prepare(p) if args.action=='prepare' else cycle(p)[0]
        print(result)
        return 0 if result in ('prepared','delegated','healthy','rolled_back') else 5 if result=='busy' else 4
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print('error: recovery blocked; inspect private policy, authority and last-good',file=sys.stderr)
        return 2


if __name__=='__main__': sys.exit(main())
