import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from blackhole import config_store
from blackhole.cli import main, load_config


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.path=self.root/'server.json'
        self.xray=self.root/'xray';self.xray.write_text('#!/bin/sh\nsleep 0.02\nexit 0\n');self.xray.chmod(0o700)
        key=self.root/'key';key.write_text('A'*43);key.chmod(0o600)
        self.base=['--config',str(self.path),'--xray',str(self.xray)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(self.base+['init','--target','example.org','--private-key-file',str(key)]),0)

    def call(self,*args):
        output=io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            result=main(self.base+list(args))
        return result,output.getvalue().strip()

    def test_concurrent_changes_preserve_all_clients_and_revisions(self):
        processes=[subprocess.Popen([sys.executable,'-m','blackhole.cli',*self.base,'add-client','device-'+str(i)],
                     stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for i in range(6)]
        for p in processes:
            out,err=p.communicate(timeout=30)
            self.assertEqual(p.returncode,0,err)
        config=load_config(self.path)
        for inbound in config['inbounds']:
            self.assertEqual(len(inbound['settings']['clients']),6)
        self.assertEqual(len(config_store.list_revisions(self.path)),6)

    def test_explicit_backup_and_restore_also_snapshot_current(self):
        original=self.path.read_bytes()
        status,revision=self.call('backup');self.assertEqual(status,0)
        self.assertEqual(self.call('add-client','phone')[0],0)
        current=self.path.read_bytes()
        self.assertEqual(self.call('restore',revision)[0],0)
        self.assertEqual(json.loads(self.path.read_bytes()),json.loads(original))
        snapshots=[p.read_bytes() for p in config_store.revisions_dir(self.path).glob('*.json')]
        self.assertIn(current,snapshots)
        self.assertEqual(self.path.stat().st_mode & 0o777,0o600)
        self.assertTrue(all(p.stat().st_mode & 0o777==0o600 for p in config_store.revisions_dir(self.path).iterdir()))

    def test_invalid_candidate_does_not_make_snapshot_or_replace(self):
        before=self.path.read_bytes()
        self.xray.write_text('#!/bin/sh\necho PRIVATE-DIAGNOSTIC >&2\nexit 1\n')
        self.assertEqual(self.call('add-client','phone')[0],2)
        self.assertEqual(self.path.read_bytes(),before)
        self.assertEqual(config_store.list_revisions(self.path),[])
        self.assertFalse(list(self.root.glob('.blackhole-*')))

    def test_backup_failure_and_replace_failure_preserve_current(self):
        before=self.path.read_bytes()
        with patch('blackhole.config_store.snapshot',side_effect=OSError('secret-failure')):
            status,message=self.call('add-client','phone')
            self.assertEqual(status,2)
        self.assertEqual(self.path.read_bytes(),before)
        with patch('blackhole.config_store.os.replace',side_effect=OSError('secret-failure')):
            self.assertEqual(self.call('add-client','phone')[0],2)
        self.assertEqual(self.path.read_bytes(),before)
        self.assertFalse(list(self.root.glob('.blackhole-*')))

    def test_restore_corrupted_or_missing_current_and_reject_bad_revision(self):
        _,revision=self.call('backup')
        self.path.write_bytes(b'corrupted')
        self.assertEqual(self.call('restore',revision)[0],0)
        self.path.unlink()
        self.assertEqual(self.call('restore',revision)[0],0)
        before=self.path.read_bytes()
        self.assertEqual(self.call('restore','../outside')[0],2)
        self.assertEqual(self.path.read_bytes(),before)
        backup=config_store.revision_path(self.path,revision)
        backup.write_text('{}')
        self.assertEqual(self.call('restore',revision)[0],2)
        self.assertEqual(self.path.read_bytes(),before)

    def test_unsafe_lock_backup_directory_and_config_are_rejected(self):
        before=self.path.read_bytes()
        lock=self.root/'.server.json.lock';lock.unlink();lock.symlink_to(self.path)
        self.assertEqual(self.call('add-client','phone')[0],2)
        lock.unlink()
        self.path.chmod(0o644)
        self.assertEqual(self.call('add-client','phone')[0],2)
        self.path.chmod(0o600)
        other=self.root/'other';other.mkdir(mode=0o700)
        directory=self.root/'.server.json.backups';directory.symlink_to(other)
        self.assertEqual(self.call('add-client','phone')[0],2)
        self.assertEqual(self.path.read_bytes(),before)

    def test_lock_timeout_is_bounded(self):
        with config_store.locked(self.path):
            with self.assertRaises(TimeoutError):
                with config_store.locked(self.path,timeout=0.02):pass

    def test_malformed_structures_fail_without_traceback(self):
        for data in ([], {'inbounds': [None]}, {'inbounds': [{'tag':'vless-reality', 'protocol':'vless', 'settings':None}]},
                     {'inbounds': [{'tag':'vless-reality', 'protocol':'vless', 'settings':{'clients':['secret-payload']}}]}):
            self.path.write_text(json.dumps(data))
            self.assertEqual(self.call('add-client','phone')[0],2)
