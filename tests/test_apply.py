import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackhole import apply, devices
from blackhole.cli import main, load_config


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.config=self.root/'server.json'
        key=self.root/'key';key.write_text('A'*43);key.chmod(0o600)
        self.xray=self.root/'xray';self.xray.write_text('#!/bin/sh\nexit 0\n');self.xray.chmod(0o700)
        self.base=['--config',str(self.config),'--xray',str(self.xray)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(self.base+['init','--target','example.org','--private-key-file',str(key)]),0)
            self.assertEqual(main(self.base+['add-client','probe']),0)
            self.assertEqual(main(self.base+['add-client','phone']),0)
        self.p={'config':str(self.config),'unit':'blackholevpn-test.service','xray':str(self.xray),
                'public_key_file':str(key),'probe_device':'probe','url':'https://example.org/','sha256':'0'*64}
        self.command=patch('blackhole.apply.command',return_value=True).start()
        self.binding=patch('blackhole.apply.bound',return_value=True).start()
        self.static=patch('blackhole.apply.configured',return_value=True).start()
        self.health=patch('blackhole.apply.healthy',return_value=True).start()
        self.addCleanup(patch.stopall)
        self.assertEqual(apply.operate(self.p,'adopt'),'healthy')
        self.command.reset_mock()
        self.candidate=self.root/'candidate.json';self.candidate.write_bytes(self.config.read_bytes());self.candidate.chmod(0o600)

    def test_success_and_private_last_good(self):
        self.assertEqual(apply.operate(self.p,'apply',self.candidate),'healthy')
        self.command.assert_any_call(self.p,'restart')
        self.assertEqual(apply.paths(self.config)[0].stat().st_mode & 0o777,0o600)
        self.assertEqual(apply.operate(self.p,'status'),'healthy')

    def test_failed_health_rolls_back_without_revoked_uuid(self):
        original=load_config(self.config)['inbounds'][0]['settings']['clients']
        revoked=next(c['id'] for c in original if c['email']=='phone')
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(main(self.base+['revoke-client','phone']),0)
        self.health.side_effect=[False,True]
        self.assertEqual(apply.operate(self.p,'apply',self.candidate),'rolled_back')
        for source in (self.config,apply.paths(self.config)[0]):
            value=json.loads(source.read_text())
            for inbound in value['inbounds']:
                self.assertEqual([c['email'] for c in inbound['settings']['clients']],['probe'])
                self.assertNotIn(revoked,[c['id'] for c in inbound['settings']['clients']])
        self.assertEqual(devices.load(self.config)['devices'][1]['status'],'revoked')

    def test_rollback_failure_stops_and_reports_failure(self):
        self.health.return_value=False
        self.assertEqual(apply.operate(self.p,'apply',self.candidate),'rollback_failed')
        self.command.assert_any_call(self.p,'stop')
        self.assertEqual(apply.operate(self.p,'status'),'rollback_failed')

    def test_pending_apply_refused_until_explicit_recovery(self):
        apply.state(self.config,'applying')
        with self.assertRaises(ValueError):apply.operate(self.p,'apply',self.candidate)
        self.command.assert_not_called()
        self.assertEqual(apply.operate(self.p,'recover'),'rolled_back')

    def test_invalid_candidate_or_mismatched_unit_never_restarts(self):
        self.candidate.write_text('{}')
        with self.assertRaises(ValueError):apply.operate(self.p,'apply',self.candidate)
        self.command.assert_not_called()
        self.static.return_value=False
        with self.assertRaises(ValueError):apply.operate(self.p,'recover')
        self.command.assert_not_called()

    def test_lost_authority_blocks_apply_and_recovery(self):
        devices.paths(self.config)[0].unlink()
        for action in ('apply','recover'):
            with self.assertRaises(OSError):apply.operate(self.p,action,self.candidate)
        self.command.assert_not_called()

    def test_baseline_cannot_be_overwritten_by_second_adoption(self):
        before=apply.paths(self.config)[0].read_bytes()
        with self.assertRaises(ValueError):apply.operate(self.p,'adopt')
        self.assertEqual(apply.paths(self.config)[0].read_bytes(),before)

    def test_corrupt_journal_cannot_be_treated_as_healthy(self):
        for value in ([], {'version':2,'phase':'healthy'}, {'version':True,'phase':'healthy'}):
            apply.paths(self.config)[1].write_text(json.dumps(value))
            with self.assertRaises(ValueError):apply.operate(self.p,'apply',self.candidate)
        self.command.assert_not_called()
        self.assertEqual(apply.operate(self.p,'recover'),'rolled_back')


class BindingTests(unittest.TestCase):
    def test_effective_systemd_binary_and_arguments_must_both_match(self):
        from types import SimpleNamespace
        p={'unit':'blackholevpn-test.service','xray':'/opt/xray','config':'/private/server.json'}
        good='{ path=/opt/xray ; argv[]=/opt/xray run -config /private/server.json ; ignore_errors=no ; }'
        with patch('blackhole.apply.subprocess.run') as run:
            run.return_value=SimpleNamespace(returncode=0,stdout=good)
            self.assertTrue(apply.configured(p))
            run.return_value=SimpleNamespace(returncode=0,stdout=good.replace('path=/opt/xray','path=/bin/sh'))
            self.assertFalse(apply.configured(p))
            run.return_value=SimpleNamespace(returncode=0,stdout=good+good)
            self.assertFalse(apply.configured(p))
            run.return_value=SimpleNamespace(returncode=0,stdout=good.replace('/private/server.json','/private/other.json'))
            self.assertFalse(apply.configured(p))

    def test_startup_grace_waits_for_actual_process_identity(self):
        with patch('blackhole.apply.command',return_value=True), patch('blackhole.apply.bound',side_effect=[False,True]) as bound, patch('blackhole.apply.time.sleep'):
            self.assertTrue(apply.wait_running({}))
            self.assertEqual(bound.call_count,2)
        with patch('blackhole.apply.command',return_value=False):
            self.assertFalse(apply.wait_running({},timeout=0))


class ProbeTests(unittest.TestCase):
    def test_retry_uses_same_explicit_proxy_and_no_direct_fallback(self):
        from types import SimpleNamespace
        import hashlib
        with tempfile.TemporaryDirectory() as t:
            p={'config':str(Path(t)/'server.json'),'xray':'/opt/xray','public_key_file':'/private/key',
               'probe_device':'probe','url':'https://example.org/','sha256':hashlib.sha256(b'ok').hexdigest()}
            requests=[]
            def curl(args,**kwargs):
                requests.append((args,kwargs))
                Path(args[args.index('--output')+1]).write_bytes(b'ok')
                return SimpleNamespace(returncode=1 if len(requests)==1 else 0,stdout=b'200')
            with patch('blackhole.apply.wait_running',return_value=True), patch('blackhole.apply.command',return_value=True), patch('blackhole.apply.bound',return_value=True), patch('blackhole.apply.private_file',return_value='B'*43), patch('blackhole.apply.make_client_config',return_value={}), patch('blackhole.apply.socket.create_connection'), patch('blackhole.apply.time.sleep'), patch('blackhole.apply.subprocess.Popen') as proc, patch('blackhole.apply.subprocess.run',side_effect=curl):
                proc.return_value.poll.return_value=None
                self.assertTrue(apply.healthy(p,{}))
            self.assertEqual(len(requests),3)
            for args,kwargs in requests:
                self.assertIn('--proxy',args)
                self.assertTrue(args[args.index('--proxy')+1].startswith('socks5h://127.0.0.1:'))
                self.assertEqual(args[args.index('--noproxy')+1],'')
                self.assertFalse(any('proxy' in key.lower() for key in kwargs['env']))
