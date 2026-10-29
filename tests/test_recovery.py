import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackhole import apply, recovery, config_store as store, devices
from blackhole.cli import main, load_config


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name);self.config=root/'server.json'
        key=root/'key';key.write_text('A'*43);key.chmod(0o600)
        self.xray=root/'xray';self.xray.write_text('#!/bin/sh\nexit 0\n');self.xray.chmod(0o700)
        self.base=['--config',str(self.config),'--xray',str(self.xray)]
        self.call('init','--target','example.org','--private-key-file',str(key))
        self.call('add-client','probe');self.call('add-client','phone')
        self.original=self.config.read_bytes()
        apply.atomic(apply.paths(self.config)[0],self.original);apply.state(self.config,'healthy')
        self.p={'config':str(self.config),'unit':'blackholevpn-test.service','xray':str(self.xray)}
        self.configured=patch('blackhole.apply.configured',return_value=True).start()
        self.command=patch('blackhole.apply.command',return_value=True).start()
        patch('blackhole.apply.bound',return_value=True).start()
        self.health=patch('blackhole.apply.healthy',return_value=True).start()
        self.fp=patch('blackhole.recovery.fingerprint',return_value=('cfg','reg','state',b'123')).start()
        self.addCleanup(patch.stopall)

    def call(self,*args):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(self.base+list(args)),0)

    def assert_only_probe(self):
        for inbound in load_config(self.config)['inbounds']:
            self.assertEqual([c['email'] for c in inbound['settings']['clients']],['probe'])

    def test_boot_guard_ignores_stale_candidate_and_revoked_snapshot_uuid(self):
        self.call('revoke-client','phone');self.config.write_bytes(self.original)
        self.assertEqual(recovery.prepare(self.p),'prepared')
        self.assert_only_probe();self.command.assert_not_called()
        self.assertEqual(apply.read_state(self.config)['phase'],'recovering')

    def test_live_lock_ticket_avoids_restart_guard_deadlock(self):
        with store.locked(self.config):
            self.assertEqual(recovery.lock_owner(self.config),os.getpid())
            recovery.issue_ticket(self.p)
            before=self.config.read_bytes()
            self.assertEqual(recovery.prepare(self.p),'delegated')
            self.assertEqual(self.config.read_bytes(),before)
            recovery.clear_ticket(self.p)
        self.assertFalse(recovery.ticket_path(self.config).exists())

    def test_stale_boot_or_changed_generation_ticket_cannot_bypass_lock(self):
        with store.locked(self.config):
            recovery.issue_ticket(self.p)
            ticket=recovery.ticket_path(self.config)
            original=json.loads(ticket.read_text())
            for changes in ({'boot':'previous-boot'},{'start':'0'},{'config':'0'*64},{'registry':'0'*64}):
                ticket.write_text(json.dumps(dict(original,**changes)))
                with self.assertRaises(ValueError):recovery.prepare(self.p)
            ticket.write_text(json.dumps(original));recovery.clear_ticket(self.p)

    def test_ticket_from_dead_controller_is_not_used_when_lock_free(self):
        with store.locked(self.config):recovery.issue_ticket(self.p)
        ticket=recovery.ticket_path(self.config)
        value=json.loads(ticket.read_text());value['pid']=2147483647;ticket.write_text(json.dumps(value))
        self.call('revoke-client','phone');self.config.write_bytes(self.original)
        self.assertEqual(recovery.prepare(self.p),'prepared');self.assert_only_probe()

    def test_busy_without_delegation_never_starts_or_mutates(self):
        with store.locked(self.config):
            with self.assertRaises(OSError):recovery.prepare(self.p)
        self.assertEqual(self.config.read_bytes(),self.original)
        self.command.assert_not_called()

    def test_supervisor_recovers_interrupted_apply_with_latest_authority(self):
        self.call('revoke-client','phone');apply.state(self.config,'applying')
        self.config.write_bytes(self.original)
        result,verified=recovery.cycle(self.p)
        self.assertEqual(result,'rolled_back');self.assertIsNotNone(verified)
        self.assert_only_probe();self.command.assert_any_call(self.p,'restart')

    def test_supervisor_does_not_interrupt_active_apply(self):
        with store.locked(self.config):
            result,verified=recovery.cycle(self.p,('old',))
        self.assertEqual((result,verified),('busy',('old',)))
        self.command.assert_not_called();self.health.assert_not_called()

    def test_supervisor_caches_only_verified_generation(self):
        status,verified=recovery.cycle(self.p)
        self.assertEqual(status,'healthy');self.health.assert_called_once()
        self.health.reset_mock()
        self.assertEqual(recovery.cycle(self.p,verified),(status,verified))
        self.health.assert_not_called()

    def test_missing_authority_stops_instead_of_recreating(self):
        devices.paths(self.config)[0].unlink()
        self.assertEqual(recovery.cycle(self.p)[0],'recovery_failed')
        self.command.assert_any_call(self.p,'stop')
        with self.assertRaises(OSError):recovery.prepare(self.p)
        self.assertFalse(devices.paths(self.config)[0].exists())

    def test_missing_current_or_journal_is_automatically_recovered(self):
        self.call('revoke-client','phone');self.config.unlink()
        self.assertEqual(recovery.cycle(self.p)[0],'rolled_back');self.assert_only_probe()
        apply.paths(self.config)[1].unlink()
        self.assertEqual(recovery.cycle(self.p)[0],'rolled_back');self.assert_only_probe()

    def test_unsafe_lock_directory_stops_configured_instance(self):
        self.config.parent.chmod(0o755)
        try:
            self.assertEqual(recovery.cycle(self.p)[0],'recovery_failed')
            self.command.assert_any_call(self.p,'stop')
        finally:self.config.parent.chmod(0o700)
