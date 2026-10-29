import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackhole import devices, config_store
from blackhole.cli import main, load_config, save_validated


class DeviceRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.config=self.root/'server.json'
        self.key=self.root/'key';self.key.write_text('A'*43);self.key.chmod(0o600)
        self.xray=self.root/'xray';self.xray.write_text('#!/bin/sh\nexit 0\n');self.xray.chmod(0o700)
        self.base=['--config',str(self.config),'--xray',str(self.xray)]
        self.assertEqual(self.call('init','--target','example.org','--private-key-file',str(self.key))[0],0)

    def call(self,*args):
        out=io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(io.StringIO()):result=main(self.base+list(args))
        return result,out.getvalue().strip()

    def active(self):
        return {c['email']:c['id'] for c in load_config(self.config)['inbounds'][0]['settings']['clients']}

    def test_restore_cannot_resurrect_revoked_and_keeps_new_active_device(self):
        self.call('add-client','old');old=self.active()['old']
        _,revision=self.call('backup')
        self.call('add-client','new');new=self.active()['new']
        self.call('revoke-client','old')
        registry_before=devices.paths(self.config)[0].read_bytes()
        self.assertEqual(self.call('restore',revision)[0],0)
        self.assertEqual(self.active(),{'new':new})
        for inbound in load_config(self.config)['inbounds']:
            self.assertNotIn(old,[c['id'] for c in inbound['settings']['clients']])
        self.assertEqual(devices.paths(self.config)[0].read_bytes(),registry_before)

    def test_reissue_name_uses_new_uuid_and_old_uuid_stays_revoked(self):
        self.call('add-client','phone');old=self.active()['phone'];_,revision=self.call('backup')
        self.call('revoke-client','phone');self.call('add-client','phone');new=self.active()['phone']
        self.assertNotEqual(old,new)
        self.assertEqual(self.call('restore',revision)[0],0)
        self.assertEqual(self.active(),{'phone':new})
        state=devices.load(self.config)
        self.assertEqual(next(d['status'] for d in state['devices'] if d['uuid']==old),'revoked')
        status,output=self.call('list-devices');self.assertEqual(status,0)
        self.assertNotIn(old,output);self.assertNotIn(new,output)

    def test_failed_revoke_publication_retains_tombstone_then_reconcile(self):
        self.call('add-client','phone');_,revision=self.call('backup');old=self.config.read_bytes()
        self.xray.write_text('#!/bin/sh\nexit 1\n')
        self.assertEqual(self.call('revoke-client','phone')[0],2)
        self.assertEqual(self.config.read_bytes(),old)
        self.assertEqual(devices.load(self.config)['devices'][0]['status'],'revoked')
        self.assertEqual(self.call('validate')[0],2)
        self.xray.write_text('#!/bin/sh\nexit 0\n')
        self.assertEqual(self.call('reconcile')[0],0);self.assertEqual(self.active(),{})
        self.assertEqual(self.call('restore',revision)[0],0);self.assertEqual(self.active(),{})
        self.assertEqual(self.call('revoke-client','phone')[0],0)

    def test_registry_write_failure_does_not_publish_config(self):
        self.call('add-client','phone');old=self.config.read_bytes()
        with patch('blackhole.devices.write',side_effect=OSError('failure')):
            self.assertEqual(self.call('revoke-client','phone')[0],2)
        self.assertEqual(self.config.read_bytes(),old)
        self.assertEqual(devices.load(self.config)['devices'][0]['status'],'active')

    def test_add_failure_reuses_registered_uuid(self):
        with patch('blackhole.config_store.publish',side_effect=OSError('failure')):
            self.assertEqual(self.call('add-client','phone')[0],2)
        identity=devices.load(self.config)['devices'][0]['uuid']
        self.assertEqual(self.call('add-client','phone')[0],0)
        self.assertEqual(self.active()['phone'],identity)
        self.assertEqual(len(devices.load(self.config)['devices']),1)

    def test_missing_corrupt_or_unsafe_authority_fails_closed(self):
        self.call('add-client','phone');_,revision=self.call('backup')
        registry,marker=devices.paths(self.config);data=registry.read_bytes();before=self.config.read_bytes()
        registry.unlink()
        for command in [('restore',revision),('registry-init',),('reconcile',),('add-client','other')]:
            self.assertEqual(self.call(*command)[0],2)
        self.assertEqual(self.config.read_bytes(),before)
        registry.write_bytes(b'{}');registry.chmod(0o600)
        self.assertEqual(self.call('restore',revision)[0],2)
        registry.unlink();registry.symlink_to(self.config)
        self.assertEqual(self.call('restore',revision)[0],2)
        registry.unlink();registry.write_bytes(data);registry.chmod(0o644)
        self.assertEqual(self.call('restore',revision)[0],2)
        registry.chmod(0o600);marker.unlink()
        self.assertEqual(self.call('restore',revision)[0],2)

    def test_unknown_legacy_entries_removed_and_low_level_write_guarded(self):
        self.call('add-client','phone');old=load_config(self.config);_,revision=self.call('backup')
        self.call('revoke-client','phone')
        with self.assertRaises(ValueError):save_validated(self.config,old,str(self.xray))
        backup=config_store.revision_path(self.config,revision)
        for inbound in old['inbounds']:
            inbound['settings']['clients'][0]['id']='22222222-2222-4222-8222-222222222222'
        backup.write_text(json.dumps(old))
        self.assertEqual(self.call('restore',revision)[0],0);self.assertEqual(self.active(),{})

    def test_explicit_legacy_migration_is_one_time_and_requires_valid_config(self):
        legacy=self.root/'legacy.json';legacy.write_bytes(self.config.read_bytes());legacy.chmod(0o600)
        args=['--config',str(legacy),'--xray',str(self.xray)]
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(args+['validate']),2)
            self.xray.write_text('#!/bin/sh\nexit 1\n')
            self.assertEqual(main(args+['registry-init']),2)
            self.assertFalse(devices.initialized(legacy))
            self.xray.write_text('#!/bin/sh\nexit 0\n')
            self.assertEqual(main(args+['registry-init']),0)
            self.assertEqual(main(args+['registry-init']),2)
            self.assertEqual(main(args+['validate']),0)

    def test_unmanaged_inbound_cannot_restore_revoked_uuid(self):
        self.call('add-client','phone');_,revision=self.call('backup')
        old=load_config(self.config);self.call('revoke-client','phone')
        before=self.config.read_bytes()
        for tag,protocol in [('unmanaged','vless'),('vless-xhttp','vmess')]:
            candidate=json.loads(json.dumps(old))
            extra=json.loads(json.dumps(old['inbounds'][0]));extra['tag']=tag;extra['protocol']=protocol
            candidate['inbounds'].append(extra)
            config_store.revision_path(self.config,revision).write_text(json.dumps(candidate))
            self.assertEqual(self.call('restore',revision)[0],2)
            self.assertEqual(self.config.read_bytes(),before)
