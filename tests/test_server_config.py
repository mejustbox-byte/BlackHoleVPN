import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from blackhole.cli import build_config, clients, save_validated, main

class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.path = self.root/'config.json'
        self.fake = self.root/'xray'; self.fake.write_text('#!/bin/sh\nexit 0\n'); self.fake.chmod(0o700)
        self.key = 'A'*43
    def test_config_shape_and_permissions(self):
        cfg = build_config('example.org', self.key, 'a'*16, 443)
        save_validated(self.path, cfg, str(self.fake))
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.path.read_text())['inbounds'][0]['streamSettings']['security'], 'reality')
    def test_failed_validation_preserves_existing(self):
        self.path.write_text('original'); self.fake.write_text('#!/bin/sh\nexit 1\n')
        with self.assertRaises(ValueError): save_validated(self.path, build_config('example.org',self.key,'a'*16,443), str(self.fake))
        self.assertEqual(self.path.read_text(), 'original')
    def test_add_revoke_and_duplicate(self):
        keyfile=self.root/'key'; keyfile.write_text(self.key)
        base=['--config',str(self.path),'--xray',str(self.fake)]
        self.assertEqual(main(base+['init','--target','example.org','--private-key-file',str(keyfile)]),0)
        self.assertEqual(main(base+['add-client','phone']),0)
        self.assertEqual(main(base+['add-client','phone']),2)
        self.assertEqual(len(clients(json.loads(self.path.read_text()))),1)
        self.assertEqual(main(base+['revoke-client','phone']),0)
        self.assertEqual(len(clients(json.loads(self.path.read_text()))),0)
    def test_invalid_values(self):
        for target,key,short,port in [('bad host','A'*43,'a'*16,443),('example.org','bad','a'*16,443),('example.org','A'*43,'a'*16,0)]:
            with self.assertRaises(ValueError): build_config(target,key,short,port)
    def test_no_overwrite_on_init(self):
        self.path.write_text('keep'); keyfile=self.root/'key'; keyfile.write_text(self.key)
        self.assertEqual(main(['--config',str(self.path),'--xray',str(self.fake),'init','--target','example.org','--private-key-file',str(keyfile)]),2)
        self.assertEqual(self.path.read_text(),'keep')

if __name__ == '__main__': unittest.main()
