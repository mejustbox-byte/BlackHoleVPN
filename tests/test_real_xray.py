"""Opt-in compatibility test against an operator-provided real Xray binary.

Set BLACKHOLE_TEST_XRAY to its absolute path. Uses generated ephemeral keys,
loopback-free validation only, and does not launch a server or connect to a target.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

XRAY = os.environ.get('BLACKHOLE_TEST_XRAY')

@unittest.skipUnless(XRAY, 'set BLACKHOLE_TEST_XRAY to test a real Xray executable')
class XrayCompatibility(unittest.TestCase):
    def test_init_add_validate_revoke(self):
        binary = Path(XRAY)
        self.assertTrue(binary.is_absolute() and binary.is_file(), 'provide an absolute binary path')
        pair = subprocess.run([str(binary), 'x25519'], capture_output=True, text=True, check=True, timeout=15)
        match = re.search(r'^\s*PrivateKey:\s*([A-Za-z0-9_-]{43})\s*$', pair.stdout, re.MULTILINE | re.IGNORECASE)
        self.assertIsNotNone(match, 'unrecognized Xray x25519 output; check version compatibility')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / 'key'; key.write_text(match.group(1), encoding='ascii'); key.chmod(0o600)
            config = root / 'server.json'
            base = [sys.executable, '-m', 'blackhole.cli', '--config', str(config), '--xray', str(binary)]
            def run(*args):
                p = subprocess.run(base + list(args), capture_output=True, text=True, timeout=40)
                self.assertEqual(p.returncode, 0, p.stderr)
            run('init', '--target', 'example.org', '--private-key-file', str(key), '--port', '14443')
            run('add-client', 'test-device')
            data = json.loads(config.read_text(encoding='utf-8'))
            self.assertEqual(len(data['inbounds'][0]['settings']['clients']), 1)
            run('validate')
            public = re.search(r'^\s*(?:PublicKey|Password \(PublicKey\)):\s*([A-Za-z0-9_-]{43})\s*$', pair.stdout, re.MULTILINE | re.IGNORECASE)
            self.assertIsNotNone(public, 'unrecognized Xray public key output')
            pubfile = root / 'public'; pubfile.write_text(public.group(1)); pubfile.chmod(0o600)
            for transport in ('xhttp', 'tcp'):
                for fragment in (False, True):
                    output = root / (transport + ('-fragment' if fragment else '-plain') + '.json')
                    command = [sys.executable, '-m', 'blackhole.export', '--config', str(config),
                               '--name', 'test-device', '--address', '127.0.0.1',
                               '--public-key-file', str(pubfile), '--transport', transport,
                               '--output', str(output), '--xray', str(binary)]
                    if fragment: command.append('--fragment')
                    result = subprocess.run(command, capture_output=True, text=True, timeout=40)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            backup = subprocess.run(base + ['backup'], capture_output=True, text=True, timeout=40)
            self.assertEqual(backup.returncode, 0, backup.stderr)
            revision = backup.stdout.strip()
            self.assertRegex(revision, r'^[0-9a-f]{32}$')
            run('revoke-client', 'test-device')
            self.assertEqual(len(json.loads(config.read_text())['inbounds'][0]['settings']['clients']), 0)
            run('validate')
            run('restore', revision)
            self.assertEqual(len(json.loads(config.read_text())['inbounds'][0]['settings']['clients']), 1)
            run('revoke-client', 'test-device')
            run('validate')

if __name__ == '__main__': unittest.main()
