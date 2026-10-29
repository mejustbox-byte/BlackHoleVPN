import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

class ProcessTests(unittest.TestCase):
    def test_xray_failure_leaves_no_candidate_and_no_secrets(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); key=root/'key'; key.write_text('A'*43); fake=root/'xray'
            fake.write_text('#!/bin/sh\necho fake-private-key >&2\nexit 1\n'); fake.chmod(0o700)
            target=root/'server.json'
            p=subprocess.run([sys.executable,'-m','blackhole.cli','--config',str(target),'--xray',str(fake),'init','--target','example.org','--private-key-file',str(key)],capture_output=True,text=True)
            self.assertEqual(p.returncode,2)
            self.assertFalse(target.exists())
            self.assertNotIn('fake-private-key',p.stderr)
            self.assertFalse(list(root.glob('.blackhole-*')))
    def test_symlink_config_refused(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); actual=root/'real'; actual.write_text('{}'); link=root/'link'; link.symlink_to(actual)
            p=subprocess.run([sys.executable,'-m','blackhole.cli','--config',str(link),'validate'],capture_output=True,text=True)
            self.assertEqual(p.returncode,2)
            self.assertEqual(actual.read_text(),'{}')
    def test_adaptive_rejects_nonfinite_json(self):
        with tempfile.TemporaryDirectory() as t:
            pth=Path(t)/'input.json'; pth.write_text('{"current":"a","routes":{"a":[{"ok":true,"latency_ms":NaN}]}}')
            p=subprocess.run([sys.executable,'adaptive/selector.py',str(pth)],capture_output=True,text=True)
            self.assertEqual(p.returncode,2)
            self.assertEqual(p.stdout,'')

if __name__ == '__main__': unittest.main()
