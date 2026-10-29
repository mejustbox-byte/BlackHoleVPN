import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from blackhole.subscription import application

PROFILE='vless://11111111-1111-4111-8111-111111111111@example.org:443?type=tcp&security=reality#test'

class CommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.d=Path(self.tmp.name); self.db=self.d/'data.db'; self.tok=self.d/'token'; self.profiles=self.d/'profiles.json'
        self.profiles.write_text(json.dumps([PROFILE])); self.profiles.chmod(0o600)
    def run_cli(self,*args):
        return subprocess.run([sys.executable,'-m','blackhole.subctl','--db',str(self.db),*map(str,args)],capture_output=True,text=True)
    def fetch(self):
        statuses=[]; token=self.tok.read_text().strip()
        body=b''.join(application(self.db)({'REQUEST_METHOD':'GET','PATH_INFO':'/s/'+token},lambda s,h:statuses.append(s)))
        return statuses[0],body
    def test_issue_update_revoke(self):
        p=self.run_cli('issue','--profiles-file',self.profiles,'--token-file',self.tok)
        self.assertEqual(p.returncode,0); token=self.tok.read_text().strip()
        self.assertNotIn(token,p.stdout+p.stderr); self.assertEqual(self.tok.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.db.stat().st_mode & 0o777,0o600)
        self.assertEqual(base64.b64decode(self.fetch()[1]).decode().strip(),PROFILE)
        self.assertEqual(self.run_cli('update','--profiles-file',self.profiles,'--token-file',self.tok).returncode,0)
        self.assertEqual(self.run_cli('revoke','--token-file',self.tok).returncode,0)
        self.assertEqual(self.fetch()[0],'404 Not Found')
    def test_existing_token_not_overwritten(self):
        self.tok.write_text('keep'); self.tok.chmod(0o600)
        self.assertEqual(self.run_cli('issue','--profiles-file',self.profiles,'--token-file',self.tok).returncode,2)
        self.assertEqual(self.tok.read_text(),'keep')
    def test_world_readable_input_refused(self):
        self.profiles.chmod(0o644)
        self.assertEqual(self.run_cli('issue','--profiles-file',self.profiles,'--token-file',self.tok).returncode,2)
        self.assertFalse(self.tok.exists())
    def test_symlink_input_refused(self):
        link=self.d/'link'; link.symlink_to(self.profiles)
        self.assertEqual(self.run_cli('issue','--profiles-file',link,'--token-file',self.tok).returncode,2)
        self.assertFalse(self.tok.exists())
    def test_bad_update_does_not_destroy_old(self):
        self.assertEqual(self.run_cli('issue','--profiles-file',self.profiles,'--token-file',self.tok).returncode,0)
        self.profiles.write_text('["bad"]')
        self.assertEqual(self.run_cli('update','--profiles-file',self.profiles,'--token-file',self.tok).returncode,2)
        self.assertEqual(base64.b64decode(self.fetch()[1]).decode().strip(),PROFILE)

if __name__=='__main__': unittest.main()
