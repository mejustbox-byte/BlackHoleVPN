import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from adaptive.diagnose import main

class DiagnoseTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup)
        self.path=Path(self.t.name)/'config.json'
        self.config={'target':'https://health.example.org/check','current':'primary','routes':{'primary':{'host':'127.0.0.1','port':1111},'fallback':{'host':'127.0.0.1','port':2222}}}
    @patch('adaptive.diagnose.time.sleep')
    @patch('adaptive.probe.probe',return_value={'ok':True,'latency_ms':30})
    def test_one_shot(self,probe,sleep):
        self.path.write_text(json.dumps(self.config)); out=StringIO()
        with redirect_stdout(out): code=main(['--config',str(self.path)])
        self.assertEqual(code,0); self.assertEqual(probe.call_count,6)
        result=json.loads(out.getvalue()); self.assertEqual(result['routes']['primary']['samples'],3)
        self.assertNotIn('health.example.org',out.getvalue())
    @patch('adaptive.diagnose.measure_round')
    def test_reject_remote_proxy(self,measure):
        self.config['routes']['primary']['host']='example.org'; self.path.write_text(json.dumps(self.config))
        with redirect_stderr(StringIO()): code=main(['--config',str(self.path)])
        self.assertEqual(code,2); measure.assert_not_called()

if __name__ == '__main__': unittest.main()
