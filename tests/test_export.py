import copy
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blackhole.cli import build_config, client_groups
from blackhole.export import make_client_config, main, write_validated


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.server = build_config('example.org', 'A'*43, 'a'*16, 443)
        for tag, group in client_groups(self.server).items():
            group.append({'id': '11111111-1111-4111-8111-111111111111', 'email': 'phone',
                          **({'flow': 'xtls-rprx-vision'} if tag == 'vless-reality' else {})})

    def test_four_variants_and_no_server_secrets_or_direct_route(self):
        before = copy.deepcopy(self.server)
        for transport in ('xhttp', 'tcp'):
            for fragment in (False, True):
                with self.subTest(transport=transport, fragment=fragment):
                    c = make_client_config(self.server, 'phone', '2001:db8::1', 'B'*43,
                                           transport=transport, fragment=fragment)
                    self.assertEqual(c['inbounds'][0]['listen'], '127.0.0.1')
                    self.assertFalse(c['inbounds'][0]['settings']['udp'])
                    self.assertEqual(len(c['outbounds']), 1)
                    o = c['outbounds'][0]
                    self.assertEqual(o['protocol'], 'vless')
                    self.assertEqual(o['settings']['vnext'][0]['address'], '2001:db8::1')
                    self.assertNotIn('privateKey', json.dumps(c))
                    self.assertNotIn('A'*43, json.dumps(c))
                    self.assertEqual('finalmask' in o['streamSettings'], fragment)
                    u = o['settings']['vnext'][0]['users'][0]
                    self.assertEqual('flow' in u, transport == 'tcp')
                    if fragment:
                        self.assertEqual(o['streamSettings']['finalmask']['tcp'][0]['settings']['packets'], 'tlshello')
        self.assertEqual(self.server, before)

    def test_invalid_inputs_and_unknown_client(self):
        for kw in ({'transport':'udp'}, {'listen_port':True}, {'listen_port':0},
                   {'fragment':'yes'}, {'fragment':True, 'delays':['-1']}):
            with self.assertRaises(ValueError):
                make_client_config(self.server, 'phone', 'example.org', 'B'*43, **kw)
        with self.assertRaises(ValueError):
            make_client_config(self.server, 'missing', 'example.org', 'B'*43)

    def test_validation_failure_and_no_clobber(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/'client.json'
            with patch('blackhole.export.subprocess.run') as run:
                run.return_value.returncode = 1
                with self.assertRaises(ValueError): write_validated(p, {'secret':'hidden'}, 'xray')
                self.assertEqual(list(Path(t).iterdir()), [])
                run.return_value.returncode = 0
                write_validated(p, {'old':True}, 'xray')
                self.assertEqual(p.stat().st_mode & 0o777, 0o600)
                with self.assertRaises(FileExistsError): write_validated(p, {'old':False}, 'xray')
                self.assertTrue(json.loads(p.read_text())['old'])
                link=Path(t)/'link.json';link.symlink_to(p)
                with self.assertRaises(FileExistsError): write_validated(link, {}, 'xray')
                self.assertEqual(sorted(x.name for x in Path(t).iterdir()), ['client.json','link.json'])

    def test_cli_errors_do_not_print_input_or_xray_output(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);server=root/'server.json';key=root/'key'
            server.write_text(json.dumps(self.server));server.chmod(0o600)
            key.write_text('B'*43);key.chmod(0o600)
            args=['--config',str(server),'--name','phone','--address','example.org',
                  '--public-key-file',str(key),'--transport','tcp','--output',str(root/'out.json')]
            out=io.StringIO();err=io.StringIO()
            with patch('blackhole.export.subprocess.run') as run, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                run.return_value.returncode=1
                self.assertEqual(main(args),2)
                self.assertEqual(main(args+['--fragment-delay','1']),2)
                server.chmod(0o644)
                self.assertEqual(main(args),2)
            self.assertEqual(out.getvalue(),'')
            self.assertNotIn('A'*43,err.getvalue());self.assertNotIn('B'*43,err.getvalue())
            self.assertFalse((root/'out.json').exists())
