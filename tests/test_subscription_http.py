"""Local HTTP integration; this test does not enable production serving."""
import base64
from contextlib import closing
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen
from wsgiref.simple_server import WSGIRequestHandler, make_server
from blackhole.subscription import application, connect, issue, revoke, update

PROFILE_A = 'vless://11111111-1111-4111-8111-111111111111@example.org:443?type=tcp&security=reality#main'
PROFILE_B = 'vless://22222222-2222-4222-8222-222222222222@example.org:8443?type=xhttp&security=reality#backup'

class QuietHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        pass

class SubscriptionHttpTests(unittest.TestCase):
    def test_http_update_revoke(self):
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp)/'db.sqlite')
            with closing(connect(path)) as db:
                token = issue(db, [PROFILE_A])
                with make_server('127.0.0.1', 0, application(path), handler_class=QuietHandler) as server:
                    worker = threading.Thread(target=server.serve_forever, daemon=True)
                    worker.start()
                    self.addCleanup(worker.join, 2)
                    self.addCleanup(server.shutdown)
                    url = 'http://127.0.0.1:%d/s/%s' % (server.server_port, token)
                    with urlopen(url, timeout=3) as response:
                        self.assertIn('no-store', response.headers['Cache-Control'])
                        self.assertEqual(base64.b64decode(response.read()).decode().strip(), PROFILE_A)
                    update(db, token, [PROFILE_A, PROFILE_B])
                    with urlopen(url, timeout=3) as response:
                        self.assertEqual(base64.b64decode(response.read()).decode().splitlines(), [PROFILE_A, PROFILE_B])
                    self.assertTrue(revoke(db, token))
                    with self.assertRaises(HTTPError) as error:
                        urlopen(url, timeout=3)
                    self.assertEqual(error.exception.code, 404)
                    server.shutdown(); worker.join(2)

if __name__ == '__main__': unittest.main()
