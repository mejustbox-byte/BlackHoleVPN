import base64
import io
import tempfile
import unittest
from pathlib import Path
from blackhole.subscription import application, connect, issue, revoke, update, validate_profiles

P1 = 'vless://11111111-1111-4111-8111-111111111111@example.org:443?type=tcp&security=reality#main'
P2 = 'vless://22222222-2222-4222-8222-222222222222@example.org:8443?type=xhttp&security=reality#backup'

class SubscriptionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name)/'test.sqlite'); self.db = connect(self.path); self.addCleanup(self.db.close)
    def request(self, token, method='GET'):
        status=[]
        body=b''.join(application(self.path)({'REQUEST_METHOD':method,'PATH_INFO':'/s/'+token},lambda s,h:status.append((s,dict(h)))))
        return status[0],body
    def test_issue_update_revoke(self):
        token=issue(self.db,[P1,P2]); (status,headers),body=self.request(token)
        self.assertEqual(status,'200 OK'); self.assertIn('no-store',headers['Cache-Control'])
        self.assertEqual(base64.b64decode(body).decode(), P1+'\n'+P2+'\n')
        self.assertNotIn(token, str(self.db.execute('SELECT * FROM subscriptions').fetchall()))
        update(self.db,token,[P2]); self.assertEqual(base64.b64decode(self.request(token)[1]).decode(),P2+'\n')
        self.assertTrue(revoke(self.db,token)); self.assertEqual(self.request(token)[0][0],'404 Not Found')
    def test_invalid_update_preserves_existing(self):
        token=issue(self.db,[P1]); before=self.request(token)[1]
        with self.assertRaises(ValueError): update(self.db,token,['https://example.org/'])
        self.assertEqual(self.request(token)[1],before)
    def test_invalid_requests_and_tokens(self):
        token=issue(self.db,[P1]); self.assertEqual(self.request(token,'POST')[0][0],'405 Method Not Allowed')
        self.assertEqual(self.request('invalid')[0][0],'404 Not Found')
        for item in [[],['vless://x@example.org:443\nextra'],['vless://x@example.org:99999']]:
            with self.assertRaises(ValueError): validate_profiles(item)
    def test_separate_subscriptions(self):
        a=issue(self.db,[P1]); b=issue(self.db,[P2]); revoke(self.db,a)
        self.assertEqual(self.request(b)[0][0],'200 OK')

if __name__ == '__main__': unittest.main()
