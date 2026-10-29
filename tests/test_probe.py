import unittest
from unittest.mock import patch
from adaptive.behavior import Analyzer
from adaptive.probe import probe, validate_target, validate_proxy, measure_round

class MockResponse:
    status=204
    def close(self): pass

class FakeConnection:
    instances=[]
    def __init__(self,host,port,**kwargs):
        self.host,self.port=host,port; self.kwargs=kwargs; self.tunnel=None; self.requests=[]; self.closed=False
        self.instances.append(self)
    def set_tunnel(self,host,port): self.tunnel=(host,port)
    def request(self,*args,**kwargs): self.requests.append((args,kwargs))
    def getresponse(self): return MockResponse()
    def close(self): self.closed=True

class ProbeTests(unittest.TestCase):
    @patch('adaptive.probe.http.client.HTTPSConnection',FakeConnection)
    def test_explicit_proxy_and_tls(self):
        r=probe('https://health.example.org/check','127.0.0.1',1080)
        c=FakeConnection.instances[-1]
        self.assertTrue(r['ok']); self.assertEqual((c.host,c.port),('127.0.0.1',1080))
        self.assertEqual(c.tunnel,('health.example.org',443)); self.assertEqual(c.requests[0][0],('HEAD','/check'))
        self.assertTrue(c.kwargs['context'].check_hostname); self.assertTrue(c.closed)
    def test_invalid_destinations(self):
        for target in ['http://example.org','https://u:p@example.org','https://example.org/?token=x','https://127.0.0.1','https://localhost','https://example.org/#x']:
            with self.assertRaises(ValueError): validate_target(target)
        for host,port in [('example.org',80),('0.0.0.0',80),('127.0.0.1',0)]:
            with self.assertRaises(ValueError): validate_proxy(host,port)
    @patch('adaptive.probe.http.client.HTTPSConnection',FakeConnection)
    def test_failing_proxy_no_direct_retry(self):
        with patch.object(FakeConnection,'request',side_effect=OSError('offline')):
            before=len(FakeConnection.instances); r=probe('https://health.example.org/','127.0.0.1',1080)
            self.assertFalse(r['ok']); self.assertEqual(len(FakeConnection.instances),before+1)
    @patch('adaptive.probe.http.client.HTTPSConnection',FakeConnection)
    def test_round_reaches_analyzer(self):
        a=Analyzer(['main','backup']); proxies={'main':('127.0.0.1',1111),'backup':('127.0.0.1',2222)}
        for _ in range(3): measure_round(a,'https://health.example.org/check',proxies)
        r=a.analyze('main'); self.assertEqual(r['routes']['main']['samples'],3); self.assertTrue(r['routes']['backup']['healthy'])
    def test_reject_missing_route_before_probing(self):
        with patch('adaptive.probe.probe') as p:
            with self.assertRaises(ValueError): measure_round(Analyzer(['a','b']),'https://health.example.org',{'a':('127.0.0.1',1111)})
            p.assert_not_called()

if __name__ == '__main__': unittest.main()

class ConnectIntegrationTests(unittest.TestCase):
    def test_connect_failure_never_falls_back(self):
        import socketserver
        import threading
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.server.received.append(self.request.recv(4096))
                self.request.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
        with socketserver.TCPServer(('127.0.0.1',0),Handler) as server:
            server.received=[]
            worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
            try:
                result=probe('https://health.example.org/check','127.0.0.1',server.server_address[1],timeout=2)
                self.assertFalse(result['ok']); self.assertEqual(len(server.received),1)
                self.assertTrue(server.received[0].startswith(b'CONNECT health.example.org:443 HTTP/'))
            finally:
                server.shutdown(); worker.join(2)
