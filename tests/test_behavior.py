import unittest
from adaptive.behavior import Analyzer

class Clock:
    def __init__(self): self.now=1000
    def __call__(self): return self.now

class BehaviorTests(unittest.TestCase):
    def setUp(self):
        self.clock=Clock(); self.a=Analyzer(['main','backup'], window_seconds=60,cooldown_seconds=30,clock=self.clock)
    def add(self, route, samples):
        for value in samples: self.a.observe(route,value is not None,value)
    def test_failure_and_success(self):
        self.add('main',[None,None,None]); self.add('backup',[90,100,110])
        r=self.a.analyze('main'); self.assertEqual((r['decision'],r['route']),('recommend_switch','backup'))
        self.assertEqual(r['routes']['main']['failures'],3)
    def test_expired_data_no_switch(self):
        self.add('backup',[10,10,10]); self.clock.now+=61
        self.assertEqual(self.a.analyze('main')['decision'],'hold')
    def test_network_offline_no_switch(self):
        self.add('backup',[10,10,10]); self.assertEqual(self.a.analyze('main',False)['reason'],'local network unavailable')
    def test_cooldown_starts_only_after_confirm(self):
        self.add('backup',[10,10,10]); self.assertEqual(self.a.analyze('main')['decision'],'recommend_switch')
        self.a.confirm_switch(); self.assertEqual(self.a.analyze('main')['reason'],'switch cooldown')
        self.clock.now+=31; self.assertEqual(self.a.analyze('main')['decision'],'recommend_switch')
    def test_bad_data_rejected(self):
        for args in [('backup',True,float('nan')),('main',False,10),('wrong',True,1),('main',1,1)]:
            with self.assertRaises(ValueError): self.a.observe(*args)
    def test_bounded_history_and_no_payload(self):
        for i in range(30): self.a.observe('main',True,50)
        result=self.a.analyze('main'); self.assertEqual(result['routes']['main']['samples'],20)
        self.assertNotIn('address',str(result))

if __name__ == '__main__': unittest.main()
