import unittest
from adaptive.selector import recommend


def samples(*values):
    return [{'ok': False} if x is None else {'ok': True, 'latency_ms': x} for x in values]

class SelectionTests(unittest.TestCase):
    def test_failed_current_selects_healthy(self):
        out = recommend({'current':'a', 'routes':{'a':samples(None,None,None), 'b':samples(80,90,100)}})
        self.assertEqual((out['decision'],out['route']), ('recommend_switch','b'))
    def test_all_failed_never_recommends_direct(self):
        out = recommend({'current':'a','routes':{'a':samples(None,None,None),'b':samples(None,None,None)}})
        self.assertEqual((out['decision'],out['route']), ('hold','a'))
    def test_hysteresis(self):
        self.assertEqual(recommend({'current':'a','routes':{'a':samples(100,100,100),'b':samples(80,80,80)}})['route'],'a')
        self.assertEqual(recommend({'current':'a','routes':{'a':samples(200,200,200),'b':samples(100,100,100)}})['route'],'b')
    def test_one_success_insufficient(self):
        self.assertEqual(recommend({'current':'a','routes':{'a':samples(None,None,1),'b':samples(100,100,100)}})['route'],'b')
    def test_invalid_samples_fail_closed(self):
        for sample in ({'ok':1}, {'ok':True,'latency_ms':-1}, {'ok':True,'latency_ms':float('nan')}):
            with self.assertRaises(ValueError): recommend({'current':'a','routes':{'a':[sample]}})

if __name__ == '__main__': unittest.main()
