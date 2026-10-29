import unittest
from experiments.matrix import summarize

class MatrixTests(unittest.TestCase):
    def row(self,**kw):
        d={'stage':1,'case':'xhttp','network':'wifi','client':'win','status':'pass','latency_ms':100}; d.update(kw); return d
    def test_aggregate_not_run_not_success(self):
        r=summarize({'results':[self.row(),self.row(status='fail',latency_ms=None),self.row(status='not_run',latency_ms=None)]})
        self.assertEqual(r['groups'][0]['success_rate'],0.5)
        self.assertEqual(r['groups'][0]['not_run'],1); self.assertEqual(r['stages_without_measurements'],[2,3,4,5,6])
    def test_no_samples_is_not_success(self):
        r=summarize({'results':[self.row(status='not_run',latency_ms=None)]})
        self.assertIsNone(r['groups'][0]['success_rate']); self.assertEqual(r['stages_without_measurements'],[1,2,3,4,5,6])
    def test_reject_secrets_and_invalid_values(self):
        for change in ({'case':'vless://secret'}, {'stage':True}, {'latency_ms':float('nan')}, {'status':'fail','latency_ms':1}, {'extra':'token'}):
            with self.assertRaises(ValueError): summarize({'results':[self.row(**change)]})

if __name__=='__main__': unittest.main()
