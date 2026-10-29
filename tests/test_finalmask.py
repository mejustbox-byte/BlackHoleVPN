import copy
import unittest
from blackhole.cli import build_config
from blackhole.finalmask import add_tlshello_fragment

class FinalMaskTests(unittest.TestCase):
    def test_client_only_opt_in_and_no_mutation(self):
        original={'protocol':'vless','streamSettings':{'network':'xhttp','security':'reality'}}
        before=copy.deepcopy(original); result=add_tlshello_fragment(original)
        self.assertEqual(original,before)
        self.assertEqual(result['streamSettings']['finalmask']['tcp'][0]['settings']['packets'],'tlshello')
    def test_reject_existing_or_invalid(self):
        for value in ({'streamSettings':{'network':'tcp','security':'reality','finalmask':{}}}, {'streamSettings':{'network':'udp','security':'reality'}}, {}):
            with self.assertRaises(ValueError): add_tlshello_fragment(value)
        for kwargs in ({'lengths':['0']},{'delays':['4-1']},{'max_split':'0'}, {'lengths':[]}):
            with self.assertRaises(ValueError): add_tlshello_fragment({'streamSettings':{'network':'tcp','security':'reality'}},**kwargs)
    def test_reality_target_on_both_inbounds(self):
        config=build_config('example.org','A'*43,'a'*16,443)
        for inbound in config['inbounds']:
            stream=inbound['streamSettings']; self.assertEqual(stream['realitySettings']['target'],'example.org:443')
            self.assertEqual(stream['realitySettings']['serverNames'],['example.org'])
            self.assertNotIn('fallbacks',inbound['settings'])

if __name__ == '__main__': unittest.main()
