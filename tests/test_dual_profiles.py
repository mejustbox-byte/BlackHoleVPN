import unittest
from urllib.parse import urlsplit, parse_qs
from blackhole.cli import build_config, client_groups
from blackhole.profiles import make_profiles

class DualProfilesTests(unittest.TestCase):
    def test_two_inbounds_and_profile_settings(self):
        c=build_config('example.org','A'*43,'a'*16,443)
        self.assertEqual(c['log'],{'access':'none','error':'none','loglevel':'none','dnsLog':False})
        x,t=c['inbounds']; self.assertEqual(x['streamSettings']['xhttpSettings']['mode'],'stream-one'); self.assertEqual(t['port'],8443)
        for tag,group in client_groups(c).items():
            item={'id':'11111111-1111-4111-8111-111111111111','email':'phone'}
            if tag == 'vless-reality': item['flow']='xtls-rprx-vision'
            group.append(item)
        a,b=make_profiles(c,'phone','server.example.org','B'*43)
        qa,qb=parse_qs(urlsplit(a).query),parse_qs(urlsplit(b).query)
        self.assertEqual(qa['fp'],['firefox']); self.assertEqual(qa['type'],['xhttp']); self.assertNotIn('flow',qa)
        self.assertEqual(qb['flow'],['xtls-rprx-vision']); self.assertEqual(qb['fp'],['firefox'])
        self.assertEqual(parse_qs(urlsplit(make_profiles(c,'phone','server.example.org','B'*43,'chrome')[0]).query)['fp'],['chrome'])
    def test_ports_must_differ(self):
        with self.assertRaises(ValueError): build_config('example.org','A'*43,'a'*16,443,443)

if __name__ == '__main__': unittest.main()
