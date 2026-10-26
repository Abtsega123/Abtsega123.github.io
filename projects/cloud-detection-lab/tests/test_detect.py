import sys
import json
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from detect import detect,run

class TestDetect(unittest.TestCase):
    def test_fixture_finds_three_distinct_rules(self):
        alerts=run(Path(__file__).parents[1]/'examples/cloudtrail.jsonl')['alerts']
        self.assertEqual({a['rule'] for a in alerts},{'CLOUD-001','CLOUD-002','CLOUD-003'})
    def test_login_failures_outside_window(self):
        base={'eventName':'ConsoleLogin','sourceIPAddress':'198.51.100.12','userIdentity':{'arn':'arn:aws:iam::1:user/a'},'responseElements':{'ConsoleLogin':'Failure'}}
        events=[dict(base,eventTime=f'2026-10-20T12:{i:02}:00Z') for i in (0,15,30)]
        self.assertEqual(detect(events),[])
    def test_distinct_ip_buckets(self):
        base={'eventName':'ConsoleLogin','userIdentity':{'arn':'arn:aws:iam::1:user/a'},'responseElements':{'ConsoleLogin':'Failure'}}
        events=[dict(base,eventTime=f'2026-10-20T12:0{i}:00Z',sourceIPAddress=f'192.0.2.{i}') for i in range(3)]
        self.assertEqual(detect(events),[])
    def test_invalid_time_ignored(self):
        self.assertEqual(detect([{'eventTime':'bad','eventName':'ConsoleLogin','userIdentity':{'arn':'x'},'sourceIPAddress':'x'}]),[])
    def test_benign_ingress(self):
        event={'eventTime':'2026-10-20T12:00:00Z','eventName':'AuthorizeSecurityGroupIngress','userIdentity':{'arn':'x'},'sourceIPAddress':'198.51.100.2','requestParameters':{'cidrIp':'10.0.0.0/8','fromPort':22,'toPort':22}}
        self.assertEqual(detect([event]),[])
    def test_invalid_json_line_counted(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as d:
            p=Path(d)/'in.jsonl'; p.write_text('bad\n{}\n')
            self.assertEqual(run(p)['invalid_json_lines'],1)
if __name__=='__main__': unittest.main()
