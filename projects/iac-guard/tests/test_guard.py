import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from guard import scan_text, scan_directory, sarif_output

class TestGuard(unittest.TestCase):
    def test_insecure_fixture(self):
        source=(Path(__file__).parents[1]/'examples/insecure.tf').read_text()
        findings=scan_text(source)
        self.assertEqual([f.rule for f in findings], ['IAC-001','IAC-002','IAC-004','IAC-005'])
        self.assertTrue(all(f.line>0 for f in findings))
    def test_hardened_fixture(self):
        self.assertEqual(scan_directory(Path(__file__).parents[1]/'examples/hardened.tf'),[])
    def test_comments_are_ignored(self):
        self.assertEqual(scan_text('''# resource "aws_s3_bucket" "a" { acl = "public-read" }\n/* resource "aws_db_instance" "db" { publicly_accessible = true } */'''),[])
    def test_string_with_braces(self):
        self.assertEqual(scan_text('resource "aws_ebs_volume" "x" { tags = { Name = "hello } world" } encrypted = false }')[0].rule,'IAC-005')
    def test_missing_resource_no_findings(self):
        self.assertEqual(scan_text('variable "token" { default = "secret" }'),[])
    def test_sarif_format(self):
        data=sarif_output(scan_text('resource "aws_db_instance" "db" { publicly_accessible = true }'))
        self.assertEqual(data['version'],'2.1.0')
        self.assertEqual(data['runs'][0]['results'][0]['ruleId'],'IAC-004')
if __name__=='__main__': unittest.main()
