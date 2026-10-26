import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from fastapi.testclient import TestClient
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import create_app, make_demo_token

SECRET='TEST_ONLY__'*6
class TicketAPITest(unittest.TestCase):
    def setUp(self):
        self.tmp=TemporaryDirectory()
        self.api=TestClient(create_app(database_path=str(Path(self.tmp.name)/'db.sqlite'),token_secret=SECRET))
        self.support=self.header('acme','support')
        self.other=self.header('another-company','support')
    def tearDown(self):
        self.api.close();self.tmp.cleanup()
    def header(self,tenant='acme',role='viewer',expires=None):
        token=make_demo_token(secret=SECRET,sub='synthetic-user',tenant=tenant,role=role,expires_at=expires or (int(time.time())+120))
        return {'Authorization':'Bearer '+token}
    def create(self,title='Simulated security ticket'):
        return self.api.post('/v1/tickets',json={'title':title,'description':'synthetic evidence'},headers=self.support)
    def test_healthy_and_hardened_headers(self):
        r=self.api.get('/health');self.assertEqual(r.status_code,200)
        self.assertEqual(r.headers['x-content-type-options'],'nosniff')
    def test_missing_token(self): self.assertEqual(self.api.get('/v1/tickets/TKT-123').status_code,401)
    def test_viewer_cannot_create(self):
        self.assertEqual(self.api.post('/v1/tickets',headers=self.header(),json={'title':'A real title','description':''}).status_code,403)
    def test_creates_and_reads_own_tenant(self):
        r=self.create();self.assertEqual(r.status_code,201)
        ticket_id=r.json()['id'];get=self.api.get('/v1/tickets/'+ticket_id,headers=self.support)
        self.assertEqual(get.status_code,200)
        self.assertEqual(get.json()['tenant'],'acme')
    def test_cross_tenant_idor_prevented(self):
        ticket_id=self.create().json()['id']
        self.assertEqual(self.api.get('/v1/tickets/'+ticket_id,headers=self.other).status_code,404)
    def test_tampered_token_rejected(self):
        header=self.header();header['Authorization']+='x'
        self.assertEqual(self.api.get('/v1/tickets/abc',headers=header).status_code,401)
    def test_expired_token_rejected(self):
        hdr=self.header(expires=int(time.time())-100)
        self.assertEqual(self.api.get('/v1/tickets/abc',headers=hdr).status_code,401)
    def test_title_validation(self):
        self.assertEqual(self.create(title='A').status_code,422)
    def test_parameterized_query(self):
        ticket_id=self.create().json()['id']
        bad=self.api.get("/v1/tickets/"+"%27%20OR%201%3D1--",headers=self.other)
        self.assertEqual(bad.status_code,404)
        self.assertEqual(self.api.get('/v1/tickets/'+ticket_id,headers=self.support).status_code,200)
    def test_no_reflection_of_auth_token(self):
        r=self.api.get('/v1/tickets/missing',headers=self.support)
        self.assertNotIn(self.support['Authorization'].split(' ')[1],r.text)
if __name__=='__main__':unittest.main()
