import os
os.environ['DATABASE_URL']='sqlite:///./test-sentinel.db'
os.environ['JWT_SECRET']='test-secret-only-not-for-production-1234567890'
from fastapi.testclient import TestClient
from backend.app.main import app, score_risk, DEFAULT_WEIGHTS, extract
client=TestClient(app)
def auth(email='admin@sentinel.demo'):
 r=client.post('/api/auth/login',json={'email':email,'password':'Demo@12345'}); assert r.status_code==200
 return {'Authorization':'Bearer '+r.json()['token']}
def test_authentication_required(): assert client.get('/api/customers').status_code==401
def test_invalid_credentials(): assert client.post('/api/auth/login',json={'email':'admin@sentinel.demo','password':'bad'}).status_code==401
def test_seed_counts():
 h=auth(); assert len(client.get('/api/customers',headers=h).json())>=32
 assert len(client.get('/api/documents',headers=h).json())>=54
 assert len(client.get('/api/reviews/pending',headers=h).json())>=5
def test_expanded_seed_has_critical_case_and_is_idempotent():
 from backend.app.main import seed, seed_id
 h=auth(); before=len(client.get('/api/customers',headers=h).json()); seed()
 assert len(client.get('/api/customers',headers=h).json())==before
 case=client.get('/api/kyc/applications/'+seed_id('application',20),headers=h).json()
 assert case['risk']['level']=='Critical' and case['status']=='Human Review'
 assert {f['factor'] for f in case['findings']}=={'mismatch','expired','duplicate','incomplete','screening'}
def test_risk_deduplicates_and_caps():
 assert score_risk([{'factor':'mismatch'}]*4,DEFAULT_WEIGHTS)['score']==25
 assert score_risk([{'factor':f} for f in DEFAULT_WEIGHTS],DEFAULT_WEIGHTS)['score']==100
def test_risk_categories():
 for score,level in [(0,'Low'),(30,'Medium'),(60,'High'),(80,'Critical')]:
  assert score_risk([{'factor':'mismatch'}],{**{k:0 for k in DEFAULT_WEIGHTS},'mismatch':score})['level']==level
def test_end_to_end_human_review():
 h=auth(); c=client.post('/api/customers',headers=h,json={'name':'Integration Synthetic','email':'integration@example.invalid','dob':'1990-01-01','phone':'000','address':'Synthetic road','country':'India'}).json()
 a=client.post('/api/kyc/applications',headers=h,json={'customer_id':c['id'],'consent':True,'document_number':'TEST-ONLY','expiry':'2020-01-01'}).json()
 r=client.post('/api/kyc/applications/'+a['id']+'/verify',headers=h); assert r.status_code==200
 assert r.json()['status']=='Human Review'; assert any(f['factor']=='expired' for f in r.json()['findings'])
 assert len(client.get('/api/agents/executions/'+a['id'],headers=h).json())==9
 review=next(x for x in client.get('/api/reviews/pending',headers=h).json() if x['application_id']==a['id'])
 assert client.post('/api/reviews/'+review['id']+'/approve',headers=auth('analyst@sentinel.demo'),json={'reason':'Analyst cannot approve this case'}).status_code==403
 assert client.post('/api/reviews/'+review['id']+'/approve',headers=h,json={'reason':'Manually inspected synthetic evidence'}).status_code==200
 assert client.post('/api/reviews/'+review['id']+'/reject',headers=h,json={'reason':'Repeated review must be blocked'}).status_code==409
 assert client.post('/api/kyc/applications/'+a['id']+'/verify',headers=h).status_code==409
def test_read_only_cannot_write(): assert client.post('/api/customers',headers=auth('auditor@sentinel.demo'),json={'name':'Test','email':'test@example.invalid'}).status_code==403
def test_consent_required():
 h=auth(); c=client.get('/api/customers',headers=h).json()[0]
 assert client.post('/api/kyc/applications',headers=h,json={'customer_id':c['id'],'consent':False}).status_code==422
def test_document_types():
 h=auth(); a=client.get('/api/kyc/applications',headers=h).json()[0]
 assert client.post('/api/documents/upload',headers=h,data={'application_id':a['id']},files={'file':('bad.exe',b'bad','application/octet-stream')}).status_code==415
def test_pdf_extraction():
 import fitz
 pdf=fitz.open(); p=pdf.new_page(); p.insert_text((40,40),'Name: Test Synthetic\nDOB: 1990-01-01'); raw=pdf.tobytes();pdf.close()
 fields,confidence=extract(raw,'application/pdf'); assert fields['name']=='Test Synthetic' and fields['dob']=='1990-01-01' and confidence==1
def test_exports():
 h=auth(); assert client.get('/api/reports/export?format=pdf',headers=h).content.startswith(b'%PDF')
 assert 'Application,Customer' in client.get('/api/reports/export',headers=h).text
def test_policy_admin_only():
 h=auth('officer@sentinel.demo'); policy=client.get('/api/settings',headers=h).json()
 assert client.put('/api/settings',headers=h,json=policy).status_code==403
