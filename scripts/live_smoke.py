"""Verify a protected deployment using authenticated Vercel CLI. Never prints tokens."""
import json, os, subprocess
URL='https://agentic-ai-kyc-identity-risk-assess.vercel.app'
env={**os.environ,'PATH':r'C:\Program Files\Git\mingw64\bin;'+os.environ['PATH']}
def request(path, method='GET', body=None, token=None):
 args=['vercel.cmd','curl',path,'--deployment',URL,'--','--silent','--show-error','-X',method]
 if body is not None: args+=['-H','Content-Type: application/json','--data',json.dumps(body)]
 if token: args+=['-H','Authorization: Bearer '+token]
 r=subprocess.run(args,capture_output=True,text=True,env=env,check=True)
 try: return json.loads(r.stdout)
 except ValueError: raise RuntimeError('Non-JSON response: '+r.stdout[:200])
h=request('/api/health'); assert h['status']=='ok'; print('PASS health: '+h['persistence'])
l=request('/api/auth/login','POST',{'email':'admin@sentinel.demo','password':'Demo@12345'})
assert 'token' in l, str(l); print('PASS demo login')
t=l['token']
for path in ['/auth/me','/customers','/kyc/applications','/documents','/reviews/pending','/agents/status','/reports/dashboard','/settings','/audit-logs','/notifications']:
 r=request('/api'+path,token=t)
 assert not isinstance(r,dict) or 'detail' not in r, str(r)
 print('PASS '+path)
