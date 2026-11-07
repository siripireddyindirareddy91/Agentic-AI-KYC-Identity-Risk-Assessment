import os, io, json, uuid, time, hashlib, secrets, csv, re
from datetime import datetime, timezone, timedelta, date
from difflib import SequenceMatcher
from typing import TypedDict
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Request
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, String, Text, DateTime, select
from sqlalchemy.orm import declarative_base, sessionmaker
import jwt, bcrypt
from langgraph.graph import StateGraph, END

DEMO = os.getenv('DEMO_MODE', 'true').lower() == 'true'
SECRET = os.getenv('JWT_SECRET') or secrets.token_hex(32)
if not DEMO and not os.getenv('JWT_SECRET'): raise RuntimeError('JWT_SECRET required outside demo mode')
DB = os.getenv('DATABASE_URL') or ('sqlite:////tmp/sentinel.db' if os.getenv('VERCEL') else 'sqlite:///./sentinel.db')
if DB.startswith('postgres://'): DB = DB.replace('postgres://', 'postgresql://', 1)
engine = create_engine(DB, connect_args={'check_same_thread':False} if DB.startswith('sqlite') else {}, pool_pre_ping=True)
Session = sessionmaker(engine)
Base = declarative_base()
class Record(Base):
    __tablename__ = 'records'
    id = Column(String, primary_key=True)
    kind = Column(String, index=True, nullable=False)
    data = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
Base.metadata.create_all(engine)
def now(): return datetime.now(timezone.utc).isoformat()
def put(kind, data, id=None):
    id = id or data.get('id') or str(uuid.uuid4())
    data = {**data, 'id':id, 'updated_at':now()}
    with Session.begin() as s:
        row = s.get(Record,id)
        if row: row.data = json.dumps(data)
        else: s.add(Record(id=id,kind=kind,data=json.dumps(data)))
    return data
def items(kind):
    with Session() as s: return [json.loads(r.data) for r in s.scalars(select(Record).where(Record.kind==kind)).all()]
def get(id, kind=None):
    with Session() as s:
        r=s.get(Record,id)
        if not r or (kind and r.kind != kind): raise HTTPException(404,'Record not found')
        return json.loads(r.data)
def audit(actor,action,target): put('audit_logs',{'actor':actor['email'],'action':action,'target':target,'timestamp':now()})
def notify(title,application_id): put('notifications',{'title':title,'application_id':application_id,'read':False,'timestamp':now()})
DEFAULT_WEIGHTS={'mismatch':25,'expired':15,'duplicate':20,'incomplete':10,'screening':20,'suspicious':10}
AGENTS=['Customer Profiling','Document Intelligence','Identity Verification','AML & Sanctions Screening','Fraud Detection','Identity Risk Assessment','Compliance Decision Support','Human Escalation','Report Generation']
def settings():
    rows=items('system_settings')
    return rows[0] if rows else {'weights':DEFAULT_WEIGHTS,'organization':'Sentinel Financial','retention_days':90,'screening_source':'Synthetic demonstration watchlist v1'}
def score_risk(findings,weights):
    unique={f['factor'] for f in findings if f.get('factor') in weights}
    score=min(100,round(sum(weights[k] for k in unique)*100/max(100,sum(weights.values()))))
    return {'score':score,'level':'Critical' if score>=80 else 'High' if score>=60 else 'Medium' if score>=30 else 'Low','breakdown':[{'factor':k,'points':weights[k]} for k in sorted(unique)],'assessed_at':now(),'weights':weights}
class State(TypedDict):
    application:dict
    customer:dict
    findings:list
    executions:list
    risk:dict
def node(index):
    def execute(state):
        start=time.perf_counter(); a=state['application']; c=state['customer']; fs=list(state['findings']); output=''
        def finding(factor,message): fs.append({'factor':factor,'message':message,'agent':AGENTS[index]})
        if index==0:
            missing=[k for k in ['name','dob','email','phone','address','country'] if not c.get(k)]
            if missing: finding('incomplete','Missing profile fields: '+', '.join(missing))
            output='Validated profile; '+str(len(missing))+' missing fields'
        elif index==1:
            docs=[d for d in items('identity_documents') if d['application_id']==a['id']]
            if not docs: finding('incomplete','No identity documents uploaded')
            for d in docs:
                if d.get('processing_error'): finding('incomplete',d['processing_error'])
                fields=d.get('extracted',{})
                if fields.get('name') and SequenceMatcher(None,fields['name'].casefold(),c['name'].casefold()).ratio()<0.85: finding('mismatch','Extracted name differs from submitted name')
                if fields.get('dob') and fields['dob']!=c.get('dob'): finding('mismatch','Extracted date of birth differs from profile')
                if not fields: finding('incomplete','OCR fields unavailable; manual document review needed')
            output=f'Inspected {len(docs)} document records. OCR does not prove authenticity.'
        elif index==2:
            if a.get('expiry') and a['expiry']<date.today().isoformat(): finding('expired','Declared identity document has expired')
            if a.get('issue_date') and a.get('expiry') and a['issue_date']>a['expiry']: finding('mismatch','Issue date follows expiry date')
            if not a.get('document_hash'): finding('incomplete','Document number missing')
            output='Checked document dates and identity field completeness'
        elif index==3:
            candidates=['Alex Morgan Demo','Jordan Ellis Demo','Taylor Quinn Demo']
            matches=[{'name':n,'confidence':round(SequenceMatcher(None,c['name'].lower(),n.lower()).ratio(),3)} for n in candidates]
            matches=[m for m in matches if m['confidence']>=0.8]
            if matches: finding('screening','Possible synthetic watchlist name match; requires investigation, not identity confirmation')
            put('screening_results',{'application_id':a['id'],'matches':matches,'source':'Synthetic demonstration watchlist v1','timestamp':now()})
            output=f'{len(matches)} possible matches against synthetic dataset only'
        elif index==4:
            duplicates=[x for x in items('kyc_applications') if x['id']!=a['id'] and a.get('document_hash') and x.get('document_hash')==a['document_hash']]
            if duplicates: finding('duplicate','Document identifier also appears in another application')
            output=f'{len(duplicates)} duplicate document indicators; no trained anomaly model configured'
        elif index==5:
            state['risk']=score_risk(fs,settings()['weights']); output=f"Reproducible rule score: {state['risk']['score']}/100"
            put('risk_assessments',{**state['risk'],'application_id':a['id']},'risk-'+a['id'])
        elif index==6:
            output='Recommendation: human review required before any final approval or rejection'
        elif index==7:
            existing=[r for r in items('human_review_tasks') if r['application_id']==a['id'] and r['status']=='Pending']
            if not existing: put('human_review_tasks',{'application_id':a['id'],'customer_id':c['id'],'name':c['name'],'status':'Pending','risk':state['risk'],'created_at':now()})
            output='Application routed to an authorized human reviewer'
        else: output='Structured investigation report generated; PDF available on request'
        event={'application_id':a['id'],'agent':AGENTS[index],'status':'Completed','duration_ms':round((time.perf_counter()-start)*1000,2),'output':output,'timestamp':now()}
        put('agent_executions',event)
        return {**state,'findings':fs,'executions':state['executions']+[event]}
    return execute
graph=StateGraph(State)
for i in range(9): graph.add_node(str(i),node(i))
graph.set_entry_point('0')
for i in range(8): graph.add_edge(str(i),str(i+1))
graph.add_edge('8',END)
workflow=graph.compile()
def run(a,actor):
    if a['status'] in ['Approved','Rejected']: raise HTTPException(409,'Finalized applications cannot be rerun')
    result=workflow.invoke({'application':a,'customer':get(a['customer_id'],'customers'),'findings':[],'executions':[],'risk':{}})
    a=put('kyc_applications',{**a,'status':'Human Review','risk':result['risk'],'findings':result['findings'],'last_run':now()})
    put('verification_results',{'application_id':a['id'],'findings':result['findings'],'risk':result['risk']},'verification-'+a['id'])
    audit(actor,'Verification workflow completed',a['id']); notify('Human review required',a['id'])
    return a
def seed():
    if items('customers'): return
    put('system_settings',settings(),'settings')
    names=['Alex Morgan Demo','Priya Sharma Demo','Liam Anderson Demo','Sofia Chen Demo','Jordan Ellis Demo','Aarav Patel Demo','Emma Wilson Demo','Oliver Brown Demo','Taylor Quinn Demo','Noah Williams Demo','Isabella Garcia Demo','Ethan Davis Demo','Mia Martinez Demo','Lucas Robinson Demo','Amelia Clark Demo','James Lewis Demo','Charlotte Walker Demo','Benjamin Hall Demo','Harper Young Demo','Henry King Demo']
    actor={'email':'system@sentinel.demo'}
    for i,name in enumerate(names):
        c=put('customers',{'name':name,'email':f'customer{i+1}@example.invalid','dob':'1990-05-15','phone':'+1 202 555 01'+str(i).zfill(2),'address':f'{i+10} Synthetic Avenue','city':'Demo City','country':['India','United States','United Kingdom','Singapore'][i%4],'nationality':'Demo','occupation':'Professional','customer_type':'Individual','synthetic':True,'created_at':(datetime.now(timezone.utc)-timedelta(days=20-i)).isoformat()})
        a=put('kyc_applications',{'customer_id':c['id'],'name':name,'status':'Draft','document_type':'Passport','document_hash':hashlib.sha256(f'SYNTHETIC-{i if i!=6 else 1}'.encode()).hexdigest(),'document_last4':f'{i:04}','expiry':'2020-01-01' if i%3==0 else '2030-01-01','consent':True,'synthetic':True,'created_at':c['created_at']})
        for j in range(2 if i<10 else 1): put('identity_documents',{'application_id':a['id'],'name':f'synthetic-identity-{i+1}-{j+1}.txt','mime':'text/plain','size':120,'extracted':{'name':'Different Demo Name' if i%5==0 else name,'dob':c['dob']},'confidence':1.0,'synthetic':True,'status':'Processed','created_at':now()})
        a=run(a,actor)
        if i>7:
            put('kyc_applications',{**a,'status':'Approved' if i%4 else 'Rejected'})
            for r in items('human_review_tasks'):
                if r['application_id']==a['id']:
                    put('human_review_tasks',{**r,'status':'Completed'})
                    put('reviewer_decisions',{'application_id':a['id'],'reviewer':'Synthetic reviewer','action':'approve' if i%4 else 'reject','reason':'Synthetic seed decision for demonstration only','timestamp':now()})
seed()
app=FastAPI(title='Sentinel KYC API',version='1.0.0')
app.add_middleware(CORSMiddleware,allow_origins=os.getenv('CORS_ORIGINS','http://localhost:3000').split(','),allow_credentials=True,allow_methods=['*'],allow_headers=['*'])
security=HTTPBearer(auto_error=False)
def user(auth:HTTPAuthorizationCredentials=Depends(security)):
    if not auth: raise HTTPException(401,'Authentication required')
    try: return jwt.decode(auth.credentials,SECRET,algorithms=['HS256'])
    except jwt.PyJWTError: raise HTTPException(401,'Session expired; sign in again')
def writer(u=Depends(user)):
    if u['role'] not in ['Admin','Compliance Officer','KYC Analyst']: raise HTTPException(403,'Write access required')
    return u
class Login(BaseModel):
    email:str
    password:str
class Customer(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    email:str=Field(pattern=r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
    dob:str=''
    phone:str=''
    address:str=''
    city:str=''
    state:str=''
    postal_code:str=''
    country:str=''
    nationality:str=''
    occupation:str=''
    customer_type:str='Individual'
class Application(BaseModel):
    customer_id:str
    document_type:str='Passport'
    document_number:str=Field(default='',max_length=100)
    expiry:str=''
    issue_date:str=''
    issuing_country:str=''
    consent:bool=False
class Decision(BaseModel):
    reason:str=Field(min_length=10,max_length=2000)
class Settings(BaseModel):
    organization:str=Field(min_length=2,max_length=120)
    weights:dict[str,int]
    retention_days:int=Field(ge=1,le=3650)
    screening_source:str='Synthetic demonstration watchlist v1'
@app.get('/api/health')
def health(): return {'status':'ok','demo':DEMO,'persistence':'ephemeral' if os.getenv('VERCEL') and DB.startswith('sqlite') else 'durable','llm':'deterministic Python fallback','screening':'synthetic dataset only'}
@app.post('/api/auth/login')
def login(body:Login):
    roles={'admin@sentinel.demo':'Admin','officer@sentinel.demo':'Compliance Officer','analyst@sentinel.demo':'KYC Analyst','auditor@sentinel.demo':'Read Only Auditor'}
    valid=DEMO and body.email in roles and secrets.compare_digest(body.password,'Demo@12345')
    if not DEMO: valid=body.email==os.getenv('ADMIN_EMAIL') and bool(os.getenv('ADMIN_PASSWORD')) and secrets.compare_digest(body.password,os.getenv('ADMIN_PASSWORD',''))
    if not valid: raise HTTPException(401,'Invalid email or password')
    u={'email':body.email,'role':roles.get(body.email,'Admin'),'exp':datetime.now(timezone.utc)+timedelta(hours=8)}
    return {'token':jwt.encode(u,SECRET,algorithm='HS256'),'user':{'email':u['email'],'role':u['role']}}
@app.get('/api/auth/me')
def me(u=Depends(user)): return u
@app.get('/api/customers')
def customers(u=Depends(user)): return [c for c in items('customers') if not c.get('archived')]
@app.post('/api/customers')
def create_customer(body:Customer,u=Depends(writer)):
    c=put('customers',{**body.model_dump(),'synthetic':DEMO,'created_at':now()}); audit(u,'Customer registered',c['id']); return c
@app.get('/api/customers/{id}')
def customer(id:str,u=Depends(user)): return get(id,'customers')
@app.put('/api/customers/{id}')
def edit_customer(id:str,body:Customer,u=Depends(writer)):
    c=put('customers',{**get(id,'customers'),**body.model_dump()}); audit(u,'Customer updated',id); return c
@app.delete('/api/customers/{id}')
def archive_customer(id:str,u=Depends(writer)):
    if u['role']!='Admin': raise HTTPException(403,'Administrator required')
    c=put('customers',{**get(id,'customers'),'archived':True}); audit(u,'Customer archived',id); return c
@app.get('/api/kyc/applications')
def applications(u=Depends(user)): return items('kyc_applications')
@app.post('/api/kyc/applications')
def create_application(body:Application,u=Depends(writer)):
    c=get(body.customer_id,'customers')
    if not body.consent: raise HTTPException(422,'Customer consent is required')
    data=body.model_dump(); number=data.pop('document_number')
    a=put('kyc_applications',{**data,'document_hash':hashlib.sha256(number.strip().upper().encode()).hexdigest() if number else None,'document_last4':number[-4:],'name':c['name'],'status':'Draft','created_at':now(),'synthetic':DEMO})
    audit(u,'Application created',a['id']); return a
@app.get('/api/kyc/applications/{id}')
def application(id:str,u=Depends(user)): return get(id,'kyc_applications')
@app.post('/api/kyc/applications/{id}/submit')
@app.post('/api/kyc/applications/{id}/verify')
@app.post('/api/agents/run/{id}')
def verify(id:str,u=Depends(writer)): return run(get(id,'kyc_applications'),u)
@app.get('/api/agents/executions/{id}')
def executions(id:str,u=Depends(user)): return [e for e in items('agent_executions') if e['application_id']==id]
@app.get('/api/agents/status')
def agents(u=Depends(user)):
    all=items('agent_executions')
    return [{'name':n,'tasks':len([e for e in all if e['agent']==n]),'last':next((e for e in reversed(all) if e['agent']==n),None)} for n in AGENTS]
def extract(content,mime):
    if mime=='application/pdf':
        import fitz
        with fitz.open(stream=content,filetype='pdf') as pdf:
            if len(pdf)>20: raise ValueError('Maximum 20 PDF pages')
            text='\n'.join(p.get_text() for p in pdf)
        if not text.strip(): raise ValueError('Scanned PDF needs OCR; upload a clear image for local Tesseract processing')
        confidence=1.0
    elif mime.startswith('image/'):
        from PIL import Image
        import pytesseract
        Image.MAX_IMAGE_PIXELS=20_000_000
        image=Image.open(io.BytesIO(content)); image.verify(); image=Image.open(io.BytesIO(content)).convert('L')
        data=pytesseract.image_to_data(image,output_type=pytesseract.Output.DICT,timeout=20)
        text=' '.join(t for t in data['text'] if t.strip()); conf=[float(c) for c in data['conf'] if float(c)>=0]; confidence=sum(conf)/len(conf)/100 if conf else 0
    else: raise ValueError('Unsupported content')
    fields={}
    for key,pattern in {'name':r'(?:Full Name|Name)\s*[:\-]\s*([^\n]+)','dob':r'(?:DOB|Date of Birth)\s*[:\-]\s*(\d{4}-\d{2}-\d{2})','expiry':r'(?:Expiry|Expiration)\s*[:\-]\s*(\d{4}-\d{2}-\d{2})'}.items():
        match=re.search(pattern,text,re.I)
        if match: fields[key]=match.group(1).strip()[:100]
    return fields,confidence
@app.post('/api/documents/upload')
async def upload(application_id:str=Form(...),file:UploadFile=File(...),u=Depends(writer)):
    get(application_id,'kyc_applications')
    content=await file.read(10*1024*1024+1)
    if len(content)>10*1024*1024: raise HTTPException(413,'Maximum upload is 10 MB')
    mime=file.content_type or ''
    if mime not in ['application/pdf','image/jpeg','image/png']: raise HTTPException(415,'Only PDF, JPEG and PNG accepted')
    error=None; fields={}; confidence=0
    try: fields,confidence=extract(content,mime)
    except Exception as e: error='Document processing unavailable: '+str(e)[:180]
    # Original bytes are not retained in demo mode; extracted evidence is persisted.
    d=put('identity_documents',{'application_id':application_id,'name':os.path.basename(file.filename or 'document'),'mime':mime,'size':len(content),'sha256':hashlib.sha256(content).hexdigest(),'extracted':fields,'confidence':confidence,'processing_error':error,'status':'Processing Error' if error else 'Processed','created_at':now(),'storage':'Original not retained in demonstration mode'})
    audit(u,'Document processed' if not error else 'Document processing failed',d['id']); return d
@app.get('/api/documents')
def documents(u=Depends(user)): return items('identity_documents')
@app.get('/api/documents/{id}')
def document(id:str,u=Depends(user)): return get(id,'identity_documents')
@app.post('/api/documents/{id}/process')
def process(id:str,u=Depends(writer)):
    d=get(id,'identity_documents')
    if d.get('processing_error'): raise HTTPException(409,'Re-upload the original document to retry processing')
    return d
@app.get('/api/risk/{id}')
def risk(id:str,u=Depends(user)): return get(id,'kyc_applications').get('risk',{})
@app.post('/api/risk/assess/{id}')
def assess(id:str,u=Depends(writer)): return verify(id,u)['risk']
@app.get('/api/reviews/pending')
def reviews(u=Depends(user)): return [r for r in items('human_review_tasks') if r['status']=='Pending']
@app.post('/api/reviews/{id}/{action}')
def decision(id:str,action:str,body:Decision,u=Depends(user)):
    if u['role'] not in ['Admin','Compliance Officer']: raise HTTPException(403,'Authorized compliance reviewer required')
    statuses={'approve':'Approved','reject':'Rejected','request-documents':'Additional Documents','escalate':'Escalated'}
    if action not in statuses: raise HTTPException(400,'Unknown review action')
    r=get(id,'human_review_tasks')
    if r['status']!='Pending': raise HTTPException(409,'Review already resolved')
    a=get(r['application_id'],'kyc_applications')
    put('kyc_applications',{**a,'status':statuses[action]}); put('human_review_tasks',{**r,'status':'Completed','decision':action})
    d=put('reviewer_decisions',{'application_id':a['id'],'reviewer':u['email'],'reason':body.reason,'action':action,'timestamp':now()})
    audit(u,'Review decision: '+action,a['id']); notify('Review decision: '+statuses[action],a['id']); return d
@app.get('/api/reports/dashboard')
def dashboard(u=Depends(user)):
    apps=items('kyc_applications'); executions=items('agent_executions')
    return {'customers':len([c for c in items('customers') if not c.get('archived')]),'applications':len(apps),'approved':sum(a['status']=='Approved' for a in apps),'pending':sum(a['status'] in ['Human Review','Draft','Escalated','Additional Documents'] for a in apps),'high_risk':sum(a.get('risk',{}).get('score',0)>=60 for a in apps),'rejected':sum(a['status']=='Rejected' for a in apps),'avg_ms':round(sum(e['duration_ms'] for e in executions)/max(1,len(apps)),1),'risk_distribution':[{'name':n,'value':sum(a.get('risk',{}).get('level')==n for a in apps)} for n in ['Low','Medium','High','Critical']],'trends':[{'date':(datetime.now(timezone.utc)-timedelta(days=i)).strftime('%d %b'),'applications':sum(a['created_at'][:10]==(datetime.now(timezone.utc)-timedelta(days=i)).date().isoformat() for a in apps)} for i in reversed(range(21))]}
@app.get('/api/reports/kyc')
def reports(u=Depends(user)): return items('verification_results')
@app.get('/api/reports/export')
def export(format:str='csv',application_id:str|None=None,u=Depends(user)):
    apps=items('kyc_applications')
    if application_id: apps=[get(application_id,'kyc_applications')]
    if format=='pdf':
        from reportlab.pdfgen import canvas
        buffer=io.BytesIO(); pdf=canvas.Canvas(buffer)
        for a in apps:
            pdf.setFont('Helvetica-Bold',16); pdf.drawString(45,800,'SENTINEL | KYC Investigation Report')
            pdf.setFont('Helvetica',10); lines=['SYNTHETIC DEMONSTRATION - decision support only',a['name'],'Application: '+a['id'],'Status: '+a['status'],'Risk: '+str(a.get('risk',{}).get('score','Unassessed'))+'/100']+[f['message'] for f in a.get('findings',[])]
            for i,line in enumerate(lines): pdf.drawString(45,765-i*22,line[:110])
            pdf.showPage()
        pdf.save(); return Response(buffer.getvalue(),media_type='application/pdf',headers={'Content-Disposition':'attachment; filename=sentinel-report.pdf'})
    buffer=io.StringIO(); w=csv.writer(buffer); w.writerow(['Application','Customer','Status','Risk score','Risk level'])
    for a in apps:
        name=a['name']; name="'"+name if name.startswith(('=','+','-','@')) else name
        w.writerow([a['id'],name,a['status'],a.get('risk',{}).get('score'),a.get('risk',{}).get('level')])
    return Response(buffer.getvalue(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=sentinel-report.csv'})
@app.get('/api/audit-logs')
def logs(u=Depends(user)): return list(reversed(items('audit_logs')))
@app.get('/api/notifications')
def notifications(u=Depends(user)): return list(reversed(items('notifications')))
@app.put('/api/notifications/{id}')
def read_notification(id:str,u=Depends(user)): return put('notifications',{**get(id,'notifications'),'read':True})
@app.get('/api/settings')
def read_settings(u=Depends(user)): return settings()
@app.put('/api/settings')
def save_settings(body:Settings,u=Depends(user)):
    if u['role']!='Admin': raise HTTPException(403,'Administrator required')
    if set(body.weights)!=set(DEFAULT_WEIGHTS) or any(w<0 or w>100 for w in body.weights.values()): raise HTTPException(422,'Provide all six weights in range 0–100')
    audit(u,'Risk policy updated','settings'); return put('system_settings',body.model_dump(),'settings')
