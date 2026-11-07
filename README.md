# Sentinel — Agentic KYC & Identity Risk Assessment

Next.js / TypeScript frontend, FastAPI / SQLAlchemy backend, and a real nine-node LangGraph workflow. Includes onboarding, PDF/image extraction, explainable risk scoring, human review, audit logs, analytics, and PDF/CSV export.

## Local setup

Requires Node 20.9+ and Python 3.12+.

```powershell
npm ci
python -m pip install -r backend/requirements.txt
$env:JWT_SECRET = 'replace-with-a-long-random-secret'
python -m uvicorn backend.app.main:app --reload --port 8000
# Second terminal
npm run dev
```

Open http://localhost:3000. Python API docs: http://localhost:8000/docs.

Demo: **Enter demo workspace**, or `admin@sentinel.demo` / `Demo@12345`. Other demo roles: `officer@sentinel.demo`, `analyst@sentinel.demo`, `auditor@sentinel.demo`, same password. Synthetic seed data is created automatically in an empty database. Sessions last eight hours. Configure a stable JWT_SECRET across instances.

```powershell
python -m pytest backend/tests -q
npm run typecheck
npm run build
```

## Deployment

Import the repository into Vercel, framework Next.js, root directory `.`. The Python function in api/index.py serves the API. Set JWT_SECRET, DEMO_MODE=true, and DATABASE_URL to a Supabase PostgreSQL pooled connection string. Run database/schema.sql in Supabase. Credentials stay server-side.

Without DATABASE_URL, local SQLite persists locally; **Vercel SQLite is ephemeral /tmp storage and can reset between instances/deployments**. The health endpoint and settings disclose persistence mode. Vercel supports text-PDF extraction; image OCR needs Tesseract, available in backend/Dockerfile for Render deployment. render.yaml is included.

## Scope and remaining production work

This is an executable synthetic demonstration, not certified identity verification. All nine agents run deterministic Python functions; no LLM or trained anomaly model is configured. Screening uses a synthetic watchlist. A possible name match never confirms identity. Every final approval or rejection requires an authorized human.

Uploads are processed in memory and discarded; extracted fields and errors persist. Original file retention/previews, Supabase Storage/Auth, account provisioning, external LLM providers, anomaly training, scheduled retention enforcement, and password recovery infrastructure are not integrated. Data uses 15 logical record kinds in one SQLAlchemy envelope table rather than 15 normalized tables. RLS denies direct client access; authorization is enforced by the backend. Production mode supports an environment-configured administrator.

The demo is shared between demo users. Before real use, add tenant isolation, external identity management, transactional review locking, durable original storage, rate limits, managed secrets, retention jobs, and security review. No real personal data should be entered.

See docs/architecture.md, docs/deployment.md, and docs/api-documentation.md.
