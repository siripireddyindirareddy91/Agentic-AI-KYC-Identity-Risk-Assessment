-- Fifteen logical record kinds share a server-only SQLAlchemy JSON envelope.
create table if not exists public.records (
 id text primary key,
 kind text not null,
 data text not null,
 created_at timestamptz not null default now(),
 constraint known_record_kind check (kind in ('profiles','customers','kyc_applications','identity_documents','document_extractions','verification_results','agent_executions','agent_findings','risk_assessments','screening_results','human_review_tasks','reviewer_decisions','audit_logs','notifications','system_settings'))
);
create index if not exists records_kind_idx on public.records(kind);
alter table public.records enable row level security;
revoke all on public.records from anon, authenticated;
-- Only the backend database owner can access these records. No browser service key.
