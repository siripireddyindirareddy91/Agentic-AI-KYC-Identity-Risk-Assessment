# Validation

- 12 backend pytest tests passed: auth, invalid credentials, seed volume, score deduplication/capping, category boundaries, end-to-end workflow, human approval, analyst denial, repeat-decision blocking, finalized-run blocking, auditor write denial, consent, document MIME validation, actual PDF extraction, PDF/CSV export, admin-only settings.
- Next.js production build passed on Windows with filesystem escalation. TypeScript passed as part of the build.
- Vercel Linux deployment reached READY; protected live /api/health returned status ok.
- Browser visual QA and live Supabase integration have not been verified. No Supabase credentials were supplied.
