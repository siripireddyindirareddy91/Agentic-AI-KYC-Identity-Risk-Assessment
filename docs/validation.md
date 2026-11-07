# Validation

- Backend regression suite covers auth, invalid credentials, expanded seed volume and idempotency, critical-risk evidence, score deduplication/capping, category boundaries, end-to-end workflow, human approval, analyst denial, repeat-decision blocking, finalized-run blocking, auditor write denial, consent, document MIME validation, actual PDF extraction, PDF/CSV export, and admin-only settings.
- Next.js production build passed on Windows with filesystem escalation. TypeScript passed as part of the build.
- Vercel Linux deployment reached READY; protected live /api/health returned status ok.
- Browser demo login and narrow-screen layout were inspected. Live authenticated smoke checks passed for all ten primary read endpoints. No Supabase credentials were supplied; live Supabase integration remains unverified.
