# Deployment

1. Import the GitHub repository into Vercel, framework Next.js, root `.`.
2. Set a stable cryptographically random JWT_SECRET, DEMO_MODE=true.
3. For durable data create a Supabase project, apply database/schema.sql, and set DATABASE_URL to a pooled PostgreSQL URL (URL-encode passwords).
4. Deploy. Check /api/health, sign in, submit a synthetic application, review, and export.
5. For image OCR deploy backend/Dockerfile on Render; it installs Tesseract. Set frontend API_URL and replace the Vercel API rewrite with the Render backend URL. Configure CORS_ORIGINS.

Vercel-only limitations: SQLite is ephemeral, Tesseract is unavailable, cold starts seed synthetic data. Supabase Auth/Storage are not integrated. Do not ingest real identities without completing production storage and security work.
