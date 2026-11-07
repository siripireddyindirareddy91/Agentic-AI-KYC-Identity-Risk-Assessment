# API reference

OpenAPI: /docs on the Python server. All /api endpoints except health/login require Authorization: Bearer TOKEN.

- POST /api/auth/login; GET /api/auth/me
- GET/POST /api/customers; GET/PUT/DELETE /api/customers/{id}
- GET/POST /api/kyc/applications; GET /api/kyc/applications/{id}; POST .../{id}/submit and verify
- POST /api/documents/upload (multipart application_id and file); GET /api/documents and /api/documents/{id}; POST .../{id}/process
- POST /api/agents/run/{id}; GET /api/agents/executions/{id} and /api/agents/status
- GET /api/risk/{id}; POST /api/risk/assess/{id}
- GET /api/reviews/pending; POST /api/reviews/{id}/{approve|reject|request-documents|escalate} with reason of at least 10 characters
- GET /api/reports/dashboard, /api/reports/kyc, /api/reports/export?format=csv|pdf&application_id=optional
- GET /api/audit-logs, /api/notifications; PUT /api/notifications/{id}
- GET/PUT /api/settings (admin required for PUT)
