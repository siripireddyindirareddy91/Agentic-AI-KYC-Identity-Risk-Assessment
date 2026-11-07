# Architecture

Browser → Next.js App Router → FastAPI → SQLAlchemy → SQLite/PostgreSQL.

LangGraph StateGraph runs Customer Profiling → Document Intelligence → Identity Verification → AML Screening → Fraud Detection → Risk Assessment → Compliance Decision Support → Human Escalation → Report Generation. Every node persists execution events. All applications end at a human checkpoint. Human decisions require officer/admin roles, a reason, and an audit record. Finalized applications cannot be rerun.

Risk categories are deduplicated and normalized, capped at 100. Assessment stores weights and timestamp. Screening uses synthetic names. PyMuPDF extracts text PDFs; Pillow/Tesseract extracts image text. Unsupported or unavailable OCR produces clear errors.

Current workflow is synchronous. Durable retries, streaming, asynchronous queues, external LLMs, trained anomaly models, normalized relational schema and tenant isolation are not implemented.
