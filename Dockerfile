FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ ./backend/
COPY eval/ ./eval/
COPY demo/ ./demo/
COPY frontend/ ./frontend/

# Create data directory for SQLite databases
RUN mkdir -p /app/backend/data

# Render sets $PORT — default 8000 for local dev
ENV PORT=8000
ENV KYA_SIGNING_SECRET=""
ENV KYA_DEMO_ISSUER_KEY=""
ENV KYA_LOG_LEVEL="INFO"
ENV KYA_PAYMENT_PROVIDER="mock"
ENV KYA_IDENTITY_MODE="hmac"
ENV KYA_INTENT_CLASSIFIER="keyword"
ENV KYA_RISK_MODEL="basic"

EXPOSE 8000

# Use shell form so $PORT is expanded at runtime
CMD uvicorn backend.main:app --host 0.0.0.0 --port ${PORT} --workers 1
