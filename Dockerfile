FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY eval/ ./eval/
COPY demo/ ./demo/
COPY frontend/ ./frontend/

RUN mkdir -p /app/backend/data

ENV KYA_SIGNING_SECRET=""
ENV KYA_DEMO_ISSUER_KEY=""
ENV KYA_LOG_LEVEL="INFO"
ENV KYA_PAYMENT_PROVIDER="mock"
ENV KYA_IDENTITY_MODE="hmac"
ENV KYA_INTENT_CLASSIFIER="keyword"
ENV KYA_RISK_MODEL="basic"

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
