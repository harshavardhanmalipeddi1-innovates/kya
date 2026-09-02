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

# Create data directory
RUN mkdir -p backend/data

# Set environment variables
ENV KYA_SIGNING_SECRET=""
ENV KYA_DEMO_ISSUER_KEY=""
ENV KYA_LOG_LEVEL="INFO"
ENV KYA_PAYMENT_PROVIDER="mock"
ENV KYA_IDENTITY_MODE="hmac"
ENV KYA_ALLOWED_ORIGINS="http://localhost:3000"

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Run with uvicorn
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
