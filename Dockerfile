# AEGIS-IR — Enterprise Incident Response Platform
# Deploys to Google Cloud Run with all integrations
FROM python:3.11-slim AS base

# Install system deps for forensic tools + performance
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e . 2>/dev/null || pip install --no-cache-dir \
    "google-adk>=1.32.0" \
    "google-genai>=1.9.0" \
    "arize-phoenix>=7.0" \
    "openinference-instrumentation-google-adk>=0.1.11" \
    "opentelemetry-sdk>=1.27.0" \
    "opentelemetry-exporter-otlp-proto-http>=1.27.0" \
    "arize-phoenix-evals>=0.17.0" \
    "arize-phoenix-client>=2.0.0" \
    "fastapi>=0.115.0" \
    "uvicorn[standard]>=0.30.0" \
    "websockets>=12.0" \
    "jinja2>=3.1.0" \
    "python-multipart>=0.0.9" \
    "pydantic>=2.10.0" \
    "pyyaml>=6.0" \
    "python-dotenv>=1.0.1" \
    "structlog>=24.0.0" \
    "aiofiles>=24.0.0" \
    "asyncpg>=0.29.0" \
    "python-jose[cryptography]>=3.3.0" \
    "bcrypt>=4.0.0" \
    "httpx>=0.27.0" \
    "email-validator>=2.0.0" \
    "pandas>=2.0.0" \
    "alembic>=1.13.0"

# Copy source
COPY src/ src/
COPY sample_data/ sample_data/
COPY start_server.py .
COPY alembic.ini .

# Cloud Run uses PORT env var
ENV PORT=8080
EXPOSE 8080

# Health check for Cloud Run
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -f http://localhost:8080/api/health || exit 1

# Start with production settings
CMD ["python", "start_server.py"]
