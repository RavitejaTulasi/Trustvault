# ==============================================================================
# TrustVault - Production Web Application Dockerfile
# ==============================================================================

FROM node:24-bookworm-slim AS frontend-build

WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy application code and Alembic migrations
COPY backend /app/backend
COPY alembic.ini /app/alembic.ini
# Public Supabase root CA so sslmode=verify-full works for both the
# pre-deploy migration instance and the running web service.
COPY certs /app/certs
COPY .env.example /app/.env.example
COPY --from=frontend-build /frontend/dist /app/frontend_dist

RUN chmod 644 /app/certs/prod-ca-2021.crt

# Create directory for private persistent document storage
RUN mkdir -p /app/private_storage && chmod 700 /app/private_storage

# Create a non-privileged user to run the application (Defense in depth)
RUN adduser --disabled-password --gecos "" trustvault && \
    chown -R trustvault:trustvault /app
USER trustvault

EXPOSE 8000

# Health check probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f "http://localhost:${PORT:-8000}/health" || exit 1

# Render injects PORT; default to 8000 for local Docker and the health probe.
# Migrations remain a separate pre-deploy step, not part of application startup.
CMD ["sh", "-c", "exec uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
