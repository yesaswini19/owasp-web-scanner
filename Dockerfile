# ──────────────────────────────────────────────────────────
# Dockerfile — OWASP Security Scanner v2
# Multi-stage build → lean, non-root, Gunicorn production image
# ──────────────────────────────────────────────────────────

# ── Stage 1: Build ─────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Build tools for C-extension packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Production ────────────────────────────────────
FROM python:3.12-slim

# Non-root user for container security
RUN groupadd -r scanner && useradd -r -g scanner -d /app -s /sbin/nologin scanner

WORKDIR /app

# Copy installed packages
COPY --from=builder /install /usr/local

# Copy source
COPY app.py scanner.py report.py ./
COPY templates/ templates/

# Logs directory (writable by non-root)
RUN mkdir -p /app/logs && chown -R scanner:scanner /app

USER scanner

EXPOSE 5000

ENV FLASK_ENV=production \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Gunicorn: 4 workers, 120s timeout, bind all interfaces
CMD ["gunicorn", \
     "--workers", "4", \
     "--worker-class", "sync", \
     "--bind", "0.0.0.0:5000", \
     "--timeout", "120", \
     "--keep-alive", "5", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "app:app"]
