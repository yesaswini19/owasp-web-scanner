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

# Ensure the non-root user owns the application files.
RUN chown -R scanner:scanner /app

USER scanner

EXPOSE 5000

ENV FLASK_ENV=production \
    SCANNER_ENV=production \
    PORT=5000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Threaded workers keep health and dashboard requests responsive during scans.
CMD ["sh", "-c", "exec gunicorn --workers 2 --worker-class gthread --threads 4 --bind \"0.0.0.0:${PORT:-5000}\" --timeout 180 --keep-alive 5 --access-logfile - --error-logfile - --log-level info app:app"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; port = os.environ.get('PORT', '5000'); urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=3)"]
