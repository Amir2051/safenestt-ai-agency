# syntax=docker/dockerfile:1
FROM python:3.14-slim AS base

WORKDIR /app

# Non-root user
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --create-home appuser

# Install dependencies first (layer caching)
COPY pyproject.toml .
COPY README.md* .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e ".[dev]" && \
    pip install --no-cache-dir uvloop httptools

# Copy application
COPY . .

# Switch to non-root
RUN chown -R appuser:appuser /app
USER appuser

# Environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    HOST=0.0.0.0 \
    MODE=production \
    WORKERS=4

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/v1/health')" || exit 1

CMD ["sh", "-c", "uvicorn safenestt.api.app:app --host ${HOST} --port ${PORT} --workers ${WORKERS} --loop uvloop --http httptools --proxy-headers"]
