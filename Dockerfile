# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PROXY_BACKEND=mock

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ src/
COPY policies/ policies/

# Run as an unprivileged user.
RUN useradd --system --uid 10001 proxy && chown -R proxy /app
USER proxy

ENV SECURITY_POLICY_PATH=/app/policies/security_policy.yaml
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["uvicorn", "proxy.main:app", "--app-dir", "src", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
