FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CERTS_DIR=/app/certs \
    WEB_CONCURRENCY=4

WORKDIR /app

# ca-certificates: almacén de certificados del SO (se usa como raíces de confianza)
# curl: sólo para el HEALTHCHECK
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

RUN useradd --system --no-create-home --uid 10001 appuser

COPY app/ ./app/
COPY certs/ ./certs/

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

# Uvicorn lee WEB_CONCURRENCY como número de procesos (workers).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
