FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DAPPILITY_DATA_DIR=/data

WORKDIR /srv/dapptility

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY scanner/pyproject.toml scanner/README.md /srv/dapptility/scanner/
COPY scanner/src /srv/dapptility/scanner/src

COPY app/pyproject.toml app/README.md /srv/dapptility/app/
COPY app/src /srv/dapptility/app/src

RUN pip install -e /srv/dapptility/scanner -e /srv/dapptility/app

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data/reports /data/raw \
    && chown -R appuser:appuser /data

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "dapptility_app.main:app", "--host", "0.0.0.0", "--port", "8000"]
