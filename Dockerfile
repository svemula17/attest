# Attest — continuous compliance control plane. Single image, SQLite by default;
# point ATTEST_CONFIG at a mounted attest.toml to use Postgres, sources and schedules.
FROM python:3.13-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN useradd --create-home --uid 10001 attest
WORKDIR /app
COPY pyproject.toml README.md ./
COPY attest ./attest
COPY dashboard ./dashboard
COPY examples ./examples
RUN pip install --no-cache-dir ".[postgres]" && mkdir -p /data && chown -R attest:attest /app /data
USER attest
VOLUME ["/data"]
ENV ATTEST_CONFIG=/data/attest.toml ATTEST_HOST=0.0.0.0
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=4).status == 200 else 1)"
# first boot: write a config if the volume is empty, run migrations, serve
ENTRYPOINT ["/bin/sh", "-c", "[ -f /data/attest.toml ] || attest init --dir /data --mode ${ATTEST_MODE:-production} --storage-url ${ATTEST_STORAGE_URL:-sqlite:////data/attest.db} --admin-email ${ATTEST_ADMIN_EMAIL:-admin@example.com} --admin-password ${ATTEST_ADMIN_PASSWORD:-change-me}; exec attest serve --host 0.0.0.0"]
