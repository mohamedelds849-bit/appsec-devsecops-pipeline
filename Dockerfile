# AgriSouss order portal (lab image, used by CI for Trivy image scan and ZAP baseline).
# Debian 13 slim base, rebuilt often upstream; Dependabot proposes base image updates.
FROM python:3.11-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
# Build tools are not needed at run time: removing setuptools (which vendors
# jaraco.context, CVE-2026-23949) and wheel (CVE-2026-24049) shrinks the attack
# surface. Both were flagged HIGH by the Trivy image gate on the first CI run.
RUN pip install --no-cache-dir -r requirements.txt \
    && pip uninstall -y setuptools wheel

COPY portal/ portal/
COPY run.py .

# Unprivileged user; only the SQLite folder is writable.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin portal \
    && mkdir -p /app/instance && chown portal:portal /app/instance
USER portal

# run.py binds 127.0.0.1 only: start with `docker run --network host` (Linux CI).
# PORTAL_SECRET_KEY must be given at run time (-e), never baked into the image.
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/login', timeout=2)"
CMD ["python", "run.py"]
