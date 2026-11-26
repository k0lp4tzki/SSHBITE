# syntax=docker/dockerfile:1
# SSHBITE image (spec 8.2): node:22 builds the frontend, python:3.12-slim runs the tool as uid 10001.
#
#   docker build -t sshbite .
#   docker compose -f docs/compose.example.yaml up -d        (see docs/install.md)

# ---- 1. frontend: Svelte/Vite build -> sshbite/web/static/ ------------------------------------------
FROM node:22-bookworm-slim AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- 2. wheel: the Python package with the built frontend inside ------------------------------------
FROM python:3.12-slim AS wheel
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY requirements-build.lock ./
RUN pip install --require-hashes -r requirements-build.lock
COPY pyproject.toml setup.py README.md ./
COPY sshbite/ sshbite/
COPY --from=frontend /src/sshbite/web/static/ sshbite/web/static/
RUN test -f sshbite/web/static/index.html \
 && SSHBITE_SKIP_FRONTEND=1 pip wheel --no-deps --no-build-isolation -w /dist .

# ---- 3. runtime ----------------------------------------------------------------------------------------
FROM python:3.12-slim
LABEL org.opencontainers.image.title="SSHBITE" \
      org.opencontainers.image.description="Read-only SSH access audit: crawls from a verified entry point and maps who may connect from where to where" \
      org.opencontainers.image.source="https://github.com/k0lp4tzki/SSHBITE"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SSHBITE_IN_CONTAINER=1 \
    SSHBITE_CONFIG=/etc/sshbite/sshbite.yaml
# runtime dependencies only (no test extra) from the hash-pinned lock, then the wheel without resolving anything else
COPY requirements-runtime.lock /tmp/requirements.lock
RUN pip install --require-hashes -r /tmp/requirements.lock && rm /tmp/requirements.lock
COPY --from=wheel /dist/ /tmp/dist/
RUN pip install --no-deps /tmp/dist/sshbite-*.whl && rm -rf /tmp/dist \
 && groupadd --gid 10001 sshbite \
 && useradd --uid 10001 --gid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin sshbite \
 && mkdir -p /data /etc/sshbite \
 && chown 10001:10001 /data \
 && chmod 0700 /data
USER 10001:10001
WORKDIR /data
# /data: the database (and its pre-update backups). /etc/sshbite: config and audit key - mount it read-only.
VOLUME ["/data", "/etc/sshbite"]
EXPOSE 8722
# the health check assumes web.port 8722; override it in compose if you change the port
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8722/', timeout=4)"]
CMD ["sshbite", "serve"]
