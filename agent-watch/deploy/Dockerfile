# agent-watch Zone A image: the isolated, internet-facing honeypot (synthetic content only).
# Build from the project root:   docker build -f deploy/Dockerfile -t agent-watch:zone-a .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# non-root user agentwatch (UID/GID 10001), no login shell, no home directory
RUN groupadd --gid 10001 agentwatch \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin agentwatch \
 && mkdir /app /data \
 && chown 10001:10001 /data

WORKDIR /app
COPY deploy/requirements-deploy.txt ./requirements-deploy.txt
RUN pip install -r requirements-deploy.txt
COPY agentwatch ./agentwatch
COPY deploy/gunicorn.conf.py ./gunicorn.conf.py

# Writable state lives ONLY under /data (a volume); the root filesystem can be mounted read-only.
ENV AGENT_WATCH_DATA=/data \
    AGENT_WATCH_SALT_FILE=/data/scrub.salt \
    AGENT_WATCH_BEHIND_PROXY=1 \
    AGENT_WATCH_BIND=127.0.0.1:8000

USER 10001:10001
VOLUME ["/data"]
EXPOSE 8000

# TCP-level check only: an HTTP probe would itself be logged as a visitor.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8000), 2).close()"]

# AGENT_WATCH_BIND is 127.0.0.1:8000 unless the compose file opts in to 0.0.0.0 on its internal network.
CMD ["gunicorn", "-c", "gunicorn.conf.py", \
     "--workers", "2", "--threads", "4", "--timeout", "10", \
     "--limit-request-line", "4094", "--limit-request-fields", "50", \
     "--worker-tmp-dir", "/tmp", \
     "agentwatch.wsgi:app"]
