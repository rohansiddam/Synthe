# Synthe commit broker in a container (isolation mode "container").
#
# Build from the repo root:
#   docker build -f deploy/docker/Dockerfile -t synthe-broker:0.6 .
# Run: see compose.yaml and docs/ISOLATION.md. The broker runs as the
# unprivileged user `synthe` (uid 10001); its key, registry, ledger, receipts
# and GitHub token live in the /synthe volume, never in the image.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir cryptography \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin synthe \
 && install -d -o synthe -g synthe -m 700 /synthe

COPY src/ /opt/synthe/src/

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER synthe
WORKDIR /synthe
VOLUME ["/synthe"]
EXPOSE 8791

# The bearer token agents must present comes from $SYNTHE_BROKER_TOKEN at run time.
ENTRYPOINT ["python3", "/opt/synthe/src/synthe_commit.py"]
CMD ["serve", "--config", "/synthe/broker.json", "--listen", "0.0.0.0:8791"]
