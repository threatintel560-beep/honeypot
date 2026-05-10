FROM python:3.12-slim AS base

# Non-root runtime user
RUN useradd -u 1500 -m -s /bin/bash hp && \
    apt-get update && apt-get install -y --no-install-recommends \
        openssh-client netbase ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies
COPY services/ssh/requirements.txt /tmp/req.txt
RUN pip install --no-cache-dir -r /tmp/req.txt

# Shared library
COPY honeycore /app/honeycore
# Service code
COPY services/ssh /app/service

# Log + key dirs
RUN mkdir -p /var/log/honeypot /app/host_key && \
    chown -R hp:hp /var/log/honeypot /app/host_key

USER hp
ENV PYTHONPATH=/app
EXPOSE 2222

CMD ["python", "-u", "service/server.py"]
