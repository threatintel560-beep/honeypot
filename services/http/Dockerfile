FROM python:3.12-slim

RUN useradd -u 1500 -m -s /bin/bash hp && \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/http/requirements.txt /tmp/req.txt
RUN pip install --no-cache-dir -r /tmp/req.txt

COPY honeycore /app/honeycore
COPY services/http /app/service

RUN mkdir -p /var/log/honeypot && chown -R hp:hp /var/log/honeypot

USER hp
ENV PYTHONPATH=/app
EXPOSE 8080

CMD ["python", "-u", "-m", "uvicorn", "service.server:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
