FROM python:3.12-slim

RUN useradd -u 1500 -m -s /bin/bash hp && \
    apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY intel/requirements.txt /tmp/req.txt
RUN pip install --no-cache-dir -r /tmp/req.txt

COPY honeycore /app/honeycore
COPY intel     /app/intel

# Mount points provided by docker-compose
RUN mkdir -p /data /app/generated_plugins && \
    chown -R hp:hp /data /app/generated_plugins

USER hp
ENV PYTHONPATH=/app

EXPOSE 8090

CMD ["python", "-u", "-m", "uvicorn", "intel.webapp:app", \
     "--host", "0.0.0.0", "--port", "8090", "--no-access-log"]
