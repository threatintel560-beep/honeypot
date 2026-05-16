FROM python:3.12-slim

RUN useradd -u 1500 -m -s /bin/bash hp

WORKDIR /app

COPY honeycore /app/honeycore
COPY services/redis /app/service

RUN mkdir -p /var/log/honeypot && chown -R hp:hp /var/log/honeypot

USER hp
ENV PYTHONPATH=/app
EXPOSE 6379

CMD ["python", "-u", "/app/service/server.py"]
