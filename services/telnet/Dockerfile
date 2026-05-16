FROM python:3.12-slim

RUN useradd -u 1500 -m -s /bin/bash hp

WORKDIR /app

COPY honeycore /app/honeycore
COPY services/telnet /app/service

RUN mkdir -p /var/log/honeypot && chown -R hp:hp /var/log/honeypot

USER hp
ENV PYTHONPATH=/app
EXPOSE 23

CMD ["python", "-u", "/app/service/server.py"]
