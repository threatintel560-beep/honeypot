.PHONY: up down rebuild logs tail rotate reload-http reload-ssh export clean ps

# Auto-detect docker-compose vs docker compose (prefer docker-compose if available)
COMPOSE := $(shell command -v docker-compose > /dev/null 2>&1 && echo "docker-compose" || echo "docker compose")

up:
	@test -f .env || cp .env.example .env
	$(COMPOSE) up -d --build
	@echo ""
	@echo "  Intel:    http://localhost:$${INTEL_PORT:-8090}"
	@echo "  Kibana:   http://localhost:$${KIBANA_PORT:-5601}"
	@echo "  SSH pot:  localhost:$${SSH_PORT:-2222}"
	@echo "  HTTP pot: localhost:$${HTTP_PORT:-8080}"
	@echo ""

down:
	$(COMPOSE) down

rebuild:
	$(COMPOSE) up -d --build --force-recreate

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs -f --tail=200

tail:
	$(COMPOSE) logs -f ssh-honeypot http-honeypot

rotate:
	./scripts/gen_hostkey.sh
	$(COMPOSE) restart ssh-honeypot http-honeypot

reload-http:
	$(COMPOSE) restart http-honeypot

reload-ssh:
	$(COMPOSE) restart ssh-honeypot

reload-intel:
	$(COMPOSE) restart intel

export:
	mkdir -p exports
	$(COMPOSE) exec -T elasticsearch curl -s -u elastic:$${ELASTIC_PASSWORD:-changeme} \
		"http://localhost:9200/honeypot-events-*/_search?size=10000&pretty" \
		> exports/events-$$(date +%Y%m%d-%H%M%S).json
	@echo "Exported to exports/"

clean:
	$(COMPOSE) down -v
	rm -rf logs/ data/ exports/

# ──────────────── Demo ────────────────
PYTHON := $(shell command -v python3 > /dev/null 2>&1 && echo "python3" || echo "python")

demo: .venv
	@echo "Running end-to-end intelligence lifecycle demo..."
	.venv/bin/python scripts/demo_flow.py --cve CVE-2024-4577

demo-all: .venv
	@echo "Running demo for all CVEs..."
	.venv/bin/python scripts/demo_flow.py --all

.venv:
	$(PYTHON) -m venv .venv
	.venv/bin/pip install --quiet httpx
