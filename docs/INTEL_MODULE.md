# Intel Module — CVE research, AI plugin generation, IOC extraction

The intel service at `http://<host>:8090` ties the whole framework together.
It does three things:

1. **Watches CVE feeds** (CISA KEV + NVD) for new vulnerabilities worth honeypot coverage
2. **Generates plugin drafts** using a local LLM (Ollama) or OpenAI-compatible API
3. **Extracts IOCs** from captured honeypot traffic and emits STIX 2.1 for MISP/OpenCTI

All configuration is web-based — no terminal needed once it's running.

---

## Pages

| URL | What you do there |
|---|---|
| `/` | Dashboard: counts, recent CVEs, quick "poll feeds" button |
| `/cves` | Browse tracked CVEs, filter by KEV / status |
| `/cves/<id>` | CVE detail, research links, one-click AI plugin generation |
| `/plugins` | List of plugin drafts with status (draft / reviewed / deployed) |
| `/plugins/<id>` | Edit generated Python code; deploy to disk |
| `/iocs` | Browse IOCs by type; download STIX 2.1 bundle |
| `/config` | Set LLM backend, watched products, CVSS threshold, ES URL |

---

## First-time setup

### Option A: Local LLM via Ollama (recommended, free, private)

On your Mac:

```bash
# Install and start Ollama
brew install ollama
ollama serve &

# Pull a coding model (pick one)
ollama pull qwen2.5-coder:14b      # best quality, ~9 GB, ~10 GB RAM
# or
ollama pull llama3.1:8b            # lighter, ~5 GB, ~6 GB RAM
```

Open `http://localhost:8090/config`:

- **Mode:** `ollama`
- **Model:** `qwen2.5-coder:14b`
- **Ollama host:** `http://host.docker.internal:11434` (Docker Desktop default)

Click **Test LLM** — should say "pong".

### Option B: OpenAI-compatible API (Claude via proxy, GPT-4, Together, Groq…)

- **Mode:** `openai`
- **Model:** `gpt-4o-mini` (or Groq's `llama-3.1-70b`, or Together's models)
- **API key:** your key

### Option C: Template-only (no AI)

- **Mode:** `template`
- Generates a well-structured skeleton you then fill in by hand. Always works.

---

## Workflow: discover → research → draft → review → deploy

```
1. Dashboard → Poll KEV + NVD now
     ↓
2. CVEs page → pick a high-severity CVE → detail page
     ↓
3. Click the research links (NVD, GitHub PoCs, Exploit-DB) — open in tabs
     ↓
4. Click "Generate plugin with AI"
     ↓
5. Plugin detail page → review the code, edit if needed → Save
     ↓
6. Click "Mark reviewed" → "Deploy"
     ↓
7. Host: make reload-http   (picks up the new plugin)
```

---

## Configuration knobs (all editable in the web UI)

| Setting | Meaning |
|---|---|
| `llm_mode` | `ollama` / `openai` / `template` |
| `llm_model` | Model ID for the chosen backend |
| `llm_ollama_host` | Ollama server URL (default works on Docker Desktop) |
| `cve_watch_products` | One per line — only CVEs mentioning these go into the DB |
| `cve_min_cvss` | CVSS threshold for non-KEV CVEs |
| `cve_only_kev` | Ignore NVD, only track actively exploited CVEs |
| `es_url` | Elasticsearch URL used by the IOC extractor |
| `es_index` | Index pattern for honeypot events |

---

## Background jobs

The intel container runs two scheduled jobs automatically:

- **CVE watcher** — every 6 hours; also runnable via dashboard button
- **IOC extractor** — every 10 minutes; also runnable on the IOCs page

All activity is visible in `docker logs hp-intel`.

---

## Deploying plugin drafts to the HTTP honeypot

When you click **Deploy** in the intel UI, the plugin is written to
`/app/generated_plugins` inside the intel container. That path is bind-mounted
to `services/http/plugins` on the host, so the HTTP honeypot picks it up after:

```bash
make reload-http
```

You can override the output directory in `docker-compose.yml` if you want
manual promotion.

---

## STIX 2.1 export

On the IOCs page, click **Download STIX 2.1**. You get a bundle of
`indicator` objects (URLs, IPs, domains, hashes) with custom
`x_honeyforge_*` fields carrying sensor & CVE correlation.

Feed it into:

- **MISP** — Import → Upload STIX 2
- **OpenCTI** — Data → Import
- **TAXII 2.1 server** — POST the bundle to a collection

---

## Troubleshooting

**LLM test fails with "connection refused":**
- Make sure Ollama is running: `curl http://localhost:11434/api/tags`
- On Docker Desktop, `host.docker.internal` must resolve — it does automatically.
- On plain Linux, use your host IP instead of `host.docker.internal`.

**No IOCs appearing:**
- Check Elasticsearch is reachable: `curl http://localhost:9200/_cat/indices`
- Make sure some attacker events exist (see `make tail`).

**Generated plugin has syntax errors:**
- The generator validates AST before saving, but the LLM may hallucinate.
  Hit **Save** after editing — the form accepts any code.
- As a fallback, set LLM mode to `template` to get a guaranteed-valid skeleton.
