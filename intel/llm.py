"""
LLM client abstraction.

Three backends:
  * ollama   — local Ollama server (recommended, free, private)
  * openai   — OpenAI-compatible API (for Claude / GPT-4 via proxy)
  * template — deterministic template fallback, no AI, always works

Configure via the web UI (intel → config) or env vars.
"""
from __future__ import annotations

import json
import logging
from typing import Protocol

import httpx

log = logging.getLogger("intel.llm")


class LLMBackend(Protocol):
    name: str
    def generate(self, system: str, user: str, max_tokens: int = 2048) -> str: ...


class OllamaBackend:
    name = "ollama"

    def __init__(self, host: str, model: str):
        self.host = host.rstrip("/")
        self.model = model

    def generate(self, system: str, user: str, max_tokens: int = 2048) -> str:
        url = f"{self.host}/api/chat"
        payload = {
            "model": self.model,
            "stream": False,
            "options": {"num_predict": max_tokens, "temperature": 0.2},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        }
        try:
            r = httpx.post(url, json=payload, timeout=180.0)
            r.raise_for_status()
            data = r.json()
            return data.get("message", {}).get("content", "").strip()
        except Exception as e:
            log.warning("ollama_failed: %s", e)
            raise


class OpenAIBackend:
    name = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4o-mini",
                 base_url: str = "https://api.openai.com/v1"):
        self.api_key = api_key
        self.model   = model
        self.base    = base_url.rstrip("/")

    def generate(self, system: str, user: str, max_tokens: int = 2048) -> str:
        url = f"{self.base}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}",
                   "Content-Type": "application/json"}
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        }
        r = httpx.post(url, headers=headers, json=payload, timeout=120.0)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()


class TemplateBackend:
    """Deterministic fallback — never fails, never calls network."""
    name = "template"

    def generate(self, system: str, user: str, max_tokens: int = 2048) -> str:
        # The plugin_generator knows to use its hand-written fallback
        # when this backend is selected; it never actually invokes this method.
        raise NotImplementedError("template backend uses structural fallback")


def make_backend(cfg: dict[str, str]) -> LLMBackend:
    mode = cfg.get("llm_mode", "template")
    if mode == "ollama":
        return OllamaBackend(
            host=cfg.get("llm_ollama_host", "http://host.docker.internal:11434"),
            model=cfg.get("llm_model", "qwen2.5-coder:14b"),
        )
    if mode == "openai":
        return OpenAIBackend(
            api_key=cfg.get("llm_openai_key", ""),
            model=cfg.get("llm_model", "gpt-4o-mini"),
        )
    return TemplateBackend()


def probe(backend: LLMBackend) -> tuple[bool, str]:
    """Return (ok, message) — used by the config page health check."""
    if backend.name == "template":
        return True, "Template backend always available"
    try:
        out = backend.generate(
            "You are a test.", "Reply with the single word: pong",
            max_tokens=10,
        )
        return True, f"OK — model replied: {out[:60]}"
    except Exception as e:
        return False, f"Error: {e}"
