"""
intel — threat intelligence module.

Four components:
  - cve_watcher:     polls CISA KEV + NVD, stores new CVEs
  - plugin_generator: uses local LLM to draft CVE plugin code
  - ioc_extractor:   mines Elasticsearch for URLs / IPs / hashes, emits STIX
  - webapp:          FastAPI + HTMX dashboard tying it all together
"""
__version__ = "0.1.0"
