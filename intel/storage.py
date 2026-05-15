"""
SQLite-backed storage for the intel module.

Tables:
  cves      — CVE records ingested from KEV / NVD
  plugins   — generated plugin drafts (status: draft / reviewed / deployed)
  iocs      — extracted indicators (type: url / ip / sha256 / domain)
  config    — key/value runtime config editable from the web UI
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

DB_PATH = Path("/data/intel.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id        TEXT PRIMARY KEY,
    product       TEXT,
    vendor        TEXT,
    severity      TEXT,
    cvss          REAL,
    description   TEXT,
    in_kev        INTEGER DEFAULT 0,
    kev_date      TEXT,
    nvd_published TEXT,
    refs_json     TEXT,
    status        TEXT DEFAULT 'new',  -- new / researched / plugin_drafted / deployed / skipped
    added_at      INTEGER
);

CREATE TABLE IF NOT EXISTS plugins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id        TEXT,
    service       TEXT,      -- http / ssh
    filename      TEXT,
    code          TEXT,
    model_used    TEXT,
    status        TEXT DEFAULT 'draft',  -- draft / reviewed / deployed
    created_at    INTEGER,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

CREATE TABLE IF NOT EXISTS iocs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type      TEXT,      -- url / ipv4 / sha256 / domain / cve
    value         TEXT,
    first_seen    INTEGER,
    last_seen     INTEGER,
    hit_count     INTEGER DEFAULT 1,
    source_cves   TEXT,      -- JSON array of CVE IDs
    sensors       TEXT,      -- JSON array of deployment_ids
    tags          TEXT,      -- JSON array
    UNIQUE(ioc_type, value)
);

CREATE TABLE IF NOT EXISTS config (
    key           TEXT PRIMARY KEY,
    value         TEXT
);

CREATE TABLE IF NOT EXISTS sensors (
    sensor_id     TEXT PRIMARY KEY,
    public_ip     TEXT,
    services      TEXT,      -- JSON array of "service:port" strings
    plugins       TEXT,      -- JSON array of CVE IDs loaded
    last_seen     INTEGER,
    event_count   INTEGER DEFAULT 0,
    registered_at INTEGER
);

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id     TEXT,
    event_type    TEXT,
    src_ip        TEXT,
    cve           TEXT,
    raw_json      TEXT,
    received_at   INTEGER
);

CREATE TABLE IF NOT EXISTS sensor_plugins (
    sensor_id     TEXT,
    plugin_id     INTEGER,
    assigned_at   INTEGER,
    PRIMARY KEY (sensor_id, plugin_id),
    FOREIGN KEY (plugin_id) REFERENCES plugins(id)
);

CREATE INDEX IF NOT EXISTS idx_cves_status ON cves(status);
CREATE INDEX IF NOT EXISTS idx_cves_kev    ON cves(in_kev);
CREATE INDEX IF NOT EXISTS idx_iocs_type   ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_last   ON iocs(last_seen);
CREATE INDEX IF NOT EXISTS idx_events_sensor ON events(sensor_id);
CREATE INDEX IF NOT EXISTS idx_events_type   ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_sensors_last  ON sensors(last_seen);
"""

_DEFAULT_CONFIG = {
    "llm_mode":            "ollama",        # ollama | openai | template
    "llm_ollama_host":     "http://host.docker.internal:11434",
    "llm_model":           "qwen2.5-coder:14b",
    "llm_openai_key":      "",
    "cve_watch_products":  json.dumps([
        "Apache", "nginx", "PHP", "WordPress", "Atlassian", "Confluence",
        "Jira", "Fortinet", "Citrix", "Palo Alto", "Cisco", "Ivanti",
        "VMware", "Microsoft Exchange", "GitLab", "Jenkins", "ActiveMQ",
        "Spring", "Struts", "Log4j", "SolarWinds", "ManageEngine",
    ]),
    "cve_min_cvss":        "9.0",
    "cve_only_kev":        "false",
    "es_url":              "http://elasticsearch:9200",
    "es_index":            "honeypot-events-*",
    "auto_deploy_mode":    "auto_kev",      # manual | auto_kev | auto_all
    "taxii_api_key":       "",              # empty = no auth required
    "sensor_api_key":      "",              # shared secret for remote sensors
}


# ────────────────────────────────────────────────────────────────────
def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with _connect() as c:
        c.executescript(_SCHEMA)
        # seed default config
        for k, v in _DEFAULT_CONFIG.items():
            c.execute("INSERT OR IGNORE INTO config(key,value) VALUES(?,?)", (k, v))


@contextmanager
def db():
    conn = _connect()
    try:
        yield conn
    finally:
        conn.close()


# ── Config helpers ──────────────────────────────────────────────────
def get_config(key: str, default: str = "") -> str:
    with db() as c:
        row = c.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


def set_config(key: str, value: str) -> None:
    with db() as c:
        c.execute("INSERT OR REPLACE INTO config(key,value) VALUES(?,?)", (key, value))


def all_config() -> dict[str, str]:
    with db() as c:
        rows = c.execute("SELECT key,value FROM config").fetchall()
        return {r["key"]: r["value"] for r in rows}


# ── CVE helpers ─────────────────────────────────────────────────────
def upsert_cve(cve: dict[str, Any]) -> bool:
    """Return True if this CVE was newly inserted (vs updated)."""
    with db() as c:
        existing = c.execute("SELECT cve_id FROM cves WHERE cve_id=?",
                             (cve["cve_id"],)).fetchone()
        c.execute(
            """INSERT OR REPLACE INTO cves
               (cve_id, product, vendor, severity, cvss, description,
                in_kev, kev_date, nvd_published, refs_json, status, added_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,
                       COALESCE((SELECT status FROM cves WHERE cve_id=?),'new'),
                       COALESCE((SELECT added_at FROM cves WHERE cve_id=?),?))""",
            (cve["cve_id"], cve.get("product"), cve.get("vendor"),
             cve.get("severity"), cve.get("cvss"), cve.get("description"),
             1 if cve.get("in_kev") else 0, cve.get("kev_date"),
             cve.get("nvd_published"), json.dumps(cve.get("refs", [])),
             cve["cve_id"], cve["cve_id"], int(time.time())),
        )
        return existing is None


def list_cves(status: str | None = None, limit: int = 500) -> list[dict]:
    q = "SELECT * FROM cves"
    params: tuple = ()
    if status:
        q += " WHERE status=?"
        params = (status,)
    q += " ORDER BY in_kev DESC, cvss DESC, added_at DESC LIMIT ?"
    with db() as c:
        return [dict(r) for r in c.execute(q, params + (limit,))]


def get_cve(cve_id: str) -> dict | None:
    with db() as c:
        row = c.execute("SELECT * FROM cves WHERE cve_id=?", (cve_id,)).fetchone()
        return dict(row) if row else None


def update_cve_status(cve_id: str, status: str) -> None:
    with db() as c:
        c.execute("UPDATE cves SET status=? WHERE cve_id=?", (status, cve_id))


# ── Plugin helpers ──────────────────────────────────────────────────
def save_plugin(cve_id: str, service: str, filename: str,
                code: str, model_used: str) -> int:
    with db() as c:
        cur = c.execute(
            """INSERT INTO plugins(cve_id, service, filename, code, model_used, created_at)
               VALUES (?,?,?,?,?,?)""",
            (cve_id, service, filename, code, model_used, int(time.time())),
        )
        return cur.lastrowid or 0


def list_plugins(cve_id: str | None = None) -> list[dict]:
    q = "SELECT * FROM plugins"
    params: tuple = ()
    if cve_id:
        q += " WHERE cve_id=?"
        params = (cve_id,)
    q += " ORDER BY created_at DESC"
    with db() as c:
        return [dict(r) for r in c.execute(q, params)]


def get_plugin(plugin_id: int) -> dict | None:
    with db() as c:
        row = c.execute("SELECT * FROM plugins WHERE id=?", (plugin_id,)).fetchone()
        return dict(row) if row else None


def update_plugin(plugin_id: int, code: str | None = None,
                  status: str | None = None) -> None:
    with db() as c:
        if code is not None:
            c.execute("UPDATE plugins SET code=? WHERE id=?", (code, plugin_id))
        if status is not None:
            c.execute("UPDATE plugins SET status=? WHERE id=?", (status, plugin_id))


# ── IOC helpers ─────────────────────────────────────────────────────
def upsert_ioc(ioc_type: str, value: str, cves: Iterable[str] = (),
               sensors: Iterable[str] = (), tags: Iterable[str] = ()) -> None:
    now = int(time.time())
    with db() as c:
        existing = c.execute(
            "SELECT id, source_cves, sensors, tags, hit_count FROM iocs "
            "WHERE ioc_type=? AND value=?",
            (ioc_type, value),
        ).fetchone()
        if existing:
            merged_cves    = sorted(set(json.loads(existing["source_cves"] or "[]")) | set(cves))
            merged_sensors = sorted(set(json.loads(existing["sensors"] or "[]")) | set(sensors))
            merged_tags    = sorted(set(json.loads(existing["tags"] or "[]")) | set(tags))
            c.execute(
                """UPDATE iocs SET last_seen=?, hit_count=hit_count+1,
                   source_cves=?, sensors=?, tags=? WHERE id=?""",
                (now, json.dumps(merged_cves), json.dumps(merged_sensors),
                 json.dumps(merged_tags), existing["id"]),
            )
        else:
            c.execute(
                """INSERT INTO iocs(ioc_type,value,first_seen,last_seen,
                   source_cves,sensors,tags) VALUES(?,?,?,?,?,?,?)""",
                (ioc_type, value, now, now,
                 json.dumps(sorted(set(cves))),
                 json.dumps(sorted(set(sensors))),
                 json.dumps(sorted(set(tags)))),
            )


def list_iocs(ioc_type: str | None = None, since: int | None = None,
              limit: int = 1000) -> list[dict]:
    q = "SELECT * FROM iocs WHERE 1=1"
    params: list = []
    if ioc_type:
        q += " AND ioc_type=?"
        params.append(ioc_type)
    if since:
        q += " AND last_seen >= ?"
        params.append(since)
    q += " ORDER BY last_seen DESC LIMIT ?"
    params.append(limit)
    with db() as c:
        return [dict(r) for r in c.execute(q, params)]


def ioc_stats() -> dict[str, int]:
    with db() as c:
        rows = c.execute("SELECT ioc_type, COUNT(*) as n FROM iocs GROUP BY ioc_type").fetchall()
        return {r["ioc_type"]: r["n"] for r in rows}


# ── Sensor helpers ──────────────────────────────────────────────────
def upsert_sensor(sensor_id: str, public_ip: str,
                  services: list[str], plugins: list[str]) -> None:
    now = int(time.time())
    with db() as c:
        c.execute(
            """INSERT OR REPLACE INTO sensors
               (sensor_id, public_ip, services, plugins, last_seen,
                event_count, registered_at)
               VALUES (?,?,?,?,?,
                       COALESCE((SELECT event_count FROM sensors WHERE sensor_id=?), 0),
                       COALESCE((SELECT registered_at FROM sensors WHERE sensor_id=?), ?))""",
            (sensor_id, public_ip, json.dumps(services), json.dumps(plugins),
             now, sensor_id, sensor_id, now),
        )


def update_sensor_heartbeat(sensor_id: str, new_events: int = 0) -> None:
    now = int(time.time())
    with db() as c:
        c.execute(
            """UPDATE sensors SET last_seen=?, event_count=event_count+?
               WHERE sensor_id=?""",
            (now, new_events, sensor_id),
        )


def list_sensors() -> list[dict]:
    with db() as c:
        rows = c.execute(
            "SELECT * FROM sensors ORDER BY last_seen DESC"
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["services_list"] = json.loads(d.get("services") or "[]")
            d["plugins_list"] = json.loads(d.get("plugins") or "[]")
            d["is_online"] = (int(time.time()) - (d.get("last_seen") or 0)) < 120
            result.append(d)
        return result


def get_sensor(sensor_id: str) -> dict | None:
    with db() as c:
        row = c.execute("SELECT * FROM sensors WHERE sensor_id=?",
                        (sensor_id,)).fetchone()
        if row:
            d = dict(row)
            d["services_list"] = json.loads(d.get("services") or "[]")
            d["plugins_list"] = json.loads(d.get("plugins") or "[]")
            d["is_online"] = (int(time.time()) - (d.get("last_seen") or 0)) < 120
            return d
        return None


# ── Event storage (lightweight — for non-ES deployments) ────────────
def store_event(event: dict) -> None:
    now = int(time.time())
    with db() as c:
        c.execute(
            """INSERT INTO events(sensor_id, event_type, src_ip, cve, raw_json, received_at)
               VALUES (?,?,?,?,?,?)""",
            (event.get("deployment", "unknown"),
             event.get("event", "unknown"),
             event.get("src_ip", ""),
             event.get("cve", ""),
             json.dumps(event, default=str),
             now),
        )


def list_events(sensor_id: str | None = None, event_type: str | None = None,
                limit: int = 100) -> list[dict]:
    q = "SELECT * FROM events WHERE 1=1"
    params: list = []
    if sensor_id:
        q += " AND sensor_id=?"
        params.append(sensor_id)
    if event_type:
        q += " AND event_type=?"
        params.append(event_type)
    q += " ORDER BY received_at DESC LIMIT ?"
    params.append(limit)
    with db() as c:
        return [dict(r) for r in c.execute(q, params)]


def event_stats() -> dict[str, int]:
    with db() as c:
        rows = c.execute(
            "SELECT event_type, COUNT(*) as n FROM events GROUP BY event_type"
        ).fetchall()
        return {r["event_type"]: r["n"] for r in rows}



# ── Sensor-plugin assignments ──────────────────────────────────────
def assign_plugin_to_sensor(sensor_id: str, plugin_id: int) -> None:
    now = int(time.time())
    with db() as c:
        c.execute(
            """INSERT OR IGNORE INTO sensor_plugins(sensor_id, plugin_id, assigned_at)
               VALUES (?,?,?)""",
            (sensor_id, plugin_id, now),
        )


def unassign_plugin_from_sensor(sensor_id: str, plugin_id: int) -> None:
    with db() as c:
        c.execute(
            "DELETE FROM sensor_plugins WHERE sensor_id=? AND plugin_id=?",
            (sensor_id, plugin_id),
        )


def list_sensor_plugins(sensor_id: str) -> list[dict]:
    """Return all plugins assigned to a sensor, with full plugin data."""
    with db() as c:
        rows = c.execute(
            """SELECT p.* FROM plugins p
               JOIN sensor_plugins sp ON sp.plugin_id = p.id
               WHERE sp.sensor_id = ?
               ORDER BY sp.assigned_at DESC""",
            (sensor_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def list_plugins_with_sensors() -> list[dict]:
    """Return all plugins with the sensors they're assigned to."""
    with db() as c:
        plugins = c.execute("SELECT * FROM plugins ORDER BY created_at DESC").fetchall()
        result = []
        for p in plugins:
            d = dict(p)
            sensors = c.execute(
                "SELECT sensor_id FROM sensor_plugins WHERE plugin_id=?",
                (p["id"],),
            ).fetchall()
            d["sensor_ids"] = [s["sensor_id"] for s in sensors]
            result.append(d)
        return result
