"""
CVE plugin system.

Each plugin is a subclass of CVEPlugin dropped into a service's plugins/ dir.
The service auto-discovers them at startup (no central registration needed).

Plugin authoring contract:
    class MyCVE(CVEPlugin):
        cve_id   = "CVE-2024-12345"
        product  = "SomeProduct"
        severity = "critical"

        def matches(self, ctx) -> bool: ...   # cheap predicate
        def handle(self, ctx) -> Response: ...  # realistic exploitation path
"""
from __future__ import annotations

import importlib.util
import inspect
import logging
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


@dataclass
class PluginContext:
    """
    Generic context object passed to plugins. Protocol-specific services
    subclass or extend this (e.g. HttpPluginContext with request fields).
    """
    service: str
    session: Any                       # honeycore.Session
    logger: logging.Logger
    request: dict[str, Any] = field(default_factory=dict)


class CVEPlugin(ABC):
    """Base class for all CVE-specific exploitation emulators."""

    cve_id: str = ""
    product: str = ""
    severity: str = "medium"     # low | medium | high | critical
    description: str = ""

    @abstractmethod
    def matches(self, ctx: PluginContext) -> bool:
        """Return True if this plugin should handle the request."""

    @abstractmethod
    def handle(self, ctx: PluginContext) -> Any:
        """
        Emulate the exploitation flow and return a protocol-appropriate
        response. Should log a `cve_exploit_attempt` event.
        """

    # ── helpers available to all plugins ────────────────────────────
    def log_attempt(self, ctx: PluginContext, **extras: Any) -> None:
        ctx.session.event(
            ctx.logger,
            "cve_exploit_attempt",
            cve=self.cve_id,
            product=self.product,
            severity=self.severity,
            **extras,
        )


class PluginRegistry:
    """Discovers and dispatches CVE plugins for one service."""

    def __init__(self, logger: logging.Logger):
        self._plugins: list[CVEPlugin] = []
        self._log = logger

    def load_from_dir(self, plugins_dir: str | Path) -> int:
        """Import every .py file under plugins_dir and register CVEPlugin subclasses."""
        path = Path(plugins_dir)
        if not path.is_dir():
            self._log.warning("plugin_dir_missing", extra={"data": {"dir": str(path)}})
            return 0

        loaded = 0
        for py in sorted(path.glob("*.py")):
            if py.name.startswith("_"):
                continue
            spec = importlib.util.spec_from_file_location(f"hp_plugin_{py.stem}", py)
            if not spec or not spec.loader:
                continue
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
            except Exception as e:  # plugin errors shouldn't kill the service
                self._log.error("plugin_load_failed",
                                extra={"data": {"file": py.name, "err": str(e)}})
                continue

            for _, obj in inspect.getmembers(module, inspect.isclass):
                if obj is CVEPlugin or not issubclass(obj, CVEPlugin):
                    continue
                if obj.__module__ != module.__name__:
                    continue
                try:
                    instance = obj()
                    self._plugins.append(instance)
                    loaded += 1
                    self._log.info("plugin_loaded",
                                   extra={"data": {"cve": instance.cve_id,
                                                   "product": instance.product}})
                except Exception as e:
                    self._log.error("plugin_init_failed",
                                    extra={"data": {"class": obj.__name__,
                                                    "err": str(e)}})
        return loaded

    def dispatch(self, ctx: PluginContext) -> CVEPlugin | None:
        """Return the first plugin that claims the request, or None."""
        for plugin in self._plugins:
            try:
                if plugin.matches(ctx):
                    return plugin
            except Exception as e:
                self._log.error("plugin_match_error",
                                extra={"data": {"cve": plugin.cve_id, "err": str(e)}})
        return None

    def all(self) -> Iterable[CVEPlugin]:
        return iter(self._plugins)

    def __len__(self) -> int:
        return len(self._plugins)
