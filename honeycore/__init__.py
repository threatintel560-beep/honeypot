"""
honeycore — shared primitives for all honeypot services.

Imports:
    from honeycore.logger import get_logger
    from honeycore.session import Session
    from honeycore.deception import Deception
    from honeycore.plugins import PluginRegistry, CVEPlugin
"""
from .logger import get_logger
from .session import Session
from .deception import Deception
from .plugins import PluginRegistry, CVEPlugin

__all__ = ["get_logger", "Session", "Deception", "PluginRegistry", "CVEPlugin"]
__version__ = "0.1.0"
