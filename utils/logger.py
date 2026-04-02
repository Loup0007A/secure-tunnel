"""
Logger structuré
-----------------
Format uniforme pour tous les modules du tunnel.
Niveaux configurables via variable d'environnement LOG_LEVEL.
"""

import logging
import os
import sys


def setup_logging(name: str | None = None) -> logging.Logger:
    """
    Configure et retourne un logger prêt à l'emploi.
    LOG_LEVEL=DEBUG/INFO/WARNING (défaut: INFO)
    """
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level      = getattr(logging, level_name, logging.INFO)

    # Formatter lisible
    fmt = logging.Formatter(
        fmt   = "%(asctime)s [%(levelname)-8s] %(name)-20s %(message)s",
        datefmt = "%H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(fmt)

    root = logging.getLogger()
    if not root.handlers:
        root.addHandler(handler)
    root.setLevel(level)

    return logging.getLogger(name) if name else root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
