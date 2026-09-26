"""Structured logging setup."""
from __future__ import annotations

import logging


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    level = (logging.DEBUG if verbose else
             logging.ERROR if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    return logging.getLogger("websentinel")
