"""Structured logging setup."""
from __future__ import annotations

import logging
import re

_SECRET_RE = re.compile(
    r"(authorization|cookie|set-cookie|x-api-key)('?\"?[:\s]+)([^'\";]+)",
    re.IGNORECASE)


class RedactFilter(logging.Filter):
    """Mask credentials/tokens/cookies in all log output."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _SECRET_RE.sub(r"\1\2[REDACTED]", str(record.msg))
        record.args = ()
        return True


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    level = (logging.DEBUG if verbose else
             logging.ERROR if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger().handlers[0].addFilter(RedactFilter())
    return logging.getLogger("websentinel")
