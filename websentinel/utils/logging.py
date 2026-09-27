"""Structured logging setup with credential and token redaction."""
from __future__ import annotations

import logging
import re

_URL_CREDS_RE = re.compile(r"://([^:@\s]+):([^@\s]+)@")
_SECRET_RE = re.compile(
    r"(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|x-auth-token)('?\"?[:\s]+)([^'\";]+)",
    re.IGNORECASE,
)


class RedactFilter(logging.Filter):
    """Mask credentials, tokens, cookies, and URL passwords in all log output."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = str(record.msg)
        msg = _URL_CREDS_RE.sub(r"://\1:[REDACTED]@", msg)
        msg = _SECRET_RE.sub(r"\1\2[REDACTED]", msg)
        record.msg = msg
        record.args = ()
        return True


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    level = (
        logging.DEBUG
        if verbose
        else logging.ERROR
        if quiet
        else logging.INFO
    )
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    rf = RedactFilter()
    for h in logging.getLogger().handlers:
        h.addFilter(rf)
    logger = logging.getLogger("websentinel")
    logger.addFilter(rf)
    return logger
