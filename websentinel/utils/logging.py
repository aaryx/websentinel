"""Structured logging setup with credential and token redaction."""
from __future__ import annotations

import logging
import re
from websentinel.utils.redaction import Redactor

_URL_CREDS_RE = re.compile(r"://([^:@\s]+):([^@\s]+)@")
_SECRET_RE = re.compile(
    r"(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|x-auth-token)('?\"?[:\s]+)([^'\";]+)",
    re.IGNORECASE,
)


class RedactFilter(logging.Filter):
    """Mask credentials, tokens, cookies, and URL passwords in all log output."""

    def __init__(self, secrets=()):
        super().__init__()
        self.redactor = Redactor(secrets)

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        msg = _URL_CREDS_RE.sub(r"://\1:[REDACTED]@", msg)
        msg = _SECRET_RE.sub(r"\1\2[REDACTED]", msg)
        msg = self.redactor.text(msg)
        record.msg = msg
        record.args = ()
        return True


def setup_logging(verbose: bool = False, quiet: bool = False, secrets=()) -> logging.Logger:
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
    rf = RedactFilter(secrets)
    for h in logging.getLogger().handlers:
        for old in list(h.filters):
            if isinstance(old, RedactFilter):
                h.removeFilter(old)
        h.addFilter(rf)
    logger = logging.getLogger("websentinel")
    for old in list(logger.filters):
        if isinstance(old, RedactFilter):
            logger.removeFilter(old)
    logger.addFilter(rf)
    return logger
