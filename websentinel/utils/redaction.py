"""Shared output-boundary redaction; operational request data stays untouched."""
from dataclasses import fields, is_dataclass, replace
from functools import wraps
import re
from urllib.parse import parse_qsl, quote, quote_plus, unquote, urlsplit

_SENSITIVE = re.compile(r"password|passwd|secret|token|api.?key|authorization|session|credential|signature|^sig$|^code$", re.I)
_URL = re.compile(r"https?://[^\s<>\"']+", re.I)
_TOKENS = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b")
_ASSIGNMENT = re.compile(r"(?i)\b(password|passwd|(?:client_)?secret|access_token|refresh_token|api[_-]?key)([\"']?\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s\"';&<>]+)")


def sensitive_values(url):
    try:
        p = urlsplit(url)
        return [unquote(p.password)] if p.password else []
    except ValueError:
        return []


def query_secrets(url):
    try:
        return [v for k, v in parse_qsl(urlsplit(url).query) if _SENSITIVE.search(k) and v]
    except ValueError:
        return []


class Redactor:
    def __init__(self, secrets=()):
        secrets = [part for value in secrets for part in (
            [value, value.partition(" ")[2]] if value.lower().startswith(("bearer ", "basic ")) else [value]
        )]
        self.secrets = sorted({encoded for value in secrets if value and value != "[REDACTED]"
                               for encoded in (value, quote(value, safe=""), quote_plus(value))}, key=len, reverse=True)
        self.pattern = re.compile("|".join(map(re.escape, self.secrets))) if self.secrets else None

    def text(self, value):
        # URLs are handled before generic key/value evidence to preserve query names.
        from websentinel.utils.urls import sanitize_url_for_logging
        value = _URL.sub(lambda m: sanitize_url_for_logging(m.group()), value)
        value = _TOKENS.sub("[REDACTED]", value)
        value = _ASSIGNMENT.sub(r"\1\2[REDACTED]", value)
        value = re.sub(r"(?im)\b(?:proxy-authorization|authorization|cookie|set-cookie):[^\r\n]*", "[REDACTED HEADER]", value)
        if self.pattern:
            # One substitution pass prevents a short secret from rewriting newly
            # inserted markers and growing the output exponentially.
            value = self.pattern.sub("[REDACTED]", value)
        return value

    def clean(self, value):
        if isinstance(value, str):
            # Enums are str subclasses and must retain their type.
            return self.text(value) if type(value) is str else value
        if isinstance(value, list):
            return [self.clean(item) for item in value]
        if isinstance(value, dict):
            return {key: item if key == "status" else self.clean(item) for key, item in value.items()}
        if is_dataclass(value):
            structural = {"id", "scanner_check", "method", "scheme", "http_version", "started", "timestamp", "cwe", "owasp"}
            return replace(value, **{f.name: self.clean(getattr(value, f.name)) for f in fields(value)
                                     if f.name not in structural})
        return value


def safe_report(render):
    """Sanitize a detached report snapshot for every renderer, including API use."""
    @wraps(render)
    def wrapped(result, *args, **kwargs):
        secrets = list(result.redaction_values)
        urls = [result.target.url, result.target.original, *result.pages]
        urls.extend(f.url for f in result.findings)
        for response in result.responses:
            urls.extend([response.url, response.final_url, *response.redirect_chain])
            for cookie in response.set_cookies:
                value = cookie.split(";", 1)[0].partition("=")[2].strip('"')
                if value:
                    secrets.append(value)
        for url in urls:
            secrets.extend(sensitive_values(url) + query_secrets(url))
        snapshot = replace(result, redaction_values=[], responses=[
            replace(r, body="", headers={}, set_cookies=[]) for r in result.responses
        ])
        return render(Redactor(secrets).clean(snapshot), *args, **kwargs)
    return wrapped
