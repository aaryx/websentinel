# Externally sourced validation — 2026-09-28

## Source and attribution

Behavioral cases in `tests/test_external_observatory_cases.py` are adapted from
MDN HTTP Observatory, revision **2dda68a02859ce3514281b584e8ecf02a5c33151**:

- [HSTS tests](https://github.com/mdn/mdn-http-observatory/blob/2dda68a02859ce3514281b584e8ecf02a5c33151/test/strict-transport-security.test.js)
- [Cookie tests](https://github.com/mdn/mdn-http-observatory/blob/2dda68a02859ce3514281b584e8ecf02a5c33151/test/cookies.test.js)
- [CORS tests reviewed](https://github.com/mdn/mdn-http-observatory/blob/2dda68a02859ce3514281b584e8ecf02a5c33151/test/cors.test.js)

Upstream is Mozilla Public License 2.0. The adapted test file is distributed under
MPL-2.0; see its header and <https://www.mozilla.org/MPL/2.0/>. The rest of this
project retains its existing license. Upstream authors are credited through the
source links; this project is not affiliated with or endorsed by Mozilla/MDN.

## Method and scope

Thirteen cases map upstream observable expectations to WebSentinel finding IDs:
five HSTS cases and eight cookie cases. These tests exercise the Python analyzers
against adapted fixtures; they do **not** execute MDN's scanner or compare full
scanner grades. All thirteen pass after fixes for comma-combined HSTS, short HSTS
max-age, and empty SameSite values.

Deliberate differences are not hidden: MDN treats wildcard public CORS as passing;
WebSentinel emits a contextual observation. MDN tests active origin reflection,
preload lists, and grading behavior which are not mapped to WebSentinel's passive
checks. The whole upstream suite is not claimed as supported or passed.

This is externally sourced conformance testing performed by the implementer,
**not an independent security assessment or representative precision/recall study**.

## Additional adversarial review

The local boundary suite found and fixed:
- IDNA2003 versus HTTPX IDNA mismatch, including `faß.de` being changed to `fass.de`.
- Unicode scope comparisons and TLS SNI/DNS host consistency.
- Quoted JSON credential values escaping generic evidence redaction.
- Internal XML entity expansion in sitemap input (DTDs/entities are now rejected).
- Network failure misclassified as missing security.txt.

Current code remains subject to independent review. The corpus contains synthetic
data and no live credentials or third-party target scans.
