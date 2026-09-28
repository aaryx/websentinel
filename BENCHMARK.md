# Detection conformance benchmark

`tests/benchmark_cases.json` is a version-controlled, first-party corpus of 35
labelled positive and negative cases. Each label evaluates one named finding ID,
not every possible observation on that response. Two CORS cases also constrain
severity. Fixtures contain synthetic values only and require no external targets.

Run:

```console
python -m pytest tests/test_detection_benchmark.py -q -s
```

Measured result: **18 true positives, 17 true negatives, 0 false positives,
0 false negatives**. Precision and recall are both 1.000 **on this corpus only**.
This is regression/conformance evidence, not an independent or representative
estimate of real-world vulnerability detection accuracy.

## Label basis

| Cases | Reference and expected behavior |
| --- | --- |
| HSTS | [RFC 6797 §6.1.1](https://www.rfc-editor.org/rfc/rfc6797#section-6.1.1): max-age must be valid; zero disables policy |
| CSP | [CSP Level 3](https://www.w3.org/TR/CSP3/): nonce/hash, strict-dynamic, directive precedence and framing controls |
| Cookies | [HTTP cookies](https://httpwg.org/specs/rfc6265.html), [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie): parsed flags, SameSite and prefix constraints |
| CORS | [Fetch CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol): credentials `true` and serialized `null` are case-sensitive |
| Forms/resources | [Mixed Content](https://www.w3.org/TR/mixed-content/): HTTP subresource references differ from canonical metadata links |
| JS | Local documented signatures: token-shaped strings and source-map references are indicators, not verified live credentials |

The corpus found errors in backward-compatible nonce CSP evaluation, CORS case
sensitivity, cookie-prefix checks, and mixed-content classification. Corrected
implementations are protected by the same labels. Extend the corpus with reviewed
real-world anonymized cases; do not weaken labels to make a failing implementation
pass. A separate held-out dataset and independent label review remain necessary
before publishing general accuracy claims.
