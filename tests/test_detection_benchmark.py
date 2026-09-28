"""First-party labelled conformance corpus; not an independent accuracy claim."""
import json
from pathlib import Path

import pytest

from conftest import make_response
from websentinel.analyzers.cookies import analyze_cookies
from websentinel.analyzers.cors import analyze_cors
from websentinel.analyzers.headers import analyze_headers
from websentinel.analyzers.html import analyze_html
from websentinel.analyzers.javascript import analyze_javascript

CASES = json.loads(Path(__file__).with_name("benchmark_cases.json").read_text(encoding="utf-8"))


def evaluate(case):
    response = make_response(headers=case.get("headers", {}), cookies=case.get("cookies", []), body=case.get("body", ""))
    functions = {"headers": lambda: analyze_headers(response, True), "cookies": lambda: analyze_cookies(response, True),
                 "cors": lambda: analyze_cors(response), "html": lambda: analyze_html(response, True),
                 "js": lambda: analyze_javascript(response.url, response.body)}
    return [f for f in functions[case["analyzer"]]() if f.id == case["rule"]]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_labelled_detection(case):
    findings = evaluate(case)
    assert bool(findings) is case["positive"]
    if "severity" in case:
        assert findings[0].severity.value == case["severity"]


def test_benchmark_metrics():
    tp = fp = fn = tn = 0
    for case in CASES:
        detected = bool(evaluate(case))
        tp += detected and case["positive"]
        fp += detected and not case["positive"]
        fn += not detected and case["positive"]
        tn += not detected and not case["positive"]
    print(f"Conformance corpus: cases={len(CASES)} TP={tp} TN={tn} FP={fp} FN={fn} precision={tp / (tp + fp):.3f} recall={tp / (tp + fn):.3f}")
    assert fp == fn == 0
