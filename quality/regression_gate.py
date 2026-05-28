#!/usr/bin/env python3
"""Regression gate for regression examples."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


QUALITY_GATE_PATH = Path(__file__).with_name("quality_gate.py")


def load_quality_gate():
    spec = importlib.util.spec_from_file_location("quality_gate", QUALITY_GATE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load quality_gate.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def issue_matches(issue: dict[str, Any], expected: dict[str, Any]) -> bool:
    category = expected.get("category")
    contains = expected.get("contains")
    if category and issue.get("category") != category:
        return False
    if contains:
        haystack = json.dumps(issue, ensure_ascii=False)
        if contains not in haystack:
            return False
    return True


def run_case(case_dir: Path, quality_gate) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    expected_path = case_dir / "expected-quality-issues.json"
    expected = load_json(expected_path)
    gate = expected.get("gate", "all")
    result = quality_gate.run_gate(case_dir / "audit-v2", gate)
    issues = result.get("issues", [])
    misses = []
    for exp in expected.get("expectedIssues", []):
        if not any(issue_matches(issue, exp) for issue in issues):
            misses.append(exp)
    unexpected_blockers = []
    if not expected.get("expectedIssues"):
        unexpected_blockers = [
            issue for issue in issues
            if issue.get("severity") in ("blocker", "error")
        ]
    return result, misses + unexpected_blockers


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run regression gate")
    parser.add_argument("--examples-dir", default="examples/ems")
    args = parser.parse_args(argv)

    quality_gate = load_quality_gate()
    examples_dir = Path(args.examples_dir)
    cases = sorted(path for path in examples_dir.iterdir() if (path / "expected-quality-issues.json").exists())

    all_issues: list[dict[str, Any]] = []
    case_results = []
    for case in cases:
        result, failures = run_case(case, quality_gate)
        case_results.append({
            "case": case.name,
            "qualitySummary": result.get("summary", {}),
            "failures": failures,
        })
        for failure in failures:
            all_issues.append({
                "severity": "blocker",
                "category": "regression-mismatch",
                "message": f"regression case {case.name} did not match expectation",
                "expected": failure,
                "actual": result.get("issues", []),
                "fixable": False,
                "autoFixed": False,
            })

    summary = {"blocker": len(all_issues), "error": 0, "warning": 0, "info": len(case_results)}
    exit_code = 2 if all_issues else 0
    output = {
        "schemaVersion": "quality-result/v1",
        "runId": "qr-regression-local",
        "gate": "regression",
        "target": str(examples_dir),
        "summary": summary,
        "issues": all_issues,
        "cases": case_results,
        "exit": {"code": exit_code, "reason": "regression_failed" if all_issues else "ok"},
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
