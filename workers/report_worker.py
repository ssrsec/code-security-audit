#!/usr/bin/env python3
"""report worker.

Builds report_model.json from structured artifacts. Rendering remains delegated
to report/render_report.py so Markdown is never the source of truth.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPORTABLE_STATUSES = {"confirmed", "reported", "patched"}


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text:
            rows.append(json.loads(text))
    return rows


def status_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        status = str(finding.get("status", "unknown"))
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", "unknown"))
        counts[severity] = counts.get(severity, 0) + 1
    return dict(sorted(counts.items()))


def collect_recommendations(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    recommendations: list[dict[str, str]] = []
    seen: set[str] = set()
    for finding in findings:
        fix = finding.get("fix") or {}
        text = fix.get("longTerm") or fix.get("emergency")
        if not text or text in seen:
            continue
        seen.add(text)
        recommendations.append({
            "title": f"{finding.get('id')}: {text}",
            "findingId": str(finding.get("id", "")),
        })
    return recommendations


def build_model(audit_dir: Path) -> dict[str, Any]:
    project = load_json(audit_dir / "project.json", {})
    attack_surface = load_json(audit_dir / "attack_surface.json", {})
    findings = load_jsonl(audit_dir / "findings.jsonl")
    chains = load_jsonl(audit_dir / "attack_chains.jsonl")
    validation_tasks = load_jsonl(audit_dir / "validation_queue.jsonl")
    decompilation_plan = load_json(audit_dir / "decompilation_plan.json", {})

    reportable = [
        finding for finding in findings
        if finding.get("status") in REPORTABLE_STATUSES
    ]
    reportable_ids = [str(finding["id"]) for finding in reportable if finding.get("id")]
    chain_ids = [str(chain["id"]) for chain in chains if chain.get("id")]
    pending_validation = [
        task for task in validation_tasks
        if task.get("status") in ("pending", "claimed", "blocked", "failed")
    ]

    limitations: list[str] = []
    omitted = len(findings) - len(reportable)
    if omitted:
        limitations.append(f"{omitted} findings are not included because they are not confirmed/reported/patched.")
    if pending_validation:
        limitations.append(f"{len(pending_validation)} validation tasks remain open.")
    for task in decompilation_plan.get("tasks") or []:
        if task.get("status") != "completed":
            limitations.append(
                f"decompilation task {task.get('taskId')} for {task.get('artifactPath')} remains {task.get('status')} ({task.get('blockerType')})."
            )

    return {
        "schemaVersion": "report-model/v1",
        "project": {
            "name": project.get("projectId") or project.get("name") or "代码安全审计报告",
            "projectRoot": project.get("projectRoot", ""),
            "auditMode": project.get("auditMode", ""),
            "sourceShape": project.get("sourceShape", ""),
        },
        "coverage": {
            "entries": len(attack_surface.get("entries") or []),
            "sinks": len(attack_surface.get("sinks") or []),
            "secrets": len(attack_surface.get("secrets") or []),
        },
        "summary": {
            "statusCounts": status_counts(findings),
            "severityCounts": severity_counts(reportable),
            "reportableFindings": len(reportable),
            "attackChains": len(chains),
        },
        "findings": reportable_ids,
        "chains": chain_ids,
        "recommendations": collect_recommendations(reportable),
        "limitations": limitations,
        "evidencePolicy": "full-internal-evidence-no-redaction",
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run report worker")
    parser.add_argument("--audit-dir", default="audit-v2")
    args = parser.parse_args(argv)

    audit_dir = Path(args.audit_dir)
    model = build_model(audit_dir)
    output = audit_dir / "report_model.json"
    output.write_text(json.dumps(model, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "ok": True,
        "reportModel": str(output),
        "findings": len(model["findings"]),
        "chains": len(model["chains"]),
        "limitations": len(model["limitations"]),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
