#!/usr/bin/env python3
"""reviewer worker.

Reviews structured artifacts and quality results without changing facts.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


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


def by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row.get("id")): row for row in rows if row.get("id")}


def issue(severity: str, category: str, message: str, path: str = "") -> dict[str, str]:
    item = {
        "severity": severity,
        "category": category,
        "message": message,
    }
    if path:
        item["path"] = path
    return item


def review(audit_dir: Path, quality_result_path: Path | None) -> dict[str, Any]:
    findings = by_id(load_jsonl(audit_dir / "findings.jsonl"))
    chains = by_id(load_jsonl(audit_dir / "attack_chains.jsonl"))
    validation_tasks = load_jsonl(audit_dir / "validation_queue.jsonl")
    project = load_json(audit_dir / "project.json", {})
    decompilation_plan = load_json(audit_dir / "decompilation_plan.json", {})
    model = load_json(audit_dir / "report_model.json", {})
    quality = load_json(quality_result_path, {}) if quality_result_path else {}

    issues: list[dict[str, str]] = []

    if not model:
        issues.append(issue("blocker", "missing-report-model", "report_model.json is required before rendering", "report_model.json"))
    if model and model.get("evidencePolicy") != "full-internal-evidence-no-redaction":
        issues.append(issue("blocker", "invalid-evidence-policy", "internal report model must preserve full evidence", "report_model.json.evidencePolicy"))

    for fid in model.get("findings") or []:
        finding = findings.get(str(fid))
        if not finding:
            issues.append(issue("blocker", "missing-finding", f"report model references missing finding {fid}", "report_model.json.findings"))
            continue
        if finding.get("status") not in ("confirmed", "reported", "patched"):
            issues.append(issue("blocker", "unconfirmed-report-finding", f"report model includes non-reportable finding {fid}", f"findings:{fid}.status"))

    for chain_id in model.get("chains") or []:
        if str(chain_id) not in chains:
            issues.append(issue("blocker", "missing-chain", f"report model references missing attack chain {chain_id}", "report_model.json.chains"))

    for task in validation_tasks:
        if task.get("status") in ("pending", "claimed", "blocked", "failed"):
            issues.append(issue(
                "warning",
                "open-validation-task",
                f"validation task {task.get('taskId')} remains {task.get('status')}",
                "validation_queue.jsonl",
            ))

    decompilation = project.get("decompilation") or {}
    if decompilation.get("required") is True and not decompilation_plan:
        issues.append(issue(
            "blocker",
            "missing-decompilation-plan",
            "project requires decompilation but decompilation_plan.json is missing",
            "decompilation_plan.json",
        ))
    for task in decompilation_plan.get("tasks") or []:
        if task.get("status") != "completed":
            issues.append(issue(
                "warning",
                "decompilation-not-complete",
                f"decompilation task {task.get('taskId')} remains {task.get('status')} ({task.get('blockerType')})",
                "decompilation_plan.json",
            ))

    exit_code = (quality.get("exit") or {}).get("code")
    if exit_code not in (None, 0):
        issues.append(issue("blocker", "quality-gate-not-clean", f"quality gate exited with code {exit_code}", "quality-result"))

    summary = {"blocker": 0, "error": 0, "warning": 0, "info": 0}
    for item in issues:
        summary[item["severity"]] += 1

    return {
        "schemaVersion": "reviewer-result/v1",
        "auditDir": str(audit_dir),
        "summary": summary,
        "issues": issues,
        "decision": "blocked" if summary["blocker"] or summary["error"] else "pass-with-warnings" if summary["warning"] else "pass",
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run reviewer worker")
    parser.add_argument("--audit-dir", default="audit-v2")
    parser.add_argument("--quality-result")
    args = parser.parse_args(argv)

    audit_dir = Path(args.audit_dir)
    quality_result_path = Path(args.quality_result) if args.quality_result else None
    result = review(audit_dir, quality_result_path)
    output = audit_dir / "reviewer_notes.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "ok": result["decision"] != "blocked",
        "decision": result["decision"],
        "reviewerNotes": str(output),
        "summary": result["summary"],
    }, ensure_ascii=False))
    return 2 if result["decision"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
