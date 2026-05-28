#!/usr/bin/env python3
"""validation worker.

Creates validation queue tasks from candidate findings. It intentionally does
not upgrade findings to confirmed without evidence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


PRIORITY_BY_SEVERITY = {
    "critical": "P0",
    "high": "P0",
    "medium": "P1",
    "low": "P2",
}


SAFE_LEVEL_BY_OPERATION = {
    "read-only": "L1",
    "write-capable": "L2",
    "state-changing": "L2",
    "destructive": "L3",
    "unknown": "L1",
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text:
            rows.append(json.loads(text))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def providers_for(finding: dict[str, Any], capabilities: list[dict[str, Any]]) -> list[str]:
    required = set(finding.get("requiresCapabilities") or [])
    if not required:
        return []
    providers: list[str] = []
    for capability in capabilities:
        cap_id = capability.get("id")
        provided = set(capability.get("provides") or [])
        if cap_id in required or required.intersection(provided):
            providers.append(str(cap_id))
    return sorted(set(providers))


def make_task(idx: int, finding: dict[str, Any], capabilities: list[dict[str, Any]]) -> dict[str, Any]:
    operation_classes = finding.get("operationClasses") or ["unknown"]
    safe_level = max(
        (SAFE_LEVEL_BY_OPERATION.get(op, "L1") for op in operation_classes),
        key=lambda level: {"L1": 1, "L2": 2, "L3": 3}[level],
    )
    required = finding.get("requiresCapabilities") or []
    candidate_providers = providers_for(finding, capabilities)
    blocker_type = "none"
    next_action = "Validate source controllability, reachability, evidence, and PoC before any status upgrade."
    if required and not candidate_providers:
        blocker_type = "needs-user-hint"
        next_action = "Required capability has no provider; find or validate a provider before proof execution."
    return {
        "schemaVersion": "validation-task/v1",
        "taskId": f"val-{idx:04d}",
        "findingId": finding["id"],
        "priority": PRIORITY_BY_SEVERITY.get(finding.get("severity", "medium"), "P2"),
        "status": "pending",
        "requiredCapabilities": required,
        "candidateProviders": candidate_providers,
        "blockerType": blocker_type,
        "nextAction": next_action,
        "safeLevel": safe_level,
        "attempts": []
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run validate worker")
    parser.add_argument("--audit-dir", default="audit-v2")
    args = parser.parse_args(argv)

    audit_dir = Path(args.audit_dir)
    findings = load_jsonl(audit_dir / "findings.jsonl")
    capabilities = load_jsonl(audit_dir / "capabilities.jsonl")
    tasks = []
    for finding in findings:
        if finding.get("status") in ("confirmed", "rejected", "reported"):
            continue
        tasks.append(make_task(len(tasks) + 1, finding, capabilities))
    write_jsonl(audit_dir / "validation_queue.jsonl", tasks)
    print(json.dumps({"ok": True, "validationTasks": len(tasks)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
