#!/usr/bin/env python3
"""Local dispatcher for worker intents.

This is a process-local dispatcher for Cursor/CLI usage. It claims intents from
SQLite state, runs the matching worker, imports produced artifacts back into
state, and records completion/failure events.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STATE_CLI = ROOT / "state" / "state_cli.py"
WORKERS = {
    "recon": ROOT / "workers" / "recon_worker.py",
    "audit": ROOT / "workers" / "audit_worker.py",
    "validate": ROOT / "workers" / "validate_worker.py",
    "chain": ROOT / "workers" / "chain_worker.py",
    "report": ROOT / "workers" / "report_worker.py",
    "review": ROOT / "workers" / "reviewer_worker.py",
}


def run(cmd: list[str], *, allow_nonzero: bool = False) -> dict[str, Any]:
    proc = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True)
    if proc.returncode != 0 and not allow_nonzero:
        raise RuntimeError(
            "command failed: {}\nstdout:\n{}\nstderr:\n{}".format(" ".join(cmd), proc.stdout, proc.stderr)
        )
    data: dict[str, Any]
    if proc.stdout.strip():
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            data = {"stdout": proc.stdout}
    else:
        data = {}
    data["returncode"] = proc.returncode
    if proc.stderr.strip():
        data["stderr"] = proc.stderr[-2000:]
    return data


def state_cmd(audit_dir: Path, *args: str, allow_nonzero: bool = False) -> dict[str, Any]:
    return run([sys.executable, str(STATE_CLI), "--audit-dir", str(audit_dir), *args], allow_nonzero=allow_nonzero)


def import_jsonl(audit_dir: Path, project_id: str, kind: str, filename: str) -> dict[str, Any] | None:
    path = audit_dir / filename
    if not path.exists():
        return None
    return state_cmd(audit_dir, "import-jsonl", "--project-id", project_id, "--kind", kind, "--file", str(path))


def import_json(audit_dir: Path, project_id: str, kind: str, filename: str) -> dict[str, Any] | None:
    path = audit_dir / filename
    if not path.exists():
        return None
    return state_cmd(audit_dir, "import-json", "--project-id", project_id, "--kind", kind, "--file", str(path))


def import_outputs(audit_dir: Path, project_id: str, intent_type: str) -> list[dict[str, Any]]:
    mapping = {
        "audit": [
            ("findings", "findings.jsonl"),
            ("callchains", "callchains.jsonl"),
            ("capabilities", "capabilities.jsonl"),
        ],
        "validate": [("validation-tasks", "validation_queue.jsonl")],
        "chain": [("attack-chains", "attack_chains.jsonl")],
    }
    imported: list[dict[str, Any]] = []
    for kind, filename in mapping.get(intent_type, []):
        result = import_jsonl(audit_dir, project_id, kind, filename)
        if result is not None:
            imported.append(result)
    if intent_type == "report":
        result = import_json(audit_dir, project_id, "report-model", "report_model.json")
        if result is not None:
            imported.append(result)
    return imported


def run_worker(audit_dir: Path, intent: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    intent_type = intent["intent_type"]
    input_data = intent.get("input") or {}
    worker = WORKERS[intent_type]

    if intent_type == "recon":
        project_root = input_data.get("projectRoot") or args.project_root
        if not project_root:
            raise ValueError("recon intent requires projectRoot")
        cmd = [
            sys.executable,
            str(worker),
            "--project-root",
            str(project_root),
            "--audit-dir",
            str(audit_dir),
            "--project-id",
            args.project_id,
            "--audit-mode",
            input_data.get("auditMode", args.audit_mode),
            "--source-shape",
            input_data.get("sourceShape", args.source_shape),
        ]
    elif intent_type == "audit":
        cmd = [sys.executable, str(worker), "--audit-dir", str(audit_dir), "--limit", str(input_data.get("limit", args.audit_limit))]
    elif intent_type in ("validate", "chain", "report"):
        cmd = [sys.executable, str(worker), "--audit-dir", str(audit_dir)]
    elif intent_type == "review":
        quality_result = input_data.get("qualityResult") or str(audit_dir / "quality-result.json")
        cmd = [sys.executable, str(worker), "--audit-dir", str(audit_dir), "--quality-result", quality_result]
    else:
        raise ValueError(f"unsupported intent type: {intent_type}")

    return run(cmd, allow_nonzero=intent_type == "review")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run local dispatcher")
    parser.add_argument("--audit-dir", default="audit-v2")
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--worker-type", choices=sorted(WORKERS), required=True)
    parser.add_argument("--max-intents", type=int, default=1)
    parser.add_argument("--project-root")
    parser.add_argument("--audit-mode", choices=["redteam", "full"], default="full")
    parser.add_argument("--source-shape", choices=["source-only", "compiled-only", "mixed"], default="source-only")
    parser.add_argument("--audit-limit", type=int, default=50)
    args = parser.parse_args(argv)

    audit_dir = Path(args.audit_dir).resolve()
    state_cmd(audit_dir, "register-worker", "--project-id", args.project_id, "--worker-id", args.worker_id, "--worker-type", args.worker_type)

    processed: list[dict[str, Any]] = []
    for _ in range(args.max_intents):
        claim = state_cmd(
            audit_dir,
            "claim-intent",
            "--project-id",
            args.project_id,
            "--worker-id",
            args.worker_id,
            "--intent-type",
            args.worker_type,
        )
        if not claim.get("claimed"):
            break
        intent = claim["intent"]
        try:
            worker_result = run_worker(audit_dir, intent, args)
            imports = import_outputs(audit_dir, args.project_id, intent["intent_type"])
            status = "completed" if worker_result.get("returncode") == 0 else "failed"
            finish = state_cmd(
                audit_dir,
                "finish-intent",
                "--worker-id",
                args.worker_id,
                "--intent-id",
                intent["id"],
                "--status",
                status,
                "--payload",
                json.dumps({"workerResult": worker_result, "imports": imports}, ensure_ascii=False),
            )
            processed.append({"intent": intent["id"], "status": status, "workerResult": worker_result, "imports": imports, "finish": finish})
        except Exception as exc:
            finish = state_cmd(
                audit_dir,
                "finish-intent",
                "--worker-id",
                args.worker_id,
                "--intent-id",
                intent["id"],
                "--status",
                "failed",
                "--severity",
                "error",
                "--message",
                str(exc),
                allow_nonzero=True,
            )
            processed.append({"intent": intent["id"], "status": "failed", "error": str(exc), "finish": finish})

    print(json.dumps({
        "ok": all(item["status"] == "completed" for item in processed),
        "processed": processed,
    }, ensure_ascii=False, indent=2))
    return 0 if all(item["status"] == "completed" for item in processed) else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
