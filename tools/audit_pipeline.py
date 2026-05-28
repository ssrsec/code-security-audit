#!/usr/bin/env python3
"""Run the structured audit pipeline for a project path."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from runtime_env import reexec_in_project_venv


ROOT = Path(__file__).resolve().parents[1]
RECON_WORKER = ROOT / "workers" / "recon_worker.py"
AUDIT_WORKER = ROOT / "workers" / "audit_worker.py"
VALIDATE_WORKER = ROOT / "workers" / "validate_worker.py"
CHAIN_WORKER = ROOT / "workers" / "chain_worker.py"
REPORT_WORKER = ROOT / "workers" / "report_worker.py"
REVIEWER_WORKER = ROOT / "workers" / "reviewer_worker.py"
DECOMPILE_STUB = ROOT / "tools" / "decompile_stub.py"
STATE_CLI = ROOT / "state" / "state_cli.py"
QUALITY_GATE = ROOT / "quality" / "quality_gate.py"
RENDER_REPORT = ROOT / "report" / "render_report.py"


def run(cmd: list[str], *, allow_nonzero: bool = False) -> dict[str, Any]:
    proc = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True)
    if proc.returncode != 0 and not allow_nonzero:
        raise RuntimeError(
            "command failed: {}\nstdout:\n{}\nstderr:\n{}".format(" ".join(cmd), proc.stdout, proc.stderr)
        )
    if not proc.stdout.strip():
        return {"returncode": proc.returncode}
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        data = {"stdout": proc.stdout}
    data.setdefault("returncode", proc.returncode)
    return data


def import_jsonl_steps(audit_dir: Path, project_id: str) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for kind, filename in (
        ("findings", "findings.jsonl"),
        ("callchains", "callchains.jsonl"),
        ("requests", "requests.jsonl"),
        ("evidence", "evidence.jsonl"),
        ("capabilities", "capabilities.jsonl"),
        ("mutations", "mutations.jsonl"),
        ("validation-tasks", "validation_queue.jsonl"),
        ("attack-chains", "attack_chains.jsonl"),
    ):
        path = audit_dir / filename
        if not path.exists():
            continue
        steps.append(run([
            sys.executable,
            str(STATE_CLI),
            "--audit-dir",
            str(audit_dir),
            "import-jsonl",
            "--project-id",
            project_id,
            "--kind",
            kind,
            "--file",
            str(path),
        ]))
    return steps


def import_json_step(audit_dir: Path, project_id: str, kind: str, filename: str) -> dict[str, Any] | None:
    path = audit_dir / filename
    if not path.exists():
        return None
    return run([
        sys.executable,
        str(STATE_CLI),
        "--audit-dir",
        str(audit_dir),
        "import-json",
        "--project-id",
        project_id,
        "--kind",
        kind,
        "--file",
        str(path),
    ])


def main(argv: list[str]) -> int:
    reexec_in_project_venv()
    parser = argparse.ArgumentParser(description="Run audit pipeline")
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--audit-dir", default="audit-v2")
    parser.add_argument("--project-id", default="proj-default")
    parser.add_argument("--audit-mode", choices=["redteam", "full"], default="full")
    parser.add_argument("--source-shape", choices=["source-only", "compiled-only", "mixed"], default="source-only")
    parser.add_argument("--audit-limit", type=int, default=50)
    args = parser.parse_args(argv)

    project_root = Path(args.project_root).resolve()
    audit_dir = Path(args.audit_dir).resolve()
    audit_dir.mkdir(parents=True, exist_ok=True)

    steps: list[dict[str, Any]] = []
    steps.append(run([
        sys.executable,
        str(RECON_WORKER),
        "--project-root",
        str(project_root),
        "--audit-dir",
        str(audit_dir),
        "--project-id",
        args.project_id,
        "--audit-mode",
        args.audit_mode,
        "--source-shape",
        args.source_shape,
    ]))
    project = json.loads((audit_dir / "project.json").read_text(encoding="utf-8"))
    if (project.get("decompilation") or {}).get("required"):
        steps.append(run([
            sys.executable,
            str(DECOMPILE_STUB),
            "--audit-dir",
            str(audit_dir),
        ]))
    steps.append(run([
        sys.executable,
        str(AUDIT_WORKER),
        "--audit-dir",
        str(audit_dir),
        "--limit",
        str(args.audit_limit),
    ]))
    steps.append(run([sys.executable, str(VALIDATE_WORKER), "--audit-dir", str(audit_dir)]))
    steps.append(run([sys.executable, str(CHAIN_WORKER), "--audit-dir", str(audit_dir)]))
    steps.append(run([sys.executable, str(REPORT_WORKER), "--audit-dir", str(audit_dir)]))

    rendered = run([sys.executable, str(RENDER_REPORT), "--audit-dir", str(audit_dir)])

    quality = run([
        sys.executable,
        str(QUALITY_GATE),
        "--audit-dir",
        str(audit_dir),
        "--gate",
        "all",
    ], allow_nonzero=True)
    quality_path = audit_dir / "quality-result.json"
    quality_path.write_text(json.dumps(quality, ensure_ascii=False, indent=2), encoding="utf-8")

    reviewer = run([
        sys.executable,
        str(REVIEWER_WORKER),
        "--audit-dir",
        str(audit_dir),
        "--quality-result",
        str(quality_path),
    ], allow_nonzero=True)

    steps.append(run([
        sys.executable,
        str(STATE_CLI),
        "--audit-dir",
        str(audit_dir),
        "init",
        "--project-id",
        args.project_id,
        "--project-root",
        str(project_root),
        "--audit-mode",
        args.audit_mode,
        "--source-shape",
        args.source_shape,
    ]))
    steps.extend(import_jsonl_steps(audit_dir, args.project_id))
    for item in (
        import_json_step(audit_dir, args.project_id, "quality-result", "quality-result.json"),
        import_json_step(audit_dir, args.project_id, "report-model", "report_model.json"),
        import_json_step(audit_dir, args.project_id, "decompilation-plan", "decompilation_plan.json"),
    ):
        if item is not None:
            steps.append(item)
    state = run([sys.executable, str(STATE_CLI), "--audit-dir", str(audit_dir), "status"])

    output = {
        "ok": quality.get("exit", {}).get("code") == 0 and reviewer.get("returncode", 0) == 0,
        "projectRoot": str(project_root),
        "auditDir": str(audit_dir),
        "steps": steps,
        "quality": quality.get("summary", {}),
        "reviewer": {
            "decision": reviewer.get("decision"),
            "summary": reviewer.get("summary"),
        },
        "report": rendered.get("output"),
        "state": state.get("counts", {}),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if output["ok"] else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
