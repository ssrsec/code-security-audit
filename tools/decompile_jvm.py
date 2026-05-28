#!/usr/bin/env python3
"""Run JVM decompilation tasks from decompilation_plan.json.

Default mode is dry-run. Use --execute to call the repository's CFR wrapper.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
UNIX_WRAPPER = ROOT / "scripts" / "tools" / "decompilers" / "bin" / "decompile-java.sh"
WINDOWS_WRAPPER = ROOT / "scripts" / "tools" / "decompilers" / "bin" / "decompile-java.cmd"


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def wrapper_command(input_path: Path, output_dir: Path) -> list[str]:
    if platform.system().lower().startswith("win"):
        return [str(WINDOWS_WRAPPER), str(input_path), str(output_dir)]
    return ["bash", str(UNIX_WRAPPER), str(input_path), str(output_dir)]


def is_jvm_task(task: dict[str, Any]) -> bool:
    return task.get("platform") == "jvm" or "decompilation.jvm" in (task.get("recommendedAssets") or [])


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run JVM decompilation tasks")
    parser.add_argument("--audit-dir", default="audit-v2")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--write-plan", action="store_true", help="write status updates back to decompilation_plan.json")
    args = parser.parse_args(argv)

    audit_dir = Path(args.audit_dir)
    project = load_json(audit_dir / "project.json")
    plan_path = audit_dir / "decompilation_plan.json"
    plan = load_json(plan_path)
    project_root = Path(project["projectRoot"])

    results: list[dict[str, Any]] = []
    exit_code = 0
    for task in plan.get("tasks") or []:
        if not is_jvm_task(task):
            continue
        artifact_path = project_root / str(task["artifactPath"])
        output_dir = audit_dir / str(task["outputDir"])
        cmd = wrapper_command(artifact_path, output_dir)
        result: dict[str, Any] = {
            "taskId": task["taskId"],
            "artifactPath": str(artifact_path),
            "outputDir": str(output_dir),
            "command": cmd,
            "execute": args.execute,
        }
        if args.execute:
            task["status"] = "running"
            proc = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True)
            result["returncode"] = proc.returncode
            result["stdout"] = proc.stdout[-4000:]
            result["stderr"] = proc.stderr[-4000:]
            task["tool"] = "cfr"
            task["toolVersion"] = "0.152"
            task["updatedAt"] = now()
            if proc.returncode == 0:
                task["status"] = "completed"
                task["blockerType"] = "none"
            else:
                task["status"] = "failed"
                task["blockerType"] = "failed"
                task["limitations"] = [proc.stderr[-1000:] or proc.stdout[-1000:] or "decompiler failed"]
                exit_code = 2
        results.append(result)

    if args.write_plan:
        write_json(plan_path, plan)

    print(json.dumps({
        "ok": exit_code == 0,
        "mode": "execute" if args.execute else "dry-run",
        "tasks": len(results),
        "results": results,
        "plan": str(plan_path),
    }, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
