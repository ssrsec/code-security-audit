#!/usr/bin/env python3
"""Create a decompilation execution plan from recon artifacts.

This tool does not pretend to decompile without a configured backend. It turns
compiledArtifacts into explicit work items so compiled-only projects become
blocked/plannable instead of silently under-audited.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_plan(audit_dir: Path, output_dir: str) -> dict[str, Any]:
    project = load_json(audit_dir / "project.json")
    project_root = Path(project.get("projectRoot", ""))
    artifacts = project.get("compiledArtifacts") or []
    decompilation = project.get("decompilation") or {}
    tasks = []
    for artifact in artifacts:
        platform_name = artifact.get("platform", "unknown")
        recommended_assets = [
            asset for asset in decompilation.get("recommendedAssets", [])
            if platform_name in asset or asset.endswith("generic")
        ] or decompilation.get("recommendedAssets", [])
        artifact_path = artifact.get("path")
        artifact_sha = sha256_file(project_root / str(artifact_path)) if artifact_path else None
        task = {
            "taskId": f"decompile-{len(tasks)+1:04d}",
            "artifactId": artifact.get("id"),
            "artifactPath": artifact_path,
            "platform": platform_name,
            "artifactType": artifact.get("artifactType"),
            "recommendedAssets": recommended_assets,
            "outputDir": str(Path(output_dir) / str(artifact.get("id"))),
            "status": "planned",
            "blockerType": "decompiler-not-configured",
        }
        if artifact_sha:
            task["artifactSha256"] = artifact_sha
        tasks.append(task)
    return {
        "schemaVersion": "decompilation-plan/v1",
        "createdAt": now(),
        "projectId": project.get("projectId"),
        "required": bool(artifacts),
        "tasks": tasks,
        "limitations": [] if tasks else ["No compiled artifacts detected."],
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Build decompilation plan")
    parser.add_argument("--audit-dir", default="audit-v2")
    parser.add_argument("--output-dir", default="decompiled")
    args = parser.parse_args(argv)

    audit_dir = Path(args.audit_dir)
    plan = build_plan(audit_dir, args.output_dir)
    output = audit_dir / "decompilation_plan.json"
    output.write_text(json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "ok": True,
        "required": plan["required"],
        "tasks": len(plan["tasks"]),
        "output": str(output),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
