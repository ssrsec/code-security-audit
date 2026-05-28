#!/usr/bin/env python3
"""Run a local end-to-end smoke pipeline on a structured sample."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATE_CLI = ROOT / "state" / "state_cli.py"
QUALITY_GATE = ROOT / "quality" / "quality_gate.py"
RENDER_REPORT = ROOT / "report" / "render_report.py"


def run(cmd: list[str], *, cwd: Path = ROOT) -> dict:
    proc = subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(
            "command failed: {}\nstdout:\n{}\nstderr:\n{}".format(" ".join(cmd), proc.stdout, proc.stderr)
        )
    if proc.stdout.strip():
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {"stdout": proc.stdout}
    return {}


def copy_sample(sample_dir: Path, work_dir: Path) -> None:
    src = sample_dir / "audit-v2"
    if not src.is_dir():
        raise FileNotFoundError(f"sample audit-v2 not found: {src}")
    if work_dir.exists():
        shutil.rmtree(work_dir)
    shutil.copytree(src, work_dir)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run smoke pipeline")
    parser.add_argument("--sample-dir", default="examples/ems/vul001-render-good")
    parser.add_argument("--work-dir", default="/tmp/code-security-audit-smoke")
    parser.add_argument("--project-id", default="proj-smoke")
    args = parser.parse_args(argv)

    sample_dir = (ROOT / args.sample_dir).resolve() if not Path(args.sample_dir).is_absolute() else Path(args.sample_dir)
    work_dir = Path(args.work_dir).resolve()
    copy_sample(sample_dir, work_dir)

    steps = []
    steps.append(run([
        sys.executable,
        str(STATE_CLI),
        "--audit-dir",
        str(work_dir),
        "init",
        "--project-id",
        args.project_id,
        "--project-root",
        str(ROOT),
        "--audit-mode",
        "redteam",
        "--source-shape",
        "source-only",
    ]))

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
        path = work_dir / filename
        if path.exists():
            steps.append(run([
                sys.executable,
                str(STATE_CLI),
                "--audit-dir",
                str(work_dir),
                "import-jsonl",
                "--project-id",
                args.project_id,
                "--kind",
                kind,
                "--file",
                str(path),
            ]))

    rendered = run([
        sys.executable,
        str(RENDER_REPORT),
        "--audit-dir",
        str(work_dir),
    ])

    quality = run([
        sys.executable,
        str(QUALITY_GATE),
        "--audit-dir",
        str(work_dir),
        "--gate",
        "all",
    ])
    if quality["exit"]["code"] != 0:
        raise RuntimeError(f"quality gate failed: {json.dumps(quality, ensure_ascii=False)}")
    quality_path = work_dir / "quality-result.json"
    quality_path.write_text(json.dumps(quality, ensure_ascii=False, indent=2), encoding="utf-8")
    steps.append(run([
        sys.executable,
        str(STATE_CLI),
        "--audit-dir",
        str(work_dir),
        "import-json",
        "--project-id",
        args.project_id,
        "--kind",
        "quality-result",
        "--file",
        str(quality_path),
    ]))

    report_model = work_dir / "report_model.json"
    if report_model.exists():
        steps.append(run([
            sys.executable,
            str(STATE_CLI),
            "--audit-dir",
            str(work_dir),
            "import-json",
            "--project-id",
            args.project_id,
            "--kind",
            "report-model",
            "--file",
            str(report_model),
        ]))

    status = run([
        sys.executable,
        str(STATE_CLI),
        "--audit-dir",
        str(work_dir),
        "status",
    ])

    result = {
        "ok": True,
        "sample": str(sample_dir),
        "workDir": str(work_dir),
        "steps": steps,
        "quality": quality["summary"],
        "report": rendered["output"],
        "state": status["counts"],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
