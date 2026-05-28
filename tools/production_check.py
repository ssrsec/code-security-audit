#!/usr/bin/env python3
"""Run production readiness checks that do not require a live target."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from runtime_env import ensure_project_venv, venv_python


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def ensure_runtime_python() -> dict[str, Any]:
    try:
        python = ensure_project_venv()
    except subprocess.CalledProcessError as exc:
        return {
            "ok": False,
            "name": "runtime-venv",
            "python": str(venv_python()),
            "returncode": exc.returncode,
            "command": exc.cmd,
        }
    return {"ok": True, "name": "runtime-venv", "python": str(python)}


def run(cmd: list[str], *, allow_nonzero: bool = False) -> dict[str, Any]:
    proc = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True)
    result: dict[str, Any] = {
        "command": cmd,
        "returncode": proc.returncode,
    }
    if proc.stdout.strip():
        try:
            result["output"] = json.loads(proc.stdout)
        except json.JSONDecodeError:
            result["stdout"] = proc.stdout[-4000:]
    if proc.stderr.strip():
        result["stderr"] = proc.stderr[-4000:]
    if proc.returncode != 0 and not allow_nonzero:
        result["ok"] = False
        return result
    result["ok"] = True
    return result


def all_ok(results: list[dict[str, Any]]) -> bool:
    return all(result.get("ok") for result in results)


def run_dispatcher_smoke(temp_root: Path) -> dict[str, Any]:
    audit_dir = temp_root / "dispatcher-smoke"
    commands = [
        [
            PYTHON,
            "state/state_cli.py",
            "--audit-dir",
            str(audit_dir),
            "init",
            "--project-id",
            "dispatcher-generic",
            "--project-root",
            "examples/generic/python-sqli-app/source",
            "--audit-mode",
            "redteam",
            "--source-shape",
            "source-only",
        ],
        [
            PYTHON,
            "workers/recon_worker.py",
            "--project-root",
            "examples/generic/python-sqli-app/source",
            "--audit-dir",
            str(audit_dir),
            "--project-id",
            "dispatcher-generic",
            "--audit-mode",
            "redteam",
            "--source-shape",
            "source-only",
        ],
        [
            PYTHON,
            "state/state_cli.py",
            "--audit-dir",
            str(audit_dir),
            "add-intent",
            "--project-id",
            "dispatcher-generic",
            "--intent-id",
            "intent-audit-001",
            "--intent-type",
            "audit",
            "--priority",
            "P1",
            "--description",
            "audit generic fixture",
            "--input-json",
            "{\"limit\":10}",
        ],
        [
            PYTHON,
            "tools/dispatcher.py",
            "--audit-dir",
            str(audit_dir),
            "--project-id",
            "dispatcher-generic",
            "--worker-id",
            "worker-audit-1",
            "--worker-type",
            "audit",
            "--max-intents",
            "1",
        ],
        [
            PYTHON,
            "state/state_cli.py",
            "--audit-dir",
            str(audit_dir),
            "status",
        ],
    ]
    steps = []
    for cmd in commands:
        result = run(cmd)
        steps.append(result)
        if not result.get("ok"):
            return {"ok": False, "name": "dispatcher-smoke", "steps": steps}

    status = steps[-1].get("output", {})
    counts = status.get("counts", {})
    expected = {
        "workers": 1,
        "intents": 1,
        "findings": 1,
        "callchains": 1,
        "capabilities": 1,
    }
    failures = {
        key: {"expected": value, "actual": counts.get(key)}
        for key, value in expected.items()
        if counts.get(key) != value
    }
    return {
        "ok": not failures,
        "name": "dispatcher-smoke",
        "steps": steps,
        "expected": expected,
        "actual": counts,
        "failures": failures,
    }


def run_compiled_artifact_smoke(temp_root: Path) -> dict[str, Any]:
    audit_dir = temp_root / "compiled-jvm-recon"
    result = run([
        PYTHON,
        "workers/recon_worker.py",
        "--project-root",
        "examples/generic/compiled-jvm-app",
        "--audit-dir",
        str(audit_dir),
        "--project-id",
        "generic-compiled-jvm",
        "--audit-mode",
        "redteam",
        "--source-shape",
        "compiled-only",
    ])
    if not result.get("ok"):
        return {"ok": False, "name": "compiled-artifact-smoke", "steps": [result]}
    decompile = run([
        PYTHON,
        "tools/decompile_stub.py",
        "--audit-dir",
        str(audit_dir),
    ])
    if not decompile.get("ok"):
        return {"ok": False, "name": "compiled-artifact-smoke", "steps": [result, decompile]}
    jvm_dry_run = run([
        PYTHON,
        "tools/decompile_jvm.py",
        "--audit-dir",
        str(audit_dir),
    ])
    if not jvm_dry_run.get("ok"):
        return {"ok": False, "name": "compiled-artifact-smoke", "steps": [result, decompile, jvm_dry_run]}
    state_init = run([
        PYTHON,
        "state/state_cli.py",
        "--audit-dir",
        str(audit_dir),
        "init",
        "--project-id",
        "generic-compiled-jvm",
        "--project-root",
        "examples/generic/compiled-jvm-app",
        "--audit-mode",
        "redteam",
        "--source-shape",
        "compiled-only",
    ])
    state_import = run([
        PYTHON,
        "state/state_cli.py",
        "--audit-dir",
        str(audit_dir),
        "import-json",
        "--project-id",
        "generic-compiled-jvm",
        "--kind",
        "decompilation-plan",
        "--file",
        str(audit_dir / "decompilation_plan.json"),
    ])
    state_status = run([
        PYTHON,
        "state/state_cli.py",
        "--audit-dir",
        str(audit_dir),
        "status",
    ])
    project = json.loads((audit_dir / "project.json").read_text(encoding="utf-8"))
    plan = json.loads((audit_dir / "decompilation_plan.json").read_text(encoding="utf-8"))
    decompilation = project.get("decompilation") or {}
    failures: dict[str, Any] = {}
    if result.get("output", {}).get("compiledArtifacts") != 1:
        failures["compiledArtifacts"] = {
            "expected": 1,
            "actual": result.get("output", {}).get("compiledArtifacts"),
        }
    if decompilation.get("required") is not True:
        failures["decompilation.required"] = {
            "expected": True,
            "actual": decompilation.get("required"),
        }
    if "decompilation.jvm" not in (decompilation.get("recommendedAssets") or []):
        failures["decompilation.recommendedAssets"] = {
            "expected": "decompilation.jvm",
            "actual": decompilation.get("recommendedAssets"),
        }
    if decompile.get("output", {}).get("tasks") != 1 or len(plan.get("tasks") or []) != 1:
        failures["decompilation_plan.tasks"] = {
            "expected": 1,
            "actual": decompile.get("output", {}).get("tasks"),
        }
    if state_status.get("output", {}).get("counts", {}).get("decompilation_tasks") != 1:
        failures["state.decompilation_tasks"] = {
            "expected": 1,
            "actual": state_status.get("output", {}).get("counts", {}).get("decompilation_tasks"),
        }
    return {
        "ok": not failures,
        "name": "compiled-artifact-smoke",
        "steps": [result, decompile, jvm_dry_run, state_init, state_import, state_status],
        "failures": failures,
    }


def run_dotnet_decompilation_smoke(temp_root: Path) -> dict[str, Any]:
    project_root = temp_root / "dotnet-compiled-app"
    artifact_dir = project_root / "bin"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    # The dry-run wrapper only needs a real path so hashing and command planning are exercised.
    (artifact_dir / "Example.dll").write_bytes(b"MZ\x00dotnet-fixture")

    audit_dir = temp_root / "dotnet-decompilation"
    recon = run([
        PYTHON,
        "workers/recon_worker.py",
        "--project-root",
        str(project_root),
        "--audit-dir",
        str(audit_dir),
        "--project-id",
        "generic-dotnet-compiled",
        "--audit-mode",
        "redteam",
        "--source-shape",
        "compiled-only",
    ])
    if not recon.get("ok"):
        return {"ok": False, "name": "dotnet-decompilation-smoke", "steps": [recon]}
    plan_result = run([
        PYTHON,
        "tools/decompile_stub.py",
        "--audit-dir",
        str(audit_dir),
    ])
    if not plan_result.get("ok"):
        return {"ok": False, "name": "dotnet-decompilation-smoke", "steps": [recon, plan_result]}
    dotnet_dry_run = run([
        PYTHON,
        "tools/decompile_dotnet.py",
        "--audit-dir",
        str(audit_dir),
    ])
    project = json.loads((audit_dir / "project.json").read_text(encoding="utf-8"))
    plan = json.loads((audit_dir / "decompilation_plan.json").read_text(encoding="utf-8"))
    failures: dict[str, Any] = {}
    if recon.get("output", {}).get("compiledArtifacts") != 1:
        failures["compiledArtifacts"] = {
            "expected": 1,
            "actual": recon.get("output", {}).get("compiledArtifacts"),
        }
    if "decompilation.dotnet" not in ((project.get("decompilation") or {}).get("recommendedAssets") or []):
        failures["decompilation.recommendedAssets"] = {
            "expected": "decompilation.dotnet",
            "actual": (project.get("decompilation") or {}).get("recommendedAssets"),
        }
    if plan_result.get("output", {}).get("tasks") != 1 or len(plan.get("tasks") or []) != 1:
        failures["decompilation_plan.tasks"] = {
            "expected": 1,
            "actual": plan_result.get("output", {}).get("tasks"),
        }
    if dotnet_dry_run.get("output", {}).get("tasks") != 1:
        failures["dotnet_dry_run.tasks"] = {
            "expected": 1,
            "actual": dotnet_dry_run.get("output", {}).get("tasks"),
        }
    return {
        "ok": dotnet_dry_run.get("ok") and not failures,
        "name": "dotnet-decompilation-smoke",
        "steps": [recon, plan_result, dotnet_dry_run],
        "failures": failures,
    }


def write_language_matrix_project(project_root: Path) -> None:
    files = {
        "php/composer.json": "{\"require\":{\"slim/slim\":\"*\"}}\n",
        "php/index.php": "<?php\n$id = $_GET['id'];\n$pdo->query(\"SELECT * FROM users WHERE id = \" . $id);\n",
        "java/pom.xml": "<project></project>\n",
        "java/UserController.java": "class UserController { @GetMapping(\"/admin\") void admin(HttpServletRequest request, java.sql.Statement st) throws Exception { st.executeQuery(\"SELECT * FROM users WHERE id=\" + request.getParameter(\"id\")); } }\n",
        "dotnet/App.csproj": "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        "dotnet/UsersController.cs": "class UsersController : ControllerBase { [HttpGet(\"/admin\")] void Get() { var id = Request.Query[\"id\"]; System.Diagnostics.Process.Start(id); } }\n",
        "go/go.mod": "module example.com/app\n",
        "go/main.go": "package main\nimport \"net/http\"\nfunc main(){ http.HandleFunc(\"/admin\", func(w http.ResponseWriter, r *http.Request){ id := r.URL.Query().Get(\"id\"); db.Query(\"SELECT * FROM users WHERE id=\"+id) }) }\n",
        "python/pyproject.toml": "[project]\nname='matrix'\n",
        "python/app.py": "from flask import request\n@app.route('/admin')\ndef admin():\n    cursor.execute('SELECT * FROM users WHERE id=' + request.args['id'])\n",
        "node/package.json": "{\"scripts\":{\"start\":\"node app.ts\"},\"dependencies\":{\"express\":\"*\"}}\n",
        "node/app.ts": "app.get('/admin', (req, res) => { db.query('SELECT * FROM users WHERE id=' + req.query.id) })\n",
        "ruby/Gemfile": "gem 'sinatra'\n",
        "ruby/app.rb": "get '/admin' do\n  id = params[:id]\n  DB.execute('SELECT * FROM users WHERE id=' + id)\nend\n",
        "rust/Cargo.toml": "[package]\nname='matrix'\nversion='0.1.0'\n",
        "rust/src/main.rs": "fn main(){ let app = Router::new().route(\"/admin\", get(handler)); sqlx::query(\"SELECT * FROM users\"); std::process::Command::new(\"sh\"); }\n",
        "kotlin/build.gradle.kts": "plugins { kotlin(\"jvm\") version \"1.9.0\" }\n",
        "kotlin/UserController.kt": "class UserController { @GetMapping(\"/admin\") fun admin(request: HttpServletRequest) { jdbcTemplate.queryForList(\"SELECT * FROM users WHERE id=\" + request.getParameter(\"id\")) } }\n",
        "deno/deno.json": "{\"tasks\":{\"start\":\"deno run server.ts\"}}\n",
        "deno/server.ts": "Deno.serve((req) => { const id = new URL(req.url).searchParams.get('id'); return fetch('http://internal/' + id); });\n",
        "bun/bun.lockb": "fixture\n",
        "bun/server.ts": "Bun.serve({ fetch(req) { const id = new URL(req.url).searchParams.get('id'); return fetch('http://internal/' + id); } });\n",
    }
    for rel, content in files.items():
        path = project_root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def run_language_matrix_smoke(temp_root: Path) -> dict[str, Any]:
    project_root = temp_root / "language-matrix-project"
    write_language_matrix_project(project_root)
    audit_dir = temp_root / "language-matrix"
    recon = run([
        PYTHON,
        "workers/recon_worker.py",
        "--project-root",
        str(project_root),
        "--audit-dir",
        str(audit_dir),
        "--project-id",
        "language-matrix",
        "--audit-mode",
        "redteam",
        "--source-shape",
        "source-only",
    ])
    if not recon.get("ok"):
        return {"ok": False, "name": "language-matrix-smoke", "steps": [recon]}
    audit = run([
        PYTHON,
        "workers/audit_worker.py",
        "--audit-dir",
        str(audit_dir),
        "--limit",
        "60",
    ])
    project = json.loads((audit_dir / "project.json").read_text(encoding="utf-8"))
    surface = json.loads((audit_dir / "attack_surface.json").read_text(encoding="utf-8"))
    findings = [
        json.loads(line)
        for line in (audit_dir / "findings.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    expected_languages = {"php", "java", "csharp", "go", "python", "typescript", "ruby", "rust", "kotlin"}
    expected_frameworks = {"php", "jvm", "dotnet", "go", "python", "node", "ruby", "rust", "kotlin", "deno", "bun"}
    languages = set(project.get("languages") or [])
    frameworks = set(project.get("frameworks") or [])
    failures: dict[str, Any] = {}
    missing_languages = sorted(expected_languages - languages)
    missing_frameworks = sorted(expected_frameworks - frameworks)
    if missing_languages:
        failures["languages"] = {"missing": missing_languages, "actual": sorted(languages)}
    if missing_frameworks:
        failures["frameworks"] = {"missing": missing_frameworks, "actual": sorted(frameworks)}
    for key, minimum in {"entries": 10, "sources": 10, "sinks": 10, "findings": 10}.items():
        actual = len(findings) if key == "findings" else len(surface.get(key) or [])
        if actual < minimum:
            failures[key] = {"expectedAtLeast": minimum, "actual": actual}
    return {
        "ok": audit.get("ok") and not failures,
        "name": "language-matrix-smoke",
        "steps": [recon, audit],
        "expectedLanguages": sorted(expected_languages),
        "actualLanguages": sorted(languages),
        "expectedFrameworks": sorted(expected_frameworks),
        "actualFrameworks": sorted(frameworks),
        "counts": {
            "entries": len(surface.get("entries") or []),
            "sources": len(surface.get("sources") or []),
            "sinks": len(surface.get("sinks") or []),
            "findings": len(findings),
        },
        "failures": failures,
    }


def run_http_l2_guard(temp_root: Path) -> dict[str, Any]:
    audit_dir = temp_root / "http-l2-guard"
    audit_dir.mkdir(parents=True, exist_ok=True)
    requests_file = audit_dir / "requests.jsonl"
    requests_file.write_text(
        json.dumps({
            "schemaVersion": "http-request/v1",
            "id": "req-l2-guard",
            "findingId": "vul-900",
            "raw": "POST /admin/delete HTTP/1.1\r\nHost: example.local\r\nContent-Type: application/json\r\n\r\n{\"id\":\"1\"}",
            "method": "POST",
            "path": "/admin/delete",
            "host": "example.local",
            "contentType": "application/json",
            "authUsage": "none",
            "obtainedBy": [],
            "variables": [],
            "safeLevel": "L2",
            "purpose": "proof",
        }, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    result = run([
        PYTHON,
        "tools/http_replay.py",
        "--audit-dir",
        str(audit_dir),
        "--execute",
    ], allow_nonzero=True)
    output = result.get("output") or {}
    blocked = (
        result.get("returncode") == 2
        and output.get("ok") is False
        and output.get("results", [{}])[0].get("allowed") is False
    )
    return {
        "ok": blocked,
        "name": "http-l2-guard",
        "result": result,
    }


def run_entrypoint_guard() -> dict[str, Any]:
    root_skill_path = ROOT / "SKILL.md"
    root_text = root_skill_path.read_text(encoding="utf-8")
    root_is_production_default = (
        "name: code-security-audit\n" in root_text
        and "本入口默认执行生产协议" in root_text
        and "python3 tools/production_check.py" in root_text
        and "audit-v2/" in root_text
    )
    no_versioned_impl_dir = not (ROOT / "v2").exists()
    ok = root_is_production_default and no_versioned_impl_dir
    return {
        "ok": ok,
        "name": "entrypoint-guard",
        "rootSkill": {
            "path": str(root_skill_path),
            "expected": "production default entrypoint",
            "actual": "production-default" if root_is_production_default else "not-production-default",
        },
        "versionedImplementationDir": {
            "path": str(ROOT / "v2"),
            "expected": "absent",
            "actual": "present" if not no_versioned_impl_dir else "absent",
        },
    }


def run_packaging_guard() -> dict[str, Any]:
    gitignore = ROOT / ".gitignore"
    patterns = set(gitignore.read_text(encoding="utf-8").splitlines()) if gitignore.exists() else set()
    required = {".venv/", "__pycache__/", "*.py[cod]", ".pytest_cache/", ".mypy_cache/", ".ruff_cache/"}
    missing = sorted(required - patterns)
    return {
        "ok": not missing,
        "name": "packaging-guard",
        "checked": str(gitignore),
        "missingPatterns": missing,
    }


def run_self_project_pipeline(temp_root: Path) -> dict[str, Any]:
    audit_dir = temp_root / "self-project-pipeline"
    result = run([
        PYTHON,
        "tools/audit_pipeline.py",
        "--project-root",
        ".",
        "--audit-dir",
        str(audit_dir),
        "--project-id",
        "code-security-audit-self",
        "--audit-mode",
        "redteam",
        "--source-shape",
        "source-only",
        "--audit-limit",
        "25",
    ])
    output = result.get("output") or {}
    state = output.get("state") or {}
    failures: dict[str, Any] = {}
    expected_counts = {
        "findings": 1,
        "validation_tasks": 1,
        "decompilation_tasks": 1,
    }
    for key, minimum in expected_counts.items():
        actual = state.get(key, 0)
        if actual < minimum:
            failures[f"state.{key}"] = {"expectedAtLeast": minimum, "actual": actual}
    if output.get("ok") is not True:
        failures["pipeline.ok"] = {"expected": True, "actual": output.get("ok")}
    if (output.get("quality") or {}).get("blocker", 0) != 0:
        failures["quality.blocker"] = {"expected": 0, "actual": (output.get("quality") or {}).get("blocker")}
    return {
        "ok": result.get("ok") and not failures,
        "name": "self-project-pipeline",
        "result": result,
        "failures": failures,
    }


def main(argv: list[str]) -> int:
    global PYTHON
    parser = argparse.ArgumentParser(description="Run production readiness checks")
    parser.add_argument("--keep-workdirs", action="store_true")
    args = parser.parse_args(argv)

    temp_root = Path(tempfile.mkdtemp(prefix="code-security-audit-prod-check."))
    results: list[dict[str, Any]] = [ensure_runtime_python()]
    if results[0].get("ok"):
        PYTHON = str(results[0]["python"])

    commands = [
        [
            PYTHON,
            "-m",
            "py_compile",
            "tools/bootstrap.py",
            "tools/decompile_jvm.py",
            "tools/decompile_dotnet.py",
            "tools/decompile_stub.py",
            "tools/dispatcher.py",
            "tools/runtime_env.py",
            "tools/audit_pipeline.py",
            "tools/audit_smoke.py",
            "tools/http_replay.py",
            "tools/validate_assets.py",
            "quality/quality_gate.py",
            "quality/regression_gate.py",
            "state/state_cli.py",
            "report/render_report.py",
            "workers/recon_worker.py",
            "workers/audit_worker.py",
            "workers/validate_worker.py",
            "workers/chain_worker.py",
            "workers/report_worker.py",
            "workers/reviewer_worker.py",
        ],
        [PYTHON, "tools/validate_assets.py"],
        [PYTHON, "tools/bootstrap.py"],
        [PYTHON, "tools/audit_smoke.py", "--work-dir", str(temp_root / "audit-smoke")],
        [PYTHON, "quality/regression_gate.py"],
        [
            PYTHON,
            "tools/audit_pipeline.py",
            "--project-root",
            "examples/generic/python-sqli-app/source",
            "--audit-dir",
            str(temp_root / "generic-pipeline"),
            "--project-id",
            "generic-python-sqli",
            "--audit-mode",
            "redteam",
            "--source-shape",
            "source-only",
            "--audit-limit",
            "10",
        ],
        [
            PYTHON,
            "tools/http_replay.py",
            "--audit-dir",
            "examples/ems/vul127-chain-good/audit-v2",
        ],
        [
            PYTHON,
            "tools/audit_pipeline.py",
            "--project-root",
            "examples/generic/node-sqli-app/source",
            "--audit-dir",
            str(temp_root / "generic-node-pipeline"),
            "--project-id",
            "generic-node-sqli",
            "--audit-mode",
            "redteam",
            "--source-shape",
            "source-only",
            "--audit-limit",
            "10",
        ],
        [
            PYTHON,
            "tools/audit_pipeline.py",
            "--project-root",
            "examples/generic/node-authz-app/source",
            "--audit-dir",
            str(temp_root / "generic-authz-pipeline"),
            "--project-id",
            "generic-node-authz",
            "--audit-mode",
            "redteam",
            "--source-shape",
            "source-only",
            "--audit-limit",
            "10",
        ],
    ]

    if all_ok(results):
        for cmd in commands:
            result = run(cmd)
            results.append(result)
            if not result.get("ok"):
                break
    if all_ok(results):
        results.append(run_dispatcher_smoke(temp_root))
    if all_ok(results):
        results.append(run_compiled_artifact_smoke(temp_root))
    if all_ok(results):
        results.append(run_dotnet_decompilation_smoke(temp_root))
    if all_ok(results):
        results.append(run_language_matrix_smoke(temp_root))
    if all_ok(results):
        results.append(run_self_project_pipeline(temp_root))
    if all_ok(results):
        results.append(run_http_l2_guard(temp_root))
    if all_ok(results):
        results.append(run_entrypoint_guard())
    if all_ok(results):
        results.append(run_packaging_guard())

    ok = all_ok(results)
    output = {
        "ok": ok,
        "checks": len(results),
        "workDir": str(temp_root),
        "results": results,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))

    if not args.keep_workdirs:
        shutil.rmtree(temp_root, ignore_errors=True)
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
