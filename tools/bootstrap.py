#!/usr/bin/env python3
"""Bootstrap checks for code-security-audit.

The script is intentionally conservative:
- It never downgrades installed packages.
- It installs only missing required packages when --install is provided.
- It installs into a project-local .venv, never into the user's global Python.
- It works on macOS, Linux, and Windows.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "requirements.txt"
VENV = ROOT / ".venv"
MIN_PYTHON = (3, 10)
REQUIRED_TOOL_FILES = [
    "scripts/tools/decompilers/bin/decompile-java.sh",
    "scripts/tools/decompilers/bin/decompile-java.cmd",
    "scripts/tools/decompilers/bin/decompile-dotnet.sh",
    "scripts/tools/decompilers/bin/decompile-dotnet.cmd",
    "scripts/tools/decompilers/java/cfr-0.152.jar",
    "tools/decompile_jvm.py",
    "tools/decompile_dotnet.py",
    "tools/production_check.py",
    "quality/quality_gate.py",
    "state/state_cli.py",
]


def venv_python() -> Path:
    if platform.system().lower().startswith("win"):
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def create_venv() -> dict[str, object] | None:
    if venv_python().exists():
        return None
    cmd = [sys.executable, "-m", "venv", str(VENV)]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    return {
        "action": "create-venv",
        "command": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
    }


@dataclass(frozen=True)
class Dependency:
    package: str
    import_name: str


REQUIRED_DEPENDENCIES = [
    Dependency("jsonschema", "jsonschema"),
]


def dependency_present(dep: Dependency, python: Path) -> bool:
    if not python.exists():
        return False
    proc = subprocess.run(
        [str(python), "-c", f"import {dep.import_name}"],
        text=True,
        capture_output=True,
    )
    return proc.returncode == 0


def install_missing(missing: list[Dependency], python: Path) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    if not missing:
        return results
    cmd = [
        str(python),
        "-m",
        "pip",
        "install",
        "--upgrade-strategy",
        "only-if-needed",
        "-r",
        str(REQUIREMENTS),
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    results.append({
        "packages": [dep.package for dep in missing],
        "command": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
    })
    return results


def tool_file_status() -> list[dict[str, object]]:
    return [
        {
            "path": item,
            "present": (ROOT / item).exists(),
        }
        for item in REQUIRED_TOOL_FILES
    ]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Check or install runtime dependencies")
    parser.add_argument("--install", action="store_true", help="create .venv and install missing dependencies")
    args = parser.parse_args(argv)

    python = venv_python()
    venv_result = None
    if args.install:
        venv_result = create_venv()
    missing = [dep for dep in REQUIRED_DEPENDENCIES if not dependency_present(dep, python)]
    install_results: list[dict[str, object]] = []
    if missing and args.install:
        install_results = install_missing(missing, python)
        missing = [dep for dep in REQUIRED_DEPENDENCIES if not dependency_present(dep, python)]

    python_ok = sys.version_info[:2] >= MIN_PYTHON
    tools = tool_file_status()
    missing_tools = [item for item in tools if not item["present"]]
    output = {
        "ok": not missing and python_ok and not missing_tools,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
            "pythonOk": python_ok,
            "minPython": ".".join(str(part) for part in MIN_PYTHON),
            "executable": sys.executable,
        },
        "venv": {
            "path": str(VENV),
            "python": str(python),
            "present": python.exists(),
            "created": bool(venv_result and venv_result.get("returncode") == 0),
        },
        "requirements": str(REQUIREMENTS),
        "toolFiles": tools,
        "missingToolFiles": missing_tools,
        "dependencies": [
            {
                "package": dep.package,
                "importName": dep.import_name,
                "present": dependency_present(dep, python),
            }
            for dep in REQUIRED_DEPENDENCIES
        ],
        "venvResult": venv_result,
        "installAttempted": bool(install_results),
        "installResults": install_results,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if output["ok"] else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
