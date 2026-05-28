#!/usr/bin/env python3
"""Project-local Python runtime helpers."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".venv"
REQUIREMENTS = ROOT / "requirements.txt"
REQUIRED_MODULES = ("jsonschema",)


def venv_python() -> Path:
    if sys.platform.startswith("win"):
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def in_project_venv() -> bool:
    return Path(sys.executable).resolve() == venv_python().resolve()


def module_available(python: Path, module: str) -> bool:
    if not python.exists():
        return False
    proc = subprocess.run([str(python), "-c", f"import {module}"], cwd=str(ROOT), text=True, capture_output=True)
    return proc.returncode == 0


def ensure_project_venv() -> Path:
    python = venv_python()
    if not python.exists():
        subprocess.run([sys.executable, "-m", "venv", str(VENV)], cwd=str(ROOT), check=True)
    missing = [module for module in REQUIRED_MODULES if not module_available(python, module)]
    if missing:
        subprocess.run(
            [str(python), "-m", "pip", "install", "--upgrade-strategy", "only-if-needed", "-r", str(REQUIREMENTS)],
            cwd=str(ROOT),
            check=True,
        )
    return python


def reexec_in_project_venv() -> None:
    if os.environ.get("CODE_SECURITY_AUDIT_NO_REEXEC") == "1":
        return
    python = ensure_project_venv()
    if not in_project_venv():
        os.execv(str(python), [str(python), *sys.argv])
