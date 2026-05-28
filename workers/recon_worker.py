#!/usr/bin/env python3
"""recon worker.

This script produces project.json and attack_surface.json from a real project
path. It is deterministic and conservative; semantic framework analysis can
append more structured facts without replacing these baseline artifacts.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


EXCLUDE_DIRS = {
    ".git", ".idea", ".vscode", "node_modules", "vendor", "target",
    "build", "dist", "out", "__pycache__", ".venv", "venv", ".cache",
    ".terraform", "logs", "tmp", "temp",
}
ALWAYS_EXCLUDE_ARTIFACT_DIRS = {".store", "third-libs"}

LANG_BY_EXT = {
    ".java": "java",
    ".kt": "kotlin",
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".php": "php",
    ".cs": "csharp",
    ".rb": "ruby",
    ".rs": "rust",
    ".xml": "xml",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".properties": "properties",
    ".sql": "sql",
    ".jsp": "jsp",
    ".jspx": "jsp",
    ".md": "markdown",
}
HTTP_EXTS = {".java", ".kt", ".py", ".js", ".ts", ".tsx", ".php", ".cs", ".jsp", ".go", ".rb", ".rs"}
COMPILED_ARTIFACT_EXTS = {
    ".jar": ("jvm", "archive"),
    ".war": ("jvm", "web-archive"),
    ".ear": ("jvm", "enterprise-archive"),
    ".class": ("jvm", "bytecode"),
    ".dex": ("android", "bytecode"),
    ".apk": ("android", "package"),
    ".dll": ("dotnet", "assembly"),
    ".exe": ("native-or-dotnet", "binary"),
    ".so": ("native", "shared-object"),
    ".dylib": ("native", "shared-object"),
}

ENTRY_PATTERNS = [
    re.compile(r"controller|handler|router|route|servlet|filter|interceptor|security|gateway|action", re.I),
    re.compile(r"login|auth|sso|oauth|callback|upload|download|export|import|admin|role|permission", re.I),
    re.compile(r"app\.(get|post|put|patch|delete)\s*\(|router\.(get|post|put|patch|delete)\s*\(|@(?:Get|Post|Put|Delete)Mapping|@RequestMapping|@app\.route", re.I),
    re.compile(r"http\.HandleFunc|http\.Handle\(|func\s+\w+\s*\([^)]*http\.ResponseWriter[^)]*\*http\.Request", re.I),
    re.compile(r"\[(HttpGet|HttpPost|HttpPut|HttpDelete|Route)\]|ControllerBase|Controller\b", re.I),
    re.compile(r"\b(get|post|put|patch|delete)\s+['\"]/|Sinatra|Rails\.application\.routes", re.I),
    re.compile(r"Router::new|\.route\(|axum::|actix_web::|warp::", re.I),
    re.compile(r"Deno\.serve|Bun\.serve|serve\(", re.I),
]

SOURCE_PATTERNS = {
    "http-param": re.compile(
        r"request\.(query|args|form|json|body)|req\.(query|params|body)|getParameter|get_param|params\[|QueryString|Form\[|Request\.(Query|Form)|\$_(GET|POST|REQUEST)|r\.URL\.Query|FormValue|c\.Query|URLSearchParams|\.searchParams|\.query\(",
        re.I,
    ),
    "http-header": re.compile(r"headers?\[|getHeader|Header\(|cookies?\[|Cookie", re.I),
    "file-input": re.compile(r"read_text\(|readBytes|readAllBytes|readFile|FileUpload|MultipartFile", re.I),
}

SINK_PATTERNS = {
    "sql": re.compile(r"Statement\.execute|executeQuery|executeUpdate|cursor\.execute|\.execute\(|\.query\(|\$sql\$|\$querySql\$|SELECT .* FROM|INSERT INTO|UPDATE .* SET|DB::select|PDO::query|mysqli_query|sqlx::query|diesel::sql_query|jdbcTemplate\.query|db\.Query|ActiveRecord::Base\.connection", re.I),
    "command": re.compile(r"Runtime\.exec|ProcessBuilder|os\.system|subprocess|child_process\.exec|Process\.Start|exec\(|shell_exec|system\(|Command::new|std::process::Command", re.I),
    "file": re.compile(r"FileInputStream|Files\.write|File\.Read|fs\.readFile|open\(|MultipartFile|transferTo|download|file_get_contents|File\.read|std::fs::read|Deno\.readTextFile|Bun\.file", re.I),
    "ssrf": re.compile(r"HttpClient|RestTemplate|WebClient|URL\.openConnection|requests\.get|axios|fetch\(|Net::HTTP|reqwest::|curl_exec", re.I),
    "deserialization": re.compile(r"ObjectInputStream|readObject|parseObject|fromXML|pickle\.loads|yaml\.load|BinaryFormatter", re.I),
}

SECRET_PATTERN = re.compile(r"password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|jdbc|redis", re.I)


def should_skip(path: Path, root: Path) -> bool:
    rel_parts = path.relative_to(root).parts
    return any(part in EXCLUDE_DIRS for part in rel_parts)


def should_skip_compiled_artifact(path: Path, root: Path) -> bool:
    rel_parts = path.relative_to(root).parts
    if len(rel_parts) >= 2 and rel_parts[0] == "scripts" and rel_parts[1] == "tools":
        return True
    return any(part in ALWAYS_EXCLUDE_ARTIFACT_DIRS for part in rel_parts)


def iter_files(root: Path) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in COMPILED_ARTIFACT_EXTS and should_skip_compiled_artifact(path, root):
            continue
        if should_skip(path, root) and path.suffix.lower() not in COMPILED_ARTIFACT_EXTS:
            continue
        files.append(path)
    return sorted(files)


def read_sample(path: Path, limit: int = 20000) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""
    return text[:limit]


def detect_frameworks(files: list[Path], root: Path) -> list[str]:
    names = {p.name for p in files}
    rels = {str(p.relative_to(root)).replace("\\", "/") for p in files}
    frameworks = set()
    if "pom.xml" in names or "build.gradle" in names:
        frameworks.add("jvm")
    if "package.json" in names:
        frameworks.add("node")
    if "requirements.txt" in names or "pyproject.toml" in names:
        frameworks.add("python")
    if "composer.json" in names:
        frameworks.add("php")
    if "go.mod" in names:
        frameworks.add("go")
    if any(rel.endswith(".csproj") or rel.endswith(".sln") for rel in rels):
        frameworks.add("dotnet")
    if "Gemfile" in names:
        frameworks.add("ruby")
    if "Cargo.toml" in names:
        frameworks.add("rust")
    if "deno.json" in names or "deno.jsonc" in names:
        frameworks.add("deno")
    if "bun.lockb" in names or "bun.lock" in names or any("bunfig.toml" == name for name in names):
        frameworks.add("bun")
    if "build.gradle.kts" in names or any(rel.endswith(".kt") for rel in rels):
        frameworks.add("kotlin")
    return sorted(frameworks)


def detect_compiled_artifacts(files: list[Path], root: Path) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for path in files:
        ext = path.suffix.lower()
        if ext not in COMPILED_ARTIFACT_EXTS:
            continue
        platform_name, artifact_type = COMPILED_ARTIFACT_EXTS[ext]
        artifacts.append({
            "id": f"artifact-{len(artifacts)+1:04d}",
            "path": str(path.relative_to(root)).replace("\\", "/"),
            "extension": ext,
            "platform": platform_name,
            "artifactType": artifact_type,
            "decompileRequired": True,
        })
    return artifacts


def decompilation_plan(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    if not artifacts:
        return {"required": False, "targets": [], "recommendedAssets": []}
    asset_by_platform = {
        "jvm": "decompilation.jvm",
        "android": "decompilation.android",
        "dotnet": "decompilation.dotnet",
        "native-or-dotnet": "decompilation.dotnet-or-native",
        "native": "decompilation.native",
    }
    assets = sorted({
        asset_by_platform.get(str(item.get("platform")), "decompilation.generic")
        for item in artifacts
    })
    return {
        "required": True,
        "targets": [item["id"] for item in artifacts],
        "recommendedAssets": assets,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run recon")
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--audit-dir", default="audit-v2")
    parser.add_argument("--project-id", default="proj-default")
    parser.add_argument("--audit-mode", choices=["redteam", "full"], default="full")
    parser.add_argument("--source-shape", choices=["source-only", "compiled-only", "mixed"], default="source-only")
    args = parser.parse_args(argv)

    root = Path(args.project_root).resolve()
    audit_dir = Path(args.audit_dir)
    audit_dir.mkdir(parents=True, exist_ok=True)
    if not root.is_dir():
        raise FileNotFoundError(f"project root not found: {root}")

    files = iter_files(root)
    lang_counts = Counter(LANG_BY_EXT.get(path.suffix.lower(), "unknown") for path in files)
    languages = sorted(k for k, v in lang_counts.items() if v and k != "unknown")
    frameworks = detect_frameworks(files, root)
    compiled_artifacts = detect_compiled_artifacts(files, root)

    entries: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []

    for path in files:
        rel = str(path.relative_to(root)).replace("\\", "/")
        text = read_sample(path)
        if any(pattern.search(rel) or pattern.search(text[:4000]) for pattern in ENTRY_PATTERNS):
            entry_match = next((pattern.search(text[:4000]) for pattern in ENTRY_PATTERNS if pattern.search(text[:4000])), None)
            entry_line = text[:entry_match.start()].count("\n") + 1 if entry_match else 0
            entries.append({
                "id": f"entry-{len(entries)+1:04d}",
                "type": "http" if path.suffix.lower() in HTTP_EXTS else "unknown",
                "file": rel,
                "line": entry_line,
                "location": rel,
                "evidence": entry_match.group(0)[:200] if entry_match else rel,
                "authRequired": "unknown"
            })
        for kind, pattern in SOURCE_PATTERNS.items():
            match = pattern.search(text)
            if match:
                line = text[:match.start()].count("\n") + 1
                sources.append({
                    "id": f"source-{len(sources)+1:04d}",
                    "kind": kind,
                    "file": rel,
                    "line": line,
                    "symbol": match.group(0)[:120],
                    "evidence": match.group(0)[:200]
                })
        for kind, pattern in SINK_PATTERNS.items():
            match = pattern.search(text)
            if match:
                line = text[:match.start()].count("\n") + 1
                sinks.append({
                    "id": f"sink-{len(sinks)+1:04d}",
                    "kind": kind,
                    "file": rel,
                    "line": line,
                    "symbol": match.group(0)[:120],
                    "evidence": match.group(0)[:200]
                })
        if SECRET_PATTERN.search(rel) or SECRET_PATTERN.search(text[:2000]):
            secrets.append({"file": rel, "reason": "keyword-match"})

    project = {
        "schemaVersion": "project/v1",
        "projectId": args.project_id,
        "projectRoot": str(root),
        "auditMode": args.audit_mode,
        "sourceShape": args.source_shape,
        "languages": languages,
        "frameworks": frameworks,
        "buildSystems": [],
        "runtimeServices": [],
        "dataStores": [],
        "knownSystems": [],
        "compiledArtifacts": compiled_artifacts,
        "decompilation": decompilation_plan(compiled_artifacts),
        "authModel": {"status": "unknown", "unknowns": ["recon requires framework-specific auth resolution"]},
        "unknowns": []
    }
    attack_surface = {
        "schemaVersion": "attack-surface/v1",
        "projectId": args.project_id,
        "entries": entries,
        "sources": sources,
        "sinks": sinks,
        "secrets": secrets,
        "dependencies": [],
        "compiledArtifacts": compiled_artifacts,
        "highValueAssets": [],
        "trustBoundaries": []
    }

    (audit_dir / "project.json").write_text(json.dumps(project, ensure_ascii=False, indent=2), encoding="utf-8")
    (audit_dir / "attack_surface.json").write_text(json.dumps(attack_surface, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({
        "ok": True,
        "project": str(audit_dir / "project.json"),
        "attackSurface": str(audit_dir / "attack_surface.json"),
        "files": len(files),
        "languages": languages,
        "entries": len(entries),
        "sources": len(sources),
        "sinks": len(sinks),
        "secrets": len(secrets),
        "compiledArtifacts": len(compiled_artifacts),
        "decompilationRequired": bool(compiled_artifacts)
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
