#!/usr/bin/env python3
"""
覆盖率/完成度检查：对比「审阅文件清单」与应审文件列表（或项目文件列表），计算覆盖率。
从 shared/config/file_scope.json 读取 include_extensions 与 exclude_dirs（若存在）；否则使用脚本内默认值（与 file_scope.json 一致）。
用法: python coverage_diff.py <project_root> <reviewed_list_file> [--ext .java .kt] [--in-scope in_scope_files.txt]
若提供 --in-scope，则应审文件列表以该文件为唯一权威（阶段 1 产出），不按扩展名重新枚举。
输出: 覆盖率百分比、未覆盖文件列表（退出码 1 若 <100%）
"""

import json
import argparse
from pathlib import Path

# 与 shared/config/file_scope.json 默认一致
DEFAULT_INCLUDE_EXTENSIONS = [
    ".java", ".kt", ".go", ".py", ".js", ".ts", ".tsx", ".php", ".cs", ".rb", ".rs",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".m", ".mm", ".swift", ".scala",
    ".xml", ".yml", ".yaml", ".properties", ".conf", ".ini", ".toml", ".json",
    ".proto", ".graphql", ".sql", ".jsp", ".ftl", ".vm",
]
DEFAULT_EXCLUDE_DIRS = [
    ".git", ".idea", ".vscode", "node_modules", "vendor", "target", "build",
    "dist", "out", ".gradle", ".mvn", "__pycache__", "site-packages", ".venv", "venv",
]


def load_config(config_path: Path | None) -> tuple[set[str], set[str]]:
    if config_path and config_path.exists():
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            exts = set(e if e.startswith(".") else f".{e}" for e in (data.get("include_extensions") or []))
            dirs = set(data.get("exclude_dirs") or [])
            if exts:
                return (exts, dirs)
        except Exception:
            pass
    exts = set(e if e.startswith(".") else f".{e}" for e in DEFAULT_INCLUDE_EXTENSIONS)
    return (exts, set(DEFAULT_EXCLUDE_DIRS))


def load_reviewed(path: str) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    text = p.read_text(encoding="utf-8", errors="ignore").strip()
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return {str(x).strip() for x in data if x}
        if isinstance(data, dict) and "paths" in data:
            return {str(x).strip() for x in data["paths"] if x}
        if isinstance(data, dict):
            return {str(k).strip() for k in data if k}
    except json.JSONDecodeError:
        pass
    return {line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")}


def load_in_scope(path: str) -> set[str] | None:
    p = Path(path)
    if not p.exists():
        return None
    lines = [ln.strip() for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
    return set(lines) if lines else None


def collect_project_files(root: Path, exts: set[str], exclude_dirs: set[str]) -> set[str]:
    out = set()
    for f in root.rglob("*"):
        if not f.is_file():
            continue
        rel = str(f.relative_to(root)).replace("\\", "/")
        if any(d in rel for d in exclude_dirs):
            continue
        if exts and f.suffix.lower() not in exts and ("." + f.suffix.lower().lstrip(".")) not in exts:
            continue
        out.add(rel)
    return out


def normalize(s: set[str]) -> set[str]:
    return {x.replace("\\", "/").strip("/") for x in s}


def main():
    ap = argparse.ArgumentParser(description="Coverage: diff reviewed list vs in-scope or project files")
    ap.add_argument("project_root", help="Project root")
    ap.add_argument("reviewed_list_file", help="File with reviewed paths (one per line or JSON array)")
    ap.add_argument("--ext", nargs="*", help="Extensions (default: from file_scope.json or built-in)")
    ap.add_argument("--config", "-c", help="Path to file_scope.json")
    ap.add_argument("--in-scope", help="阶段 1 in_scope_files.txt; if set, use as denominator (authoritative)")
    args = ap.parse_args()

    script_dir = Path(__file__).resolve().parent
    config_path = Path(args.config) if args.config else (script_dir.parent / "shared" / "config" / "file_scope.json")
    exts, exclude_dirs = load_config(config_path)
    if args.ext:
        exts = set(e if e.startswith(".") else "." + e for e in args.ext)

    root = Path(args.project_root).resolve()
    if not root.is_dir():
        print("Error: project_root is not a directory")
        exit(2)

    reviewed = normalize(load_reviewed(args.reviewed_list_file))

    in_scope = None
    if args.in_scope:
        in_scope = load_in_scope(args.in_scope)
    if in_scope is not None:
        all_files = normalize(in_scope)
    else:
        all_files = normalize(collect_project_files(root, exts, exclude_dirs))

    if not all_files:
        print("No project/in-scope files found; coverage N/A")
        exit(0)

    covered = reviewed & all_files
    missing = all_files - reviewed
    pct = 100.0 * len(covered) / len(all_files) if all_files else 100.0
    completion_passed = pct >= 100.0
    print(f"Reviewed: {len(reviewed)} | In-scope: {len(all_files)} | Covered: {len(covered)} | Coverage: {pct:.1f}% | 完成度: {'通过' if completion_passed else '未通过'}")
    if missing:
        print("Missing (not reviewed):")
        for m in sorted(missing)[:100]:
            print(f"  {m}")
        if len(missing) > 100:
            print(f"  ... and {len(missing) - 100} more")
        exit(1)
    print("Coverage 100% — 完成度通过.")
    exit(0)


if __name__ == "__main__":
    main()
