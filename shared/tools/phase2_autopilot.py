#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
阶段 2 大项目“自动补扫”驾驶员（本地脚本，不依赖对话上下文）

目标：
- 把“需要用户反复说继续”的交互，降级为“脚本在本地自动跑批次，AI 只负责读批次输出并做安全判断”。
- 适用于任意语言/框架的仓库：只做文件枚举/去重/覆盖率统计/批次计划，不做漏洞结论（避免幻觉）。

约定的输入/输出文件（在项目根目录下的 audit/）：
- 输入（若存在则复用）：audit/phase1/phase1_tier_list.json（可选）
- 输出（必写）：
  - audit/phase2/project_file_list.txt（应审文件列表）
  - audit/phase2/phase2_reviewed_paths_merged.txt（已审路径合并清单）
  - audit/phase2/phase2_batch_targets.txt（下一批目标文件列表）
  - audit/phase2/phase2_coverage_status.json（覆盖率状态 JSON）
  - audit/phase2/phase2_supplement_plan.md（补扫计划/断点）

用法：
  1) 在项目根目录运行：
     python3 audit/tools/phase2_autopilot.py plan
  2) 让 AI 只审阅 audit/phase2/phase2_batch_targets.txt 里的文件，并把已审文件逐行追加到 audit/phase2/phase2_reviewed_paths_merged.txt
  3) 然后运行：
     python3 audit/tools/phase2_autopilot.py update
  4) 循环直到 coverage=100%
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

# 默认与 shared/config/file_scope.json、priority_keywords.json 一致；脚本优先从配置读取
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".idea", ".vscode", "node_modules", "vendor", "target", "build",
    "dist", "out", ".gradle", ".mvn", "__pycache__", "site-packages", ".venv", "venv",
}
DEFAULT_INCLUDE_EXTS = {
    ".java", ".kt", ".go", ".py", ".js", ".ts", ".tsx", ".php", ".cs", ".rb", ".rs",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".m", ".mm", ".swift", ".scala",
    ".xml", ".yml", ".yaml", ".properties", ".conf", ".ini", ".toml", ".json",
    ".proto", ".graphql", ".sql", ".jsp", ".ftl", ".vm",
}
DEFAULT_P0_KEYWORDS = [
    "security", "gateway", "filter", "interceptor", "auth", "oauth", "sso",
    "callback", "webhook", "openapi", "actuator", "druid", "swagger",
    "file", "upload", "download", "export", "import", "log",
]
DEFAULT_P1_KEYWORDS = ["controller", "route", "router", "handler", "endpoint", "api", "rest", "service"]
DEFAULT_P2_KEYWORDS = ["admin", "system", "management"]


@dataclass(frozen=True)
class Coverage:
    total: int
    reviewed: int

    @property
    def ratio(self) -> float:
        return 0.0 if self.total == 0 else self.reviewed / self.total


def _repo_root() -> Path:
    return Path.cwd()


def _audit_dir(root: Path) -> Path:
    return root / "audit"


def _read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _config_dir(root: Path) -> Path:
    # 脚本在 shared/tools/ 时，config 在 shared/config/
    script_dir = Path(__file__).resolve().parent
    candidate = (script_dir / "../config").resolve()
    if candidate.exists():
        return candidate
    # 项目根下 shared/config（用户可能复制了 config）
    return root / "shared" / "config"


def _load_json(path: Path, default: Optional[dict] = None) -> dict:
    if not path.exists():
        return default or {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default or {}


def _load_tier_list(tier_json: Path) -> Optional[Dict[str, Dict]]:
    if not tier_json.exists():
        return None
    try:
        data = json.loads(tier_json.read_text(encoding="utf-8"))
        # 兼容数组格式，转换为 path -> {tier} 对象
        if isinstance(data, list):
            return {item["path"]: {"tier": item.get("tier", "T2")} for item in data if isinstance(item, dict) and item.get("path")}
        return data
    except Exception:
        return None


def _iter_files(root: Path, exclude_dirs: Set[str]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        # prune
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs and not d.startswith(".")]
        for fn in filenames:
            p = Path(dirpath) / fn
            yield p


def _is_in_audit_dir(root: Path, p: Path) -> bool:
    try:
        p.relative_to(root / "audit")
        return True
    except Exception:
        return False


def _should_include(p: Path, include_exts: Set[str]) -> bool:
    if not p.is_file():
        return False
    if p.name.startswith("."):
        return False
    return p.suffix.lower() in include_exts


def build_project_file_list(
    root: Path,
    include_exts: Set[str],
    exclude_dirs: Set[str],
) -> List[str]:
    files: List[str] = []
    for p in _iter_files(root, exclude_dirs):
        if _is_in_audit_dir(root, p):
            continue
        if _should_include(p, include_exts):
            files.append(str(p.relative_to(root)).replace("\\", "/"))
    files.sort()
    return files


def load_reviewed_set(reviewed_merged: Path) -> Set[str]:
    return set(_read_lines(reviewed_merged))


def compute_coverage(project_files: List[str], reviewed: Set[str]) -> Coverage:
    total = len(project_files)
    reviewed_count = sum(1 for f in project_files if f in reviewed)
    return Coverage(total=total, reviewed=reviewed_count)


def _priority_bucket(path: str, p0_keywords: List[str], p1_keywords: List[str], p2_keywords: List[str]) -> int:
    """
    越小优先级越高：P0(0) → P1(1) → P2(2) → 其他(3)
    关键词来自 priority_keywords.json，默认与 shared/config 一致。
    """
    p = path.lower()
    if any(k in p for k in p0_keywords):
        return 0
    if any(k in p for k in p1_keywords):
        return 1
    if any(k in p for k in p2_keywords):
        return 2
    return 3


def select_next_batch(
    project_files: List[str],
    reviewed: Set[str],
    tier_list: Optional[Dict[str, Dict]],
    batch_size: int,
    p0_keywords: List[str],
    p1_keywords: List[str],
    p2_keywords: List[str],
) -> List[str]:
    remaining = [f for f in project_files if f not in reviewed]

    def key_fn(f: str) -> Tuple[int, int, str]:
        p_bucket = _priority_bucket(f, p0_keywords, p1_keywords, p2_keywords)
        tier_rank = 9
        if tier_list and f in tier_list:
            tier = str(tier_list[f].get("tier", "")).upper()
            tier_rank = {"T1": 0, "T2": 1, "T3": 2}.get(tier, 3)
        return (p_bucket, tier_rank, f)

    remaining.sort(key=key_fn)
    return remaining[: max(0, batch_size)]


def write_status_files(
    audit: Path,
    project_files: List[str],
    reviewed: Set[str],
    batch_targets: List[str],
    coverage: Coverage,
) -> None:
    phase2_dir = audit / "phase2"
    phase2_dir.mkdir(parents=True, exist_ok=True)
    _write_lines(phase2_dir / "project_file_list.txt", project_files)
    _write_lines(phase2_dir / "phase2_batch_targets.txt", batch_targets)

    completion_passed = coverage.ratio >= 1.0
    status = {
        "total_files": coverage.total,
        "reviewed_files": coverage.reviewed,
        "coverage_ratio": round(coverage.ratio, 6),
        "coverage_percent": round(coverage.ratio * 100, 2),
        "completion_passed": completion_passed,
        "next_batch_size": len(batch_targets),
    }
    (phase2_dir / "phase2_coverage_status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    plan_md = [
        "# 阶段 2 补扫计划（自动生成）",
        "",
        f"- 当前覆盖率：**{status['coverage_percent']}%**（{coverage.reviewed} / {coverage.total}）",
        f"- 完成度：**{'通过' if completion_passed else '未通过'}**",
        f"- 下一批文件数：**{len(batch_targets)}**（见 `audit/phase2/phase2_batch_targets.txt`）",
        "",
        "## 断点续跑",
        "",
        "- 先按 `audit/phase2/phase2_batch_targets.txt` 审阅文件；每审完一个文件，把相对路径逐行追加到 `audit/phase2/phase2_reviewed_paths_merged.txt`。",
        "- 然后运行：`python3 audit/tools/phase2_autopilot.py update` 生成下一批与最新覆盖率。",
        "",
        "## 批次优先级（摘要）",
        "",
        "- P0 未认证可达 / 安全配置 / 网关 / 过滤器 / 文件读写 / 回调入口优先",
        "- P1 已认证低权限入口其次",
        "- P2 管理员/高权限最后",
        "",
    ]
    (phase2_dir / "phase2_supplement_plan.md").write_text("\n".join(plan_md), encoding="utf-8")


def cmd_plan(batch_size: int) -> int:
    root = _repo_root()
    audit = _audit_dir(root)
    audit.mkdir(parents=True, exist_ok=True)

    # 应审文件列表：优先使用 阶段 1 产出的 in_scope_files.txt（唯一权威）
    config_dir = _config_dir(root)
    in_scope_path = audit / "phase1" / "in_scope_files.txt"
    if in_scope_path.exists():
        project_files = _read_lines(in_scope_path)
    else:
        fs = _load_json(config_dir / "file_scope.json")
        include_exts = set(fs.get("include_extensions") or DEFAULT_INCLUDE_EXTS)
        include_exts = {e if e.startswith(".") else f".{e}" for e in include_exts}
        exclude_dirs = set(fs.get("exclude_dirs") or DEFAULT_EXCLUDE_DIRS)
        project_files = build_project_file_list(root, include_exts, exclude_dirs)

    reviewed_path = audit / "phase2" / "phase2_reviewed_paths_merged.txt"
    reviewed = load_reviewed_set(reviewed_path)
    tier_list = _load_tier_list(audit / "phase1" / "phase1_tier_list.json")

    pk = _load_json(config_dir / "priority_keywords.json")
    p0_kw = pk.get("p0") or DEFAULT_P0_KEYWORDS
    p1_kw = pk.get("p1") or DEFAULT_P1_KEYWORDS
    p2_kw = pk.get("p2") or DEFAULT_P2_KEYWORDS

    batch_targets = select_next_batch(
        project_files, reviewed, tier_list, batch_size=batch_size,
        p0_keywords=p0_kw, p1_keywords=p1_kw, p2_keywords=p2_kw,
    )
    coverage = compute_coverage(project_files, reviewed)
    write_status_files(audit, project_files, reviewed, batch_targets, coverage)
    return 0


def cmd_update(batch_size: int) -> int:
    # update == re-plan after reviewed_merged updated
    return cmd_plan(batch_size=batch_size)


def _parse_args(argv: List[str]) -> Tuple[str, int]:
    if len(argv) < 2 or argv[1] in {"-h", "--help"}:
        return ("help", 0)
    cmd = argv[1]
    batch_size = 80
    if "--batch-size" in argv:
        try:
            batch_size = int(argv[argv.index("--batch-size") + 1])
        except Exception:
            pass
    return (cmd, batch_size)


def main(argv: List[str]) -> int:
    cmd, batch_size = _parse_args(argv)
    if cmd == "help":
        print(__doc__.strip())
        print("\nCommands: plan | update\nOptions: --batch-size N (default 80)")
        return 0
    if cmd == "plan":
        return cmd_plan(batch_size=batch_size)
    if cmd == "update":
        return cmd_update(batch_size=batch_size)
    print(f"Unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

