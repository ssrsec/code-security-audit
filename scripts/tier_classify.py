#!/usr/bin/env python3
"""
Tier 分类脚本：基于目录/注解/包名的启发式，输出 T1/T2/T3/SKIP。
从 shared/config/tier_rules.json 读取规则（若存在）；否则使用脚本内默认规则。支持多语言。
用法: python tier_classify.py <project_root> [--output tier_list.json] [--config tier_rules.json]
输出格式：{ "path/to/file.java": { "tier": "T1" }, ... }（路径为 key，与 phase2_autopilot 兼容）
"""

import os
import re
import json
import argparse
from pathlib import Path

# 默认规则（与 shared/config/tier_rules.json 默认内容一致，当无配置时使用）
DEFAULT_ENTRY_DIRS = ("controller", "controllers", "web", "filter", "filters", "api", "rest", "servlet")
DEFAULT_BUSINESS_DIRS = ("service", "services", "dao", "mapper", "mappers", "util", "utils", "helper", "config")
DEFAULT_DATA_DIRS = ("entity", "entities", "vo", "dto", "model", "models", "pojo", "domain")
DEFAULT_VENDOR_PREFIXES = (
    "com/alibaba/", "org/springframework/", "org/apache/",
    "javax/", "jakarta/", "ch/qos/", "org/slf4j/",
    "org/hibernate/", "org/mybatis/", "io/swagger/",
)
DEFAULT_SKIP_PATTERNS = ("test/", "/test/", "tests/", "__tests__/", "spec/", ".spec.")
DEFAULT_EXTENSIONS = (".java", ".kt", ".xml", ".yml", ".yaml", ".properties")
DEFAULT_TIER_WHEN_UNKNOWN = "T2"


def load_config(config_path: Path | None) -> dict:
    if config_path and config_path.exists():
        try:
            return json.loads(config_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def get_ext(path: str) -> str:
    return (path or "").split(".")[-1].lower()


def path_tier(rel: str, entry_dirs: tuple, business_dirs: tuple, data_dirs: tuple,
              vendor_prefixes: tuple, skip_patterns: tuple) -> str | None:
    rel_lower = rel.replace("\\", "/").lower()
    parts = rel_lower.split("/")
    for v in vendor_prefixes:
        if v in rel_lower:
            return "SKIP"
    for s in skip_patterns:
        if s in rel_lower or rel_lower.startswith(s.lstrip("/")):
            return "SKIP"
    for p in parts:
        if p in entry_dirs:
            return "T1"
        if p in business_dirs:
            return "T2"
        if p in data_dirs:
            return "T3"
    return None


def content_tier(content: str, annotations: dict) -> str | None:
    if not content or len(content) > 20000:
        return None
    for tier in ("T1", "T2", "T3"):
        ann_list = (annotations or {}).get(tier) or []
        if not ann_list:
            continue
        pattern = r"@(" + "|".join(re.escape(a) for a in ann_list) + r")\b"
        if re.search(pattern, content):
            return tier
    return None


def classify(root: str, config: dict, scan_content: bool = True) -> list[dict]:
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        return []

    # 从 config 解析规则（多语言合并或按首语言）
    languages = config.get("languages") or []
    entry_dirs = set()
    business_dirs = set()
    data_dirs = set()
    vendor_prefixes = list(DEFAULT_VENDOR_PREFIXES)
    skip_patterns = list(DEFAULT_SKIP_PATTERNS)
    extensions = set(DEFAULT_EXTENSIONS)
    annotations_map = {}
    tier_unknown = config.get("default_tier_when_unknown") or DEFAULT_TIER_WHEN_UNKNOWN

    for lang in languages:
        if isinstance(lang, dict):
            entry_dirs.update(lang.get("entry_layer") or [])
            business_dirs.update(lang.get("business_layer") or [])
            data_dirs.update(lang.get("data_layer") or [])
            ext_list = lang.get("extensions") or []
            for e in ext_list:
                extensions.add(e if e.startswith(".") else "." + e)
            vp = lang.get("vendor_prefixes") or []
            vendor_prefixes = list(set(vendor_prefixes) | set(vp))
            ann = lang.get("annotations") or {}
            for k, v in ann.items():
                annotations_map.setdefault(k, []).extend(v or [])

    if not entry_dirs:
        entry_dirs = set(DEFAULT_ENTRY_DIRS)
    if not business_dirs:
        business_dirs = set(DEFAULT_BUSINESS_DIRS)
    if not data_dirs:
        data_dirs = set(DEFAULT_DATA_DIRS)
    vendor_prefixes = tuple(vendor_prefixes)
    skip_patterns = tuple(skip_patterns)
    entry_dirs = tuple(entry_dirs)
    business_dirs = tuple(business_dirs)
    data_dirs = tuple(data_dirs)

    results = []
    for f in root_path.rglob("*"):
        if not f.is_file():
            continue
        rel = str(f.relative_to(root_path)).replace("\\", "/")
        if f.suffix.lower() not in extensions and ("." + get_ext(rel)) not in extensions:
            continue
        tier = path_tier(rel, entry_dirs, business_dirs, data_dirs, vendor_prefixes, skip_patterns)
        if tier is None and scan_content and f.suffix.lower() in (".java", ".kt", ".py", ".go", ".cs"):
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                tier = content_tier(content, annotations_map)
            except Exception:
                pass
        if tier is None:
            tier = tier_unknown
        results.append({"path": rel, "tier": tier})
    return results


def main():
    ap = argparse.ArgumentParser(description="Tier classification for audit")
    ap.add_argument("project_root", help="Project root path")
    ap.add_argument("--output", "-o", default="tier_list.json", help="Output file")
    ap.add_argument("--config", "-c", help="Path to tier_rules.json (default: <script_dir>/../shared/config/tier_rules.json)")
    ap.add_argument("--no-content", action="store_true", help="Skip content-based annotation scan")
    args = ap.parse_args()

    script_dir = Path(__file__).resolve().parent
    config_path = Path(args.config) if args.config else (script_dir.parent / "shared" / "config" / "tier_rules.json")
    config = load_config(config_path)

    data = classify(args.project_root, config, scan_content=not args.no_content)
    # 统一输出格式：路径为 key 的对象
    out_obj = {item["path"]: {"tier": item["tier"]} for item in data}
    out = Path(args.output)
    out.write_text(json.dumps(out_obj, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {len(out_obj)} entries to {out}")

if __name__ == "__main__":
    main()
