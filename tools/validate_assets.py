#!/usr/bin/env python3
"""Validate assets manifest consistency."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def issue(severity: str, category: str, message: str, path: str = "") -> dict[str, str]:
    out = {"severity": severity, "category": category, "message": message}
    if path:
        out["path"] = path
    return out


def validate_sources(issues: list[dict[str, str]], sources: list[dict[str, Any]], path_prefix: str) -> None:
    for source_idx, source in enumerate(sources or [], 1):
        source_path = source.get("path")
        if not source_path:
            issues.append(issue("blocker", "missing-asset-source-path", "asset source path is required", f"{path_prefix}.sources[{source_idx}].path"))
            continue
        full_source = ROOT / str(source_path)
        if not full_source.exists():
            issues.append(issue("blocker", "missing-asset-source-path", f"asset source path does not exist: {source_path}", f"{path_prefix}.sources[{source_idx}].path"))


def validate(manifest_path: Path) -> dict[str, Any]:
    issues: list[dict[str, str]] = []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assets_root = manifest_path.parent

    if manifest.get("schemaVersion") != "assets-manifest/v1":
        issues.append(issue("blocker", "invalid-schema-version", "assets manifest schemaVersion must be assets-manifest/v1", str(manifest_path)))

    seen: set[str] = set()
    for idx, asset in enumerate(manifest.get("assets") or [], 1):
        asset_id = asset.get("id")
        asset_path = asset.get("path")
        status = asset.get("status")
        if not asset_id:
            issues.append(issue("blocker", "missing-asset-id", "asset id is required", f"assets[{idx}]"))
        elif asset_id in seen:
            issues.append(issue("blocker", "duplicate-asset-id", f"duplicate asset id: {asset_id}", f"assets[{idx}].id"))
        else:
            seen.add(asset_id)
        if status not in ("planned", "migrated", "deprecated"):
            issues.append(issue("blocker", "invalid-asset-status", f"invalid asset status: {status}", f"assets[{idx}].status"))
        if not asset_path:
            issues.append(issue("blocker", "missing-asset-path", "asset path is required", f"assets[{idx}].path"))
            continue
        full_path = assets_root / str(asset_path)
        if not full_path.exists():
            issues.append(issue("blocker", "missing-asset-path", f"asset path does not exist: {asset_path}", f"assets[{idx}].path"))
        if not asset.get("sources"):
            issues.append(issue("warning", "missing-asset-source", f"asset has no source references: {asset_id}", f"assets[{idx}].sources"))
        validate_sources(issues, asset.get("sources") or [], f"assets[{idx}]")
        child_manifest = full_path / "manifest.json" if full_path.is_dir() else None
        if child_manifest and child_manifest.exists():
            child = json.loads(child_manifest.read_text(encoding="utf-8"))
            if child.get("id") != asset_id:
                issues.append(issue("blocker", "asset-manifest-id-mismatch", f"child manifest id does not match asset id: {asset_id}", str(child_manifest)))
            validate_sources(issues, child.get("sources") or [], f"{child_manifest.relative_to(ROOT)}")
        if not asset.get("usedBy"):
            issues.append(issue("warning", "missing-asset-consumer", f"asset has no usedBy consumers: {asset_id}", f"assets[{idx}].usedBy"))

    summary = {"blocker": 0, "error": 0, "warning": 0, "info": 0}
    for item in issues:
        summary[item["severity"]] += 1
    return {
        "ok": summary["blocker"] == 0 and summary["error"] == 0,
        "manifest": str(manifest_path),
        "assets": len(manifest.get("assets") or []),
        "summary": summary,
        "issues": issues,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate assets manifest")
    parser.add_argument("--manifest", default="assets/manifest.json")
    args = parser.parse_args(argv)

    result = validate((ROOT / args.manifest).resolve() if not Path(args.manifest).is_absolute() else Path(args.manifest))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
