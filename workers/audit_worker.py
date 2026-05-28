#!/usr/bin/env python3
"""audit worker.

Generates structured candidate findings from attack_surface.json sinks. This is
the production write path for V0 candidates; semantic auditing and validation
must add evidence before any status upgrade.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


CATEGORY_BY_SINK = {
    "sql": "injection",
    "command": "rce",
    "file": "file",
    "ssrf": "ssrf",
    "deserialization": "deserialization",
}

TITLE_BY_SINK = {
    "sql": "SQL 注入候选",
    "command": "命令执行候选",
    "file": "文件操作候选",
    "ssrf": "SSRF 候选",
    "deserialization": "反序列化候选",
}

CAPABILITY_BY_SINK = {
    "sql": ("read-db-row", "read-only"),
    "command": ("execute-command", "destructive"),
    "file": ("read-or-write-file", "state-changing"),
    "ssrf": ("ssrf-request", "read-only"),
    "deserialization": ("deserialize-input", "destructive"),
}
SENSITIVE_ENTRY_KEYWORDS = ("admin", "delete", "remove", "role", "permission", "export", "import", "config", "user")


def cvss_for_impacts(impacts: dict[str, str]) -> dict[str, Any]:
    c = "H" if impacts.get("confidentiality") == "high" else "L" if impacts.get("confidentiality") == "low" else "N"
    i = "H" if impacts.get("integrity") == "high" else "L" if impacts.get("integrity") == "low" else "N"
    a = "H" if impacts.get("availability") == "high" else "L" if impacts.get("availability") == "low" else "N"
    high_count = sum(1 for value in (c, i, a) if value == "H")
    score = {0: 0.0, 1: 7.5, 2: 9.1, 3: 9.8}[high_count]
    return {
        "vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{c}/I:{i}/A:{a}",
        "score": score,
        "rationale": {"note": "candidate score, must be recalculated during validation"}
    }


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def append_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def same_file(item: dict[str, Any], file_name: str) -> bool:
    return item.get("file") == file_name or item.get("location") == file_name


def make_hop(role: str, item: dict[str, Any], taint_state: str) -> dict[str, Any]:
    return {
        "role": role,
        "file": item.get("file") or item.get("location", ""),
        "lineStart": int(item.get("line") or 0),
        "lineEnd": int(item.get("line") or 0),
        "symbol": item.get("symbol") or item.get("type") or item.get("id", ""),
        "evidence": item.get("evidence") or item.get("location") or item.get("id", ""),
        "taintState": taint_state,
    }


def make_finding(
    idx: int,
    sink: dict[str, Any],
    entries: list[dict[str, Any]],
    sources: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    finding_id = f"vul-{idx:03d}"
    callchain_id = f"cc-{idx:04d}"
    cap_id = f"cap-{idx:04d}"
    kind = sink.get("kind", "unknown")
    category = CATEGORY_BY_SINK.get(kind, "injection")
    cap_name, operation_class = CAPABILITY_BY_SINK.get(kind, ("investigate-sink", "unknown"))
    severity = "high" if kind in {"sql", "command", "deserialization"} else "medium"
    related_entry = next((entry for entry in entries if same_file(entry, sink.get("file", ""))), None)
    related_source = next((source for source in sources if same_file(source, sink.get("file", ""))), None)
    source_ids = [sink.get("id", f"sink-{idx:04d}")]
    if related_source:
        source_ids.append(related_source["id"])
    impacts = {
        "confidentiality": "high" if kind in {"sql", "file", "ssrf", "deserialization"} else "none",
        "integrity": "high" if kind in {"sql", "command", "file", "deserialization"} else "none",
        "availability": "high" if kind in {"command", "deserialization"} else "none"
    }

    finding = {
        "schemaVersion": "finding/v1",
        "id": finding_id,
        "sourceIds": source_ids,
        "status": "candidate",
        "title": f"{TITLE_BY_SINK.get(kind, '危险能力候选')}（{sink.get('symbol', kind)}）",
        "category": category,
        "severity": severity,
        "validationLevel": "V0",
        "authLevel": "unknown",
        "operationClasses": [operation_class],
        "entry": {
            "type": related_entry.get("type", "unknown") if related_entry else "unknown",
            "location": related_entry.get("location", sink.get("file", "")) if related_entry else sink.get("file", "")
        },
        "callChain": [callchain_id],
        "impacts": impacts,
        "cvss": cvss_for_impacts(impacts),
        "preconditions": ["需追踪入口和攻击者可控 source"],
        "requiresCapabilities": [],
        "providesCapabilities": [cap_id],
        "evidenceRefs": [],
        "pocRefs": [],
        "cleanupRefs": [],
        "blockers": ["source-to-sink requires validation evidence"],
        "fix": {
            "emergency": "待验证后给出。",
            "longTerm": "待验证后给出。",
            "businessImpact": "待验证后评估。"
        }
    }
    hops: list[dict[str, Any]] = []
    if related_entry:
        hops.append(make_hop("entry", related_entry, "source"))
    if related_source:
        hops.append(make_hop("source", related_source, "source"))
    hops.append(make_hop("sink", sink, "sink"))
    callchain = {
        "schemaVersion": "callchain/v1",
        "id": callchain_id,
        "findingId": finding_id,
        "hops": hops,
        "reachability": {
            "sinkReachable": bool(related_entry),
            "sourceControllable": bool(related_source),
            "protectionMissing": False,
            "notes": "static source/entry/sink association; validation evidence required before confirmation"
        }
    }
    capability = {
        "schemaVersion": "capability/v1",
        "id": cap_id,
        "providerFinding": finding_id,
        "name": cap_name,
        "provides": [cap_name],
        "requires": ["source-controllability"],
        "authLevel": "unknown",
        "operationClass": operation_class,
        "evidenceRefs": [],
        "requestRefs": [],
        "constraints": ["candidate capability; not confirmed"],
        "confidence": "hypothesis"
    }
    return finding, callchain, capability


def is_sensitive_entry(entry: dict[str, Any]) -> bool:
    haystack = " ".join(str(entry.get(key, "")) for key in ("path", "location", "evidence", "method")).lower()
    return any(keyword in haystack for keyword in SENSITIVE_ENTRY_KEYWORDS)


def control_operation_class(entry: dict[str, Any]) -> str:
    haystack = " ".join(str(entry.get(key, "")) for key in ("path", "location", "evidence", "method")).lower()
    if any(keyword in haystack for keyword in ("delete", "remove", "import", "config", "role", "permission")):
        return "state-changing"
    return "read-only"


def make_control_finding(idx: int, entry: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    finding_id = f"vul-{idx:03d}"
    callchain_id = f"cc-{idx:04d}"
    cap_id = f"cap-{idx:04d}"
    operation_class = control_operation_class(entry)
    impacts = {
        "confidentiality": "high",
        "integrity": "high" if operation_class in {"state-changing", "write-capable"} else "none",
        "availability": "none",
    }
    finding = {
        "schemaVersion": "finding/v1",
        "id": finding_id,
        "sourceIds": [entry.get("id", f"entry-{idx:04d}")],
        "status": "candidate",
        "title": f"访问控制候选（{entry.get('location', entry.get('path', 'entry'))}）",
        "category": "authz",
        "severity": "high" if operation_class != "read-only" else "medium",
        "validationLevel": "V0",
        "authLevel": entry.get("authRequired", "unknown"),
        "operationClasses": [operation_class],
        "entry": {
            "type": entry.get("type", "unknown"),
            "method": entry.get("method", ""),
            "path": entry.get("path", ""),
            "location": entry.get("location", ""),
        },
        "callChain": [callchain_id],
        "impacts": impacts,
        "cvss": cvss_for_impacts(impacts),
        "preconditions": ["需确认入口认证、授权和资源归属控制"],
        "requiresCapabilities": [],
        "providesCapabilities": [cap_id],
        "evidenceRefs": [],
        "pocRefs": [],
        "cleanupRefs": [],
        "blockers": ["auth/authz/resource ownership requires validation evidence"],
        "fix": {
            "emergency": "待验证后给出。",
            "longTerm": "待验证后给出。",
            "businessImpact": "待验证后评估。"
        }
    }
    callchain = {
        "schemaVersion": "callchain/v1",
        "id": callchain_id,
        "findingId": finding_id,
        "hops": [make_hop("control", entry, "conditional")],
        "reachability": {
            "sinkReachable": True,
            "sourceControllable": False,
            "protectionMissing": False,
            "notes": "sensitive entry/control candidate; authorization validation required before confirmation"
        }
    }
    capability = {
        "schemaVersion": "capability/v1",
        "id": cap_id,
        "providerFinding": finding_id,
        "name": "access-sensitive-function",
        "provides": ["access-sensitive-function"],
        "requires": ["authz-validation"],
        "authLevel": entry.get("authRequired", "unknown"),
        "operationClass": operation_class,
        "evidenceRefs": [],
        "requestRefs": [],
        "constraints": ["candidate capability; not confirmed"],
        "confidence": "hypothesis"
    }
    return finding, callchain, capability


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run audit worker")
    parser.add_argument("--audit-dir", default="audit-v2")
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args(argv)

    audit_dir = Path(args.audit_dir)
    attack_surface = load_json(audit_dir / "attack_surface.json")
    sinks = attack_surface.get("sinks") or []
    entries = attack_surface.get("entries") or []
    sources = attack_surface.get("sources") or []

    findings: list[dict[str, Any]] = []
    callchains: list[dict[str, Any]] = []
    capabilities: list[dict[str, Any]] = []
    for idx, sink in enumerate(sinks[: args.limit], 1):
        finding, callchain, capability = make_finding(idx, sink, entries, sources)
        findings.append(finding)
        callchains.append(callchain)
        capabilities.append(capability)
    next_idx = len(findings) + 1
    for entry in entries:
        if len(findings) >= args.limit:
            break
        if entry.get("authRequired", "unknown") not in ("unknown", "none") or not is_sensitive_entry(entry):
            continue
        finding, callchain, capability = make_control_finding(next_idx, entry)
        findings.append(finding)
        callchains.append(callchain)
        capabilities.append(capability)
        next_idx += 1

    append_jsonl(audit_dir / "findings.jsonl", findings)
    append_jsonl(audit_dir / "callchains.jsonl", callchains)
    append_jsonl(audit_dir / "capabilities.jsonl", capabilities)
    print(json.dumps({
        "ok": True,
        "findings": len(findings),
        "callchains": len(callchains),
        "capabilities": len(capabilities)
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
