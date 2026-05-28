#!/usr/bin/env python3
"""chain worker.

Builds attack-chain artifacts only from explicit capability dependencies. It
does not infer chains from co-occurrence, and it does not upgrade hypothesis
facts to confirmed facts.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


CONFIRMED_FINDING_STATUSES = {"confirmed", "reported", "patched"}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text:
            rows.append(json.loads(text))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row.get("id")): row for row in rows if row.get("id")}


def chain_status(provider: dict[str, Any], consumer: dict[str, Any]) -> str:
    if (
        provider.get("confidence") == "confirmed"
        and consumer.get("status") in CONFIRMED_FINDING_STATUSES
    ):
        return "confirmed"
    return "hypothesis"


def make_chain(idx: int, capability: dict[str, Any], consumer: dict[str, Any]) -> dict[str, Any]:
    cap_id = str(capability["id"])
    finding_id = str(consumer["id"])
    provider_id = str(capability["providerFinding"])
    provided = capability.get("provides") or [capability.get("name", cap_id)]
    resulting_caps = consumer.get("providesCapabilities") or []
    evidence_refs = sorted(set((capability.get("evidenceRefs") or []) + (consumer.get("evidenceRefs") or [])))
    request_refs = sorted(set((capability.get("requestRefs") or []) + (consumer.get("pocRefs") or [])))

    return {
        "schemaVersion": "attack-chain/v1",
        "id": f"chain-{idx:04d}",
        "chainType": "mixed",
        "status": chain_status(capability, consumer),
        "nodes": [
            {"type": "finding", "id": provider_id},
            {"type": "capability", "id": cap_id},
            {"type": "finding", "id": finding_id},
        ],
        "edges": [
            {
                "from": cap_id,
                "to": finding_id,
                "transfer": "capability supplies an explicit required capability: " + ", ".join(provided),
                "evidenceRefs": evidence_refs,
            }
        ],
        "resultingCapability": resulting_caps[0] if resulting_caps else finding_id,
        "valueIncrease": ["reduces-preconditions", "enables-followup"],
        "reproduceRefs": request_refs,
        "cleanupRefs": consumer.get("cleanupRefs") or [],
    }


def build_graph(chains: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, str]] = {}
    edges: list[dict[str, str]] = []
    for chain in chains:
        for node in chain["nodes"]:
            nodes[node["id"]] = {"id": node["id"], "type": node["type"]}
        for edge in chain["edges"]:
            edges.append({
                "chainId": chain["id"],
                "from": edge["from"],
                "to": edge["to"],
                "transfer": edge["transfer"],
            })
    return {
        "schemaVersion": "attack-graph/v1",
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": edges,
        "chains": [chain["id"] for chain in chains],
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run chain worker")
    parser.add_argument("--audit-dir", default="audit-v2")
    args = parser.parse_args(argv)

    audit_dir = Path(args.audit_dir)
    findings = by_id(load_jsonl(audit_dir / "findings.jsonl"))
    capabilities = by_id(load_jsonl(audit_dir / "capabilities.jsonl"))

    chains: list[dict[str, Any]] = []
    for finding in findings.values():
        required = finding.get("requiresCapabilities") or []
        for cap_id in required:
            capability = capabilities.get(cap_id)
            if not capability:
                continue
            chains.append(make_chain(len(chains) + 1, capability, finding))

    write_jsonl(audit_dir / "attack_chains.jsonl", chains)
    write_json(audit_dir / "attack_graph.json", build_graph(chains))
    print(json.dumps({
        "ok": True,
        "attackChains": len(chains),
        "confirmed": sum(1 for chain in chains if chain["status"] == "confirmed"),
        "hypothesis": sum(1 for chain in chains if chain["status"] == "hypothesis"),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
